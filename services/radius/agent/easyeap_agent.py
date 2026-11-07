"""EasyEAP radius-agent.

Supervises FreeRADIUS and keeps it supplied with configuration and authorization data from the EasyEAP API, while
never making authentication depend on the API being reachable:

* configuration: pulled, rendered into a staging tree, validated with `freeradius -C`, swapped in atomically, then
  FreeRADIUS restarts. An invalid configuration is reported and the running one is kept. On start without the API,
  the last applied configuration is used.
* authorization: per-tenant snapshots are written into a local SQLite database (WAL) that FreeRADIUS reads. Each
  tenant's `valid_until` only advances when fresh data arrives, so a long outage fails closed.
* events: FreeRADIUS writes JSON lines to the spool; the agent ships them in batches and deletes shipped files.
* MAC allow list: its own versioned part of each tenant's snapshot, in the same store (authz_mac, meta_mac).
* device administration: the admin part of each tenant's snapshot (admin.json, 0600, never read by FreeRADIUS) and
  the TACACS+ service (tacacs.py), started once a device has admin logins on and supervised like FreeRADIUS.
* CoA: pending Disconnect-Requests (and Cisco CoA-Requests) are sent with radclient and the result reported back.
* logs: the agent's own messages and FreeRADIUS warnings and errors go to EasyEAP's system log (and from there to
  remote syslog). They wait in a bounded in-memory buffer while the API is away; FreeRADIUS output still reaches the
  container log unchanged.
"""
from __future__ import annotations

import collections
import json
import logging
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from render import render  # noqa: E402

STATE = Path(os.environ.get("EASYEAP_RADIUS_STATE", "/var/lib/easyeap-radius"))
API = os.environ.get("EASYEAP_API_URL", "http://easyeap-api:8000").rstrip("/")
TOKEN_FILE = os.environ.get("EASYEAP_AGENT_TOKEN_FILE", "/run/secrets/agent_token")
AGENT_ID = os.environ.get("EASYEAP_AGENT_ID", socket.gethostname())[:64]
POLL = float(os.environ.get("EASYEAP_POLL_SECONDS", "15"))
LIVE = STATE / "raddb" / "live"
DB = STATE / "authz.db"
SPOOL = STATE / "spool"
ADMIN_FILE = STATE / "admin.json"

# What this agent's renderer supports beyond 1.0.1, reported in its status so the console offers only what RADIUS runs.
FEATURES = ["wired", "mab", "coa-request", "tacacs"]

log = logging.getLogger("radius-agent")
_stop = threading.Event()
_nudge = threading.Event()

# ── System log buffer ───────────────────────────────────────────────────────

LOG_BUFFER_MAX = 2000
_logbuf: collections.deque[dict] = collections.deque(maxlen=LOG_BUFFER_MAX)
_logbuf_lock = threading.Lock()
_FR_LINE = re.compile(r"^.*? : (Error|ERROR|Warning|WARNING|WARN|Auth|Info|Debug|Proxy): (.*)$")


def buffer_log(level: str, source: str, message: str, logger: str = "") -> None:
    with _logbuf_lock:
        _logbuf.append({"at": time.time(), "level": level, "source": source, "logger": logger, "message": message[:4000]})


class BufferHandler(logging.Handler):
    """The agent's own INFO and above, for EasyEAP's system log."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = {logging.WARNING: "warning", logging.ERROR: "error", logging.CRITICAL: "critical"}.get(record.levelno, "info")
            msg = record.getMessage()
            if record.exc_info:
                msg = f"{msg}\n{logging.Formatter().formatException(record.exc_info)}"
            buffer_log(level, "radius-agent", msg, record.name)
        except Exception:  # noqa: BLE001, S110 — logging must never break the agent
            pass


def classify_freeradius(line: str) -> tuple[str, str] | None:
    """(level, message) for FreeRADIUS warnings and errors; None for everything else (info, auth results)."""
    m = _FR_LINE.match(line.rstrip())
    if not m:
        return None
    kind, msg = m.group(1).lower(), m.group(2)
    if kind == "error":
        return "error", msg
    if kind in ("warning", "warn"):
        return "warning", msg
    # A wrong shared secret is logged at Info and the request dropped unanswered, so the NAS only sees a timeout. It's
    # the one trace of the mistake: keep it (the console's "waiting for the first request" explains it).
    if kind == "info" and "invalid Message-Authenticator" in msg:
        return "warning", msg
    return None


def pump_freeradius(stream) -> None:
    """Copy FreeRADIUS output to the container log line by line, keeping warnings and errors for the system log.
    Runs for the life of one FreeRADIUS process; it must keep reading, or FreeRADIUS would block on a full pipe."""
    for raw in iter(stream.readline, b""):
        try:
            sys.stdout.buffer.write(raw)
            sys.stdout.flush()
        except Exception:  # noqa: BLE001, S110
            pass
        try:
            hit = classify_freeradius(raw.decode("utf-8", "replace"))
            if hit:
                buffer_log(hit[0], "freeradius", hit[1])
        except Exception:  # noqa: BLE001, S110
            pass


def ship_logs() -> int:
    """Send buffered log lines; on failure they go back to the front of the buffer (oldest dropped when full)."""
    sent = 0
    while True:
        with _logbuf_lock:
            batch = [_logbuf.popleft() for _ in range(min(len(_logbuf), 500))]
        if not batch:
            return sent
        try:
            api("POST", "/api/agent/logs", {"items": batch})
        except Exception:
            with _logbuf_lock:
                room = LOG_BUFFER_MAX - len(_logbuf)
                _logbuf.extendleft(reversed(batch[-room:] if room > 0 else []))
            raise
        sent += len(batch)


def token() -> str:
    env = os.environ.get("EASYEAP_AGENT_TOKEN")
    if env:
        return env
    return Path(TOKEN_FILE).read_text().strip()


def api(method: str, path: str, body: dict | None = None, timeout: float = 20) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — fixed internal URL
        return json.loads(r.read() or b"{}")


# ── Authorization snapshot store ────────────────────────────────────────────


def db(path: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or DB, timeout=5, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (tenant TEXT PRIMARY KEY, version INTEGER NOT NULL, built_at INTEGER NOT NULL, "
                 "valid_until INTEGER NOT NULL, applied_at INTEGER NOT NULL, digest TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS authz (tenant TEXT NOT NULL, serial TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT, "
                 "vlan TEXT, rule_id TEXT, username TEXT, extra TEXT, not_after INTEGER, PRIMARY KEY (tenant, serial))")
    # The VLAN on switch ports, where the snapshot gives one ('' = assign none). A separate table, so `authz` stays
    # exactly as older agents and configurations read and write it; the version ties each row to the snapshot that
    # wrote it, so rows left behind by a rollback to an older agent are ignored.
    conn.execute("CREATE TABLE IF NOT EXISTS authz_wired (tenant TEXT NOT NULL, serial TEXT NOT NULL, version INTEGER NOT NULL, "
                 "vlan TEXT NOT NULL, PRIMARY KEY (tenant, serial))")
    # The MAC allow list (docs/plans/mac-auth.md §4), with its own version: one row per listed MAC. vlan '' = assign
    # none; expires_at is checked by RADIUS at lookup time, so an entry expiring needs no new version.
    conn.execute("CREATE TABLE IF NOT EXISTS authz_mac (tenant TEXT NOT NULL, mac TEXT NOT NULL, version INTEGER NOT NULL, outcome TEXT NOT NULL, "
                 "reason TEXT, vlan TEXT NOT NULL, device_id TEXT, group_id TEXT, expires_at INTEGER, PRIMARY KEY (tenant, mac))")
    conn.execute("CREATE TABLE IF NOT EXISTS meta_mac (tenant TEXT PRIMARY KEY, version INTEGER NOT NULL, applied_at INTEGER NOT NULL)")
    return conn


def applied_versions(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: v for t, v in conn.execute("SELECT tenant, version FROM meta")}


def applied_mac_versions(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: v for t, v in conn.execute("SELECT tenant, version FROM meta_mac")}


_MAC = re.compile(r"^[0-9A-F]{12}$")


def apply_mac(conn: sqlite3.Connection, tid: str, version: int, entries: list[dict]) -> None:
    rows = []
    for e in entries:
        mac = str(e.get("mac") or "")
        if not _MAC.match(mac) or e.get("outcome") not in ("allow", "deny"):
            continue  # never trust a malformed row into a SQL lookup key
        rows.append((tid, mac, version, e["outcome"], e.get("reason"), str(e["vlan"]) if e.get("vlan") is not None else "",
                     e.get("device_id"), e.get("group_id"), int(e["expires_at"]) if e.get("expires_at") else None))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM authz_mac WHERE tenant = ?", (tid,))
        conn.executemany("INSERT INTO authz_mac VALUES (?,?,?,?,?,?,?,?,?)", rows)
        conn.execute("INSERT INTO meta_mac VALUES (?,?,?) ON CONFLICT(tenant) DO UPDATE SET version=excluded.version, applied_at=excluded.applied_at",
                     (tid, version, int(time.time())))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    log.info("Applied MAC allow list for tenant %s: version %s, %d entries", tid, version, len(rows))


def apply_snapshot(conn: sqlite3.Connection, snap: dict) -> None:
    tid = snap["tenant_id"]
    now = int(time.time())
    if "mac_entries" in snap and isinstance(snap.get("mac_version"), int):
        apply_mac(conn, tid, snap["mac_version"], snap["mac_entries"] or [])
    if snap.get("unchanged"):
        conn.execute("UPDATE meta SET valid_until = MAX(valid_until, ?) WHERE tenant = ? AND version = ?", (snap["valid_until"], tid, snap["version"]))
        return
    rows, wired = [], []
    for e in snap["entries"]:
        extra = ";".join(f"{a['name']}={a['value']}" for a in e.get("attributes", []) if ";" not in a["value"])
        rows.append((tid, e["serial"], e["outcome"], e.get("reason"), str(e["vlan"]) if e.get("vlan") is not None else None,
                     e.get("rule_id"), e.get("username"), extra, e.get("not_after")))
        # No key (an API from before wired 802.1X): no row, so switch ports get the Wi-Fi VLAN as they did then.
        if "wired_vlan" in e:
            wired.append((tid, e["serial"], snap["version"], str(e["wired_vlan"]) if e["wired_vlan"] is not None else ""))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM authz WHERE tenant = ?", (tid,))
        conn.execute("DELETE FROM authz_wired WHERE tenant = ?", (tid,))
        conn.executemany("INSERT INTO authz VALUES (?,?,?,?,?,?,?,?,?)", rows)
        conn.executemany("INSERT INTO authz_wired VALUES (?,?,?,?)", wired)
        conn.execute("INSERT INTO meta VALUES (?,?,?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET version=excluded.version, "
                     "built_at=excluded.built_at, valid_until=excluded.valid_until, applied_at=excluded.applied_at, digest=excluded.digest",
                     (tid, snap["version"], snap["built_at"], snap["valid_until"], now, snap.get("digest")))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    log.info("Applied snapshot for tenant %s: version %s, %d entries", tid, snap["version"], len(rows))


def drop_removed_tenants(conn: sqlite3.Connection, active: list[str]) -> None:
    for (t,) in conn.execute("SELECT tenant FROM meta").fetchall():
        if t not in active:
            conn.execute("DELETE FROM authz WHERE tenant = ?", (t,))
            conn.execute("DELETE FROM authz_wired WHERE tenant = ?", (t,))
            conn.execute("DELETE FROM meta WHERE tenant = ?", (t,))
    for (t,) in conn.execute("SELECT tenant FROM meta_mac").fetchall():
        if t not in active:
            conn.execute("DELETE FROM authz_mac WHERE tenant = ?", (t,))
            conn.execute("DELETE FROM meta_mac WHERE tenant = ?", (t,))


# ── Device administration (docs/plans/device-admin.md §4) ───────────────────


def load_admin(path: Path | None = None) -> dict:
    try:
        data = json.loads((path or ADMIN_FILE).read_text())
        return data if isinstance(data.get("tenants"), dict) else {"tenants": {}}
    except (OSError, ValueError, AttributeError):
        return {"tenants": {}}


def write_admin(state: dict, path: Path | None = None) -> None:
    """Atomically, readable by this user only: it holds TACACS+ keys, password hashes and TOTP secrets."""
    path = path or ADMIN_FILE
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, separators=(",", ":"))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def apply_admin(state: dict, snap: dict) -> bool:
    """Merge one tenant's admin part. True when admin.json must be rewritten: a new version, or validity extended by
    more than five minutes (the TACACS+ service answers ERROR once a tenant's data is past valid_until)."""
    if not isinstance(snap.get("admin_version"), int):
        return False
    tid, version, until = snap["tenant_id"], snap["admin_version"], int(snap.get("admin_valid_until") or 0)
    cur = state["tenants"].get(tid)
    if isinstance(snap.get("admin"), dict):
        state["tenants"][tid] = {"version": version, "valid_until": until, "admin": snap["admin"]}
        log.info("Applied device-admin data for tenant %s: version %s, %d devices, %d local accounts, %d directory accounts", tid, version,
                 len(snap["admin"].get("clients") or []), len(snap["admin"].get("users") or []), len(snap["admin"].get("candidates") or []))
        return True
    if cur and cur.get("version") == version and until - int(cur.get("valid_until") or 0) > 300:
        cur["valid_until"] = until
        return True
    return False


def admin_versions(state: dict) -> dict[str, int]:
    return {t: e["version"] for t, e in state["tenants"].items() if isinstance(e.get("version"), int)}


def admin_devices(state: dict) -> int:
    return sum(len((e.get("admin") or {}).get("clients") or []) for e in state["tenants"].values())


class Tacacs:
    """The TACACS+ service as a child process, like FreeRADIUS: restarted if it exits, stopped when no device has admin
    logins on."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()

    def start(self) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return
            log.info("Starting the TACACS+ service")
            self.proc = subprocess.Popen([sys.executable, str(Path(__file__).parent / "tacacs.py")], stdout=subprocess.PIPE,  # noqa: S603
                                         stderr=subprocess.STDOUT)
            threading.Thread(target=pump_child, args=(self.proc.stdout, "tacacs"), name="tacacs-log", daemon=True).start()

    def stop(self) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                log.info("Stopping the TACACS+ service")
                self.proc.terminate()
                try:
                    self.proc.wait(10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self.proc = None

    @property
    def running(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)

    def ensure(self, wanted: bool) -> None:
        if wanted and not self.running:
            self.start()
        elif not wanted and self.proc is not None:
            self.stop()


_CHILD_LINE = re.compile(r"^\S+ \S+ (?:tacacs) (WARNING|ERROR|CRITICAL) (.*)$")


def pump_child(stream, source: str) -> None:
    """Copy a child's output to the container log; its warnings and errors also go to the system log."""
    for raw in iter(stream.readline, b""):
        try:
            sys.stdout.buffer.write(raw)
            sys.stdout.flush()
            m = _CHILD_LINE.match(raw.decode("utf-8", "replace").rstrip())
            if m:
                buffer_log(m.group(1).lower(), "radius-agent", m.group(2), source)
        except Exception:  # noqa: BLE001, S110
            pass


# ── FreeRADIUS supervision ──────────────────────────────────────────────────


class Radius:
    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()
        self.restarts = 0

    def start(self) -> None:
        if not (LIVE / "radiusd.conf").exists():
            log.warning("No RADIUS configuration yet; waiting for the first one from EasyEAP")
            return
        with self.lock:
            if self.proc and self.proc.poll() is None:
                return
            log.info("Starting FreeRADIUS")
            self.proc = subprocess.Popen(["freeradius", "-f", "-l", "stdout", "-d", str(LIVE)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # noqa: S603, S607
            threading.Thread(target=pump_freeradius, args=(self.proc.stdout,), name="freeradius-log", daemon=True).start()

    def stop(self) -> None:
        with self.lock:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(10)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self.proc = None

    def restart(self) -> None:
        self.stop()
        self.start()

    @property
    def running(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)

    def watchdog(self) -> None:
        while not _stop.is_set():
            if (LIVE / "radiusd.conf").exists() and not self.running:
                self.restarts += 1
                time.sleep(min(30, 2 * self.restarts))
                self.start()
            else:
                self.restarts = 0
            _stop.wait(2)


def apply_config(radius: Radius, desired: dict) -> tuple[bool, str | None]:
    staging = STATE / "raddb" / f"staging-{int(time.time())}"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        render(desired, staging, str(STATE))
        # Validate against the staging tree (paths inside it point to staging; re-render for live after the check).
        check = subprocess.run(["freeradius", "-C", "-d", str(staging)], capture_output=True, text=True, timeout=60)
        if check.returncode != 0:
            lines = [ln for ln in (check.stdout + check.stderr).splitlines() if "rror" in ln or "nvalid" in ln or "ailed" in ln]
            return False, "\n".join(lines[-12:]) or "FreeRADIUS rejected the configuration"
        new_live = STATE / "raddb" / "live.new"
        if new_live.exists():
            shutil.rmtree(new_live)
        render(desired, new_live, str(STATE))
        _rewrite_paths(new_live, str(new_live), str(LIVE))
        old = STATE / "raddb" / "live.old"
        if old.exists():
            shutil.rmtree(old)
        if LIVE.exists():
            LIVE.rename(old)
        new_live.rename(LIVE)
        (STATE / "config.json").write_text(json.dumps({"version": desired["version"], "applied_at": int(time.time()),
                                                       "tenants": [t["id"] for t in desired.get("tenants", [])],
                                                       # Per tenant: the change counter this configuration includes, so
                                                       # the console knows when a change (e.g. Enforce) is live.
                                                       "config_versions": {t["id"]: t.get("config_version") for t in desired.get("tenants", [])}}))
        radius.restart()
        return True, None
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _rewrite_paths(tree: Path, old: str, new: str) -> None:
    for p in tree.rglob("*"):
        if p.is_file() and p.suffix not in (".pem", ".key"):
            text = p.read_text()
            if old in text:
                p.write_text(text.replace(old, new))


def current_config_version() -> str | None:
    try:
        return json.loads((STATE / "config.json").read_text())["version"]
    except (OSError, ValueError, KeyError):
        return None


def applied_config_versions() -> dict[str, int]:
    """Per tenant, the config_version of the configuration FreeRADIUS is running ({} if applied by an older agent)."""
    try:
        got = json.loads((STATE / "config.json").read_text()).get("config_versions")
        return {str(k): v for k, v in got.items() if isinstance(v, int)} if isinstance(got, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def served_tenants() -> list[str] | None:
    """Tenant IDs in the configuration FreeRADIUS is running (None if it was applied by an older agent)."""
    try:
        ids = json.loads((STATE / "config.json").read_text()).get("tenants")
        return [str(x) for x in ids] if isinstance(ids, list) else None
    except (OSError, ValueError):
        return None


# ── Event shipping ──────────────────────────────────────────────────────────


def _v(rec: dict, *names: str) -> str | None:
    for n in names:
        for key in (n, f"control:{n}", f"reply:{n}"):
            if key in rec and rec[key] not in (None, ""):
                val = rec[key]
                text = "; ".join(map(str, val)) if isinstance(val, list) else str(val)
                return text.replace("\\/", "/")
    return None


ADMIN_FIELDS = ("uid", "ts", "tenant", "client_id", "nas_ip", "username", "user_id", "source", "kind", "result", "reason", "priv_lvl",
                "command", "rem_addr", "port", "task_id", "message")


def transform(kind: str, item: dict) -> dict:
    if kind == "admin-events":
        return {k: item.get(k) for k in ADMIN_FIELDS}  # written by tacacs.py, already in shape (commands masked)
    rec = item.get("rec") or {}
    if kind == "events":
        return {"uid": item.get("uid"), "ts": item.get("ts"), "result": item.get("result"), "tenant": _v(rec, "EasyEAP-Tenant"),
                "user": _v(rec, "User-Name"), "serial": _v(rec, "EasyEAP-Serial", "TLS-Client-Cert-Serial"), "issuer": _v(rec, "TLS-Client-Cert-Issuer"),
                "mac": _v(rec, "Calling-Station-Id"), "called": _v(rec, "Called-Station-Id"), "nas_ip": _v(rec, "NAS-IP-Address", "Packet-Src-IP-Address"),
                "src_ip": _v(rec, "EasyEAP-Source", "Packet-Src-IP-Address"),
                "vlan": _v(rec, "EasyEAP-Vlan"), "rule": _v(rec, "EasyEAP-Rule"), "reason": _v(rec, "EasyEAP-Reason"), "message": _v(rec, "Module-Failure-Message"),
                "network": _v(rec, "EasyEAP-Network"), "port_id": _v(rec, "NAS-Port-Id"), "port_type": _v(rec, "NAS-Port-Type"),
                "monitor": _v(rec, "EasyEAP-Monitor"), "method": _v(rec, "EasyEAP-Method"), "device_mac": _v(rec, "EasyEAP-Mac"),
                "mac_device": _v(rec, "EasyEAP-MacDevice"), "mac_group": _v(rec, "EasyEAP-MacGroup"), "service_type": _v(rec, "Service-Type")}
    return {"ts": item.get("ts"), "tenant": _v(rec, "EasyEAP-Tenant"), "status": _v(rec, "Acct-Status-Type"), "session_id": _v(rec, "Acct-Session-Id"),
            "nas_ip": _v(rec, "NAS-IP-Address", "Packet-Src-IP-Address"), "src_ip": _v(rec, "EasyEAP-Source", "Packet-Src-IP-Address"),
            "user": _v(rec, "User-Name"), "mac": _v(rec, "Calling-Station-Id"), "called": _v(rec, "Called-Station-Id"), "framed_ip": _v(rec, "Framed-IP-Address"), "vlan": _v(rec, "Tunnel-Private-Group-Id"),
            "in_octets": _v(rec, "Acct-Input-Octets"), "out_octets": _v(rec, "Acct-Output-Octets"), "cause": _v(rec, "Acct-Terminate-Cause"),
            "network": _v(rec, "EasyEAP-Network"), "port_id": _v(rec, "NAS-Port-Id")}


def ship_events() -> int:
    offsets_file = STATE / "spool-offsets.json"
    try:
        offsets = json.loads(offsets_file.read_text())
    except (OSError, ValueError):
        offsets = {}
    sent = 0
    current_hour = time.strftime("%Y%m%d%H", time.gmtime())
    for f in sorted(SPOOL.glob("*.jsonl")):
        kind = "events" if f.name.startswith("auth-") else "admin-events" if f.name.startswith("admin-") else "accounting"
        off = offsets.get(f.name, 0)
        with f.open("rb") as fh:
            fh.seek(off)
            data = fh.read(4_000_000)
        if not data:
            if not f.name.endswith(f"{current_hour}.jsonl") and time.time() - f.stat().st_mtime > 120:
                f.unlink(missing_ok=True)
                offsets.pop(f.name, None)
            continue
        cut = data.rfind(b"\n")
        if cut < 0:
            continue
        items = []
        for line in data[:cut].splitlines():
            try:
                items.append(transform(kind, json.loads(line)))
            except ValueError:
                log.warning("Skipping malformed event line in %s", f.name)
        for i in range(0, len(items), 1000):
            api("POST", f"/api/agent/{kind}", {"items": items[i:i + 1000]})
        offsets[f.name] = off + cut + 1
        sent += len(items)
    offsets_file.write_text(json.dumps(offsets))
    return sent


# ── CoA ─────────────────────────────────────────────────────────────────────


# What radclient sends for each request kind, and the answers that mean yes / no.
COA_KINDS = {"disconnect": ("disconnect", "Disconnect-ACK", "Disconnect-NAK"),
             "reauthenticate": ("coa", "CoA-ACK", "CoA-NAK"), "bounce": ("coa", "CoA-ACK", "CoA-NAK")}


def send_coa(desired: dict | None) -> None:
    if not desired:
        return
    secrets = {c["id"]: c["secret"] for t in desired.get("tenants", []) for c in t.get("clients", [])}
    for r in api("GET", "/api/agent/coa").get("requests", []):
        secret = secrets.get(r["nas_client_id"])
        if not secret:
            api("POST", f"/api/agent/coa/{r['id']}", {"status": "failed", "detail": "Controller not in current configuration"})
            continue
        command, ack, nak = COA_KINDS.get(r.get("kind") or "disconnect", COA_KINDS["disconnect"])
        attrs = "\n".join(f'{k} = "{str(v).replace(chr(34), "")}"' for k, v in r["attributes"].items() if k and v) + "\n"
        try:
            p = subprocess.run(["radclient", "-x", "-t", "3", "-r", "2", f"{r['address']}:{r['port']}", command, secret],
                               input=attrs, capture_output=True, text=True, timeout=20)
            out = p.stdout + p.stderr
            status = "acked" if ack in out else "nak" if nak in out else "failed"
            what = "disconnect" if command == "disconnect" else "change"
            detail = f"Controller acknowledged the {what}" if status == "acked" else (
                f"Controller refused the {what} (check CoA settings and the session identifiers)" if status == "nak" else
                "No answer from the controller (check that CoA is enabled and UDP %s is allowed)" % r["port"])
        except Exception as exc:  # noqa: BLE001
            status, detail = "failed", str(exc)[:300]
        api("POST", f"/api/agent/coa/{r['id']}", {"status": status, "detail": detail})


# ── Main loop ───────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s radius-agent %(levelname)s %(message)s", stream=sys.stdout)
    logging.getLogger().addHandler(BufferHandler(level=logging.INFO))
    for d in (STATE / "raddb", SPOOL, STATE / "run", STATE / "radacct"):
        d.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    conn = db()
    radius = Radius()
    tacacs = Tacacs()
    admin = load_admin()
    tacacs.ensure(admin_devices(admin) > 0)  # last known admin data, independent of the API

    def stop(*_):
        _stop.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGHUP, lambda *_: _nudge.set())
    radius.start()  # last known configuration, independent of the API
    threading.Thread(target=radius.watchdog, daemon=True).start()
    desired: dict | None = None
    config_error: str | None = None
    last_ok = 0.0
    while not _stop.is_set():
        try:
            desired = api("GET", "/api/agent/config")
            # served_tenants() is None, or the per-tenant change counters are missing, once after upgrading from an agent
            # that didn't record them: re-apply to record them.
            if (desired.get("version") != current_config_version() or not (LIVE / "radiusd.conf").exists() or served_tenants() is None
                    or (desired.get("tenants") and not applied_config_versions())):
                if desired.get("tenants"):
                    ok, err = apply_config(radius, desired)
                    config_error = err
                    if ok:
                        log.info("Applied configuration %s (%d tenants)", desired["version"], len(desired["tenants"]))
                    else:
                        log.error("Configuration rejected, keeping the running one: %s", err)
            have = ",".join(f"{t}:{v}" for t, v in applied_versions(conn).items())
            have_mac = ",".join(f"{t}:{v}" for t, v in applied_mac_versions(conn).items())
            have_admin = ",".join(f"{t}:{v}" for t, v in admin_versions(admin).items())
            snaps = api("GET", f"/api/agent/snapshots?have={have}&have_mac={have_mac}&have_admin={have_admin}")
            changed = False
            for snap in snaps.get("snapshots", []):
                apply_snapshot(conn, snap)
                changed |= apply_admin(admin, snap)
            drop_removed_tenants(conn, snaps.get("tenants", []))
            for t in [t for t in admin["tenants"] if t not in snaps.get("tenants", [])]:
                del admin["tenants"][t]
                changed = True
            if changed:
                write_admin(admin)
            tacacs.ensure(admin_devices(admin) > 0)
            ship_events()
            ship_logs()
            send_coa(desired)
            api("POST", "/api/agent/status", {"agent_id": AGENT_ID, "config_version": current_config_version() or "", "config_ok": config_error is None,
                                              "config_error": config_error, "snapshot_versions": applied_versions(conn), "radius_running": radius.running,
                                              "detail": {"tenants": len((desired or {}).get("tenants", [])), "tenant_ids": served_tenants(),
                                                         "config_versions": applied_config_versions(), "features": FEATURES,
                                                         "mac_versions": applied_mac_versions(conn),
                                                         "admin_versions": admin_versions(admin), "tacacs_running": tacacs.running}})
            last_ok = time.time()
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if time.time() - last_ok > 60:
                log.warning("EasyEAP API unreachable (%s); RADIUS continues with local data", exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("Agent loop error: %s", exc)
        if admin_devices(admin) > 0 and not tacacs.running:
            tacacs.start()  # it exited: restart (watched every poll)
        _nudge.wait(POLL)
        _nudge.clear()
    tacacs.stop()
    radius.stop()


if __name__ == "__main__":
    main()

"""EasyEAP radius-agent.

Supervises FreeRADIUS and keeps it supplied with configuration and authorization data from the EasyEAP API, while
never making authentication depend on the API being reachable:

* configuration: pulled, rendered into a staging tree, validated with `freeradius -C`, swapped in atomically, then
  FreeRADIUS restarts. An invalid configuration is reported and the running one is kept. On start without the API,
  the last applied configuration is used.
* authorization: per-tenant snapshots are written into a local SQLite database (WAL) that FreeRADIUS reads. Each
  tenant's `valid_until` only advances when fresh data arrives, so a long outage fails closed.
* events: FreeRADIUS writes JSON lines to the spool; the agent ships them in batches and deletes shipped files.
* CoA: pending Disconnect-Requests are sent with radclient and the result reported back.
"""
from __future__ import annotations

import json
import logging
import os
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

log = logging.getLogger("radius-agent")
_stop = threading.Event()
_nudge = threading.Event()


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


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB, timeout=5, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (tenant TEXT PRIMARY KEY, version INTEGER NOT NULL, built_at INTEGER NOT NULL, "
                 "valid_until INTEGER NOT NULL, applied_at INTEGER NOT NULL, digest TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS authz (tenant TEXT NOT NULL, serial TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT, "
                 "vlan TEXT, rule_id TEXT, username TEXT, extra TEXT, not_after INTEGER, PRIMARY KEY (tenant, serial))")
    return conn


def applied_versions(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: v for t, v in conn.execute("SELECT tenant, version FROM meta")}


def apply_snapshot(conn: sqlite3.Connection, snap: dict) -> None:
    tid = snap["tenant_id"]
    now = int(time.time())
    if snap.get("unchanged"):
        conn.execute("UPDATE meta SET valid_until = MAX(valid_until, ?) WHERE tenant = ? AND version = ?", (snap["valid_until"], tid, snap["version"]))
        return
    rows = []
    for e in snap["entries"]:
        extra = ";".join(f"{a['name']}={a['value']}" for a in e.get("attributes", []) if ";" not in a["value"])
        rows.append((tid, e["serial"], e["outcome"], e.get("reason"), str(e["vlan"]) if e.get("vlan") is not None else None,
                     e.get("rule_id"), e.get("username"), extra, e.get("not_after")))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM authz WHERE tenant = ?", (tid,))
        conn.executemany("INSERT INTO authz VALUES (?,?,?,?,?,?,?,?,?)", rows)
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
            conn.execute("DELETE FROM meta WHERE tenant = ?", (t,))


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
            self.proc = subprocess.Popen(["freeradius", "-f", "-l", "stdout", "-d", str(LIVE)], stdout=sys.stdout, stderr=sys.stderr)

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
        (STATE / "config.json").write_text(json.dumps({"version": desired["version"], "applied_at": int(time.time())}))
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


# ── Event shipping ──────────────────────────────────────────────────────────


def _v(rec: dict, *names: str) -> str | None:
    for n in names:
        for key in (n, f"control:{n}", f"reply:{n}"):
            if key in rec and rec[key] not in (None, ""):
                val = rec[key]
                text = "; ".join(map(str, val)) if isinstance(val, list) else str(val)
                return text.replace("\\/", "/")
    return None


def transform(kind: str, item: dict) -> dict:
    rec = item.get("rec") or {}
    if kind == "events":
        return {"uid": item.get("uid"), "ts": item.get("ts"), "result": item.get("result"), "tenant": _v(rec, "EasyEAP-Tenant"),
                "user": _v(rec, "User-Name"), "serial": _v(rec, "EasyEAP-Serial", "TLS-Client-Cert-Serial"), "issuer": _v(rec, "TLS-Client-Cert-Issuer"),
                "mac": _v(rec, "Calling-Station-Id"), "called": _v(rec, "Called-Station-Id"), "nas_ip": _v(rec, "NAS-IP-Address", "Packet-Src-IP-Address"),
                "src_ip": _v(rec, "EasyEAP-Source", "Packet-Src-IP-Address"),
                "vlan": _v(rec, "EasyEAP-Vlan"), "rule": _v(rec, "EasyEAP-Rule"), "reason": _v(rec, "EasyEAP-Reason"), "message": _v(rec, "Module-Failure-Message")}
    return {"ts": item.get("ts"), "tenant": _v(rec, "EasyEAP-Tenant"), "status": _v(rec, "Acct-Status-Type"), "session_id": _v(rec, "Acct-Session-Id"),
            "nas_ip": _v(rec, "NAS-IP-Address", "Packet-Src-IP-Address"), "src_ip": _v(rec, "EasyEAP-Source", "Packet-Src-IP-Address"),
            "user": _v(rec, "User-Name"), "mac": _v(rec, "Calling-Station-Id"), "called": _v(rec, "Called-Station-Id"), "framed_ip": _v(rec, "Framed-IP-Address"), "vlan": _v(rec, "Tunnel-Private-Group-Id"),
            "in_octets": _v(rec, "Acct-Input-Octets"), "out_octets": _v(rec, "Acct-Output-Octets"), "cause": _v(rec, "Acct-Terminate-Cause")}


def ship_events() -> int:
    offsets_file = STATE / "spool-offsets.json"
    try:
        offsets = json.loads(offsets_file.read_text())
    except (OSError, ValueError):
        offsets = {}
    sent = 0
    current_hour = time.strftime("%Y%m%d%H", time.gmtime())
    for f in sorted(SPOOL.glob("*.jsonl")):
        kind = "events" if f.name.startswith("auth-") else "accounting"
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


def send_coa(desired: dict | None) -> None:
    if not desired:
        return
    secrets = {c["id"]: c["secret"] for t in desired.get("tenants", []) for c in t.get("clients", [])}
    for r in api("GET", "/api/agent/coa").get("requests", []):
        secret = secrets.get(r["nas_client_id"])
        if not secret:
            api("POST", f"/api/agent/coa/{r['id']}", {"status": "failed", "detail": "Controller not in current configuration"})
            continue
        attrs = "\n".join(f'{k} = "{str(v).replace(chr(34), "")}"' for k, v in r["attributes"].items() if k and v) + "\n"
        try:
            p = subprocess.run(["radclient", "-x", "-t", "3", "-r", "2", f"{r['address']}:{r['port']}", "disconnect", secret],
                               input=attrs, capture_output=True, text=True, timeout=20)
            out = p.stdout + p.stderr
            status = "acked" if "Disconnect-ACK" in out else "nak" if "Disconnect-NAK" in out else "failed"
            detail = "Controller acknowledged the disconnect" if status == "acked" else (
                "Controller refused the disconnect (check CoA settings and the session identifiers)" if status == "nak" else
                "No answer from the controller (check that CoA is enabled and UDP %s is allowed)" % r["port"])
        except Exception as exc:  # noqa: BLE001
            status, detail = "failed", str(exc)[:300]
        api("POST", f"/api/agent/coa/{r['id']}", {"status": status, "detail": detail})


# ── Main loop ───────────────────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s radius-agent %(levelname)s %(message)s", stream=sys.stdout)
    for d in (STATE / "raddb", SPOOL, STATE / "run", STATE / "radacct"):
        d.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    conn = db()
    radius = Radius()

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
            if desired.get("version") != current_config_version() or not (LIVE / "radiusd.conf").exists():
                if desired.get("tenants"):
                    ok, err = apply_config(radius, desired)
                    config_error = err
                    if ok:
                        log.info("Applied configuration %s (%d tenants)", desired["version"], len(desired["tenants"]))
                    else:
                        log.error("Configuration rejected, keeping the running one: %s", err)
            have = ",".join(f"{t}:{v}" for t, v in applied_versions(conn).items())
            snaps = api("GET", f"/api/agent/snapshots?have={have}")
            for snap in snaps.get("snapshots", []):
                apply_snapshot(conn, snap)
            drop_removed_tenants(conn, snaps.get("tenants", []))
            ship_events()
            send_coa(desired)
            api("POST", "/api/agent/status", {"agent_id": AGENT_ID, "config_version": current_config_version() or "", "config_ok": config_error is None,
                                              "config_error": config_error, "snapshot_versions": applied_versions(conn), "radius_running": radius.running,
                                              "detail": {"tenants": len((desired or {}).get("tenants", []))}})
            last_ok = time.time()
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            if time.time() - last_ok > 60:
                log.warning("EasyEAP API unreachable (%s); RADIUS continues with local data", exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("Agent loop error: %s", exc)
        _nudge.wait(POLL)
        _nudge.clear()
    radius.stop()


if __name__ == "__main__":
    main()

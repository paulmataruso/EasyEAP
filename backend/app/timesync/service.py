"""easyeap-time: keeps the host's chronyd on the console's NTP servers and reports how well the clock is kept.

docs/plans/ntp.md has the reasoning and the checked facts. In short:

* EasyEAP's servers live in /etc/chrony/sources.d/easyeap.sources (bind-mounted). After a change the service runs
  `chronyc reload sources`, which adds and removes sources without disturbing the others. The file is read again at
  every chronyd start, so the servers last through reboots and EasyEAP outages.
* "Use only these servers" switches the host's other sources off at runtime (`selectopts <IP> +noselect`), only while
  one of EasyEAP's is reachable, and re-applies that every 10 seconds (chronyd forgets it on restart, and a pool can
  replace an address). It undoes exactly what it did: those addresses are kept in the status. If none of EasyEAP's
  sources becomes usable within GRACE (they answer but chronyd won't set the clock from them: in chrony's default
  authselectmode a listed NTS server that can't be reached holds back the plain ones), the host's servers come back for
  RETRY, so a bad list never leaves the clock unsteered.
* With no chronyd to manage (no socket), the service measures the clock against the servers by SNTP every 5 minutes
  and reads the kernel's synchronised state, but steers nothing.
"""
from __future__ import annotations

import logging
import os
import signal
import statistics
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.timesync import chrony, config, kernel, sntp

log = logging.getLogger("easyeap.time")

SOURCES_DIR = Path(os.environ.get("EASYEAP_CHRONY_SOURCES_DIR", "/etc/chrony/sources.d"))
FILE_NAME = "easyeap.sources"
HEADER = ("# EasyEAP's NTP servers, from System → Time in the EasyEAP console. EasyEAP rewrites this file whenever the\n"
          "# servers change there: change them in the console, not here.\n")
TICK = 10
REPORT_EVERY = 30
SNTP_EVERY = 300
USABLE = {"best", "combined", "not_combined"}   # selectdata states of a source chronyd can set the clock from
GRACE = 600              # only these: none of EasyEAP's usable this long → the host's servers come back...
RETRY = 3600             # ...for this long, then EasyEAP's are tried alone again
LOST_SOCKET_EXIT = 120   # chronyd's socket gone this long after it worked: exit, and Docker re-mounts /run/chrony
RECHECK_EXIT = 3600      # no chronyd at all: exit hourly, so chrony installed later is found


def sources_text(settings: config.TimeSettings) -> str | None:
    if not settings.servers:
        return None
    return HEADER + "".join(s.directive() + "\n" for s in settings.servers)


def _ours(settings: config.TimeSettings) -> set[str]:
    return {s.address.lower() for s in settings.servers}


class Manager:
    """One host chronyd steered towards the settings. `run` is chrony.run (tests pass a fake).

    `switched`: the host sources EasyEAP switched off, address → configured name. selectopts changes the source record
    itself, so when a pool replaces one of those addresses (or chronyd re-resolves a name) the new address inherits
    noselect: it's recognised by its name and switched back on with the rest."""

    def __init__(self, run: Callable[..., str] = chrony.run, sources_dir: Path = SOURCES_DIR,
                 switched: dict[str, str] | None = None, now: Callable[[], float] = time.monotonic):
        self.run = run
        self.now = now
        self.dir = sources_dir
        self.switched: dict[str, str] = dict(switched or {})
        self.reloaded: str | bool | None = False   # the file text chronyd last reloaded (False: not yet, this run)
        self.unloaded = False                       # the file was changed and chronyd hasn't reloaded it yet
        self.unusable_since: float | None = None
        self.fallback_until: float | None = None
        self.fallback_revision: int | None = None
        self.applied_revision: int | None = None
        self.apply_error: str | None = None
        self.select_error: str | None = None

    # ── Settings → chronyd ──

    def apply(self, settings: config.TimeSettings) -> bool:
        """Bring easyeap.sources in line with the settings and have chronyd reload it: whenever the file changes, and
        once per run (a reload of an unchanged file keeps every source as it is). True when chronyd reloaded."""
        want = sources_text(settings)
        path = self.dir / FILE_NAME
        if not self.dir.is_dir():
            self.apply_error = (f"{self.dir} isn't available to the time service: the host's chrony has no sources.d "
                                "directory, or it isn't mounted")
            return False
        try:
            have = path.read_text() if path.exists() else None
            if have != want:
                if want is None:
                    path.unlink(missing_ok=True)
                else:
                    tmp = self.dir / f".{FILE_NAME}.tmp"   # not *.sources: chronyd never reads it half-written
                    tmp.write_text(want)
                    tmp.chmod(0o644)                      # chronyd reads it as its own user
                    tmp.replace(path)
                self.unloaded = True
        except OSError as exc:
            self.apply_error = f"EasyEAP can't write {path}: {exc.strerror or exc}"
            return False
        if self.reloaded == want:
            self.applied_revision, self.apply_error = settings.revision, None
            return False
        self.run("reload", "sources")   # a failure raises, and the next round tries again
        changed = self.unloaded or self.reloaded is not False
        self.reloaded, self.unloaded = want, False
        self.reselect()
        self.applied_revision, self.apply_error = settings.revision, None
        if not changed:                 # the run's first reload of a file chronyd already had
            return False
        if want is None:
            log.info("Time: EasyEAP's NTP servers removed from chronyd; the host's own servers keep the clock")
        else:
            log.info("Time: chronyd now uses %s", ", ".join(s.directive() for s in settings.servers))
        return True

    # ── chronyd → status ──

    def observe(self, settings: config.TimeSettings) -> dict[str, Any]:
        """chronyd's state. `names_ok` is False when its source list changed between the two listings (addresses and
        configured names) twice running: nothing is decided from that round."""
        tracking = chrony.parse_tracking(self.run("tracking"))
        for _ in range(2):
            rows = chrony.parse_sources(self.run("sources", "-a"))
            names = chrony.parse_sources(self.run("sources", "-a", named=True))
            if len(names) == len(rows):
                break
        names_ok = len(names) == len(rows)
        select = chrony.parse_selectdata(self.run("selectdata", "-a"))
        try:
            auth = chrony.parse_authdata(self.run("authdata", "-a"))
        except chrony.ChronyError:
            auth = {}
        ours = _ours(settings)
        sources: list[dict[str, Any]] = []
        unresolved: dict[str, int] = {}
        for i, r in enumerate(rows):
            name = names[i]["address"] if names_ok else r["address"]
            mine = name.lower() in ours
            if r["address"].startswith("ID#"):   # a name chronyd hasn't resolved yet (or a pool's spare slot)
                unresolved[name] = unresolved.get(name, 0) + 1
                continue
            sel = select.get(r["address"], {})
            sources.append({
                "address": r["address"], "name": name if name != r["address"] else None, "ours": mine, "mode": r["mode"],
                "state": r["state"], "select": sel.get("select"), "reachable": r["reachable"], "reach": r["reach"],
                # chronyc sources: positive when this clock is ahead of the source (chronyc(1), "sources")
                "stratum": r["stratum"], "offset": r["offset"], "error": r["error"], "last_rx": r["last_rx"],
                "authenticated": bool(sel.get("authenticated")), "nts": auth.get(r["address"]) == "NTS",
                "noselect": bool(sel.get("noselect")), "prefer": bool(sel.get("prefer")), "resolved": True,
                "switched_off_by_easyeap": r["address"] in self.switched,
            })
        resolved_names = {(s["name"] or s["address"]).lower() for s in sources}
        for name in unresolved:
            if name.lower() in resolved_names:
                continue   # a pool's spare slots while some of its servers are in use
            sources.append({"address": None, "name": name, "ours": name.lower() in ours, "mode": "server", "state": "unusable",
                            "select": None, "reachable": False, "reach": 0, "stratum": None, "offset": None, "error": None,
                            "last_rx": None, "authenticated": False, "nts": False, "noselect": False, "prefer": False,
                            "resolved": False, "switched_off_by_easyeap": False})
        if names_ok and settings.servers and self.apply_error is None and not any(s["ours"] for s in sources):
            self.apply_error = (f"chronyd isn't using {self.dir / FILE_NAME}: the host's chrony.conf needs the line "
                                f"`sourcedir {self.dir}`")
        return {**tracking, "sources": sources, "names_ok": names_ok}

    def reconcile(self, settings: config.TimeSettings, sources: list[dict[str, Any]], names_ok: bool = True) -> bool:
        """Switch the host's other sources off (only these, and one of ours reachable) or back on. True if anything
        changed."""
        if not names_ok:
            return False
        t = self.now()
        if self.fallback_revision != settings.revision:   # new settings: give them a fresh chance
            self.fallback_revision, self.fallback_until, self.unusable_since = settings.revision, None, None
        ours = [s for s in sources if s["ours"]]
        ours_ok = any(s["reachable"] for s in ours)
        usable = any(s["select"] in USABLE for s in ours)
        if not settings.only_these or usable or not self.switched:
            self.unusable_since = None
        else:
            self.unusable_since = self.unusable_since if self.unusable_since is not None else t
            if t - self.unusable_since >= GRACE:
                self.unusable_since, self.fallback_until = None, t + RETRY
                log.warning("Time: none of EasyEAP's NTP servers became usable in %d minutes (%s); the host's own servers are "
                            "back in use, and EasyEAP's are tried alone again in %d minutes", GRACE // 60,
                            ", ".join(sorted({s["select"] or "unknown" for s in ours})), RETRY // 60)
        falling_back = self.fallback_until is not None and t < self.fallback_until
        want_off = settings.only_these and ours_ok and not falling_back
        present = {s["address"]: s for s in sources if s["resolved"]}
        names_off = {n.lower() for n in self.switched.values()}
        changed = False
        self.select_error = None
        if falling_back:
            self.select_error = ("None of EasyEAP's servers could set the clock for 10 minutes, so the host's own servers are in "
                                 f"use again. EasyEAP tries its servers alone again in {max(1, round((self.fallback_until - t) / 60))} "
                                 "minutes. If an NTS server is listed, check it answers: while one is listed, chronyd sets the "
                                 "clock only when an NTS server agrees.")
        try:
            for addr, s in present.items():
                name = s["name"] or addr
                host = not s["ours"] and s["mode"] != "refclock" and chrony.is_address(addr)
                mine = addr in self.switched or (s["noselect"] and name.lower() in names_off)   # switched off by EasyEAP
                if want_off and host:
                    if not s["noselect"]:
                        self.run("selectopts", addr, "+noselect")
                        changed = True
                    if not s["noselect"] or mine:
                        self.switched[addr] = name
                elif mine:
                    if s["noselect"]:
                        self.run("selectopts", addr, "-noselect")
                        changed = True
                    self.switched.pop(addr, None)
            for addr in [a for a in self.switched if a not in present]:
                self.switched.pop(addr)   # gone: chronyd restarted without it, or a pool replaced it (the new one is matched by name)
        except chrony.ChronyError as exc:
            self.select_error = f"The host's other servers couldn't be switched {'off' if want_off else 'back on'}: {exc} (needs chrony 4.4 or later)"
        if changed:
            self.reselect()
            if want_off:
                log.info("Time: the host's own NTP servers are switched off; chronyd uses only EasyEAP's")
            else:
                log.info("Time: the host's own NTP servers are back in use%s", "" if not settings.only_these else
                         " until one of EasyEAP's can set the clock" if falling_back else " because none of EasyEAP's servers is answering")
        return changed

    def release(self) -> None:
        """Switch back on everything EasyEAP switched off (the service is stopping: nobody would watch the clock)."""
        for addr in list(self.switched):
            try:
                self.run("selectopts", addr, "-noselect")
            except chrony.ChronyError:
                pass
            self.switched.pop(addr, None)
        self.reselect()

    def reselect(self) -> None:
        """Have chronyd choose its sources again now. Changed selection options and a reloaded sources.d otherwise take
        effect at the next measurement (chronyc: "the next source selection, e.g. when a new measurement is made, or the
        reselect command is executed"), which can be 17 minutes away: until then the old reference stays in use and in
        the console."""
        try:
            self.run("reselect")
        except chrony.ChronyError as exc:
            log.debug("Time: chronyc reselect failed: %s", exc)


# ── Without chronyd ──────────────────────────────────────────────────────────


def measure(settings: config.TimeSettings, query: Callable[[str], sntp.Sample] | None = None) -> list[dict[str, Any]]:
    query = query or sntp.query
    out = []
    for s in settings.servers:
        try:
            r = query(s.address)
            out.append({"server": s.address, "address": r.address, "offset": -r.offset, "delay": r.delay, "stratum": r.stratum, "error": None})
        except sntp.SntpError as exc:
            out.append({"server": s.address, "address": None, "offset": None, "delay": None, "stratum": None, "error": str(exc)})
    return out


NO_CHRONY = ("The host doesn't run chrony (no control socket at /run/chrony), so EasyEAP measures the clock against these "
             "servers but can't set which servers the host uses. Install chrony on the host to manage time from here.")


# ── Status ───────────────────────────────────────────────────────────────────


def empty_status() -> dict[str, Any]:
    return {"mode": "sntp", "synchronised": False, "offset": None, "stratum": None, "reference": None, "reference_id": None,
            "reference_time": None, "leap": None, "rms_offset": None, "frequency_ppm": None, "skew_ppm": None, "last_offset": None,
            "root_delay": None, "root_dispersion": None, "update_interval": None, "sources": [], "checks": [],
            "applied_revision": None, "apply_error": None, "select_error": None, "problem": None, "switched_off": [],
            "kernel_synchronised": None, "kernel_maxerror": None}


def write_status(st: dict[str, Any]) -> None:
    from app import models as m
    from app.db import platform_session
    with platform_session() as s:
        row = s.get(m.PlatformSetting, config.STATUS_KEY) or m.PlatformSetting(key=config.STATUS_KEY, value={})
        row.value = {**st, "at": datetime.now(UTC).isoformat()}
        s.add(row)


def load(fn: Callable[[Any], Any]) -> Any:
    from app.db import platform_session
    with platform_session() as s:
        return fn(s)


# ── Main loop ────────────────────────────────────────────────────────────────


def _switched_out(m: Manager) -> list[dict[str, str]]:
    return [{"address": a, "name": n} for a, n in sorted(m.switched.items())]


class Service:
    """The loop's state. It keeps steering chronyd with the last settings it read while the database is away (a
    restart, a restore), so the fallback to the host's own servers never waits on the database."""

    def __init__(self, manager: Manager | None = None, now: Callable[[], float] = time.monotonic):
        self.m = manager or Manager(now=now)
        self.now = now
        self.restored = manager is not None
        self.started = now()
        self.seen_chrony = False
        self.lost_since: float | None = None
        self.last_report = -1e9
        self.last_sntp = -1e9
        self.sntp_revision: int | None = None
        self.checks: list[dict[str, Any]] = []
        self.last_tone: tuple[str, str] | None = None

    def restore(self, prior: dict[str, Any] | None) -> None:
        """What the previous run switched off (from its last status), so it can be switched back on."""
        for x in (prior or {}).get("switched_off") or []:
            if isinstance(x, dict) and x.get("address"):
                self.m.switched.setdefault(str(x["address"]), str(x.get("name") or x["address"]))
        self.restored = True

    def tick(self, settings: config.TimeSettings) -> tuple[dict[str, Any], bool]:
        """One round. Returns the status and whether it should be written now."""
        st = empty_status()
        urgent = False
        k = kernel.read()
        if k is not None:
            st["kernel_synchronised"], st["kernel_maxerror"] = k.synchronised, k.maxerror
        if chrony.available():
            self.lost_since = None
            try:
                urgent |= self.m.apply(settings)
                obs = self.m.observe(settings)
                if self.m.reconcile(settings, obs["sources"], obs["names_ok"]):
                    urgent = True
                    obs = self.m.observe(settings)
                st.update({k: v for k, v in obs.items() if k != "names_ok"})
                st.update(mode="chrony", applied_revision=self.m.applied_revision, apply_error=self.m.apply_error,
                          select_error=self.m.select_error, switched_off=_switched_out(self.m))
                self.seen_chrony = True
                return self._finish(st, settings, urgent)
            except chrony.ChronyError as exc:
                # chronyd is there but didn't answer this time (busy, restarting): say so, and try again next round.
                st.update(mode="chrony", problem=f"chronyd on the host didn't answer: {exc}", switched_off=_switched_out(self.m),
                          synchronised=bool(st["kernel_synchronised"]))
                return self._finish(st, settings, urgent)
        if self.seen_chrony:
            # The socket went away: chrony was stopped, or started again with a new directory this mount can't see.
            self.lost_since = self.lost_since or self.now()
            st.update(mode="chrony", problem="chronyd's control socket is gone (chrony stopped or restarted on the host)",
                      switched_off=_switched_out(self.m), synchronised=bool(st["kernel_synchronised"]))
            return self._finish(st, settings, urgent)
        st["problem"] = NO_CHRONY
        if settings.servers and (self.now() - self.last_sntp >= SNTP_EVERY or self.sntp_revision != settings.revision):
            self.checks, self.last_sntp, self.sntp_revision, urgent = measure(settings), self.now(), settings.revision, True
        elif not settings.servers:
            self.checks = []
        st["checks"] = self.checks
        good = [c["offset"] for c in self.checks if c["offset"] is not None]
        st["offset"] = statistics.median(good) if good else None
        st["synchronised"] = bool(st["kernel_synchronised"])
        return self._finish(st, settings, urgent)

    def _finish(self, st: dict[str, Any], settings: config.TimeSettings, urgent: bool) -> tuple[dict[str, Any], bool]:
        tone = config.assess(st, settings)
        if self.last_tone is not None and tone != self.last_tone:
            if tone[0] == "valid":
                log.info("Time: the clock is synchronised again%s", f" to {st['reference']}" if st.get("reference") else "")
            elif tone[0] != self.last_tone[0] or tone[0] == "crit":
                (log.error if tone[0] == "crit" else log.warning)("Time: %s", tone[1])
        elif self.last_tone is None and tone[0] != "valid":
            (log.error if tone[0] == "crit" else log.warning)("Time: %s", tone[1])
        urgent |= self.last_tone is None or tone[0] != self.last_tone[0]
        self.last_tone = tone
        due = urgent or self.now() - self.last_report >= REPORT_EVERY
        if due:
            self.last_report = self.now()
        return st, due

    def should_exit(self) -> int | None:
        if self.lost_since is not None and self.now() - self.lost_since >= LOST_SOCKET_EXIT:
            return 1
        if not self.seen_chrony and self.now() - self.started >= RECHECK_EXIT:
            return 0
        return None

    def stop(self) -> dict[str, Any] | None:
        """Stopping: switch the host's own servers back on (nothing will watch EasyEAP's). The status to record, if any."""
        if not self.m.switched or not chrony.available():
            return None
        self.m.release()
        log.info("Time: stopping; the host's own NTP servers are back in use until the time service runs again")
        return {"switched_off": []}


def main() -> None:
    from app.logs.dbhandler import install as install_db_logging
    from app.security.redact import configure_logging
    configure_logging()
    install_db_logging("time")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    svc = Service()
    log.info("EasyEAP time service started (%s)", "chronyd found" if chrony.available() else "no chronyd on the host")
    settings: config.TimeSettings | None = None
    db_ok = True
    first = True
    while first or not stop.wait(TICK):
        first = False
        try:
            if not svc.restored:
                svc.restore(load(config.load_status))
            settings = load(config.load)
            if not db_ok:
                log.info("Time service: the database is back")
            db_ok = True
        except Exception as exc:  # noqa: BLE001 — the database is restarting or being restored: carry on with what we have
            if db_ok:
                log.warning("Time service: the database can't be reached (%s); steering chronyd with the last settings", exc)
            db_ok = False
        if settings is not None and svc.restored:
            try:
                st, due = svc.tick(settings)
                if due and db_ok:
                    write_status(st)
            except Exception as exc:  # noqa: BLE001 — one bad round must not stop the loop
                log.warning("Time service: %s", exc)
        code = svc.should_exit()
        if code is not None:
            if code:
                log.warning("Time service: chronyd's control socket has been gone for %d s (chrony stopped or reinstalled "
                            "on the host); restarting to mount it again", LOST_SOCKET_EXIT)
            sys.exit(code)
    final = svc.stop()
    if final is not None:
        try:
            last = load(config.load_status) or {}
            write_status({**last, **final})
        except Exception as exc:  # noqa: BLE001 — nothing more to do while stopping; the next run reads chronyd anyway
            log.info("Time service: the final status wasn't recorded (%s)", exc)
    log.info("EasyEAP time service stopped")


if __name__ == "__main__":
    main()

"""Read what a Cisco switch reports about its ports and 802.1X/MAB sessions (docs/plans/switch-audit.md §3).

The OIDs and enumerations are from CISCO-AUTH-FRAMEWORK-MIB (2013-08-23), CISCO-ERR-DISABLE-MIB, IF-MIB and ENTITY-MIB.
Nothing here writes to the switch: GET, GETNEXT and GETBULK only.
"""
from __future__ import annotations

import re

from app.radius.wired import canonical_port
from app.switchaudit import snmp
from app.switchaudit.snmp import OID, Session, oid

SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"
ENT = "1.3.6.1.2.1.47.1.1.1.1"
ENT_CLASS, ENT_SERIAL, ENT_MODEL = ENT + ".5", ENT + ".11", ENT + ".13"
IF_TYPE, IF_ADMIN, IF_OPER = "1.3.6.1.2.1.2.2.1.3", "1.3.6.1.2.1.2.2.1.7", "1.3.6.1.2.1.2.2.1.8"
IF_NAME, IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.1", "1.3.6.1.2.1.31.1.1.1.18"
CAF = "1.3.6.1.4.1.9.9.656"
CAF_REG = CAF + ".1.1.2"            # cafAuthMethodRegTable: rows exist wherever the framework runs
CAF_PORT = CAF + ".1.2.1.1"         # cafPortConfigEntry, INDEX ifIndex
CAF_SESSION = CAF + ".1.4.1.1"      # cafSessionEntry, INDEX ifIndex, IMPLIED cafSessionId
CAF_METHOD_STATE = CAF + ".1.4.2.1.2"  # cafSessionMethodState, INDEX ifIndex, cafSessionId, cafSessionMethod
ERRDIS_INTERVAL = "1.3.6.1.4.1.9.9.548.1.1.1.0"  # cErrDisableRecoveryInterval
ERRDIS_CAUSE = "1.3.6.1.4.1.9.9.548.1.3.1.1.2"   # cErrDisableIfStatusCause, INDEX ifIndex, vlan

# cafPortConfigEntry and cafSessionEntry columns read
PORT_HOST_MODE, PORT_OPEN, PORT_CONTROL = 3, 4, 5
S_MAC, S_STATUS, S_DOMAIN, S_USER, S_AUTHZ_BY, S_CRITICAL, S_VLAN = 2, 5, 6, 10, 12, 13, 14

HOST_MODES = {1: "single-host", 2: "multi-host", 3: "multi-auth", 4: "multi-domain"}
CONTROL = {1: "force-unauthorized", 2: "auto", 3: "force-authorized"}
SESSION_STATUS = {1: "idle", 2: "running", 3: "no-method", 4: "authenticated", 5: "authentication-failed", 6: "authorized",
                  7: "authorization-failed"}
AUTHORIZED = 6
DOMAINS = {1: "other", 2: "data", 3: "voice"}
METHODS = {1: "other", 2: "dot1x", 3: "mab", 4: "webauth"}
METHOD_STATE = {1: "not-run", 2: "running", 3: "failed-over", 4: "success", 5: "failed"}
ERRDIS_CAUSES = {1: "UDLD", 2: "BPDU guard", 3: "EtherChannel misconfiguration", 4: "PAgP flap", 5: "DTP flap", 6: "link flap",
                 7: "L2PT guard", 8: "802.1X security violation", 9: "port security violation", 10: "invalid GBIC",
                 11: "DHCP snooping rate limit", 12: "unicast flood", 14: "storm control", 15: "inline power",
                 16: "ARP inspection", 17: "loopback", 19: "MAC limit", 58: "IP conflict", 62: "loop detected"}
ETHERNET_TYPES = {6, 62, 69, 117}  # ethernetCsmacd, fastEther, fastEtherFX, gigabitEthernet
MAX_PORTS, MAX_SESSIONS = 2000, 4000
_VERSION = re.compile(r"Version ([0-9][\w.()-]*)")


def _column(rows: list[tuple[OID, object]], base: str) -> dict[OID, object]:
    """Rows of one column, keyed by their index (the OID after the column)."""
    root = oid(base)
    return {o[len(root):]: v for o, v in rows if o[:len(root)] == root}


def _int(v: object) -> int | None:
    return v if isinstance(v, int) else None


def probe(s: Session) -> dict:
    """What the switch is, and which of the tables EasyEAP reads it answers (the capability probe)."""
    got = s.get([SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME])
    descr = snmp.text(got.get(oid(SYS_DESCR)), 400)
    obj = got.get(oid(SYS_OBJECT_ID))
    uptime = _int(got.get(oid(SYS_UPTIME)))
    mv = _VERSION.search(descr)
    facts = {"name": snmp.text(got.get(oid(SYS_NAME)), 120), "descr": descr,
             "object_id": snmp.oid_text(obj) if isinstance(obj, tuple) else "", "uptime_s": uptime // 100 if uptime is not None else None,
             "version": mv.group(1) if mv else "", "model": "", "serial": "",
             "engine_id": s.engine_id.hex() if s.engine_id else ""}
    # The first chassis in ENTITY-MIB (on a stack, the lowest-numbered member) gives the model and serial number.
    classes = s.walk(ENT_CLASS, max_rows=5000)
    chassis = [o[-1] for o, v in classes if v == 3]
    if chassis:
        idx = min(chassis)
        more = s.get([f"{ENT_SERIAL}.{idx}", f"{ENT_MODEL}.{idx}"])
        facts["serial"] = snmp.text(more.get(oid(f"{ENT_SERIAL}.{idx}")), 64)
        facts["model"] = snmp.text(more.get(oid(f"{ENT_MODEL}.{idx}")), 64)
    # The framework runs where either table answers: a Catalyst 3850 on IOS-XE 16.6.1 has no cafAuthMethodRegTable but
    # answers cafPortConfigTable (and cafSessionTable once a device authenticates).
    caf = s.first(CAF_REG) is not None or s.first(CAF_PORT) is not None
    errdis = s.get([ERRDIS_INTERVAL]).get(oid(ERRDIS_INTERVAL))
    return {"facts": facts, "capabilities": {"caf": caf, "errdisable": isinstance(errdis, int)}}


def poll(s: Session) -> dict:
    """Everything the audit compares: facts, capabilities, ports, 802.1X/MAB sessions, err-disabled ports."""
    out = probe(s)
    caps = out["capabilities"]
    types = _column(s.walk(IF_TYPE), IF_TYPE)
    names = _column(s.walk(IF_NAME), IF_NAME)
    aliases = _column(s.walk(IF_ALIAS), IF_ALIAS)
    admin = _column(s.walk(IF_ADMIN), IF_ADMIN)
    oper = _column(s.walk(IF_OPER), IF_OPER)

    caf_ports: dict[int, dict] = {}
    sessions: list[dict] = []
    partial = {"ports": False, "sessions": False}
    if caps["caf"]:
        for col, field in ((PORT_HOST_MODE, "host_mode"), (PORT_OPEN, "open"), (PORT_CONTROL, "control")):
            # Only the three columns compared. A port missing here would read as "not protected", so a switch with
            # more rows than this fails the poll rather than raising findings for ports it didn't report.
            for idx, v in _column(s.walk(f"{CAF_PORT}.{col}", max_rows=MAX_PORTS * 4), f"{CAF_PORT}.{col}").items():
                if len(idx) != 1 or not isinstance(v, int):
                    continue
                p = caf_ports.setdefault(idx[0], {"control": None, "host_mode": None, "open": None})
                p[field] = HOST_MODES.get(v) if field == "host_mode" else (v == 1) if field == "open" else CONTROL.get(v)
        sessions, partial["sessions"] = _sessions(s, names)

    errdis: dict[int, str] = {}
    if caps["errdisable"]:
        for idx, v in _column(s.walk(ERRDIS_CAUSE, max_rows=MAX_PORTS * 4), ERRDIS_CAUSE).items():
            if idx and isinstance(v, int):
                errdis.setdefault(idx[0], ERRDIS_CAUSES.get(v, f"cause {v}"))

    ports = []
    for key, raw in sorted(names.items()):
        if len(key) != 1:
            continue
        idx = key[0]
        name = snmp.text(raw, 64)
        t = types.get((idx,))
        if not name or not (t in ETHERNET_TYPES or idx in caf_ports or idx in errdis):
            continue
        ports.append({"if_index": idx, "name": canonical_port(name), "short": name, "alias": snmp.text(aliases.get((idx,)), 64),
                      "admin": "up" if admin.get((idx,)) == 1 else "down", "oper": "up" if oper.get((idx,)) == 1 else "down",
                      "auth": caf_ports.get(idx), "err_disabled": errdis.get(idx)})
        if len(ports) >= MAX_PORTS:
            partial["ports"] = True
            break
    # partial: the list was cut short, so findings for ports or devices past the cut are left as they were
    return {**out, "ports": ports, "sessions": sessions, "truncated": partial["ports"] or partial["sessions"], "partial": partial}


def _sessions(s: Session, names: dict[OID, object]) -> tuple[list[dict], bool]:
    cols: dict[int, dict[OID, object]] = {}
    for col in (S_MAC, S_STATUS, S_DOMAIN, S_USER, S_AUTHZ_BY, S_CRITICAL, S_VLAN):
        cols[col] = _column(s.walk(f"{CAF_SESSION}.{col}", max_rows=MAX_SESSIONS, truncate=True), f"{CAF_SESSION}.{col}")
    methods: dict[OID, dict[str, str]] = {}
    for idx, v in _column(s.walk(CAF_METHOD_STATE, max_rows=MAX_SESSIONS * 4, truncate=True), CAF_METHOD_STATE).items():
        # INDEX { ifIndex, cafSessionId (length-prefixed), cafSessionMethod }
        if len(idx) < 3 or idx[1] != len(idx) - 3 or not isinstance(v, int):
            continue
        methods.setdefault(idx[:1] + idx[2:-1], {})[METHODS.get(idx[-1], "other")] = METHOD_STATE.get(v, "unknown")
    keys = sorted(set().union(*(c.keys() for c in cols.values())))
    out = []
    for key in keys[:MAX_SESSIONS]:
        if len(key) < 2:
            continue
        if_index, sid = key[0], bytes(b & 0xFF for b in key[1:])
        status = _int(cols[S_STATUS].get(key))
        m = methods.get(key, {})
        method = next((k for k, st in m.items() if st == "success"), None) or next((k for k, st in m.items() if st == "running"), None)
        authz_by = snmp.text(cols[S_AUTHZ_BY].get(key), 64)
        critical = (_int(cols[S_CRITICAL].get(key)) or 0) > 0 or "critical" in authz_by.lower()
        vlan = _int(cols[S_VLAN].get(key)) or None
        out.append({"port": canonical_port(snmp.text(names.get((if_index,)), 64)) or f"ifIndex {if_index}", "if_index": if_index,
                    "id": sid.decode("ascii") if sid.isascii() and sid.decode("ascii").isprintable() else sid.hex(),
                    "mac": snmp.mac(cols[S_MAC].get(key)), "status": SESSION_STATUS.get(status, "unknown") if status else "unknown",
                    "authorized": status == AUTHORIZED, "domain": DOMAINS.get(_int(cols[S_DOMAIN].get(key)) or 0, "other"),
                    "user": snmp.text(cols[S_USER].get(key), 128), "authorized_by": authz_by, "critical": critical,
                    "vlan": vlan, "method": method, "methods": m})
    return out, len(keys) > MAX_SESSIONS

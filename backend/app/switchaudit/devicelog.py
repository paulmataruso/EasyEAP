"""Device syslog, read side (docs/plans/syslog-full.md §4–§6): sessions and wireless clients decoded from what devices
logged, and how each kind of device is told to send its log to EasyEAP.

Decoding is a fold over a device's recent messages, oldest first; nothing is stored. A coalesced row (one text, one
minute, counted) stands for an event at its first and at its last time, so "down … up … down" within a minute isn't
lost. Syslog isn't authenticated: what's decoded here is shown as what the device says, never as a finding.
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import models as m

# Everything the fold reads (notable or not: LINK lines end sessions but are kept only 3 days).
DECODE_FACILITIES = ("SESSION_MGR", "AUTHMGR", "DOT1X", "MAB", "EPM", "LINK", "ETHPORT", "CLIENT_ORCH_LOG", "CLIENT_EXCLUSION_SERVER",
                     "APF", "AAA", "hostapd", "UNIFI")
MAX_ROWS, MAX_SESSIONS = 5000, 300

_STARTING = re.compile(r"Starting '([\w-]+)'")
_WITH_REASON = re.compile(r"with reason \(([^)]{1,80})\)")
_AUTHZ_REASON = re.compile(r"Failure reason: ?(.{1,80}?)(?:\.? Authc failure reason: ?(.{1,80}?))?\.?$")
_VLAN = re.compile(r"VLAN (\d{1,4}) assigned")
_EPM_IP = re.compile(r"IP ([0-9A-Fa-f.:]{3,45})\s*\|")
_MOVED_TO = re.compile(r"to Interface (\S+?)(?: AuditSessionID|$|\s)")
_LINK_DOWN = re.compile(r"changed state to (?:administratively )?down|\bis down\b")
_NX_METHOD = re.compile(r"using authentication method (\S+?)(?: |$)")
_NX_ENDED = re.compile(r"terminated because of (.{1,60}?) and port moved to (\S+)")
_SSID = re.compile(r"(?i)\bssid ?[:(] ?([^)\s][^)]{0,63}?)\)?(?: for|$|\s+\w+:)")
_AP = re.compile(r"(?:associated to|disconnected from) AP \(([^)]{1,64})\)|AP Name: ?([^,\s]{1,64})")
_IP = re.compile(r"\b(?:IP|Ip Address:?) ?((?:\d{1,3}\.){3}\d{1,3})\b")
_AIREOS_REASON = re.compile(r"(?:Abort )?Reason:(.{1,80}?)(?: ReasonCode:\d+)?$")
_EXCLUSION_REASON = re.compile(r"reason: ?(.{1,80})$")
_EAP = re.compile(r"EAP type: (\d+) \(([^)]{1,20})\)")
_AAA_SERVER = re.compile(r"RADIUS server (\S+?) failed to respond")


def _events(rows: Iterable) -> list[tuple[datetime, int, object]]:
    """A row at its first time, and again at its last when it was repeated."""
    out = []
    for i, r in enumerate(rows):
        out.append((r.first_at, i, r))
        if (r.count or 1) > 1 and r.last_at > r.first_at:
            out.append((r.last_at, i, r))
    out.sort(key=lambda x: (x[0], x[1]))
    return out


def syslog_sessions(rows: Iterable) -> list[dict]:
    """Rows (any order) → one entry per session the device logged: wired ones per (port, MAC), wireless ones per MAC,
    NX-OS's (which name no MAC) per port. Newest first."""
    sessions: dict[tuple[str, str], dict] = {}
    by_sid: dict[str, tuple[str, str]] = {}

    def get(port: str, mac: str, at: datetime, fresh: bool = False) -> dict:
        key = (port or "", mac or "")
        cur = sessions.get(key)
        if cur is None or (fresh and cur["ended_at"] is not None):
            cur = sessions[key] = {"port": port or None, "mac": mac or None, "state": "seen", "method": None, "vlan": None, "ip": None,
                                   "session_id": None, "reason": None, "ssid": None, "ap": None, "first_at": at, "last_at": at,
                                   "ended_at": None, "ended": None}
        if cur["ended_at"] is not None and at > cur["ended_at"]:
            cur.update(ended_at=None, ended=None, reason=None)  # it came back
        cur["last_at"] = max(cur["last_at"], at)
        return cur

    def end(cur: dict, at: datetime, why: str) -> None:
        if cur["ended_at"] is None:
            cur["ended_at"], cur["ended"], cur["last_at"] = at, why, max(cur["last_at"], at)

    for at, _, r in _events(rows):
        fac, mn, text, port, mac, sid = r.facility, r.mnemonic or "", r.text or "", r.port or "", r.mac or "", r.session_id or ""
        if fac in ("SESSION_MGR", "AUTHMGR"):
            if mn == "VLANASSIGN":
                key = by_sid.get(sid) or next((k for k, v in sorted(sessions.items(), key=lambda kv: kv[1]["last_at"], reverse=True)
                                               if k[0] == port and v["ended_at"] is None), None)
                v = _VLAN.search(text)
                if key and v:
                    sessions[key]["vlan"] = int(v.group(1))
                continue
            if mn == "MACMOVE":
                if (cur := sessions.get((port, mac))) is not None:
                    to = _MOVED_TO.search(text)
                    end(cur, at, f"moved to {to.group(1)}" if to else "moved")
                continue
            if mn == "MACREPLACE":
                if (cur := sessions.get((port, mac))) is not None:
                    end(cur, at, "replaced by another MAC")
                continue
            if not mac:
                continue
            cur = get(port, mac, at, fresh=mn == "START")
            if sid:
                cur["session_id"], by_sid[sid] = sid, (port, mac)
            if mn == "START":
                s = _STARTING.search(text)
                cur.update(state="starting", method=s.group(1) if s else cur["method"], reason=None)
            elif mn == "SUCCESS":
                cur.update(state="authorized", reason=None)
            elif mn == "FAIL":
                rs = _AUTHZ_REASON.search(text)
                cur.update(state="unauthorized", reason=(rs.group(2) or rs.group(1)) if rs else cur["reason"])
            elif mn == "SECURITY_VIOLATION":
                cur.update(state="violation")
        elif fac in ("DOT1X", "MAB") and mn in ("SUCCESS", "FAIL", "SECURITY_VIOLATION", "ABORT_AUTH"):
            if not mac:
                continue
            cur = get(port, mac, at)
            if sid:
                cur["session_id"], by_sid[sid] = sid, (port, mac)
            if mn != "SECURITY_VIOLATION":
                cur["method"] = fac.lower()
            if mn == "SUCCESS":
                cur.update(state="authenticated", reason=None)
            elif mn == "FAIL":
                rs = _WITH_REASON.search(text)
                cur.update(state="failed", reason=rs.group(1) if rs else None)
            elif mn == "ABORT_AUTH":   # AireOS
                rs = _AIREOS_REASON.search(text)
                cur.update(state="failed", reason=rs.group(1) if rs else None)
            else:
                cur.update(state="violation")
        elif fac == "DOT1X" and mn in ("SESSION_CREATION", "SESSION_TERMINATION") and port:   # NX-OS: no MAC
            cur = get(port, "", at, fresh=mn == "SESSION_CREATION")
            mt = _NX_METHOD.search(text)
            if mt:
                cur["method"] = mt.group(1)
            if mn == "SESSION_CREATION":
                cur.update(state="starting")
            else:
                e = _NX_ENDED.search(text)
                end(cur, at, f"{e.group(1)} (port {e.group(2)})" if e else "terminated")
        elif fac == "EPM" and mn in ("POLICY_REQ", "IPEVENT"):
            ip = _EPM_IP.search(text)
            key = by_sid.get(sid) or next((k for k in sessions if mac and k[1] == mac), None)
            if ip and key and not ip.group(1).startswith("0."):  # 0.0.0.0 while it waits for DHCP
                sessions[key]["ip"] = ip.group(1)
        elif (fac == "LINK" and mn in ("UPDOWN", "CHANGED")) or (fac == "ETHPORT" and mn.startswith("IF_DOWN")):
            if port and (fac == "ETHPORT" or _LINK_DOWN.search(text)):
                for k, cur in sessions.items():
                    if k[0] == port:
                        end(cur, at, "link down")
        elif fac == "CLIENT_ORCH_LOG" and mac:   # Catalyst 9800
            cur = get("", mac, at, fresh=mn != "CLIENT_MOVED_TO_DELETE_STATE")
            _wireless(cur, text)
            if mn == "CLIENT_MOVED_TO_DELETE_STATE":
                end(cur, at, "disconnected")
            else:
                cur.update(state="connected", reason=None)
        elif fac == "CLIENT_EXCLUSION_SERVER" and mac:
            cur = get("", mac, at)
            _wireless(cur, text)
            rs = _EXCLUSION_REASON.search(text)
            cur.update(state="excluded", reason=rs.group(1) if rs else None)
        elif fac == "APF" and mac:   # AireOS
            cur = get("", mac, at, fresh=mn in ("ASSOC_TRAP", "AUTHENTICATION_TRAP"))
            _wireless(cur, text)
            rs = _AIREOS_REASON.search(text)
            if mn == "AUTHENTICATION_TRAP":
                cur.update(state="authenticated", reason=None)
            elif mn == "ASSOC_TRAP":
                cur.update(state="associated")
            elif mn == "AUTHFAIL_TRAP":
                cur.update(state="failed", reason=rs.group(1) if rs else None)
            elif mn == "EXCLUDED_TRAP":
                cur.update(state="excluded", reason=rs.group(1) if rs else None)
            elif mn in ("DISASSOC_TRAP", "DEAUTH_TRAP"):
                end(cur, at, rs.group(1) if rs else "disassociated")
        elif fac == "AAA" and mn == "RADIUS_RESPONSE_FAILED" and mac:
            cur = get("", mac, at)
            sv = _AAA_SERVER.search(text)
            cur.update(state="no answer", reason=f"RADIUS server {sv.group(1)} didn't answer" if sv else "a RADIUS server didn't answer")
        elif fac == "hostapd" and mac:   # UniFi access points
            cur = get("", mac, at, fresh="associated" in text and "disassociated" not in text)
            cur["ap"] = r.subject or cur["ap"]
            if "IEEE 802.1X: authenticated" in text:
                eap = _EAP.search(text)
                cur.update(state="authenticated", method=f"EAP-{eap.group(2)}" if eap else "802.1X", reason=None)
            elif "authentication failed" in text:
                eap = _EAP.search(text)
                cur.update(state="failed", reason=f"EAP-{eap.group(2)}" if eap else None)
            elif "disassociated" in text or "deauthenticated" in text:
                end(cur, at, "disassociated" if "disassociated" in text else "deauthenticated")
            elif "associated" in text:
                cur.update(state="associated")
        elif fac == "UNIFI" and mac:   # UniFi CEF
            cur = get("", mac, at, fresh=mn == "WiFi Client Connected")
            cur["ap"] = r.subject or cur["ap"]
            if mn == "WiFi Client Disconnected":
                end(cur, at, "disconnected")
            elif mn in ("WiFi Client Connected", "WiFi Client Roamed"):
                cur.update(state="connected")
    out = sorted(sessions.values(), key=lambda v: v["last_at"], reverse=True)[:MAX_SESSIONS]
    for v in out:
        for k in ("first_at", "last_at", "ended_at"):
            v[k] = v[k].isoformat() if v[k] else None
        v["active"] = v["ended_at"] is None
    return out


def _wireless(cur: dict, text: str) -> None:
    if (s := _SSID.search(text)) is not None:
        cur["ssid"] = s.group(1).strip()
    if (a := _AP.search(text)) is not None:
        cur["ap"] = a.group(1) or a.group(2)
    if (ip := _IP.search(text)) is not None and not ip.group(1).startswith("0."):
        cur["ip"] = ip.group(1)


def decode_rows(s: Session, client_id: uuid.UUID, hours: int = 24) -> list[m.SwitchSyslog]:
    return list(s.scalars(select(m.SwitchSyslog).where(
        m.SwitchSyslog.client_id == client_id, m.SwitchSyslog.last_at >= datetime.now(UTC) - timedelta(hours=hours),
        or_(m.SwitchSyslog.facility.in_(DECODE_FACILITIES), m.SwitchSyslog.notable.is_(True)))
        .order_by(m.SwitchSyslog.last_at.desc()).limit(MAX_ROWS)))


# ── How each kind of device sends its log ────────────────────────────────────


def guide(vendor: str, address: str, extra: list[str], target: tuple[str, int] | None, port_514: bool) -> dict:
    """Steps (a console, a dashboard) and/or lines to paste, and how to undo them, for sending syslog to EasyEAP.
    `target`: EasyEAP's syslog address and port (None: this server doesn't receive syslog). The device's log is
    attributed by its source address: its RADIUS address, or one of `extra`."""
    dest, port = target or ("<EasyEAP's address>", 5514)
    sources = ", ".join([address, *extra])
    can_514 = port == 514 or port_514
    out: dict = {"steps": [], "config": None, "removal": None, "notes": [], "can_send": target is not None, "port": port}
    if vendor == "cisco-9800":
        out["config"] = "\n".join([
            "! EasyEAP device syslog: the controller's whole log, decoded (802.1X failures, clients joining, exclusions,",
            "! RADIUS servers) and shown as it arrives.",
            f"logging host {dest} transport udp port {port}",
            "! Client messages are severity 5 and 6: leave logging trap at its default (informational).",
            f"! EasyEAP keeps messages sent from {sources}. The 9800 sends from its wireless management interface",
            "! (its RADIUS address). From the service port (Gi0, IOS-XE 17.6 or later), use instead the line below and add",
            "! the service port's address to this controller's syslog addresses in EasyEAP:",
            f"!   logging host {dest} vrf Mgmt-intf transport udp port {port}"])
        out["removal"] = f"no logging host {dest} transport udp port {port}\n! or: no logging host {dest} vrf Mgmt-intf transport udp port {port}"
    elif vendor == "cisco-aireos":
        out["port"] = 514
        if not can_514:
            out["can_send"] = False
            out["notes"].append(f"AireOS (and the vWLC) sends syslog to UDP 514 only, and this EasyEAP server listens on {port}. The server's "
                                "operator can publish UDP 514 as well (deploy/docker-compose.syslog514.yml).")
        out["steps"] = ["Management → Logs → Config.",
                        f"Syslog Server IP Address: {dest}, then Add (AireOS always sends to UDP 514).",
                        "Syslog Level: Informational. Apply, then Save Configuration.",
                        "Client events (authenticated, failed, excluded, associated, disassociated) are off until turned on: paste the "
                        "lines below on the controller's CLI (they also set the server and level)."]
        out["config"] = "\n".join([
            f"config logging syslog host {dest}",
            "config logging syslog level informational",
            *(f"config logging syslog facility client {e} enable" for e in ("authentication", "authfail", "deauthenticate", "excluded",
                                                                             "associate", "disassociate")),
            "save config"])
        out["removal"] = "\n".join([f"config logging syslog host {dest} delete",
                                    *(f"config logging syslog facility client {e} disable" for e in ("authentication", "authfail", "deauthenticate",
                                                                                                      "excluded", "associate", "disassociate")),
                                    "save config"])
        out["notes"].append(f"EasyEAP keeps messages sent from {sources}: the controller sends from its management interface, as it does "
                            "RADIUS.")
    elif vendor == "unifi":
        out["steps"] = ["UniFi Network 8.5 or later: Settings → Control Plane → Integrations → Activity Logging (Syslog) → SIEM Server "
                        "(some versions: Settings → CyberSecure → Traffic Logging → Activity Logging). Earlier versions: Settings → Site "
                        "→ Remote Logging, Enable Remote Syslog Server.",
                        f"Server address {dest}, port {port}. Leave Debug Logs off.",
                        "Apply. Repeat in every site whose access points use this RADIUS client."]
        out["notes"] += [f"Each access point sends its own log, from its own address: EasyEAP keeps messages from {sources}, so this "
                         "RADIUS client's range must cover the access points.",
                         "The UniFi console sends the client events (connected, disconnected, roamed) itself, from its own address: add "
                         "the console's address to this device's syslog addresses in EasyEAP, but only if the console serves this "
                         "tenant's sites alone. A console shared with other customers sends their client events too, and they can't "
                         "be told apart: leave it out, and the access points' own messages still arrive.",
                         "The UniFi Network application itself listens on UDP 5514: if it runs on the EasyEAP server, they clash."]
    elif vendor == "meraki":
        out["steps"] = ["Dashboard: Network-wide → General → Reporting → Syslog servers → Add a syslog server.",
                        f"Server IP {dest}, port {port}; roles: Switch event log and/or Wireless event log (Event Log for the rest).",
                        "Save."]
        out["notes"].append(f"Each Meraki device sends from its own address: EasyEAP keeps messages from {sources}.")
    else:
        out["steps"] = [f"Send syslog (UDP) to {dest} port {port}" + (" or 514" if port_514 and port != 514 else "") + ", severity informational."]
        out["notes"].append(f"EasyEAP keeps messages sent from {sources}.")
    return out

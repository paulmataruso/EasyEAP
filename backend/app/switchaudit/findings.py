"""Audit findings: what the switch reports compared with what EasyEAP decided and sent (docs/plans/switch-audit.md §4).

`evaluate` is pure: the polled state and a `Context` (the switch's plan and EasyEAP's own records, loaded by
app/switchaudit/service.py) in, findings out, plus the kinds it had the evidence to evaluate. Hysteresis and
acknowledgement live in the service.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime

CRITICAL, WARNING = "critical", "warning"


@dataclass(frozen=True)
class Kind:
    needs: str            # "caf" | "errdisable" | "poll" (any successful poll) | "failure" (a failed poll)
    open_after: int = 2   # consecutive polls showing it before it opens
    resolve_after: int = 2  # consecutive polls without it before it resolves
    sticky: bool = False  # resolved only by acknowledging


KINDS: dict[str, Kind] = {
    "port_not_covered": Kind("caf"),
    "open_access_in_enforce": Kind("caf"),
    "authorized_without_easyeap": Kind("caf"),
    "authorized_despite_reject": Kind("caf"),
    "authorized_after_deny": Kind("caf"),
    "vlan_mismatch": Kind("caf"),
    "mab_not_expected": Kind("caf"),
    "critical_auth": Kind("caf"),
    "err_disabled": Kind("errdisable"),
    "caf_missing": Kind("poll", open_after=1, resolve_after=1),
    "switch_changed": Kind("poll", open_after=1, sticky=True),
    "snmp_unreachable": Kind("failure", open_after=1, resolve_after=1),
    "snmp_auth": Kind("failure", open_after=1, resolve_after=1),
}


@dataclass
class Found:
    kind: str
    severity: str
    port: str = ""
    mac: str = ""
    detail: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return self.kind, self.port, self.mac


def detail_hash(detail: dict) -> str:
    """What an acknowledgement is tied to: a finding whose detail changes shows up again."""
    return hashlib.sha256(json.dumps(detail, sort_keys=True, default=str).encode()).hexdigest()[:32]


@dataclass
class Seen:
    """EasyEAP's latest answer for one MAC from this switch."""
    result: str                 # accept | reject
    at: datetime
    vlan_id: int | None = None  # what the accept sent (None: no VLAN, or monitor mode)
    monitor: bool = False
    method: str | None = None   # eap-tls | mab | mab-eap
    reason_code: str | None = None


def family(method: str | None) -> str:
    """The switch-side method an EasyEAP answer belongs to: "mab" (mab, mab-eap) or "dot1x" (EAP-TLS; NULL in older
    rows). A device's MAB and 802.1X attempts are separate sessions on the switch, so they're compared separately."""
    return "mab" if method in ("mab", "mab-eap") else "dot1x"


Key = tuple[str, str]  # (MAC, family)


@dataclass
class Context:
    mode: str                                   # monitor | enforce
    planned: set[str]                           # canonical names of the ports in the plan
    mab: bool                                   # EasyEAP answers MAC authentication for this switch
    latest_accept: dict[Key, Seen] = field(default_factory=dict)
    latest_reject: dict[Key, Seen] = field(default_factory=dict)
    denied_now: dict[Key, str] = field(default_factory=dict)      # why EasyEAP would refuse that accept's device now
    pinned: dict = field(default_factory=dict)  # {"engine_id", "serial"} from the first successful poll
    version: str = "v2c"


def evaluate(state: dict, ctx: Context) -> tuple[list[Found], set[str]]:
    """Findings for a successful poll, and the kinds evaluated (kinds whose evidence the switch didn't give are left
    out, so their open findings are neither confirmed nor resolved)."""
    caps = state.get("capabilities") or {}
    evaluated = {k for k, d in KINDS.items() if d.needs == "poll" or (d.needs == "failure") or (d.needs == "caf" and caps.get("caf"))
                 or (d.needs == "errdisable" and caps.get("errdisable"))}
    out: list[Found] = []
    enforce = ctx.mode == "enforce"
    ports = {p["name"]: p for p in state.get("ports") or []}

    facts = state.get("facts") or {}
    changed = {}
    if ctx.version == "v3" and ctx.pinned.get("engine_id") and facts.get("engine_id") and facts["engine_id"] != ctx.pinned["engine_id"]:
        changed["engine_id"] = {"was": ctx.pinned["engine_id"], "now": facts["engine_id"]}
    if ctx.pinned.get("serial") and facts.get("serial") and facts["serial"] != ctx.pinned["serial"]:
        changed["serial"] = {"was": ctx.pinned["serial"], "now": facts["serial"]}
    if changed:
        out.append(Found("switch_changed", WARNING, detail=changed))

    if not caps.get("caf"):
        if ctx.planned:
            out.append(Found("caf_missing", WARNING, detail={"version": facts.get("version") or ""}))
        return out, evaluated

    for name in sorted(ctx.planned):
        p = ports.get(name)
        if p is None:
            continue  # not on this switch (a stack member that's absent, or a typo in the plan): nothing to compare
        auth = p.get("auth")
        if not auth or auth.get("control") != "auto":
            out.append(Found("port_not_covered", CRITICAL if enforce else WARNING, port=name,
                             detail={"control": (auth or {}).get("control")}))
        elif enforce and auth.get("open"):
            out.append(Found("open_access_in_enforce", CRITICAL, port=name))

    for sess in state.get("sessions") or []:
        mac, port = sess.get("mac") or "", sess.get("port") or ""
        if not mac or not sess.get("authorized") or sess.get("method") not in ("dot1x", "mab"):
            continue
        method = sess["method"]
        key = (mac, method)
        acc, rej = ctx.latest_accept.get(key), ctx.latest_reject.get(key)
        base = {"method": method, "vlan": sess.get("vlan"), "domain": sess.get("domain")}
        if sess.get("critical"):
            out.append(Found("critical_auth", WARNING, port=port, mac=mac, detail=base))
            continue
        if method == "mab" and not ctx.mab:
            out.append(Found("mab_not_expected", WARNING, port=port, mac=mac, detail=base))
            continue
        if acc is None:
            if enforce and rej is not None:
                out.append(Found("authorized_despite_reject", CRITICAL, port=port, mac=mac, detail={**base, "reason_code": rej.reason_code}))
            else:
                out.append(Found("authorized_without_easyeap", WARNING, port=port, mac=mac,
                                 detail={**base, "authorized_by": sess.get("authorized_by") or ""}))
            continue
        if enforce and rej is not None and rej.at > acc.at:
            out.append(Found("authorized_despite_reject", CRITICAL, port=port, mac=mac, detail={**base, "reason_code": rej.reason_code}))
            continue
        why = ctx.denied_now.get(key)
        if why:
            out.append(Found("authorized_after_deny", WARNING, port=port, mac=mac, detail={**base, "reason": why}))
            continue
        if enforce and not acc.monitor and acc.vlan_id is not None and sess.get("domain") != "voice" and sess.get("vlan") != acc.vlan_id:
            out.append(Found("vlan_mismatch", WARNING, port=port, mac=mac, detail={**base, "sent": acc.vlan_id}))

    if caps.get("errdisable"):
        for name, p in sorted(ports.items()):
            cause = p.get("err_disabled")
            if cause and (name in ctx.planned or "violation" in cause):
                out.append(Found("err_disabled", WARNING, port=name, detail={"cause": cause}))
    return out, evaluated


def failure(error_kind: str, message: str) -> list[Found]:
    """The finding for a poll that failed: no answer, or the switch refused EasyEAP's credentials."""
    kind = "snmp_auth" if error_kind == "auth" else "snmp_unreachable"
    return [Found(kind, WARNING, detail={"error": message[:300]})]


# What each finding means and what to do, for the console and the docs.
TEXT: dict[str, tuple[str, str]] = {
    "port_not_covered": ("A port in the plan doesn't run 802.1X or MAC authentication: anything plugged in gets the port's VLAN.",
                         "Paste the switch configuration again, or check the port isn't set to force-authorized."),
    "open_access_in_enforce": ("Enforce mode, but the port lets traffic through before authentication (open access).",
                               "Paste the Enforce configuration again: it closes the ports (access-session closed)."),
    "authorized_without_easyeap": ("The switch authorized a device EasyEAP never accepted from this switch.",
                                   "Check the switch's RADIUS servers and any local authorization: another server or a local rule let it in."),
    "authorized_despite_reject": ("The switch authorized a device EasyEAP refused.",
                                  "Check the switch's RADIUS server list and authorization rules: something other than EasyEAP is admitting it."),
    "authorized_after_deny": ("The device still has access although EasyEAP would now refuse it (revoked, blocked or expired).",
                              "Turn on Change of Authorization for this switch, or clear the session: clear access-session mac <MAC>."),
    "vlan_mismatch": ("The session isn't in the VLAN EasyEAP sent.",
                      "Check the VLAN exists on the switch and that the port allows VLAN assignment."),
    "mab_not_expected": ("A device was admitted by MAC authentication, which EasyEAP has turned off for this switch.",
                         "Another RADIUS server answered it, or the switch's MAB configuration is out of date. Paste the configuration again."),
    "critical_auth": ("The switch authorized a device on its own while EasyEAP was unreachable (critical authentication).",
                      "Check the switch can reach EasyEAP: these sessions re-authenticate once it can."),
    "err_disabled": ("The port is err-disabled.", "Find the cause on the switch (show interfaces status err-disabled), fix it, then shut/no shut the port."),
    "caf_missing": ("This switch doesn't report its 802.1X sessions over SNMP, so EasyEAP can't audit its ports.",
                    "Check the SNMP view includes 1.3.6.1.4.1.9.9.656 (paste the monitoring block again); some IOS-XE releases don't implement it."),
    "switch_changed": ("A different switch answers at this address (its serial number or SNMP engine ID changed).",
                       "If the switch was replaced, acknowledge this. If not, find out what answers at this address."),
    "snmp_unreachable": ("EasyEAP gets no SNMP answer from the switch.",
                         "Check the address, that UDP 161 is open from EasyEAP, and that the community or user and the ACL on the switch match."),
    "snmp_auth": ("The switch refused EasyEAP's SNMP credentials.", "Paste the monitoring block again, or set up new credentials."),
}

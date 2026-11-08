"""Wired 802.1X on Cisco Meraki MS switches: Dashboard steps (docs/plans/cisco-platforms.md §6.5).

Meraki has no CLI: an access policy in the Dashboard points at EasyEAP, and switch ports use it. Open (monitor) mode
exists only on MS130/MS150 with MS 18 or later (series "ms-open"); other models use EasyEAP's server-side monitor:
with Hybrid authentication, devices that fail or skip 802.1X fall back to MAC authentication, which EasyEAP accepts
until the switch is enforced (§4).

From Meraki's "MS Switch Access Policies (802.1X)", "Configuring RADIUS Authentication with WPA2-Enterprise/802.1X" and
"Change of Authorization with RADIUS (CoA) on MS" articles (research notes, plan §12). Not verified on Meraki hardware.
"""
from __future__ import annotations

from app.radius.wired import Ctx

HOST_MODES = {"multi-auth": "Multi-Auth", "single-host": "Single-Host", "multi-host": "Multi-Host"}


MULTI_AUTH_CRITICAL = ("Meraki MS (other than the MS390) offers no critical VLAN with Multi-Auth: choose Multi-Host or "
                       "Single-Host if devices must keep working while EasyEAP is unreachable.")


def _port_vlan(c: Ctx) -> str:
    return "the VLAN these ports use" + (f" ({c.p.access_vlan})" if c.p.access_vlan else "")


def _critical(c: Ctx) -> str:
    """The critical VLAN once enforced (what the plan says)."""
    p = c.p
    if p.server_down == "vlan":
        return f"Critical VLAN: {p.server_down_vlan} (new devices while EasyEAP is unreachable)."
    if p.server_down == "open":
        return f"Critical VLAN: {_port_vlan(c)}, so new devices keep working while EasyEAP is unreachable."
    return "Critical VLAN: none, and “Suspend re-authentication when RADIUS servers are unreachable” on (devices already connected stay)."


def steps(c: Ctx) -> list[str]:
    p, open_mode = c.p, c.caps.monitor == "switch"
    out = [
        "Dashboard → Switching → Configure → Access policies → Add an access policy. Name: EasyEAP.",
        f"Authentication method: my RADIUS server. RADIUS server: host {c.server}, port {c.auth}, with the shared secret.",
        "RADIUS testing: off. (Meraki tests with the user meraki_8021x_test, which EasyEAP refuses, and Meraki doesn't say "
        "whether a refusal counts as reachable.)",
        f"RADIUS accounting: on, server {c.server}, port {c.acct}, with the same secret.",
        "RADIUS CoA support: off (Meraki needs a session ID in each answer that EasyEAP doesn't send yet).",
        f"Host mode: {HOST_MODES[p.host_mode]}. Access policy type: "
        + ("Hybrid authentication (802.1X first, then the MAC address)." if p.mab else "802.1X."),
        # Monitor mode on a model without open mode: an EasyEAP outage must not close the ports either.
        _critical(c) if open_mode else f"Critical VLAN: {_port_vlan(c)}, so devices keep working if EasyEAP is unreachable "
        "during monitor mode.",
        "Guest VLAN and failed-authentication VLAN: leave empty for now.",
    ]
    if p.host_mode == "multi-auth":
        out.append(MULTI_AUTH_CRITICAL)
    if open_mode:
        out.append("Authentication mode: Open (MS130/MS150, MS 18 or later), with a pre-authentication policy that allows "
                   "everything. Devices keep their access whatever EasyEAP answers, and EasyEAP logs what it would decide.")
    else:
        out.append("This model has no open mode. While the switch is in monitor mode in EasyEAP, EasyEAP accepts every MAC "
                   "request from it (no VLAN) and logs what it would decide. With Hybrid authentication a device that fails "
                   "802.1X, or doesn't try it within 8 seconds, falls back to its MAC address, so it keeps its access too.")
    out += [
        "Switching → Monitor → Switch ports: select ONE test port, Edit → Type: Access, Access policy: EasyEAP. Leave the "
        "uplink and ports with access points or switches alone.",
        "Plug a test device with an EasyEAP certificate into that port and watch for its first request below.",
        "Register each switch's management (LAN) IP in EasyEAP, or its Alternate Management Interface IP if you set one: "
        "that's the address its RADIUS requests come from.",
        "Then set the access policy on more ports.",
    ]
    return out


def enforce_steps(c: Ctx) -> list[str]:
    p = c.p
    out = []
    if c.caps.monitor == "switch":
        out.append("Access policies → EasyEAP → Authentication mode: Closed.")
    else:
        out += ["EasyEAP now refuses MAC requests it would refuse, so devices that aren't on the MAC allow list lose access.",
                "Access policies → EasyEAP → " + _critical(c)]
    if p.no_supplicant == "vlan":
        out.append(f"Access policies → EasyEAP → Guest VLAN: {p.no_supplicant_vlan} (devices without 802.1X that aren't on the MAC allow list).")
    out.append("Cycle the ports (Switch ports → Edit → Disabled, then Enabled) or reconnect devices, so they re-authenticate.")
    return out


def monitor_steps(c: Ctx) -> list[str]:
    out = []
    if c.caps.monitor == "switch":
        out.append("Access policies → EasyEAP → Authentication mode: Open.")
    else:
        out += ["EasyEAP accepts this switch's MAC requests again.",
                f"Access policies → EasyEAP → Critical VLAN: {_port_vlan(c)}."]
    if c.p.no_supplicant == "vlan":
        out.append("Access policies → EasyEAP → Guest VLAN: empty.")
    return out


def mab_steps(c: Ctx) -> list[str] | None:
    """After MAC authentication is turned on or off (MS130/MS150 in open mode only: other models always have it)."""
    if c.p.last_change != "mab":
        return None
    if c.p.mab:
        return ["Switching → Configure → Access policies → EasyEAP → Access policy type: Hybrid authentication (802.1X first, "
                "then the MAC address). Save."]
    return ["Switching → Configure → Access policies → EasyEAP → Access policy type: 802.1X. Save. EasyEAP now refuses MAC "
            "requests from this switch."]

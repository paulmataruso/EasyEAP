"""Device configuration for admin logins over TACACS+ (docs/plans/device-admin.md §5).

No key appears here: the configuration carries KEY_PLACEHOLDER, which the console replaces in the browser with the key
it has just shown (the same as RADIUS shared secrets in app/radius/wired.py).

Everything keeps the device's own local accounts working: the console line logs in locally, `login default` falls
back to `local` when EasyEAP doesn't answer (TACACS+ ERROR included: docs/plans/device-admin.md §2), and exec
authorization is `if-authenticated` after `local`. No command authorization in v1.
"""
from __future__ import annotations

from dataclasses import dataclass

from app import models as m

KEY_PLACEHOLDER = "<tacacs-key>"
ADDRESS_PLACEHOLDER = "<easyeap-radius-ip>"  # the same as the RADIUS guides': EASYEAP_RADIUS_ADDRESS isn't set
PORT = 49
SUPPORTED = ("cisco-switch", "cisco-9800")
NOT_SUPPORTED = {
    "unifi": "UniFi switches and gateways have no TACACS+, RADIUS or LDAP login for administrators: they're managed from UniFi Network.",
    "cisco-aireos": "AireOS controllers use a different TACACS+ configuration that EasyEAP doesn't generate yet.",
    "other": "EasyEAP generates the configuration for Cisco IOS and IOS-XE only. Other devices may work with the values "
             "below (TACACS+ on TCP 49, service shell, attribute priv-lvl), but that isn't tested.",
}


@dataclass
class Ctx:
    tenant_slug: str
    server: str          # EasyEAP's address as devices reach it
    name: str            # the device, for comments
    vendor: str
    source_interface: str = ""
    vrf: str = ""
    legacy: bool = False  # IOS without `tacacs server` (older 15.x images): tacacs-server host … key …


def ctx_for(client: m.RadiusClient, tenant: m.Tenant, server: str, *, legacy: bool = False) -> Ctx:
    p = client.wired_profile or {}
    return Ctx(tenant_slug=tenant.slug, server=server or ADDRESS_PLACEHOLDER, name=client.name, vendor=client.vendor,
               source_interface=str(p.get("source_interface") or ""), vrf=str(p.get("vrf") or ""), legacy=legacy)


def server_name(c: Ctx) -> str:
    return f"EASYEAP-ADMIN-{c.tenant_slug.upper()}"[:31]


def preflight(c: Ctx) -> list[dict]:
    vrf = f" vrf {c.vrf}" if c.vrf else ""
    return [
        {"command": "show running-config | include ^username",
         "look_for": "At least one line with privilege 15. That local account is how you log in from the console, and from SSH "
                     "while EasyEAP can't be reached. Without one, create it first: username <name> privilege 15 algorithm-type scrypt secret <password>."},
        {"command": "show running-config | include ^enable",
         "look_for": "enable secret … Enable falls back to it when EasyEAP doesn't answer."},
        {"command": "show running-config | include ^aaa|^tacacs|^radius-server|^ip tacacs",
         "look_for": "Only lines EasyEAP's wired 802.1X configuration added (aaa new-model, aaa … dot1x/network … group EASYEAP, "
                     "radius server EASYEAP-…). Lines for ISE, ACS or another TACACS+ server: stop and merge by hand."},
        {"command": "show running-config | section line vty",
         "look_for": "No “login authentication <name>” under the vty lines (they then use the default list EasyEAP sets), "
                     "and “transport input ssh”."},
        {"command": f"ping{vrf} {c.server}" + (f" source {c.source_interface}" if c.source_interface else ""),
         "look_for": "Replies. TACACS+ uses TCP 49 to this address: allow it from the device's management address."},
    ]


def config(c: Ctx) -> str:
    srv, group = server_name(c), "EASYEAP-ADMIN"
    out = [f"! EasyEAP device administration for {c.name}: administrators log in with their AD or EasyEAP account.",
           "! Paste in configuration mode after `reload in 15` (see the steps). The console line keeps the local login.",
           "aaa new-model",
           "!"]
    if c.legacy:
        out += [f"tacacs-server host {c.server} key 0 {KEY_PLACEHOLDER}",
                "tacacs-server timeout 5",
                "!",
                f"aaa group server tacacs+ {group}",
                f" server {c.server}"]
    else:
        out += [f"tacacs server {srv}",
                f" address ipv4 {c.server}",
                f" key 0 {KEY_PLACEHOLDER}",
                " timeout 5",
                "!",
                f"aaa group server tacacs+ {group}",
                f" server name {srv}"]
    if c.source_interface:
        out.append(f" ip tacacs source-interface {c.source_interface}")
    if c.vrf:
        out.append(f" ip vrf forwarding {c.vrf}")
    out += ["!",
            f"aaa authentication login default group {group} local",
            "aaa authentication login EASYEAP-CONSOLE local",
            f"aaa authentication enable default group {group} enable",
            f"aaa authorization exec default group {group} local if-authenticated",
            f"aaa accounting exec default start-stop group {group}",
            f"aaa accounting commands 1 default start-stop group {group}",
            f"aaa accounting commands 15 default start-stop group {group}",
            "!",
            "line con 0",
            " login authentication EASYEAP-CONSOLE",
            "!"]
    if c.vendor == "cisco-9800":
        out += ["! Catalyst 9800 web UI: the same accounts (not verified on hardware).",
                "ip http authentication aaa login-authentication default",
                "ip http authentication aaa exec-authorization default",
                "!"]
    return "\n".join(out) + "\n"


def rollback(c: Ctx) -> str:
    group = "EASYEAP-ADMIN"
    out = ["! Back to local logins only.",
           "aaa authentication login default local",
           "aaa authorization exec default local",
           "no aaa authentication enable default",
           f"no aaa accounting exec default start-stop group {group}",
           f"no aaa accounting commands 1 default start-stop group {group}",
           f"no aaa accounting commands 15 default start-stop group {group}",
           "line con 0",
           " no login authentication EASYEAP-CONSOLE",
           "exit",
           "no aaa authentication login EASYEAP-CONSOLE",
           f"no aaa group server tacacs+ {group}"]
    out.append(f"no tacacs-server host {c.server}" if c.legacy else f"no tacacs server {server_name(c)}")
    if c.vendor == "cisco-9800":
        out += ["no ip http authentication aaa login-authentication", "no ip http authentication aaa exec-authorization"]
    return "\n".join(out) + "\n"


def guide(c: Ctx) -> dict:
    steps = [
        "Run the checks below first. Keep your current SSH session open until the last step.",
        "Enter `reload in 15` (in enable mode, not configuration mode). If anything locks you out, the device reloads in 15 "
        "minutes with its saved configuration.",
        "`configure terminal`, paste the configuration, `end`.",
        "From a new SSH session, log in with your AD or EasyEAP account. `show privilege` shows your role's level. "
        "EasyEAP's Admin log shows the login.",
        "It works: `reload cancel`, then `write memory`. It doesn't: stay in the first session and paste the rollback, "
        "or let the reload undo it.",
    ]
    return {"server": c.server, "port": PORT, "server_name": server_name(c), "preflight": preflight(c), "steps": steps,
            "config": config(c), "rollback": rollback(c), "key_placeholder": KEY_PLACEHOLDER,
            "verified": False,
            "notes": ["Not yet verified on Cisco hardware: EasyEAP's TACACS+ service is tested against a protocol client that "
                      "follows IOS's login sequence.",
                      "TACACS+ only obfuscates its packets (RFC 8907): keep it on the management network.",
                      "Break-glass: names listed under Local-only usernames always use the device's own account."]}

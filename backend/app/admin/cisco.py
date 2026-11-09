"""Device configuration for admin logins over TACACS+ (docs/plans/device-admin.md §5; per platform:
docs/plans/cisco-platforms.md §7).

No key appears here: the configuration carries KEY_PLACEHOLDER, which the console replaces in the browser with the key
it has just shown (the same as RADIUS shared secrets in app/radius/wired.py).

Everything keeps the device's own local accounts working: the console line logs in locally, `login default` falls
back to `local` when EasyEAP doesn't answer (TACACS+ ERROR included: docs/plans/device-admin.md §2), and exec
authorization is `if-authenticated` after `local`. No command authorization in v1.
"""
from __future__ import annotations

from dataclasses import dataclass

from app import models as m
from app.radius import cisco_platforms as cp

KEY_PLACEHOLDER = "<tacacs-key>"
ADDRESS_PLACEHOLDER = "<easyeap-radius-ip>"  # the same as the RADIUS guides': EASYEAP_RADIUS_ADDRESS isn't set
PORT = 49
SUPPORTED = ("cisco-switch", "cisco-9800")
# Forms of the configuration (cisco_platforms.Caps.tacacs): named `tacacs server`, legacy `tacacs-server host` (older IOS
# and IOS-XE 3.x), NX-OS, Cisco Business (sx: C1300/Sx350/CBS350; sx-old: Sx300/Sx500 1.4) and the CBS220.
FORMS = ("named", "legacy", "nxos", "sx", "sx-old", "cbs220")
NO_TACACS = ("This switch series has no TACACS+ login for administrators (Cisco documents TACACS+ on the Catalyst 1300, "
             "CBS350/Sx350, Sx300 and CBS220 only). Its own accounts stay the way in.")
NOT_SUPPORTED = {
    "meraki": "Meraki MS switches are managed from the Meraki Dashboard: they have no TACACS+ login for administrators.",
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
    form: str = "named"   # FORMS
    os: str = "ios"       # ios | nxos | nxos-n7k: how the TACACS+ service answers authorization (shell:roles on NX-OS)


def form_of(client: m.RadiusClient, legacy: bool = False) -> str | None:
    """The configuration form for this device, or None when it has no TACACS+. Classic IOS of unknown release keeps the
    admin's "older IOS" choice; a known release decides by itself."""
    if client.vendor == "cisco-9800":
        return "named"
    if client.vendor != "cisco-switch":
        return None
    caps = cp.caps_for(client.vendor, client.wired_profile)
    t = caps.tacacs if caps else "named"
    if t == "toggle":
        return "legacy" if legacy else "named"
    if t == "legacy-xe3":
        return "legacy"
    return t


def os_of(client: m.RadiusClient) -> str:
    p = client.wired_profile or {}
    if client.vendor == "cisco-switch" and p.get("platform") == "nxos":
        return "nxos-n7k" if p.get("series") == "n7k" else "nxos"
    return "ios"


def unsupported(client: m.RadiusClient) -> str | None:
    """Why admin logins can't be turned on for this device, or None."""
    if client.vendor not in SUPPORTED:
        return NOT_SUPPORTED.get(client.vendor) or "Not supported for this device."
    if form_of(client) is None:
        return NO_TACACS
    return None


def ctx_for(client: m.RadiusClient, tenant: m.Tenant, server: str, *, legacy: bool = False) -> Ctx:
    p = client.wired_profile or {}
    form = form_of(client, legacy) or "named"
    return Ctx(tenant_slug=tenant.slug, server=server or ADDRESS_PLACEHOLDER, name=client.name, vendor=client.vendor,
               source_interface=str(p.get("source_interface") or ""), vrf=str(p.get("vrf") or ""), legacy=form == "legacy",
               form=form, os=os_of(client))


def server_name(c: Ctx) -> str:
    return f"EASYEAP-ADMIN-{c.tenant_slug.upper()}"[:31]


def preflight(c: Ctx) -> list[dict]:
    if c.form == "nxos":
        return _nxos_preflight(c)
    if c.form in ("sx", "sx-old", "cbs220"):
        return _sx_preflight(c)
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
    if c.form == "nxos":
        return _nxos_config(c)
    if c.form in ("sx", "sx-old", "cbs220"):
        return _sx_config(c)
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
    if c.form == "nxos":
        return _nxos_rollback(c)
    if c.form in ("sx", "sx-old", "cbs220"):
        return _sx_rollback(c)
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


# ── NX-OS (research nxos.md §9) ──────────────────────────────────────────────


def _nxos_vrf(c: Ctx) -> str:
    return c.vrf or "management"


def _nxos_preflight(c: Ctx) -> list[dict]:
    return [
        {"command": "show user-account",
         "look_for": "A local account with role network-admin. It's how you log in from the console, and from SSH while EasyEAP "
                     "can't be reached. A local account with the same name as an EasyEAP account overrides EasyEAP's role."},
        {"command": "show running-config aaa",
         "look_for": "No aaa authentication login lines for another TACACS+ or RADIUS group. If there are: stop and merge by hand."},
        {"command": "show tacacs-server", "look_for": "No other TACACS+ servers, or ones you mean to replace."},
        {"command": f"ping {c.server} vrf {_nxos_vrf(c)}" + (f" source-interface {c.source_interface}" if c.source_interface else ""),
         "look_for": f"Replies. TACACS+ uses TCP 49 from VRF {_nxos_vrf(c)}: set the VRF in the switch's settings if it's in-band (default)."},
    ]


def _nxos_config(c: Ctx) -> str:
    group = "EASYEAP-ADMIN"
    out = [f"! EasyEAP device administration for {c.name} (NX-OS): administrators log in with their AD or EasyEAP account.",
           "! EasyEAP answers each login's role: network-admin for a level-15 role, network-operator below"
           + (" (with vdc-admin / vdc-operator)." if c.os == "nxos-n7k" else "."),
           "! The console keeps the local login; SSH falls back to local accounts only while EasyEAP doesn't answer.",
           "feature tacacs+",
           "!",
           f"tacacs-server host {c.server} key 0 {KEY_PLACEHOLDER} port {PORT} timeout 5",
           "tacacs-server deadtime 3",
           f"aaa group server tacacs+ {group}",
           f"  server {c.server}",
           "  deadtime 3",
           f"  use-vrf {_nxos_vrf(c)}"]
    if c.source_interface:
        out.append(f"ip tacacs source-interface {c.source_interface}")
    out += ["!",
            f"aaa authentication login default group {group}",
            "aaa authentication login console local",
            f"aaa accounting default group {group}",
            "!"]
    return "\n".join(out) + "\n"


def _nxos_rollback(c: Ctx) -> str:
    group = "EASYEAP-ADMIN"
    out = ["! Back to local logins only.",
           f"no aaa accounting default group {group}",
           f"no aaa authentication login default group {group}",
           f"no aaa group server tacacs+ {group}",
           f"no tacacs-server host {c.server}"]
    if c.source_interface:
        out.append(f"no ip tacacs source-interface {c.source_interface}")
    out.append("! no feature tacacs+   (only if nothing else on this switch uses TACACS+)")
    return "\n".join(out) + "\n"


# ── Cisco Business (research smb-meraki.md §1.6) ─────────────────────────────


def _sx_preflight(c: Ctx) -> list[dict]:
    return [
        {"command": "show running-config | include username" if c.form != "cbs220" else "show running-config",
         "look_for": "A local account with privilege 15: it's how you log in from the console, and while EasyEAP can't be reached."},
        {"command": "show tacacs", "look_for": "No other TACACS+ servers, or ones you mean to replace."},
        {"command": "show authentication methods" if c.form != "cbs220" else "show running-config",
         "look_for": "Login methods: only local today. If another server is in the list: stop and merge by hand."},
        {"command": f"ping {c.server}", "look_for": "Replies. TACACS+ uses TCP 49 to this address."},
    ]


def _sx_source(name: str) -> str:
    from app.radius.wired_cbs import source_interface
    return source_interface(name)


def _sx_config(c: Ctx) -> str:
    out = [f"! EasyEAP device administration for {c.name} (Cisco Business): administrators log in with their AD or EasyEAP account.",
           "! EasyEAP's roles should use privilege level 1, 7 or 15 (the levels these switches know). The console keeps the local login.",
           f"tacacs-server host {c.server} port {PORT} timeout 5 key {KEY_PLACEHOLDER}"]
    if c.form == "cbs220":
        out += ["aaa authentication login default tacacs+ local",
                "aaa authentication login EASYEAP-CONSOLE local",
                "line console",
                " login authentication EASYEAP-CONSOLE",
                " exit",
                "! Not documented for the CBS220 (unverified): TACACS+ accounting, and how it applies the level EasyEAP answers."]
        return "\n".join(out) + "\n"
    authz = " authorization" if c.form == "sx" else ""
    if c.source_interface and c.form == "sx":
        out.append(f"tacacs-server host source-interface {_sx_source(c.source_interface)}")
    out += [f"aaa authentication login{authz} default tacacs local",
            "aaa authentication login EASYEAP-CONSOLE local",
            f"aaa authentication enable{authz} default tacacs enable",
            "aaa accounting login start-stop group tacacs+",
            "line console",
            " login authentication EASYEAP-CONSOLE",
            " exit"]
    return "\n".join(out) + "\n"


def _sx_rollback(c: Ctx) -> str:
    out = ["! Back to local logins only.", "aaa authentication login default local"]
    if c.form != "cbs220":
        out += ["no aaa authentication enable default", "no aaa accounting login start-stop"]
    out += ["line console", " no login authentication", " exit", "no aaa authentication login EASYEAP-CONSOLE",
            f"no tacacs-server host {c.server}"]
    return "\n".join(out) + "\n"


def guide(c: Ctx) -> dict:
    if c.form in ("nxos", "sx", "sx-old", "cbs220"):
        return _other_guide(c)
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
            "config": config(c), "rollback": rollback(c), "key_placeholder": KEY_PLACEHOLDER, "form": c.form,
            "verified": False,
            "notes": ["Not yet verified on Cisco hardware: EasyEAP's TACACS+ service is tested against a protocol client that "
                      "follows IOS's login sequence.",
                      "TACACS+ only obfuscates its packets (RFC 8907): keep it on the management network.",
                      "Break-glass: names listed under Local-only usernames always use the device's own account."]}


def _other_guide(c: Ctx) -> dict:
    """NX-OS and Cisco Business: no `reload in`, so a checkpoint (NX-OS) or the saved configuration is the way back."""
    if c.form == "nxos":
        steps = ["Run the checks below first. Keep your current SSH session open until the last step.",
                 "In exec mode: `checkpoint EASYEAP-ADMIN-BEFORE` (a restore point).",
                 "`configure terminal`, paste the configuration, `end`.",
                 "From a new SSH session, log in with your AD or EasyEAP account. `show user-account` shows the role EasyEAP gave you; "
                 "EasyEAP's Admin log shows the login.",
                 "It works: `copy running-config startup-config`. It doesn't: `rollback running-config checkpoint EASYEAP-ADMIN-BEFORE` "
                 "from the first session."]
        notes = ["Not yet verified on Nexus hardware: EasyEAP answers NX-OS's role request with shell:roles, from Cisco's guides.",
                 "NX-OS user names are at most 28 characters: longer EasyEAP names can't log in to a Nexus.",
                 "A local account with the same name as an EasyEAP account overrides EasyEAP's role on NX-OS.",
                 "NX-OS falls back to local accounts only when EasyEAP doesn't answer; a refused login stays refused.",
                 "TACACS+ only obfuscates its packets (RFC 8907): keep it on the management network."]
    else:
        steps = ["Run the checks below first. Keep your current session open until the last step.",
                 "Don't save before you paste: the saved configuration is the way back.",
                 "`configure terminal`, paste the configuration, `end`.",
                 "From a new SSH session, log in with your AD or EasyEAP account. EasyEAP's Admin log shows the login.",
                 "It works: `copy running-config startup-config`. It doesn't: paste the rollback from the first session, or reload "
                 "the switch without saving."]
        notes = ["Not yet verified on Cisco Business hardware.",
                 "These switches know privilege levels 1, 7 and 15" + (" (the CBS220: 1 and 15)." if c.form == "cbs220" else "."),
                 "TACACS+ only obfuscates its packets (RFC 8907): keep it on the management network.",
                 "Break-glass: names listed under Local-only usernames always use the device's own account."]
    return {"server": c.server, "port": PORT, "server_name": server_name(c), "preflight": preflight(c), "steps": steps,
            "config": config(c), "rollback": rollback(c), "key_placeholder": KEY_PLACEHOLDER, "verified": False, "form": c.form,
            "notes": notes}

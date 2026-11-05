"""Controller configuration guides, filled with the tenant's real values. Shared secrets are never re-displayed;
guides use a placeholder the administrator replaces with the secret they saved when creating the client."""
from __future__ import annotations

from app import models as m

SECRET_PLACEHOLDER = "<shared-secret-you-saved>"  # noqa: S105 — placeholder text, not a secret


def _vlans_text(vlans: list[m.Vlan]) -> str:
    return ", ".join(f"{v.vlan_id} ({v.name})" for v in sorted(vlans, key=lambda v: v.vlan_id)) or "the VLANs in your access policy"


def guide(vendor: str, *, client: m.RadiusClient | None, settings: m.RadiusSettings, radius_ip: str, vlans: list[m.Vlan], tenant: m.Tenant) -> dict:
    ssid = settings.ssid or "Corp-WiFi"
    auth, acct = (settings.auth_port, settings.acct_port) if settings.dedicated_ports else (1812, 1813)
    name = f"EASYEAP-{tenant.slug.upper()}"[:31]
    server = radius_ip or "<easyeap-radius-ip>"
    vlan_list = _vlans_text(vlans)
    common_checks = [
        f"Each VLAN EasyEAP can assign ({vlan_list}) must exist on the controller and be trunked to the access points or their switch ports.",
        "Use WPA2-Enterprise or WPA3-Enterprise. EAP-TLS needs no username or password on the device.",
        "Test with one device first, then watch Authentication Logs in EasyEAP: each attempt shows the decision and VLAN.",
    ]
    if vendor == "cisco-9800":
        cli = f"""! EasyEAP — Catalyst 9800 (IOS-XE 17.x)
aaa new-model
dot1x system-auth-control
radius server {name}
 address ipv4 {server} auth-port {auth} acct-port {acct}
 key 0 {SECRET_PLACEHOLDER}
!
aaa group server radius EASYEAP
 server name {name}
 deadtime 5
!
aaa authentication dot1x EASYEAP-AUTH group EASYEAP
aaa authorization network EASYEAP-AUTHZ group EASYEAP
aaa accounting identity EASYEAP-ACCT start-stop group EASYEAP
!
! Change of Authorization (lets EasyEAP disconnect revoked devices). The 9800 listens on UDP 1700 by default.
aaa server radius dynamic-author
 client {server} server-key 0 {SECRET_PLACEHOLDER}
 auth-type any
!
wlan {ssid[:32]} <wlan-id> {ssid[:32]}
 security dot1x authentication-list EASYEAP-AUTH
 security wpa akm dot1x
 no security wpa akm psk
 shutdown
 no shutdown
!
wireless profile policy <policy-profile>
 aaa-override
 accounting-list EASYEAP-ACCT
 vlan <default-vlan>
 no shutdown"""
        steps = [
            "Configuration → Security → AAA → Servers/Groups: add the RADIUS server and server group (or paste the CLI).",
            "Configuration → Tags & Profiles → WLANs: set Layer 2 security to WPA2/WPA3 + 802.1X and the authentication list.",
            "Configuration → Tags & Profiles → Policy: enable AAA Override so the RADIUS VLAN is applied; set the accounting list.",
            "Configuration → Security → AAA → AAA Advanced → Server Groups / CoA: add EasyEAP as a dynamic-author client.",
            "In EasyEAP set this controller's CoA port to 1700 unless you changed it on the 9800.",
        ]
        return {"vendor": vendor, "title": "Cisco Catalyst 9800", "cli": cli, "steps": steps, "checks": common_checks, "coa_port": 1700}
    if vendor == "cisco-aireos":
        cli = f"""# EasyEAP — Cisco AireOS WLC 8.x
config radius auth add 1 {server} {auth} ascii {SECRET_PLACEHOLDER}
config radius auth rfc3576 enable 1
config radius acct add 1 {server} {acct} ascii {SECRET_PLACEHOLDER}
config wlan disable <wlan-id>
config wlan security wpa akm 802.1x enable <wlan-id>
config wlan radius_server auth add <wlan-id> 1
config wlan radius_server acct add <wlan-id> 1
config wlan aaa-override enable <wlan-id>
config wlan enable <wlan-id>"""
        steps = [
            "Security → AAA → RADIUS → Authentication: add the server, enable Support for CoA (RFC 3576).",
            "Security → AAA → RADIUS → Accounting: add the same server on the accounting port.",
            "WLANs → (your SSID) → Security → Layer 2: WPA2/WPA3, 802.1X; AAA Servers: select the server.",
            "WLANs → Advanced: enable Allow AAA Override.",
        ]
        return {"vendor": vendor, "title": "Cisco AireOS WLC", "cli": cli, "steps": steps, "checks": common_checks, "coa_port": 3799}
    if vendor == "unifi":
        steps = [
            "UniFi Network → Settings → Profiles → RADIUS → Create New.",
            f"Authentication Servers: IP {server}, port {auth}, shared secret = the secret you saved.",
            f"Enable RADIUS Accounting: IP {server}, port {acct}, same secret.",
            "Enable “RADIUS Assigned VLAN for Wireless Network” (this applies the VLAN EasyEAP returns).",
            f"Settings → WiFi → {ssid}: Security Protocol WPA2/WPA3 Enterprise, RADIUS Profile = the profile above.",
            "Create each VLAN as a network (Settings → Networks) so the access points carry it.",
            "UniFi gateways do not accept CoA from external servers in all versions: leave CoA disabled for UniFi in EasyEAP unless verified.",
        ]
        return {"vendor": vendor, "title": "UniFi Network", "cli": None, "steps": steps, "checks": common_checks, "coa_port": 3799}
    steps = [
        f"Add a RADIUS authentication server {server}:{auth} and accounting server {server}:{acct} with the shared secret.",
        "Make sure requests carry Message-Authenticator (802.1X/EAP requests always do; EasyEAP rejects requests without it as Blast-RADIUS protection).",
        "Enable dynamic VLAN assignment from RADIUS attributes (Tunnel-Type 13, Tunnel-Medium-Type 6, Tunnel-Private-Group-ID).",
        "Optionally allow CoA/Disconnect from EasyEAP on UDP 3799.",
    ]
    return {"vendor": vendor, "title": "Other controller", "cli": None, "steps": steps, "checks": common_checks, "coa_port": 3799}

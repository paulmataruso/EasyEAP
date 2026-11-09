# Wireless controller and switch guides

EasyEAP works with any controller that supports WPA2/WPA3-Enterprise with an external RADIUS server and dynamic
VLAN assignment from RADIUS attributes, and with switches that run 802.1X on their ports (wired). These guides cover
the controllers and switches MSPs meet most often:

| Controller or switch | Guide | CoA port | CLI in the console |
|---|---|---|---|
| Cisco Catalyst 9800 (IOS-XE 17.x) | [cisco-catalyst-9800.md](cisco-catalyst-9800.md) | UDP 1700 | Yes |
| Cisco AireOS WLC 8.x | [cisco-aireos.md](cisco-aireos.md) | UDP 3799 | Yes |
| UniFi Network (Wi-Fi and switches) | [unifi.md](unifi.md) | not used | Steps only |
| Cisco Catalyst switches, IOS-XE and classic IOS (wired 802.1X) | [cisco-catalyst-switch.md](cisco-catalyst-switch.md) | UDP 1700 | Yes, for that switch's ports |
| Cisco Nexus switches, NX-OS (wired 802.1X) | [cisco-nexus.md](cisco-nexus.md) | UDP 1700 (Nexus 9000) | Yes |
| Cisco Business: Catalyst 1200/1300, CBS, SG/SF (wired 802.1X) | [cisco-business.md](cisco-business.md) | UDP 1700 (Catalyst 1300) | Yes (SG200: web steps) |
| Cisco Meraki MS (wired 802.1X) | [meraki-ms.md](meraki-ms.md) | not used | Dashboard steps |

Switches start in **monitor mode**: EasyEAP sends them no VLAN until you enforce. Where the switch has an open mode,
its ports stay open; Nexus, Meraki MS and classic IOS before 12.2(50)SE have none, and EasyEAP monitors from its side by
accepting their MAC requests. Some Cisco Business models have no monitor mode at all and start with one test port.
See the Catalyst guide for the rollout. **Paste `show version`** in Add switch and EasyEAP picks the family, model and
release, and offers only what that switch can do.

Each tenant's **RADIUS** screen shows the same guide filled with that tenant's values: the RADIUS address, ports,
SSID, VLAN list and a name for the server entry. Prefer it over these pages; they exist for planning and change
records.

## What every controller needs

1. **A RADIUS client in EasyEAP.** Add the controller (or switch) on the tenant's RADIUS screen with the address its requests
   come from. EasyEAP generates a 32-character shared secret and shows it. Paste it into the controller straight
   away. To paste it again later, **Fill in the shared secret** on the controller's configuration puts in the secret
   EasyEAP keeps (for administrators who may rotate it; each showing is audited). Rotate it if it may have leaked.
2. **An authentication server** at the EasyEAP RADIUS address, UDP 1812 (or the tenant's dedicated port), and an
   **accounting server** on UDP 1813 (or the dedicated accounting port), with that secret.
3. **An SSID** using WPA2-Enterprise or WPA3-Enterprise (802.1X). EAP-TLS asks the user for nothing; the device
   presents its certificate.
4. **AAA override / RADIUS-assigned VLAN** turned on, so the controller applies the VLAN EasyEAP returns:

   | Attribute | Value |
   |---|---|
   | `Tunnel-Type` | 13 (VLAN) |
   | `Tunnel-Medium-Type` | 6 (IEEE-802) |
   | `Tunnel-Private-Group-ID` | the VLAN ID from the matching rule |

5. **Every VLAN** in the tenant's access policy must exist on the controller and be trunked to the access points
   (or their switch ports). If it isn't, authentication succeeds but the device lands nowhere useful. The
   Authentication log shows this as "VLAN could not be applied".
6. **Message-Authenticator.** EasyEAP requires it on every request (`require_message_authenticator`, the Blast-RADIUS
   mitigation for CVE-2024-3596), except from switches that send MAC authentication requests without it: Nexus,
   Cisco Business, Meraki MS and classic IOS before 12.2(50)SE (the release from **Paste `show version`**). From
   those, a request that carries Proxy-State without it is still dropped. 802.1X/EAP requests always carry it, so
   elsewhere this only affects non-EAP test tools.

## Change of Authorization (CoA)

When you revoke a certificate you can ask EasyEAP to disconnect the device. EasyEAP sends a Disconnect-Request to the
controller's CoA port with the same shared secret. Turn on CoA for the client in EasyEAP only when the controller
accepts it. Without CoA, a device that is already connected stays connected until it next re-authenticates: at the
tenant's `Session-Timeout` (8 hours by default), or later if fast-roaming caches (PMK caching, OKC, 802.11r) let it
roam without a full EAP exchange. New connections with a revoked certificate are refused once RADIUS applies the
update, normally within about 15 seconds.

## Network path

RADIUS over UDP must not cross the internet unprotected. Route controller traffic to EasyEAP over the site-to-site
VPN, and firewall UDP 1812/1813 (and any dedicated tenant ports) to the controllers' addresses. If two tenants'
controllers reach EasyEAP from the same address (overlapping private ranges behind NAT), give one of them dedicated
ports on its RADIUS screen; EasyEAP refuses ambiguous client addresses.

## Test

1. Enroll one test device.
2. Connect it to the SSID.
3. Open the tenant's **Authentication log**: the attempt shows the decision, the rule that matched and the VLAN.
4. On the controller, confirm the client's VLAN matches.

# Cisco Business switches (wired 802.1X)

Catalyst 1200 and 1300, CBS220, CBS250 and CBS350, and the earlier Small Business SG/SF 200, 250, 300, 350, 500 and
550X. Add the switch from the tenant's **RADIUS** screen: **Add → Switch → Cisco**, then **Paste show version**
(paste `show system` too: the model is there), or choose **Cisco Business** and the model by hand.

**Not verified on Cisco Business hardware.** The commands come from Cisco's CLI guides for the C1300/C1300X 4.x, Sx350X
2.5, CBS350/CBS250 3.1, Sx300 1.4 and CBS220 (research notes, [plan](../plans/cisco-platforms.md) §12). Review the
configuration on one switch, with one test port, first.

## What each model family can do

| Model family | Monitor (open) mode | MAC authentication | VLANs from RADIUS | Accounting | CoA | Admin logins (TACACS+) |
|---|---|---|---|---|---|---|
| Catalyst 1300 | yes | yes | yes | yes | from firmware 4.1.3.36 | yes |
| CBS350, Sx350, SG350X, Sx550X | yes | yes | yes | yes | no | yes |
| SG300, SF300, SG500 (firmware 1.4) | yes | yes (sent as EAP-MD5) | yes | yes | no | yes |
| Catalyst 1200 | **no** | no | no | no | no | no |
| CBS250, SG250, SF250 | **no** | no | no | no | no | no |
| CBS220 | **no** | no | yes | no | no | yes |
| SG200, SF200 | **no** (web interface only) | no | no | no | no | no |

None of them has a critical VLAN: while EasyEAP is unreachable, new devices either **wait** or are **allowed on their
port's VLAN** (`aaa authentication dot1x default radius none`, one setting for the whole switch). The CBS220 has no such
fallback: new devices wait.

**No monitor mode** means a device without an EasyEAP certificate loses access as soon as its port is configured.
EasyEAP says so in the console: list **one test port** first, and leave printers, cameras and phones out of the plan.

These switches send MAC requests without Message-Authenticator, so EasyEAP doesn't require it from them (requests with
Proxy-State and no Message-Authenticator are still dropped).

## What the configuration contains (CBS350, Sx350, C1300, Sx300)

```
radius-server host <EasyEAP> auth-port 1812 acct-port 1813 timeout 5 retransmit 2 key <secret> usage dot1.x
radius-server host source-interface vlan 10      (when set; not on the Sx300)
aaa authentication dot1x default radius none     (monitor: let devices through while EasyEAP is unreachable)
aaa accounting dot1x start-stop group radius
dot1x mac-auth radius                             (MAC authentication as PAP)
aaa server radius dynamic-author                  (Catalyst 1300 from 4.1.3.36)
 client <EasyEAP> server-key <secret>
dot1x system-auth-control
interface range gi1/0/1-23
 switchport mode access
 dot1x host-mode multi-sessions                   (multi-auth)
 dot1x authentication 802.1x mac                  (802.1x only without MAC authentication)
 dot1x reauthentication
 authentication open                              (monitor mode)
 spanning-tree portfast
 dot1x port-control auto
```

**Enforce**: `no authentication open` and `dot1x radius-attributes vlan static` on the ports, the guest VLAN for devices
without 802.1X when the plan has one, `aaa authentication dot1x default radius` when new devices should wait while
EasyEAP is unreachable, then `dot1x re-authenticate`.

The CBS220 has its own command language (`radius-server host … usg-type 802.1x`, `dot1x guest-vlan N enable`,
`dot1x radius-attribute vlan static`); the SG200 gets web interface steps (Security → RADIUS, Security → 802.1X).

Port names are written as the switch prints them: `gi1/0/1`, `te1/0/1`.

## Safe paste

There's no `reload in` on these switches. The saved configuration is the way back:

1. Don't save before you paste.
2. `configure terminal`, paste, `end`.
3. Open a **new** session (SSH or the web interface) and check you can still log in.
4. Something's wrong: reload without saving, and the switch comes back with the saved configuration.
5. It works: `copy running-config startup-config`.

## Sessions, switch audit and syslog

These switches don't print a session list EasyEAP reads, so **Enforce** asks you to check the switch's 802.1X status
yourself. They have no CISCO-AUTH-FRAMEWORK-MIB: the switch audit reads ports only (not on the SG200). SNMPv3 uses
SHA-256 and AES-128; the SG300/SF300 can only encrypt with DES, so it uses SNMPv2c. The SNMP community is limited to
EasyEAP's address (not possible on the CBS220). Syslog: `logging host <EasyEAP> port <port> severity informational`.

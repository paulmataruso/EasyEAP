# Cisco Catalyst switches (wired 802.1X)

Wired 802.1X uses the same device certificates as Wi-Fi: a laptop enrolled for the SSID can authenticate on a switch
port without enrolling again. Add the switch from the tenant's **RADIUS** screen (**Add → Switch**). The wizard
generates the configuration for that switch's own ports, with the tenant's RADIUS address and ports filled in. Use the
wizard. This page explains what it generates and why, for change records and reviews.

| Configuration style | Platforms | Monitor mode | Enforce |
|---|---|---|---|
| **IOS-XE (IBNS 2.0)** | Catalyst 9200, 9300, 9400, 9500; 3650/3850 on IOS-XE 16.x | policy map `EASYEAP_MONITOR` (ports open by default) | policy map `EASYEAP_CLOSED` and `access-session closed` |
| **Classic** | IOS 15.x: 2960-X, 2960-XR, 3560-CX, 3650/3850 on IOS-XE 3.x | `authentication open` | `no authentication open` |

Run `show version | include IOS` to choose. Not sure? IOS-XE 16.x and 17.x use IBNS 2.0.

## The rollout: monitor first, then enforce

A new switch always starts in **monitor mode**:

- Every port in the plan runs 802.1X, but the port stays **open**. A device that fails, or doesn't speak 802.1X,
  keeps the access it had.
- EasyEAP decides as usual and logs the decision, but sends **no VLAN** to this switch. The Authentication log shows
  the VLAN it *would* assign ("Not sent: monitor mode").
- No fallback actions run (no critical VLAN, no "no 802.1X" VLAN). Printers and access points on a configured port
  aren't moved anywhere.

Leave it there for a few days. Then open the switch's panel on the RADIUS screen:

1. **Readiness**: what EasyEAP saw from this switch, by port: accepted devices, refused devices and the VLANs
   enforcing would assign. Devices that never try 802.1X don't appear here.
2. **Check the switch's own sessions**: paste the output of `show access-session` (IBNS 2.0) or
   `show authentication sessions` (classic). EasyEAP lists every session that isn't authorized. Each one
   **loses access** when you enforce.
3. **Enforce**: EasyEAP asks you to confirm you've checked, starts sending VLANs to the switch, and shows the change
   to paste **once RADIUS is running it** (usually within 15 seconds). Pasted any earlier, `clear access-session`
   would re-authenticate devices while EasyEAP still withholds VLANs, and they'd stay on the port's VLAN until their
   next re-authentication. Paste it with the safe-paste steps below.

**Back to monitor mode** reverses it: EasyEAP stops sending VLANs and shows the change that opens the ports again.

## Before you paste: preflight

The wizard lists these commands and what to look for in each answer:

| Command | Look for |
|---|---|
| `show version \| include IOS` | The configuration style (above). |
| `show running-config \| include aaa new-model` | A line back: tick **Already uses AAA**. EasyEAP then leaves the login and exec method lists alone. |
| `show running-config \| include dot1x\|access-session\|authentication port-control\|policy-map type control` | **Must print nothing.** If it prints anything, the switch already has 802.1X: stop and merge by hand (below). |
| `show interfaces trunk` | Uplinks and AP ports. Put them in **Ports to leave alone**. |
| `show cdp neighbors` (or `show lldp neighbors`) | Switches, routers, APs and phones: leave their ports alone. |
| `show users` | Your own session. If you're on a switch port, find it (`show mac address-table address <your-mac>`) and leave it alone. |
| `ping <easyeap-radius-ip>` | Replies. Fix routing, the source interface or the VRF first. |

**Ports to leave alone** are skipped even inside the access-port ranges: `Gi1/0/1-48` with `Gi1/0/48` left alone
configures `GigabitEthernet1/0/1 - 47`. The configuration lists them in a comment.

## Safe paste

1. In exec mode: `reload in 15`. If the paste cuts you off, the switch reboots into its saved configuration in
   15 minutes.
2. `configure terminal`, paste, `end`.
3. Open a **new** SSH session to the switch. If you can log in: `reload cancel`.
4. `write memory`.

## What the configuration contains

- **AAA.** If the switch doesn't use AAA yet, `aaa new-model` with `aaa authentication login default local` and
  `aaa authorization exec default local`, so logins keep using the switch's local users. Make sure one exists
  (`show running-config | include ^username`) before you paste.
- **The RADIUS server** `EASYEAP-<TENANT>` in server group `EASYEAP`: `timeout 5`, `retransmit 2`, `deadtime 3`, and
  `radius-server dead-criteria time 5 tries 3`. The optional source interface (`ip radius source-interface`) and VRF
  (`ip vrf forwarding`) go in the group.
- **dot1x authentication, network authorization and accounting** through `EASYEAP` (`aaa accounting identity` on
  IBNS 2.0, `aaa accounting dot1x` on classic).
- **Change of Authorization** (`aaa server radius dynamic-author`, UDP 1700) when CoA is on for the switch, so
  revoking a certificate in EasyEAP ends that device's session on the port.
- **Attributes.** `radius-server attribute 31 mac format ietf upper-case` (MAC addresses in the log match Wi-Fi's)
  and `radius-server vsa send` for authentication and accounting.
- **Per port.** `switchport mode access`, the host mode (multi-auth by default: each device behind a port
  authenticates separately), `port-control auto`, periodic re-authentication with the server's Session-Timeout,
  `dot1x pae authenticator`, `dot1x timeout tx-period 10`, `spanning-tree portfast` and `bpduguard`.
- **Violations restrict**, not shut down: a second device on a single-host port is dropped, the port stays up.
- **No MAB.** MAC Authentication Bypass isn't supported. A MAB request reaching EasyEAP is rejected and logged as
  "Switch tried MAC Authentication Bypass".

### When EasyEAP is unreachable

The port plan's **If EasyEAP is unreachable** setting applies once enforced. In every case a device already
authorized stays authorized (`AAA_SVR_DOWN_AUTHD_HOST`: pause re-authentication, authorize).

| Setting | New devices while every EasyEAP server is dead |
|---|---|
| **Wait** (default) | Refused; the port retries every 5 minutes (`authentication-restart 300`). |
| **Let them on** | Critical access on the port's own VLAN, re-authenticated when EasyEAP is back. |
| **A VLAN** | Critical access in that VLAN, re-authenticated when EasyEAP is back. |

### Devices without 802.1X

**Block** (default): once enforced, a port whose device never answers 802.1X stays closed. **A VLAN**: such
devices get that VLAN (`service-template EASYEAP_NO_8021X` on IBNS 2.0, `authentication event no-response` on
classic). Pick a restricted one. Neither applies in monitor mode.

## The switch already has 802.1X

EasyEAP doesn't merge configuration. If the preflight shows existing 802.1X, either remove it in a maintenance
window and paste EasyEAP's, or add EasyEAP's RADIUS server to your existing server group and keep your own port
configuration. Register the switch in EasyEAP either way, so requests are attributed and the log shows its ports.
EasyEAP sends the same VLAN attributes as for Wi-Fi: `Tunnel-Type` 13, `Tunnel-Medium-Type` 6,
`Tunnel-Private-Group-ID`.

## VLANs on switch ports

A rule's VLAN is the Wi-Fi VLAN. Each VLAN in **Access policy** also says what a switch port gets: the **same** VLAN
(default), the **port's own** VLAN (no VLAN is sent; the device stays where the port is), or **another** VLAN ID.
Every VLAN EasyEAP can assign must exist on the switch (`show vlan brief`). Otherwise the device is accepted, but the
switch fails the authorization. The guide's checks list the VLANs that enforcing will assign.

## How EasyEAP tells wired from Wi-Fi

Catalyst switches send `NAS-Port-Type = Ethernet`, `NAS-Port-Id` (the interface, for example
`GigabitEthernet1/0/5`) and the switch's MAC as `Called-Station-Id`. EasyEAP counts a request from a switch
registered for wired only as wired, and refuses a Wi-Fi request from it ("Network not enabled on this controller or switch"). The
Authentication log's **Network** filter shows wired attempts, with the switch and port.

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| The wizard waits for the first request, and says the address isn't registered | The switch sends RADIUS from another address. Change the registration's address, or set the source interface. |
| The wizard says the shared secret is wrong | Paste the configuration again with the secret EasyEAP showed, or rotate it. |
| `show access-session interface Gi1/0/5 details` shows `Unauth` and no request in the log | The device isn't sending 802.1X (no supplicant, or wired 802.1X not set up on it). See [enrollment](../enrollment.md#wired-8021x). |
| Accepted in the log, but the port shows `Authz Failed` | The VLAN EasyEAP sent doesn't exist on the switch. |
| Requests stop for 3 minutes after an outage | `deadtime 3`: the switch skipped a dead server. Expected; it retries after 3 minutes. |

## Not verified

EasyEAP's tests run the generated configuration's RADIUS side against real FreeRADIUS with real EAP-TLS
(`tests/radius/run.sh`, `tests/e2e/run.sh`), but **no configuration has been pasted onto a real Catalyst switch** by
these tests. The commands follow Cisco's IBNS 2.0 and classic 802.1X documentation. Review the configuration on one
switch, with one test port, before rolling it out.

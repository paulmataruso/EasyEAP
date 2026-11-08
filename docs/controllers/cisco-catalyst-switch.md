# Cisco Catalyst switches (wired 802.1X)

Wired 802.1X uses the same device certificates as Wi-Fi: a laptop enrolled for the SSID can authenticate on a switch
port without enrolling again. Add the switch from the tenant's **RADIUS** screen (**Add → Switch**). The wizard
generates the configuration for that switch's own ports, with the tenant's RADIUS address and ports filled in. Use the
wizard. This page explains what it generates and why, for change records and reviews.

| Family | Platforms | Monitor mode | Enforce |
|---|---|---|---|
| **IOS-XE (IBNS 2.0)** | Catalyst 9200, 9300, 9400, 9500 (IOS-XE 16.x, 17.x, 26.x); 3650/3850 on IOS-XE 16.x, or on 3.x | policy map `EASYEAP_MONITOR` (ports open by default) | policy map `EASYEAP_CLOSED` and `access-session closed` |
| **Classic IOS** (12.2(50)SE and later) | 2960, 2960-X, 2960-XR, 2960-L, 3560, 3560-CX, 3750, IE 2000 | `authentication open` | `no authentication open` |
| **Classic IOS** before 12.2(50)SE | the same switches on older releases (no authentication manager) | EasyEAP accepts their MAC requests (below) | `dot1x` fallback actions, then `dot1x re-authenticate` per port |

Nexus, Cisco Business and Meraki switches have guides of their own: [Nexus](cisco-nexus.md),
[Cisco Business](cisco-business.md), [Meraki MS](meraki-ms.md).

In Add switch, **Paste show version**: EasyEAP reads the family, model and release (and LAN Lite images) and generates
for that release. The release decides which form each command takes, for example:

| Release | What changes |
|---|---|
| Classic before 15.2(3)E (2960-X: 15.0(2)EX) | `radius-server host … key …` instead of the named `radius server` |
| Classic before 12.2(55)SE | no `radius-server dead-criteria`; critical access uses `dot1x critical`; multi-auth ports don't apply RADIUS VLANs |
| Classic before 12.2(52)SE | no CoA; the switch audit doesn't read err-disabled ports |
| Classic before 15.2(7)E | no VLAN for devices without 802.1X on multi-auth ports (single-host or multi-host only) |
| Classic before 15.2(7)E3 | admin logins (TACACS+) use `tacacs-server host` |
| Classic LAN Lite | no critical access, CoA or violation modes |
| IOS-XE 3.x | no `radius-server attribute 31`; admin logins use `tacacs-server host`; before 3.6: `radius-server host` |

Without a release, EasyEAP assumes a recent one (IOS 15.2(3)E or later, IOS-XE 16 or later) and says so above the
configuration. A classic release from a train Catalyst access switches don't run (SX, SY, SG…) is treated as unknown.

### Classic IOS before 12.2(50)SE

These releases have no authentication manager: no open mode, no multi-auth, no CoA. The ports use the older `dot1x`
commands (`dot1x port-control auto`, `dot1x mac-auth-bypass`, `dot1x guest-vlan`, `dot1x critical`), and EasyEAP
monitors from its side: it accepts every MAC request from the switch with no VLAN while it's in monitor mode, and logs
what it would decide. A device that tries 802.1X and fails is refused even in monitor mode, so start with one test
port. The session list is `show dot1x all summary`. Before 12.2(25)SEE there's no MAC authentication bypass: EasyEAP
asks you to upgrade the switch.

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
2. **Check the switch's own sessions**: paste the output of `show access-session` (IBNS 2.0),
   `show authentication sessions` (classic) or `show dot1x all summary` (classic before 12.2(50)SE). EasyEAP lists every session that isn't authorized. Each one
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
| `show version \| include IOS` | The family and release EasyEAP built the configuration for (above). |
| `show running-config \| include ^aaa new-model` | `aaa new-model`: tick **Already uses AAA**, and EasyEAP leaves the login and exec method lists alone. Nothing, or `no aaa new-model`: AAA is off, leave it unticked. Either way the configuration starts with `aaa new-model`, which `radius server` and every `aaa` command need (IOS-XE says “radius server” isn't a command without it). |
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
2. IOS-XE only: `authentication convert-to new-style`, and answer `yes` (releases without it: `authentication display
   new-style`). IOS-XE asks this yes/no question once, before it takes its first control policy, and the switch keeps
   the new-style (IBNS 2.0) configuration from then on. Answered now, the question can't take a line of the paste as
   its answer. If the switch offers neither command, it already uses the new style.
3. `configure terminal`, paste, `end`.
4. Open a **new** SSH session to the switch. If you can log in: `reload cancel`.
5. `write memory`.

## What the configuration contains

- **AAA.** If the switch doesn't use AAA yet, `aaa new-model` with `aaa authentication login default local` and
  `aaa authorization exec default local`, so logins keep using the switch's local users. Make sure one exists
  (`show running-config | include ^username`) before you paste. With [admin logins](../device-administration.md) on
  for the switch, those two lines are left out: the device-administration configuration sets the login lists.
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
- **MAC authentication (MAB)**, when it's on for the switch: a device that doesn't answer 802.1X (two EAP requests
  10 seconds apart, about 30 seconds after link-up) is checked against EasyEAP's **MAC allow list**, and its group's
  VLAN is sent. A device that answers 802.1X and fails never falls back to MAB. IBNS 2.0 gets `mab` on the ports and
  `authenticate using mab` in the policy; classic gets `authentication order dot1x mab`. Turning it on or off gives a
  short change to paste, in monitor mode. Without it, a MAB request reaching EasyEAP is rejected as
  "MAC authentication isn't on for this switch".

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
classic). Pick a restricted one. Neither applies in monitor mode. With MAC authentication on, this setting is where devices that
aren't on the allow list go.

Build the allow list in monitor mode: the ports stay open, and every MAC the switch asks about appears under **MAC
allow list → Seen, not allowed**, by port. Enforce warns about MACs still waiting there. A MAC address is easy to
copy, so give each group a VLAN that reaches only what its devices need.

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
| The wizard says the shared secret is wrong | Open the switch, choose **Fill in the shared secret** on its configuration, and paste the `key` line again. |
| `show access-session interface Gi1/0/5 details` shows `Unauth` and no request in the log | The device isn't sending 802.1X (no supplicant, or wired 802.1X not set up on it). See [enrollment](../enrollment.md#wired-8021x). |
| Accepted in the log, but the port shows `Authz Failed` | The VLAN EasyEAP sent doesn't exist on the switch. |
| A port in the plan never starts a session: no request, nothing in `show access-session`, and the switch audit shows the port down while its link is up | The port is a SPAN destination (`show monitor session all`, Destination Ports). The switch runs no 802.1X on it, and it forwards nothing, until the session is removed (`no monitor session <number>`). The preflight asks. |
| Requests stop for 3 minutes after an outage | `deadtime 3`: the switch skipped a dead server. Expected; it retries after 3 minutes. |

## Not verified

EasyEAP's tests run the generated configuration's RADIUS side against real FreeRADIUS with real EAP-TLS
(`tests/radius/run.sh`, `tests/e2e/run.sh`), but **no configuration has been pasted onto a real Catalyst switch** by
these tests. The commands follow Cisco's IBNS 2.0 and classic 802.1X documentation. Review the configuration on one
switch, with one test port, before rolling it out. The same goes for MAC authentication and for admin logins over TACACS+.

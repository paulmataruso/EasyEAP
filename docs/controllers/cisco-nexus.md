# Cisco Nexus switches (NX-OS, wired 802.1X)

Add the switch from the tenant's **RADIUS** screen: **Add → Switch → Cisco**, then **Paste show version** (or choose
**Nexus** and the model by hand). EasyEAP reads the model and NX-OS release and offers only what that switch can do.
This page explains what it generates and why, for change records and reviews.

**Not verified on Nexus hardware.** Every command comes from Cisco's NX-OS security configuration guides and command
references (research notes, [plan](../plans/cisco-platforms.md) §12). Review the configuration on one switch, with one
test port, before rolling it out.

## Which Nexus switches

| Model family (EasyEAP's choice) | MAC authentication | VLANs from RADIUS | Multi-auth | CoA | EasyEAP unreachable |
|---|---|---|---|---|---|
| Nexus 9300-EX, -FX, -FX2 | from 9.2(1) | yes (the first device on a multi-auth port sets it) | from 9.2(1) | from 9.2(3): re-authenticate or disconnect | wait; from 10.1(2) also "allow" (MAC-authenticated devices) |
| Nexus 9348GC-FXP | from 9.2(1) | no | from 9.2(1) | no | wait |
| Other Nexus 9000 (9300-FX3, -GX, 9500 with EX/FX line cards) | from 10.5(2) | no | from 9.2(1) | from 9.2(3) | wait |
| Nexus 3000, 3100, 3200 | from 9.2(1) | no | no | no | wait |
| Nexus 3548 | yes | yes | yes | no | wait |
| Nexus 5500, 5600, 6000 | yes | yes | no | no | wait |
| Nexus 7000, 7700 | yes | no | no | no | wait |

The **Nexus 3600** (and 9500-R) has no 802.1X on any release: EasyEAP refuses it when it reads its `show version`.
NX-OS 7.0(3)I7 on a Nexus 9000 has 802.1X only (no MAC authentication, no multi-auth).

## Monitor mode on a switch without one

NX-OS has no open mode: an 802.1X port lets a device on only once it's authorized. So EasyEAP monitors **from its own
side** while the switch is in monitor mode:

- The ports run 802.1X with MAC authentication (`dot1x mac-auth-bypass`), which is always on for a Nexus.
- A device that doesn't answer 802.1X is MAC-authenticated, and **EasyEAP accepts every MAC request** from the switch
  with no VLAN. The decision it would have made (not on the allow list, expired, blocked) is logged as a refusal in
  monitor mode, and unknown MACs appear under **MAC allow list → Seen, not allowed**.
- A device that **answers 802.1X and fails is refused**, even in monitor mode: NX-OS doesn't fall back to its MAC.
  Start with one test port, and make sure every 802.1X device there has an EasyEAP certificate.
- Accepted devices get a 30-minute session, so after Enforce they ask again within 30 minutes even where CoA isn't
  available.

Without MAC authentication (7.0(3)I7, Nexus 9000 FX3/GX before 10.5(2)) there's no monitor phase at all: the console
says so and the configuration starts with one test port.

EasyEAP doesn't require Message-Authenticator from a Nexus (NX-OS MAC requests may not carry it); requests that carry
Proxy-State without it are still dropped (BlastRADIUS).

## What the configuration contains

```
feature dot1x
radius-server host <EasyEAP> key 0 <secret> auth-port 1812 acct-port 1813 authentication accounting
radius-server host <EasyEAP> timeout 5
radius-server host <EasyEAP> retransmit 2
radius-server deadtime 3
aaa group server radius EASYEAP
  server <EasyEAP>
  use-vrf management            (or the VRF in the port plan; "default" for in-band)
  deadtime 3
aaa authentication dot1x default group EASYEAP
aaa accounting dot1x default group EASYEAP
dot1x radius-accounting
aaa server radius dynamic-author           (where the switch has CoA)
  client <EasyEAP> vrf management server-key 0 <secret>
interface Ethernet1/1-47
  switchport
  switchport mode access
  dot1x port-control auto
  dot1x host-mode multi-auth               (multi-host or single-host where multi-auth isn't available)
  dot1x mac-auth-bypass
  dot1x re-authentication
  dot1x timeout tx-period 10
  dot1x max-reauth-req 2
  spanning-tree port type edge
  spanning-tree bpduguard enable
```

**Enforce** adds `radius-server host <EasyEAP> test idle-time 5` and `authentication event server dead action authorize`
(Nexus 9300-EX/FX/FX2 on 10.1(2) or later, when the plan lets devices on while EasyEAP is unreachable), or the guest
VLAN (Nexus 5000), then `dot1x re-authenticate` so every device asks again. EasyEAP stops accepting MAC requests it
would refuse at the same moment. **Back to monitor mode** removes those lines.

Port names are written as NX-OS prints them: `Ethernet1/1`, `Ethernet1/1-48`. Leave uplinks, port-channel members, vPC
ports and the peer link out of the plan: the preflight lists the commands that show them.

## Safe paste

NX-OS has no `reload in`. The way back is a checkpoint:

1. In exec mode: `checkpoint EASYEAP-BEFORE`.
2. `configure terminal`, paste, `end`.
3. Open a **new** SSH session and check you can still log in.
4. Something's wrong: `rollback running-config checkpoint EASYEAP-BEFORE`.
5. It works: `copy running-config startup-config`.

## Sessions before you enforce

The switch's own list: `show dot1x all summary`. Paste it into **Enforce → What the switch sees**: every port that
isn't `AUTHORIZED` loses access once enforced.

## Admin logins (TACACS+)

[Device administration](../device-administration.md) generates the NX-OS form (`feature tacacs+`, a server group with
`use-vrf`, local logins on the console and as the fallback). EasyEAP answers a Nexus login with
`shell:roles="network-admin"` for a level-15 role and `"network-operator"` below (Nexus 7000: plus `vdc-admin` /
`vdc-operator`), never `priv-lvl`. Usernames over 28 characters don't work on NX-OS.

## Switch audit and syslog

NX-OS has no CISCO-AUTH-FRAMEWORK-MIB, so the switch audit reads ports (and err-disabled ports on the Nexus 9000), not
802.1X sessions. The SNMP block uses an IPv4 ACL and the `network-operator` role (NX-OS has no SNMP views). It's
SNMPv2c only: on NX-OS an SNMPv3 user is also a login account on the switch. Syslog goes to
EasyEAP's port with `logging server <EasyEAP> 5 port <port> use-vrf management`. The Nexus 5000 and 3548, and NX-OS
before 9.3(3) on the Nexus 9000 and 3000, send syslog only to UDP 514: their block says so and the audit runs on SNMP alone.

# Plan: every Cisco switch family

Status: implemented (2026-11-08), revision 2: revision 1 with the critique's 16 findings folded in (§14). The user asked for it: "we need to support all cisco switches -- Nexus, IOS-XE,
IOS. Don't guess there are plenty of guides online on how to do this." and "End goal: there should be no cisco switch
we can not work with." Nothing here has been run on Cisco hardware (EasyEAP has none). Every command comes from the
research notes listed in §12, which cite Cisco's guides line by line. A command no Cisco document confirms is marked
**unverified** in the generated configuration, never presented as known.

## 1. What exists today

- Vendor `cisco-switch` with `wired_profile.platform` = `ibns2` (IOS-XE, IBNS 2.0) or `classic` (auth manager). The
  console asks the admin to choose, from `show version | include IOS`.
- The classic output borrows IOS-XE commands that most classic releases reject:
  - named `radius server` / `address ipv4` (only 15.2(3)E+, or 15.0(2)EX on the 2960-X);
  - `deadtime` and `ip radius source-interface` inside the server group (undocumented on Catalyst);
  - `radius-server attribute 31 mac format ietf upper-case` (undocumented on classic Catalyst);
  - `authentication event no-response action authorize vlan` on multi-auth ports (only from 15.2(7)E);
  - `clear authentication sessions` (not in the Catalyst command references).
- The IOS-XE output references `DEFAULT_CRITICAL_DATA_TEMPLATE`, which Cisco documents nowhere as a built-in, and
  assumes the critical and no-802.1X VLANs exist.
- Nexus (NX-OS), Cisco Business (C1200/C1300, CBS, Sx series) and Meraki MS have no output at all. "Other switch" gives
  generic steps.
- TACACS+ (device admin) supports IOS/IOS-XE only. It never sends the NX-OS role attribute, so a Nexus admin would log
  in read-only.
- The switch audit and its syslog work on Catalyst only (CISCO-AUTH-FRAMEWORK-MIB; `%FAC-<digit>-MNEMONIC` tags).

## 2. Families, and how EasyEAP tells them apart

One vendor, `cisco-switch`, with a **platform** (the configuration language) and, where features differ by model or
release, a **series** and a **version**. Meraki MS is a separate vendor, `meraki`, because it has no CLI: it gets
Dashboard steps, like UniFi.

| platform | Covers | Language |
|---|---|---|
| `ibns2` | IOS-XE 3.2SE+ (3650, 3850, 4500E Sup7/8), 16.x, 17.x, 26.x (Catalyst 9000, IE3x00, ESS9300) | IBNS 2.0 policy |
| `classic` | Classic IOS 12.2(25)SEE – 15.2(7)E (2960, 2960-S/-Plus/-C/-X/-XR/-L, 3560, 3750, -E/-X, IE 2000/3000/4000/5000, Catalyst 1000) | auth manager (12.2(50)SE+) or the older `dot1x` dialect |
| `nxos` | Nexus 9000, 3000, 3500, 5500/5600/6000, 7000/7700 | NX-OS |
| `cbs` | Cisco Business and Small Business managed switches: C1300, C1200, CBS350/Sx350/Sx550X, Sx300/Sx500, CBS250/SG250, CBS220, SG200 | "sx" CLI (CBS220: its own CLI; SG200: web only) |

`series` values:
- `nxos`: `n9k-fx` (Nexus 9300-EX/FX/FX2), `n9k-fxp` (9348GC-FXP: no CoA, no RADIUS VLAN), `n9k` (9300-FX3/GX,
  9500 with EX/FX line cards), `n3k` (3000/3100/3200 on the unified image), `n3548`, `n5k` (5500/5600/6000), `n7k`
  (7000/7700). The Nexus 3600 (and 9500-R) has no 802.1X: detection refuses it.
- `cbs`: `c1300`, `c1200`, `sx350` (Sx350, SG350X/XG, Sx550X, CBS350), `sx300` (Sx300, Sx500, firmware 1.4), `sx250`
  (SG250, CBS250), `cbs220`, `sx200`.
- `classic`: `lanlite` true/false (from the image name, `LANLITE`).

`version` is the software release as `show version` prints it: `15.2(7)E3`, `12.2(55)SE12`, `16.6.1`, `17.9.4a`,
`9.3(8)`, `10.2(5)M`, `4.1.3.36`. Empty means unknown: EasyEAP then uses the most widely supported form and says which
assumption it made.

### 2.1 Detection from `show version`

The admin can paste `show version` (Cisco Business: `show version` plus `show system`). A pure function
`detect(text) -> {platform, series, version, lan_lite, model, evidence}` reads it. The rules, in order:

1. `Cisco Nexus Operating System (NX-OS) Software` → `nxos`. Version: `NXOS: version X`, else `system: version X`.
   Series from the chassis line (`cisco Nexus9000 C93180YC-EX chassis` → `n9k-fx` for -EX/-FX/-FX2 models; `Nexus9000`
   or `Nexus3000` otherwise → `n9k`; `Nexus 3548` → `n3548`; `Nexus5…`/`Nexus6…` → `n5k`; `Nexus7…` → `n7k`), else
   from the train (`…N1(…)` → `n5k`, `…D1(…)` or `system:` with 6.x/8.x → `n7k`).
2. `^Cisco IOS XE Software, Version (\d\d)\.(\d\d)\.(\d\d[a-z]?)` → `ibns2`, version 16/17/26. Else `IOS-XE Software`
   and `Version 0?3\.\d+\.\d+` → `ibns2`, version 3.x. Else `Denali 16.` / `Everest` / a bracketed train → `ibns2`.
3. `Cisco IOS Software, …` or `IOS (tm)` with `Version 1[25]\.\d+\(\d+[a-z]?\)[A-Z]+\d*` → `classic`; `LANLITE` in the
   image name → `lan_lite`.
4. Cisco Business: `Active-image` / `SW version` lines, or a model `C1300-`, `C1200-`, `CBS350-`, `CBS250-`, `CBS220-`,
   `SG350`, `SF350`, `SG550X`, `SG300`, `SF300`, `SG500`, `SG250`, `SF250` → `cbs` and its series.
5. Nothing matched → no guess: the admin chooses.

Detection runs in the API (`POST …/radius/cisco/detect`, read-only, no state) so the console and the tests share one
implementation. The pasted text isn't stored.

## 3. Capabilities

`caps(platform, series, version, lan_lite) -> Caps`, one table in one module (`app/radius/cisco_platforms.py`), read by
every generator, the console and the RADIUS state. Fields and the rules (sources in §12):

| Capability | ibns2 | classic auth manager | classic dot1x (< 12.2(50)SE) | nxos | cbs |
|---|---|---|---|---|---|
| monitor | switch (open by default) | switch (`authentication open`) | server | server (MAB) / none | switch: c1300, sx350, sx300; none: c1200, sx250, cbs220, sx200 |
| MAB request | pap (Call-Check) | pap | pap | pap-wired (Service-Type undocumented) | pap: c1300, sx350; eap (EAP-MD5): sx300; none: c1200, sx250, cbs220 |
| multi-auth | yes | yes | no (multi-host) | n9k ≥ 9.2(1), n3548; others single/multi-host | `multi-sessions` (c1200: yes) |
| RADIUS VLAN | yes | yes; multi-auth from 12.2(55)SE | single/multi-host only | n9k-fx (first host), n3548, n5k; not n9k, n7k | c1300, sx350, sx300, cbs220 |
| VLAN for devices without 802.1X | yes | yes; multi-auth only from 15.2(7)E | `dot1x guest-vlan` | n5k only (`dot1x guest-vlan`, after MAB fails) | guest VLAN (also used on failure) |
| EasyEAP unreachable | wait/open/VLAN | wait/open/VLAN; LAN Lite: wait only | `dot1x critical` | n9k-fx ≥ 10.1(2): open (MAB clients only); others wait | open (`radius none`, global) or wait |
| CoA | full | full from 12.2(52)SE, not LAN Lite | none | n9k ≥ 9.2(3): reauthenticate and disconnect, no bounce | c1300 ≥ 4.1.3.36 only |
| accounting | yes | yes | yes | yes | c1300, sx350, sx300 |
| RADIUS server form | named (3.6E+), legacy before | legacy `radius-server host` | legacy | NX-OS | sx / cbs220 |
| TACACS+ | named (16+); legacy with `server <ip>` on 3.x | named from 15.2(7)E3; legacy before | legacy | NX-OS, with `shell:roles` | sx (c1300, sx350, sx300 without `authorization`), cbs220; none on c1200, sx250, sx200 |
| switch audit | CAF | CAF | none (CAF from 12.2(50)SE) | ports and err-disable only | ports only |

A plan choice the switch can't do is refused when the plan is saved, with the reason: for example "VLAN for devices
without 802.1X" on a multi-auth port before 15.2(7)E says "this release supports it in single-host or multi-host
mode only (Cisco 15.2(7)E guide); choose one of those or upgrade". Host-mode choices offered are the ones the switch has.

## 4. Monitor mode where the switch has none (server-side monitor)

Monitor mode means "nothing changes for anyone until you enforce". Switches without an open mode get the closest thing
each can do, and the console says which:

1. **switch**: open mode on the switch (today's behaviour).
2. ~~guest-VLAN~~ (dropped, §14 #7: Cisco says a port must not be a static member of its guest VLAN). C1200,
   CBS250/SG250 and CBS220 are **none**.
3. **server** (Nexus with MAB, classic before 12.2(50)SE, Meraki MS other than MS130/MS150): ports run 802.1X with MAB,
   and EasyEAP **accepts** every MAC request from that switch while it's in monitor mode, with no VLAN. The decision it
   would have made (not on the allow list, expired, blocked) is logged as a refusal in monitor mode, and unknown MACs
   still appear under "Seen, not allowed". On these switches MAC authentication is always on (the port plan can't turn
   it off): it's how devices without 802.1X keep working. Devices that try 802.1X and fail are not covered (Meraki's
   hybrid mode falls back to MAB, so they are there); the console says so.
4. **none** (Nexus without MAB, C1200, CBS250/SG250, CBS220, SG200): no monitor phase. The plan's first configuration is enforcement, and the
   console says to list one test port first.

RADIUS: the client gets `easyeap_monitor_accept = yes` when its monitor style is `server` (the agent applies it only
while the switch is in monitor mode). The accept carries `Session-Timeout 1800`, so a device admitted this way asks
again within 30 minutes of Enforce even where the switch can't be told to re-authenticate (§14 #2).
In `mab_decide`, the refusals `mac_unknown`, `mac_expired`, `snapshot_stale` and the allow list's deny reasons become an
accept with no VLAN, with `control:EasyEAP-Reason` kept and `control:EasyEAP-Monitor := "accepted"`. Request-integrity
refusals (`mab_mismatch`, `mab_password`, `mab_not_enabled`) stay refusals. Ingest stores such an event as
`result = reject, monitor = true` (the decision), like a refusal from a switch in open mode, so the log, the readiness
view and "Seen, not allowed" read the same for every switch.

## 5. MAC authentication requests per family

- `pap` (Catalyst, Cisco Business C1300/Sx350): today's detection, PAP with Service-Type Call-Check and NAS-Port-Type
  Ethernet.
- `pap-wired` (Nexus, Meraki): PAP without EAP, a MAC as User-Name and User-Password, on a request EasyEAP already
  classifies as wired, with port evidence (NAS-Port-Type Ethernet, NAS-Port-Id or NAS-Port). Service-Type isn't
  required (undocumented on both), but Login, Administrative and NAS-Prompt are refused, so an admin login can never
  pass as a MAC (§14 #1). Calling-Station-Id, when present, must be the same MAC. Every optional attribute is tested
  for presence first: FreeRADIUS 3 fails a comparison with an absent attribute.
- Message-Authenticator: `require_message_authenticator = no` per client for Nexus, Cisco Business, Meraki and classic
  IOS before 12.2(50)SE, which send MAC requests without it; `limit_proxy_state = yes` stays on for every client
  (BlastRADIUS: a request with Proxy-State and no Message-Authenticator is dropped). Everyone else keeps `yes` (§14 #4).
- `eap` (UniFi, Sx300/Sx500): today's EAP-MD5 path.

The MAC forms all compare on their 12 hex digits (already true: `aabbccddeeff`, `AA-BB-…`, `aabb.ccdd.eeff`).

## 6. Generated configuration, per family

Every configuration keeps today's safety rules: placeholders for secrets, preflight first, `reload in 15` where the
platform has it, nothing that changes how admins log in except where the admin asked (device admin).

### 6.1 IOS-XE (`ibns2`)

Today's output, with these fixes:
- `EASYEAP_CRITICAL_OPEN` (a `service-template` with a description) replaces `DEFAULT_CRITICAL_DATA_TEMPLATE`. The
  templates are defined before the class-maps that match them.
- 3.x before 3.6E: `radius-server host … key` and `server <ip> auth-port … acct-port …` in the group.
- `radius-server attribute 31 mac format ietf upper-case`: 16.x and later only.
- Checks list the critical and no-802.1X VLANs ("must exist: show vlan brief"), not only the VLANs EasyEAP assigns.
- 26.x: the switch audit's v2c block warns that 26.1 blocks `snmp-server community` unless `system mode insecure`;
  SNMPv3 is recommended there.

### 6.2 Classic IOS (`classic`)

- RADIUS: `radius-server host <ip> auth-port A acct-port B timeout 5 retransmit 2 key <secret>`; group `server <ip>
  auth-port A acct-port B`; global `radius-server deadtime 3`, `ip radius source-interface X`; `ip vrf forwarding` in
  the group only when a VRF is set (with a note: IP Services image only).
- `radius-server dead-criteria` from 12.2(50)SE; `radius-server vsa send …` always (off by default on classic).
- No attribute 31 line.
- CoA only from 12.2(52)SE and not on LAN Lite.
- Ports, auth manager (≥ 12.2(50)SE or unknown): today's lines, plus:
  - Server down with a VLAN on a multi-auth port: `authentication event server dead action reinitialize vlan N`
    (Cisco's documented form for multi-auth); `authorize vlan N` on single/multi-host.
  - `no-response action authorize vlan` refused on multi-auth before 15.2(7)E (§3).
  - RADIUS VLANs on multi-auth before 12.2(55)SE: a check warns they won't be applied.
  - LAN Lite: no critical auth, no violation mode.
  - Restart sessions: `clear authentication sessions` (generic IOS; widely used on Catalyst but not in its references),
    with `clear dot1x all` as the documented fallback line in a comment.
- Ports, before 12.2(50)SE: the `dot1x` dialect (`dot1x port-control auto`, `dot1x host-mode multi-host`,
  `dot1x reauthentication`, `dot1x timeout reauth-period server`, `dot1x mac-auth-bypass`, `dot1x guest-vlan`,
  `dot1x critical` …), server-side monitor, `clear dot1x all`, `show dot1x all summary`. Before 12.2(25)SEE (no MAB,
  no `dot1x pae`): refused, "upgrade the switch".
- Preflight: no "use classic or IBNS" guessing; the detected version drives the output.

### 6.3 NX-OS (`nxos`)

```
feature dot1x
radius-server host <ip> key 0 <secret> auth-port A acct-port B authentication accounting
radius-server host <ip> timeout 5
radius-server host <ip> retransmit 2
radius-server deadtime 3
aaa group server radius EASYEAP
  server <ip>
  use-vrf <management|default|VRF>
  source-interface <if>          (when set)
aaa authentication dot1x default group EASYEAP
aaa accounting dot1x default group EASYEAP
dot1x radius-accounting
aaa server radius dynamic-author       (n9k ≥ 9.2(3) only)
  client <ip> [vrf V] server-key 0 <secret>
interface ethernet 1/1-23
  switchport
  switchport mode access
  dot1x port-control auto
  dot1x host-mode multi-auth           (or single-host / multi-host where multi-auth isn't available)
  dot1x mac-auth-bypass                (where MAB exists; never `eap`)
  dot1x re-authentication
  dot1x timeout tx-period 10
  spanning-tree port type edge
  spanning-tree bpduguard enable
```

`use-vrf` is always written: `management` by default (mgmt0), or the plan's VRF. Enforce adds
`authentication event server dead action authorize` (n9k-fx ≥ 10.1(2), when "allow while unreachable") and `dot1x
guest-vlan N` (n5k). Session restart: `dot1x re-authenticate interface …` per range (there's no `clear`). Back to
monitor on a server-monitor switch only removes the enforce-only lines (the ports keep running 802.1X; EasyEAP accepts
MAC requests again). Port names: `Ethernet1/1`, `Eth1/1-23`; mgmt0, port-channels, vPC peer links refused.

### 6.4 Cisco Business (`cbs`)

- C1300 / Sx350 / CBS350 / Sx300:
  ```
  radius-server host <ip> auth-port A acct-port B timeout 5 retransmit 2 key <secret> usage dot1.x
  radius-server host source-interface <if>      (not on sx300)
  aaa authentication dot1x default radius        ("radius none" when "allow while unreachable")
  aaa accounting dot1x start-stop group radius
  dot1x mac-auth radius username groupsize 12 separator - lowercase      (MAB as PAP; not on sx300)
  aaa server radius dynamic-author / client <ip> server-key <secret>       (c1300 ≥ 4.1.3.36)
  dot1x system-auth-control
  interface range gi1/0/1-23
   dot1x host-mode multi-sessions
   dot1x authentication 802.1x mac            (802.1x only without MAB)
   dot1x reauthentication
   authentication open                         (monitor)
   spanning-tree portfast
   dot1x port-control auto
  ```
  Enforce: `no authentication open`, `dot1x radius-attributes vlan static`, guest VLAN when chosen. No critical VLAN
  exists: "allow while unreachable" is the global `radius none`; "VLAN while unreachable" is refused.
- C1200 / CBS250 / SG250: 802.1X only, no monitor phase: start with one test port (the console says so). The guest VLAN
  (`interface vlan N` / `dot1x guest-vlan`, ports `dot1x guest-vlan enable`) is the enforce-time VLAN for devices
  without 802.1X.
- CBS220: its own syntax (`radius-server host … usg-type 802.1x`, `dot1x guest-vlan N enable`, `dot1x radius-attribute
  vlan static`); marked unverified where the guide is silent (accounting, source interface).
- SG200: web-UI steps only.
- Port names as the switch prints them: `gi1/0/1`, `te1/0/1`, `fa1/1/1`, CBS220 `gi1`.

### 6.5 Meraki MS (vendor `meraki`)

Dashboard steps (from Meraki's own guides): an access policy with EasyEAP as RADIUS server (auth 1812, accounting
1813), RADIUS testing **off** (Meraki's `meraki_8021x_test` user is refused, and Meraki doesn't say whether a refusal
counts as reachable), CoA **off** (Meraki needs an `audit-session-id` in each Accept, which EasyEAP
doesn't send yet), host mode, policy type **Hybrid authentication**, then ports. Monitor: MS130/MS150 on MS18+ use
"Authentication mode: Open" with a permit-any pre-auth policy; every other model uses server-side monitor (§4).
Server-side monitor also sets the critical VLAN to the ports' own VLAN, so an EasyEAP outage during monitor mode
closes nothing; Enforce sets the plan's critical VLAN. Meraki MS (other than the MS390) has no critical VLAN on
Multi-Auth ports: the steps say to choose Multi-Host or Single-Host where devices must keep working during an outage.
Enforce: switch Open → Closed (MS130/MS150), or the critical VLAN on other models (EasyEAP stops accepting unknown
MACs), then cycle the ports so devices re-authenticate. Register each switch's management (LAN) IP, or its Alternate
Management Interface IP.

## 7. Device administration (TACACS+)

`app/admin/cisco.py` picks its form from the switch's platform, series and version:
- IOS-XE 16+: named `tacacs server` (today). IOS-XE 3.x: legacy `tacacs-server host` with `server <ip>`.
- Classic: named from 15.2(7)E3 (where Cisco says legacy "can cause authentication failures"), legacy before. Unknown
  version: today's manual "older IOS" toggle stays.
- NX-OS: `feature tacacs+`, `tacacs-server host <ip> key 0 <key> port 49 timeout 5`, group with `use-vrf` and
  `deadtime`, `ip tacacs source-interface`, `aaa authentication login default group …` (local is the fallback when
  EasyEAP is unreachable), `aaa authentication login console local`, `aaa accounting default group …`. No command
  authorization (it turns off NX-OS RBAC).
- The TACACS+ service answers an NX-OS device's shell authorization with `shell:roles="network-admin"` for a role at
  level 15 and `shell:roles="network-operator"` below (Nexus 7000: `"network-admin vdc-admin"` /
  `"network-operator vdc-operator"`), and no `priv-lvl`, so the two can't disagree. The device list sent to the
  TACACS+ service carries `os` (`ios` | `nxos` | `nxos-n7k`).
- Cisco Business C1300 / Sx350 / CBS350: `tacacs-server host <ip> port 49 timeout 5 key <key>`, `aaa authentication
  login authorization default tacacs local`, a console list kept local, `aaa authentication enable authorization
  default tacacs enable`, `aaa accounting login start-stop group tacacs+`. Sx300: without `authorization` and
  `source-interface`. CBS220: its syntax. The roles should be level 1, 7 or 15 (the console says so).
- No TACACS+: C1200, CBS250/SG250, SG200, Meraki (the console says why).

## 8. Switch audit (SNMP) and syslog

- `config_block` per platform:
  - Catalyst: today's block. Classic: no `logging discriminator` (Cisco warns of a memory leak on 15.2(7)E; unconfirmed
    before), a plain `logging host … transport udp port N`; the receiver already keeps only what it needs.
  - NX-OS: `ip access-list EASYEAP-SNMP` + `snmp-server community C group network-operator` + `snmp-server community C
    use-ipv4acl EASYEAP-SNMP`; v3 with a warning that NX-OS turns an SNMPv3 user into a CLI user; syslog `logging
    server <ip> 5 port N use-vrf management`.
  - Cisco Business: `snmp-server server`, a view of the subtrees, `snmp-server community C ro <ip> view EASYEAP-RO`;
    v3 per series; syslog `logging host <ip> port N severity informational description EasyEAP`.
- Nexus and Cisco Business have no CISCO-AUTH-FRAMEWORK-MIB: the audit polls ports and err-disable only and shows
  "session audit: not available on this platform" instead of the `caf_missing` warning.
- Syslog: port names `Ethernet1/1`; NX-OS messages kept: `DOT1X-*-SESSION_TERMINATION`, `DOT1X-*-SECURITY_VIOLATION`,
  `ETHPORT-*-IF_DOWN_ERROR_DISABLED`, `ETHPORT-*-IF_ERRDIS_RECOVERY`, `STP-*-BLOCK_BPDUGUARD`,
  `RADIUS-*-RADIUS_SERVER_STATUS`, `VSHD-*-VSHD_SYSLOG_CONFIG_I`. Cisco Business tags with letter severities
  (`%SEC-I-…`) parse, but no 802.1X message is documented, so none is kept yet.
- Meraki: no switch audit (no 802.1X data over SNMP).

## 9. Sessions ("what enforcing would cut off")

`session_command` and `parse_sessions` per platform: `show access-session` (IBNS 2.0), `show authentication sessions`
(auth manager), `show dot1x all summary` (classic dot1x, NX-OS: `Interface PAE Client Status`). Cisco Business and
Meraki: not available (formats undocumented / no CLI).

## 10. Console

- Add switch → Cisco: a "Paste `show version`" box that fills the family, series and version, or the choices by hand
  (family, then series where it matters, then version, optional). What the switch can't do is shown before the port
  plan, in plain words ("This switch has no monitor mode: EasyEAP accepts its MAC requests while you test").
- Vendor picker: "Cisco switch (Catalyst, Nexus, Business)" and "Cisco Meraki MS".
- The plan form offers only what the platform supports (host modes, server-down choices, VLAN for devices without
  802.1X); unsupported choices aren't shown rather than shown disabled.
- Device admin: the platform's form; the "older IOS" toggle appears only when the version is unknown.

## 11. Testing

- Unit: `detect` on Cisco's published `show version` samples for every family (from the research); `caps` for each
  breakpoint; each generator's output per family/mode/MAB, asserting the version-gated lines; plan validation refusals;
  `mab_detect`/`mab_decide` rendering for `pap-wired` and `monitor_accept`; ingest of `monitor = accepted`; TACACS+
  `shell:roles` replies; NX-OS syslog parsing; session parsing for `show dot1x all summary`.
- On the demo (real RADIUS): temporary RADIUS clients (NX-OS monitor, Catalyst monitor, Meraki) and
  radclient MAB requests: unknown MAC → Accept without VLAN (server monitor) or Reject (switch monitor); allowed MAC →
  Accept; event logged as a refusal in monitor mode; sighting recorded. A TACACS+ client against the demo's TACACS+
  service as an NX-OS device, logging in with the AD account the user gave, expecting `shell:roles`. The temporary
  clients are removed afterwards.
- No Cisco hardware: every guide says "not verified on <family> hardware".

## 12. Sources

The research notes (session scratchpad, `cisco-research/`): `ios.md` (classic IOS line by line, version breakpoints,
pre-auth-manager equivalents), `iosxe.md` (IOS-XE 3.x–26.x), `tacacs-version-models.md` (TACACS+, `show version`
samples, model limits), `nxos.md` (Nexus), `smb-meraki.md` (Cisco Business and Meraki), `snmp-syslog.md`. Their
citations (Cisco configuration guides, command references, release notes, message guides) are copied into the
controller guides where a line depends on them.

## 13. Out of scope (v1)

- Meraki CoA (needs `audit-session-id` in every Accept and stored per session), the Meraki Dashboard API.
- NX-OS 10.6(3)F MDA open mode (four models), NX-OS command authorization, TACACS+ over TLS.
- Cisco Business 802.1X session polling (CISCOSB-DOT1X-MIB is documented only in a mirrored MIB file).
- IBNS 2.0 on classic 15.2E (supported by Cisco; the auth-manager form works on the same switches).

## 14. Critique (revision 1) and what changed

An independent review of revision 1 against the research notes found 16 defects. Every one was decided before
implementation:

| # | Finding | Decision |
|---|---|---|
| 1 | `pap-wired` without Service-Type would let a PAP admin login through as a MAC on a server-monitor switch | Fixed: Login/Administrative/NAS-Prompt refused, port evidence required, username must be a MAC (§5) |
| 2 | Devices accepted in monitor keep the port for 8 hours after Enforce | Fixed: monitor accepts carry Session-Timeout 1800; Enforce restarts sessions on every family (`dot1x re-authenticate` per port on NX-OS and old classic, port cycle on Meraki) |
| 3 | Meraki monitor: no critical VLAN in monitor, Multi-Auth has none, the RADIUS test probe | Fixed: critical VLAN = ports' VLAN in monitor, the Multi-Auth note, RADIUS testing off (§6.5) |
| 4 | Message-Authenticator required for every client drops Cisco Business and Nexus MAC requests | Fixed: per-client `require_message_authenticator` from the capabilities, `limit_proxy_state` kept (§5) |
| 5 | Existing classic switches would lose the named RADIUS server on re-paste | Fixed: unknown release keeps the named form; only a known release before 15.2(3)E gets `radius-server host` |
| 6 | IBNS 2.0 policy names change for switches enforced with `DEFAULT_CRITICAL_DATA_TEMPLATE` | Fixed: a switch whose attached policy uses the old template keeps it, so the policy name doesn't change |
| 7 | Guest-VLAN monitor on C1200/CBS250/CBS220 contradicts Cisco | Fixed: those series have no monitor phase (start with a test port) (§4) |
| 8 | No err-disable findings without CISCO-AUTH-FRAMEWORK-MIB | Fixed: the CAF gate moved below the err-disable check; `caf_missing` only where CAF is expected |
| 9 | Monitor accepts stored as rejects; events.py tested only `yes` | Kept as designed (the decision is what readiness and "Seen, not allowed" need), and ingest now maps `accepted` to monitor + reject |
| 10 | NX-OS capabilities too coarse | Fixed: n9k-fxp, n3k series; 7.0(3)I7 without MAB or multi-auth; FX3/GX MAB from 10.5(2); 3600 refused; `test idle-time` with critical auth; series required |
| 11 | Syslog only on 514 for some families; the discriminator on classic | No 514 listener (it would clash with existing deployments): the block says the audit works on SNMP alone. Classic gets no discriminator, and the block says how to remove the earlier one |
| 12 | Classic SNMP: numbered ACL, `priv aes` needs k9/12.2(52)SE, err-disable MIB per model | Fixed: ACL 98, a note on k9, `errdisable` per family and release. IEEE8021-PAE-MIB polling before 12.2(50)SE: not done (no audit there) |
| 13 | Non-access trains (SX, SY, SG) compared as older releases; 4500 SG unverified | Fixed: unknown train = unknown release, with a warning; IOS-XE 3.x SG/XO warns |
| 14 | Classic breakpoints (dead-criteria 12.2(55)SE, `dot1x critical` before 12.2(55)SE, violation 12.2(46)SE1, re-authenticate fallback) | Fixed as listed |
| 15 | Code gaps (vendor lists, CoA per family, syslog sources, audit refusal, TACACS+ roles, MAC list wording) | Fixed |
| 16 | Scope: six families at once, much of it unverified | Kept: the user's goal is no unsupported Cisco switch. Every guide and generated block says it isn't verified on that family's hardware |

Still open after implementation: Meraki CoA (needs the session ID in each Accept), polling 802.1X state on Cisco
Business and pre-12.2(50)SE classic switches, a syslog listener on UDP 514, and a capture of real NX-OS and Meraki MAB
requests to confirm `pap-wired`.

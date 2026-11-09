# Plan: the full device log, decoded by EasyEAP, and a live syslog view

Status: built for 1.1.0 (e7fec77, then 2a30408; 2026-11-08); §7 and the second critique in §9 say what wasn't. Requests: "send the full cisco log to the host, and decode it ourself", "a 100% live syslog
view for diag … I want to see in real time what we are getting", "logging for UniFi and vWLC and C9800 as well".

Research (Cisco syslog guides 16.12/17.3 and 9800 17.5 spreadsheets, TAC docs, AireOS 8.10 command reference, UniFi
help articles): the reports of 2026-11-08 in this session; sources are cited inline below as [switch] and [wireless].

## 0. What's wrong today

- The switch's block filters at the source: `logging discriminator EASYEAP facility includes …` sends only eight
  facilities, and the receiver keeps a fixed list of mnemonics from those. Anything else (LINK, LINEPROTO, ILPOWER,
  EPM, a START) never reaches EasyEAP or is dropped on arrival, so neither the admin nor EasyEAP sees the session's
  story. A test switch sent six messages in a day; four were thrown away and nobody can tell what they were.
- Cisco switches log START/SUCCESS of a session only with `… logging verbose` (to be confirmed against Cisco's docs:
  the command references word it as "filters"; section 2 holds until that's settled).
- Controllers (Catalyst 9800, AireOS, UniFi) can't send syslog to EasyEAP at all: sources are only the SNMP
  addresses of monitored Cisco switches. AireOS can send to UDP 514 only [wireless A1, A2]; EasyEAP listens on 5514.
- There's no way to watch what arrives. The switch panel shows the 30 newest kept messages, refreshed with the panel.

## 1. Receive everything from a known device

- A datagram from an attributed source is kept, whatever its facility, mnemonic or format. Coalescing per minute
  stays (a flood costs a counter), but the key adds the text, so "changed state to up" and "… down" are two rows.
- Messages without a Cisco tag (UniFi's hostapd, anything else) are kept too: severity from `<PRI>` (6 without one),
  facility = the RFC 3164 program (`hostapd`, `stahtd`) or empty, mnemonic empty, text = the line after the header.
- AireOS: the tag may start with `#` (CSCul11353) [wireless A8], and the body starts `[PA]file.c:line ` (stripped).
- New columns on `switch_syslog` (the table keeps its name; it now holds every device's syslog):
  - `seq bigint` from a sequence, set on insert **and on every update** (count/last_at): the live view's cursor.
    Index `(tenant_id, seq)`.
  - `notable bool`: EasyEAP decodes it (section 4) or the old keep list has it. Notable rows are kept 14 days, the rest
    3 days.
  - `source varchar(64)`: the sender's address (a UniFi AP within the client's range, or the switch).
- Quota: the tenant's 50 MB a day is shared: past 80 %, only notable messages are stored; past 100 %, only the
  priority ones (RADIUS dead/alive, err-disable), as today.
- The "poll sooner" hint only for messages in the old keep list (`FAIL` from another facility mustn't hint).
- Messages are flushed every second (was 2 s); counters every 10 s, into a new `syslog_stats` table (client_id PK,
  tenant_id, day, received, kept, quota, last_at, last_tag) for every device. `switch_states.syslog` is migrated into
  it and no longer written. Counters never touch `radius_clients`.

## 2. What the switch sends (Cisco)

- IOS-XE (ibns2) and classic IOS: no discriminator. The block becomes
  `logging host <ip> [vrf Mgmt-vrf] transport udp port <n>` plus `authentication logging verbose`,
  `dot1x logging verbose`, `mab logging verbose` **if** Cisco's docs confirm these make START/SUCCESS appear (the
  verification is running; if they suppress instead, the block says `no …` only where a switch has them).
- `logging trap` is global and governs every syslog host, so EasyEAP doesn't set it. A comment says session messages
  are severity 5 (notifications) and EPM's IP lines 6, and that `logging trap informational` is the default.
- A switch with EasyEAP's earlier block: the new block says how to replace the discriminator entry (exact commands
  pending the verification of how IOS treats a re-entered `logging host` with the same host and port).
- NX-OS: `logging server <ip> 6 [port <n>] use-vrf <vrf>` (was 5).
- Switches that can send only to UDP 514 (Nexus 5000/3548, older NX-OS 9000/3000, classic without the port option):
  EasyEAP now listens on 514 as well (section 3), so their block has the logging line again instead of "SNMP only".
- Cisco Business: unchanged (`logging host <ip> port <n> severity informational`).

## 3. Port 514

- `easyeap-syslog` is also published on `${EASYEAP_SYSLOG_BIND}:${EASYEAP_SYSLOG_STD_PORT:-514}` → 5514/udp. Same
  receiver, same rules. A host that already uses UDP 514 sets `EASYEAP_SYSLOG_STD_PORT` to another port; then AireOS
  and the 514-only switches can't send, and their blocks say so.
- Settings gain `syslog_std_port` (env `EASYEAP_SYSLOG_STD_PORT`, default 514).

## 4. Decoding

Folded on read (no new state): `service.syslog_sessions(rows)` over a device's notable rows of the last 24 hours,
oldest first, gives one entry per (port, MAC) or, without a port, per MAC: state, method, VLAN, IP, session id,
reason, SSID, AP, first/last time, ended (and why).

| Message | Effect |
|---|---|
| `SESSION_MGR-5-START` / `AUTHMGR-5-START` "Starting 'dot1x'\|'mab'\|'webauth' for client (mac) on Interface X AuditSessionID S" | starting, method |
| `DOT1X-5-SUCCESS` / `MAB-5-SUCCESS` | authenticated (method from the facility) |
| `DOT1X-5-FAIL` / `MAB-5-FAIL` "… [with reason (R)] …" | failed, reason |
| `SESSION_MGR-5-SUCCESS` / `AUTHMGR-5-SUCCESS` | authorized |
| `SESSION_MGR-5-FAIL` / `AUTHMGR-5-FAIL` "… [Failure reason: …]" | authorization failed, reason |
| `*-5-VLANASSIGN` "VLAN n assigned to Interface X AuditSessionID S" | VLAN, by session id, else the port's newest session |
| `EPM-6-POLICY_REQ` / `EPM-6-IPEVENT` "IP a\| MAC m\| AuditSessionID S\| EVENT e" | IP |
| `*-SECURITY_VIOLATION` | violation |
| `SESSION_MGR-5-MACMOVE` / `MACREPLACE` | the old port's / old MAC's session ends |
| `LINK-3-UPDOWN` "… changed state to down" | every session on that port ends (link down) |
| NX-OS `DOT1X-5-SESSION_CREATION` / `SESSION_TERMINATION` (no MAC) | port-level session started / ended, reason |
| 9800 `CLIENT_ORCH_LOG-6-CLIENT_ADDED_TO_RUN_STATE` "… joined with ssid (S) for device with MAC: m" | connected, SSID |
| 9800 `CLIENT_EXCLUSION_SERVER-5-ADD_TO_EXCLUSIONLIST_REASON_DYNAMIC` "Client MAC: m … AP Name:A … reason:R" | excluded, AP, reason |
| AireOS `APF-3-AUTHENTICATION_TRAP` "Client Authenticated: MACAddress:m … SSID:S" | authenticated, SSID |
| AireOS `APF-3-ASSOC_TRAP` / `DISASSOC_TRAP` "… Reason:R" | associated / ended, reason |
| AireOS `DOT1X-3-ABORT_AUTH` "… for client m Abort Reason:R" | failed, reason |
| UniFi hostapd "STA m IEEE 802.11: associated" / "IEEE 802.1X: authenticated - EAP type: n (X)" / "authentication failed" / "disassociated" / "deauthenticated" | associated / authenticated / failed / ended |

RADIUS-down messages (`RADIUS_DEAD`, AireOS `AAA-4-RADIUS_RESPONSE_FAILED`, UniFi "No response from Authentication
server") stay in `radius_down`. Nothing decoded from syslog opens or resolves a finding: syslog isn't authenticated.

## 5. Controllers and other devices

- `radius_clients.syslog_enabled` (bool, default false), set with `PUT /radius/clients/{id}/syslog` (radius:write,
  audited). A Cisco switch with the audit set up needs nothing: its verified SNMP address stays a source.
- Attribution: claims are networks — a verified switch's SNMP host (/32, /128), and the address (IP or CIDR) of every
  client with `syslog_enabled` (CIDRs no wider than /16 for IPv4, /48 for IPv6; `0.0.0.0/0` never). A datagram goes to
  the longest matching claim; it's dropped as unknown when two clients tie at that length, or when any matching claim
  belongs to another tenant. Unverified switch hosts still count as claims (ambiguity), as today. Lookups are cached
  per address until the next reload (30 s).
- Guidance per vendor, in the console and docs (each with the removal):
  - **Catalyst 9800**: `logging host <ip> transport udp port <n>` (service port: `vrf Mgmt-intf`); it sends from the
    wireless management interface, its RADIUS address [wireless C5].
  - **AireOS (incl. vWLC)**: Management → Logs → Config, or `config logging syslog host <ip>`, level informational,
    `config logging syslog facility client {authentication|authfail|deauthenticate|excluded|associate|disassociate}
    enable`, `save config`; port 514 only [wireless A1, A2, A4].
  - **UniFi**: Network 8.5+/9.x: Settings → Control Plane → Integrations → Activity Logging (Syslog) → SIEM Server;
    8.x and earlier: Settings → Site → Remote Logging. Address, port, debug logs off. Each AP sends from its own
    address, so the RADIUS client's range must cover the APs [wireless U4–U7].
  - **Other**: send syslog to `<ip>` UDP `<port>` from the RADIUS address.

## 6. The live view

- Route `t/:tid/syslog`, sidebar "Device syslog" under Investigate (radius:read).
- `GET /syslog/live?after=<seq>&client_id=&limit=` → rows with seq > after, oldest first (≤ 500), and `cursor`;
  without `after`: the newest 200. `before=<seq>` pages back. Same row shape as today plus `client_id`, `client_name`,
  `source`, `notable`, `seq`. Plus `receiver` (listening, ports) and `devices` (each source device with today's
  counters), so an empty view can say why.
- The page polls every second while visible and not paused; a row whose seq moved replaces its earlier copy at the
  top with the new count. Filters: device, severity, "session messages only", text (in the browser, over the ≤ 2,000
  rows held). Pause/resume, clear, "load earlier".
- Platform admins also see "from addresses that aren't a device": the heartbeat's top unknown sources, now with the
  last line each sent (redacted, 160 characters). Tenant admins don't (another tenant's addresses).
- The switch panel's "What the switch says" shows notable rows only, plus "Open the live view" (filtered to it), and a
  "Sessions the switch logged" table from section 4. Controllers get the same panel: toggle, guidance, counters,
  decoded clients, link.

## 7. Not in this change

Meraki (dashboard syslog roles) and Aruba; TLS syslog; alerting on syslog. Usernames stay redacted as today.

## 8. Tests

Parser samples from the research (IOS-XE 16/17 with and without "Switch 1 R0/0: sessmgrd:", classic 15.2, NX-OS,
9800, AireOS with `%` and `#`, UniFi hostapd and RFC 3164 headers); coalescing by text; notable/quota tiers;
attribution (CIDR, longest match, cross-tenant tie, /0 refused); live endpoint cursor/paging/RLS; decode table rows;
config blocks per family and controller; migration up/down on a copy of the demo database.

## 9. Verification and critique (2026-11-08): what changed in this plan

**`… logging verbose` (verified).** The positive form shows START/SUCCESS; `no …` filters them; failures are never
filtered. Sources: Catalyst config guides 12.2(55)SE through 9300 17.12 ("The no dot1x logging verbose … command
filters …"), Cisco-IOS-XE-dot1x/sanet/native YANG 17.12.1 ("Show verbose messages in system logs"), Cisco Live
BRKSEC-2691 (IBNS 2.0) slide 56. The command reference's "To filter detailed information … use the dot1x logging
verbose command" is a stale copy of the `no` entry. Default: on in classic IOS up to about 15.2(2)E, off in later
15.2(x)E and all IOS-XE, so the block sets all three. They're modelled in the IBNS 2.0 (sanet) YANG and appear in
new-style configurations: valid after `authentication convert-to new-style`. A 3650 on 16.6.5 with only `dot1x
logging verbose` logged DOT1X-5-SUCCESS but no SESSION_MGR START/SUCCESS: `authentication logging verbose` is the one
for the session manager. They are global (they also reach other syslog hosts and the log buffer); the block says so.

**The discriminator (verified).** "When you remove a discriminator, the associations of all entries in the logging
host list are removed" and the host entry stays (ESM command reference). So a switch with EasyEAP's earlier block
needs only `no logging discriminator EASYEAP`; it isn't in the main block (the name wouldn't exist on a new switch)
but on its own line, explained. Removal: `no logging host <ip> transport udp port <n>` ("all logging to the specified
host is disabled", which is only EasyEAP's) and, for earlier blocks, `no logging discriminator EASYEAP`.
`epm logging` (EPM's IP lines) isn't confirmed for IOS-XE 16/17: not in the block; IP comes from EPM only if the
switch already logs it.

**Critique, taken:**
- Redaction: logged configuration commands (`PARSER-5-CFGLOG_LOGGEDCMD`, anything with "logged command") keep the
  first two words of the command only. General redaction skips a type digit (`secret 5 …`, `key 7 …`), covers
  `auth|priv <algorithm> <value>`, `psk`, `wpa-psk`, `set-key`, `key-string`, CEF `suser=`/`duser=`, and hostapd
  identities. Tests with each sample.
- Attribution: claims are the address of **every** RADIUS client in every tenant (whatever its ports) plus verified
  switch SNMP hosts. A datagram goes to the longest matching claim; it's dropped (counted as ambiguous) when the best
  length ties between two clients or any matching claim is another tenant's; it's dropped as "not enabled" when the
  winner hasn't syslog on. Turning syslog on (and changing the address while it's on) is refused with 409 when the
  network overlaps another tenant's client or monitoring host. IPv4-mapped, -compatible and NAT64 ranges are refused.
  Lookup: one dict per prefix length in use, longest first, no cache.
- Extra syslog addresses per device (a 9800 sending from its service port, a UniFi console sending CEF):
  `radius_clients.syslog = {"enabled": bool, "addresses": [ip, …]}`, same checks.
- UDP 514 is **not** published by default: `deploy/docker-compose.syslog514.yml` adds it (and tells the API), and
  `install.sh` adds that file to `COMPOSE_FILE` only when UDP 514 is free and `EASYEAP_SYSLOG_PORT` isn't 514. Blocks
  for 514-only senders say what's missing otherwise. The loopback default of `EASYEAP_SYSLOG_BIND` stays.
- Receiver: the socket thread only parses and coalesces (under a lock); a writer thread flushes new rows every second
  and count updates every 5 seconds, batched per tenant (row by row only when a batch fails). Per-device token bucket
  (not per source address), open entries capped per tenant as well as overall. The heartbeat reports kernel drops
  (`/proc/net/udp*`), ambiguous and not-enabled counts, and the newest line of each top unknown source (redacted).
- Cisco tags are accepted only in the first 160 bytes and never for UniFi; PRIORITY and the poll hint match
  (facility, mnemonic) pairs.
- `seq`: set by a `BEFORE INSERT OR UPDATE` trigger from a `CACHE 1` sequence; one writer (the receiver's writer
  thread) is the invariant that keeps commit order = seq order. The live endpoint returns `reset: true` when the cursor
  is ahead of the table (after a restore).
- Panels: notable rows only; `radius_down` from its own query of RADIUS facilities.
- Decoding expands a coalesced row into events at `first_at` and `last_at`, so "down … up … down" within one minute
  isn't lost. LINK lines aren't notable (3 days), but the fold reads every decode-relevant row of the last 24 hours.
- Migration: existing rows `notable = true`; server defaults for every new column (the old receiver keeps inserting
  during an upgrade); `syslog_stats` gets the grant and row-level security of 0010 and a `bytes` counter, which the
  quota reads instead of summing the table. Prune hourly, in batches.
- The live poll doesn't refresh the console session (`X-EasyEAP-Passive: 1`), so an open tab still times out; devices
  and receiver status come with the first request and every 15 seconds.
- UniFi: CEF events from the console (`CEF:0|Ubiquiti|UniFi Network|…|401|WiFi Client Disconnected|…`) are parsed
  (`UNIFIclientMac`, `UNIFIwifiName`, `UNIFIlastConnectedToDeviceName`) and decoded (connected/disconnected/roamed).

**Not taken:** a stronger permission than radius:read (the text is redacted, and radius:read already shows the
devices' configuration); an unlogged ring of unstored messages (counters per device show quota and rate drops).

### Critique, second round (after implementation)

A reviewer with no part in the build read the finished code. No cross-tenant read path was found, and the live cursor
holds: one writer thread, `CACHE 1`, per-tenant transactions committed in order, prune only deletes.

| Finding | Decision |
|---|---|
| A tenant could save extra addresses with syslog **off** (unchecked), and they still claimed in the receiver: another tenant's switch inside them became "ambiguous" and its syslog was dropped. | Fixed: extra addresses claim only while syslog is on (receiver and conflict check), and are checked whenever they're saved. |
| A tenant using dedicated RADIUS ports may register another tenant's address, making it ambiguous. | Partly fixed: a tenant whose SNMP credentials the device at that address answers (a verified switch audit) is its owner and keeps its syslog. A RADIUS address alone proves nothing, so two such claims stay ambiguous (dropped, not leaked). |
| Unclaimed space goes to the first claimant: a Docker gateway (rewritten sources) or a console shared by several customers. | Fixed where it can be: the receiver drops datagrams from its own default gateways ("rewritten"); extra addresses are at most 256 addresses and never loopback, link-local or multicast. The UniFi guide says not to add a console shared with other customers. Platform approval of extra addresses was not built. |
| The port pattern backtracked quadratically: 57 ms for a 2 KB hyphenated datagram, before any rate limit. | Fixed: bounded pattern, first 400 characters only (2 ms), and a per-device budget of 1,000 datagrams a second before parsing. |
| An exception in the socket thread stopped receiving while the heartbeat said "running". | Fixed: each datagram is handled in a try; if either thread dies the process exits and Docker restarts it. |
| Usage could be reloaded after claims, so a restart could double a tenant's day. | Fixed: usage is loaded once, before any claim; until it loads nothing is attributed. |
| `stop()` flushed from a second thread while the writer could still be storing. | Fixed: no final flush while the writer is alive. |
| Redaction missed `psk set-key ascii`, `authentication-key 1 md5`, `snmp-server host … version 2c <community>`, AireOS `ascii <secret>` and `mgmtuser add`, hostapd `passphrase=`. | Fixed, with tests. |
| UDP 514 and 5514 share one container. | Documented (compose file and DEPLOYMENT.md). |
| No database-backed tests for the trigger, RLS, cursor and migration. | Tested by hand on a scratch copy of the demo database (upgrade, downgrade, upgrade; seq on insert and update as the app role; RLS across tenants), then on the demo itself. |


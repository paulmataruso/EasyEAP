# Plan: switch visibility and audit (SNMP, then syslog)

Status: revised after critique (2026-11-07). Request: "a way for EasyEAP to see into the switch to see if port security
is working as it should / audit — maybe SNMP + a syslog from each device."

## 1. Goal

For every Cisco switch with monitoring on, EasyEAP reads what the switch itself reports (which ports run 802.1X/MAB,
whether they're closed, who is authorized by what method and in which VLAN) and **compares it with what EasyEAP decided
and sent**. Differences become audit findings with a severity, a plain-language meaning and a fix. When it's set up, the
polled session list replaces the manual "paste `show access-session`" readiness step.

Evidence only: nothing here changes a switch or a RADIUS decision.

v1 is Cisco Catalyst over SNMPv3. UniFi has no documented 802.1X MIB (and Flex/Ultra switches have no SNMP), so it waits
for phase 2 (the UniFi Network application's API, after a hardware check). Syslog is v1.1 (§9).

## 2. Where polling runs: a collector next to RADIUS

The API and worker sit on the internal network and don't reach switches; RADIUS does (it already sends CoA to them). So
polling runs in a new **collector** process in its own container, `easyeap-collector`, built from the RADIUS image and
attached to the same networks as `easyeap-radius`, but separate from it: a slow or failing poll, a full disk or a crash
never touches FreeRADIUS.

- It authenticates to the API with its own token (`secrets/collector_token`, distinct from the RADIUS agent's) on its
  own endpoints: `GET /api/collector/targets` (switches with monitoring on: id, tenant, host, port, SNMP user, auth/priv
  protocols and keys, decrypted by the API from the tenant's Transit key) and `POST /api/collector/results`.
- Targets are cached in memory only (never on disk); results are posted per poll (≤ 256 KiB each). If the API is down,
  polls pause; nothing is spooled.
- Multi-node: one collector per deployment in v1. With several, the API assigns each switch to one collector (lowest
  collector id seen in the last 2 minutes wins). The design leaves room; v1 runs one.

## 3. What is read (SNMPv3 authPriv only)

| Data | MIB / OID | Notes |
|---|---|---|
| Ports: name, alias, admin/oper status | IF-MIB ifName .31.1.1.1.1, ifAlias .18, ifAdminStatus .2.2.1.7, ifOperStatus .8 | |
| Port control, host mode, **pre-auth open access** | CISCO-AUTH-FRAMEWORK-MIB cafPortConfigTable .9.9.656.1.2.1.1: .3 control direction, .4 cafPortPreAuthOpenAccess, .5 authorization (host) mode | `.4 = true` on an enforcing switch means `access-session closed` is missing: the port is open |
| Sessions | cafSessionTable .9.9.656.1.4.1.1: .2 MAC, .5 domain, .6 status, .10 VLAN group, .12 authz by, .13 critical, .14 user, .15 audit session id, .16 timeout | |
| Method per session | cafSessionMethodsInfoTable .9.9.656.1.4.2.1.2 (dot1x / mab, state) | |
| Err-disabled ports | CISCO-ERR-DISABLE-MIB cErrDisableIfStatusCause .9.9.548.1.3.1.1.2 | |
| Facts | sysDescr, ENTITY-MIB entPhysicalModelName / SerialNum, snmpEngineID | engine id tracked (§5) |

No forwarding-table (BRIDGE-MIB) walks: per-VLAN contexts are slow, need a wide view, and the closed-port check above
answers "does traffic pass without authorization" directly.

**Capability probe.** CAF MIB support varies by IOS-XE release and isn't documented for every Catalyst 9000 release. The
first poll (and "Test connection") walks one row of each table and records which answer. A finding that needs a missing
table is never raised; the switch's audit says "This switch doesn't report sessions over SNMP (IOS-XE x.y)" instead.
Nothing is assumed from the model.

**Budget.** One walk at a time per switch; GETBULK max-repetitions 20; 3 s timeout × 2 retries; default every 15 minutes
(5–60); the collector polls at most 8 switches at once; a switch whose last poll took more than half its interval is
polled half as often and says so. Library: pysnmp 7.1 (LeXtudio, BSD), asyncio. Defaults: SHA-256 + AES-128 (what every
supported IOS-XE has); SHA-1 and AES-256 selectable.

## 4. Audit findings

Computed by the API when results arrive, from the polled state, the port plan, the switch's mode and EasyEAP's events.
Ports are matched with one canonical interface normaliser (`Gi1/0/5` = `GigabitEthernet1/0/5`), the same one the port
plan uses.

| Finding | When | Severity |
|---|---|---|
| `port_not_covered` | A port in the plan has no 802.1X/MAB (control not `auto`, or no CAF row) | critical (enforce) / warning (monitor) |
| `open_access_in_enforce` | Enforce mode and cafPortPreAuthOpenAccess is true on a planned port | critical |
| `authorized_without_easyeap` | An authorized session (dot1x or mab) with no EasyEAP accept for its MAC from this switch during the session's lifetime. Classified: critical-auth (.13), local / another server (authz-by), unknown | warning |
| `authorized_despite_reject` | Enforce mode, a session authorized while EasyEAP's latest answer for that MAC from this switch is a reject | critical |
| `authorized_after_deny` | A session authorized now, though EasyEAP's current decision for that device is deny (revoked, blocked, expired) — the CoA didn't arrive or isn't configured | warning |
| `vlan_mismatch` | The session's VLAN ≠ the VLAN EasyEAP **sent** in its latest accept for that MAC (none when it sent none; never in monitor mode) | warning |
| `mab_not_expected` | A MAB session on a switch EasyEAP has MAB off for | warning |
| `critical_auth` | Sessions authorized by critical-auth while EasyEAP was unreachable | warning |
| `err_disabled` | A planned port err-disabled (BPDU guard, security violation) | warning |
| `snmp_unreachable` / `snmp_auth` / `snmp_engine_changed` | No answer / wrong credentials / the switch's engine id changed (replaced, or someone else answering) | warning |

**Hysteresis.** A finding opens after two consecutive polls show it and resolves after two that don't (one for
`snmp_*`). **Acknowledge** with a note hides it from the dashboard until its detail changes. An open finding is unique per
(tenant, switch, kind, port, MAC) by a partial unique index `WHERE resolved_at IS NULL`. History kept 90 days.

## 5. Data model (migration `0007_switch_audit`)

All tables carry `tenant_id` with the usual RLS policy.

- `radius_clients.monitoring` (JSONB, no secrets): enabled, **host** (the management address to poll: a RADIUS client may
  be a CIDR or use a source interface), port 161, user, auth (`sha256|sha`), priv (`aes128|aes256`), interval,
  `engine_id` (learned), capabilities (from the probe). Keys: `snmp_auth_ct`, `snmp_priv_ct` (Transit-encrypted).
- `switch_state`: one row per switch, replaced each poll: at, ok, error, duration, `ports` JSONB, `sessions` JSONB,
  facts. Capped at 512 KiB.
- `audit_findings`: tenant, client, kind, severity, port, mac, detail JSONB, first_seen, last_seen, seen_count,
  resolved_at, acknowledged_at/by/note.

## 6. Configuration generated for the switch (optional "Monitoring" block)

```
ip access-list standard EASYEAP-SNMP
 permit <collector-address>
snmp-server view EASYEAP-RO 1.3.6.1.2.1.1 included        ! system
snmp-server view EASYEAP-RO 1.3.6.1.2.1.2.2.1 included    ! ifTable
snmp-server view EASYEAP-RO 1.3.6.1.2.1.31.1.1.1 included ! ifXTable
snmp-server view EASYEAP-RO 1.3.6.1.2.1.47.1.1.1.1 included ! entPhysicalTable
snmp-server view EASYEAP-RO 1.3.6.1.4.1.9.9.656 included  ! CAF
snmp-server view EASYEAP-RO 1.3.6.1.4.1.9.9.548 included  ! err-disable
snmp-server group EASYEAP v3 priv read EASYEAP-RO access EASYEAP-SNMP
snmp-server user <user> EASYEAP v3 auth sha256 <auth> priv aes 128 <priv> access EASYEAP-SNMP
```

The keys are generated by EasyEAP and shown once, like the RADIUS secret (`snmp-server user` isn't stored in the running
configuration, so re-pasting is how they're rotated). Nothing global changes: no `logging`, timestamp or AAA lines.

## 7. Console

- Switch panel → **Audit**: last poll and its status, findings (severity, port, MAC, meaning, fix, acknowledge), and a
  **port table**: port, in plan?, control, closed?, host mode, sessions (MAC · method · user · VLAN · status),
  err-disable. "Poll now" (once a minute at most).
- **Set up monitoring** on a Cisco switch: host, protocols, then the configuration block, then **Test connection** (a
  capability probe through the collector) before it's saved as on.
- Readiness uses the polled sessions automatically when available ("from the switch, 3 minutes ago").
- Dashboard: open critical and warning findings across switches.

## 8. Security

SNMPv3 authPriv only (communities travel in clear and would sit in the database); read-only view narrowed to the six
subtrees; a switch-side ACL; keys Transit-encrypted at rest, decrypted by the API only for the collector's token, held in
the collector's memory only; the engine id pinned after the first poll; results size-capped; findings are evidence,
never used for decisions.

## 9. v1.1: syslog

Received by the collector (never RADIUS), UDP and TCP 514 when `EASYEAP_SYSLOG_BIND` is set, from registered switch
addresses only; an allow-list of mnemonics (`SESSION_MGR-5-FAIL`, `AUTHMGR-5-*`, `DOT1X-5-FAIL`, `MAB-5-FAIL`,
`PM-4-ERR_DISABLE`, `RADIUS-4-RADIUS_DEAD/ALIVE`) with the rest dropped and counted; IOS-aware redaction of user names and
passwords in AAA messages; coalesced per (switch, mnemonic, port, MAC) per minute; its own quota (100 msg/s per source,
50 MB per tenant per day) and thread; 14 days. The configuration adds only `logging host <collector> [vrf …]`,
`logging source-interface …` and `logging discriminator` lines — never global logging levels or timestamps. Syslog is
spoofable, so it's shown as "the switch says", never as a finding on its own.

## 10. Testing

Unit: OID parsing (index decoding, MAC formats, method table), result → port model, the interface normaliser, every finding
rule including monitor vs enforce, hysteresis, acknowledge, capability gating. Integration: `snmpsim` with a recorded
Catalyst-like dataset (CAF tables, err-disable) polled by the real collector over SNMPv3 SHA-256/AES-128, with a missing
table to check capability gating. Not verified on hardware: CAF support per IOS-XE release, cafSessionTable cost on large
stacks.

## 11. Phase 2

UniFi through the Network application's API; SNMP traps (cafAuthFail, MAC notification) to trigger polls; CDP/LLDP
neighbours to suggest "leave alone" ports; a scheduled audit report.

## 12. Critique and revisions

| Finding | Severity | Change |
|---|---|---|
| The worker can't reach switches and blocking SNMP walks would stall its jobs | blocker | A separate collector container next to RADIUS (§2). |
| No address to poll: a RADIUS client may be a CIDR or a source interface | blocker | `monitoring.host`, plus Test connection (§5, §7). |
| CAF MIB support isn't documented on every Catalyst 9000 release | blocker | Capability probe; findings gated on what the switch answers (§3). |
| A syslog flood or spool would fill RADIUS's disk and take it down | blocker | Syslog moves to the collector, with quotas and its own thread, and to v1.1 (§9). |
| Syslog source → tenant mapping is ambiguous (shared CIDRs, NAT) | blocker | Registered single addresses only; v1.1. |
| FDB vs sessions is slow, needs wide views and per-VLAN contexts, and is noisy | major | Dropped; `open_access_in_enforce` from cafPortPreAuthOpenAccess answers the question directly. |
| `authorized_without_easyeap` needs lifetime, classification and correlation | major | cafSession .13/.15/.16; classified; correlated by MAC and switch within the session's lifetime. |
| `vlan_mismatch` against what EasyEAP would decide now is wrong after a policy change | major | Compared with what was **sent** in the latest accept. |
| Interface names differ between SNMP, RADIUS and the plan | major | One canonical normaliser shared with the port plan; `port_not_covered`. |
| Findings flap and can't be silenced | major | Two-poll hysteresis, acknowledge, partial unique index (§4). |
| Missing: authorized despite a reject, and after a later deny | major | `authorized_despite_reject`, `authorized_after_deny`. |
| The config changed global logging and timestamps | major | No global lines; `logging source-interface`/vrf only (v1.1). |
| Syslog can be spoofed and carries user names | major | Allow-listed mnemonics, redaction, "the switch says" only. |
| Storage per poll grows without bound | major | One `switch_state` row per switch; findings carry the history. |
| Tables without `tenant_id` can't use RLS | major | `tenant_id` everywhere. |
| The collector reused the RADIUS agent's token | major | Its own token and endpoints. |
| UniFi has no 802.1X MIB | major | Cut from v1. |
| MAB sessions weren't considered | major | Method per session; `mab_not_expected`. |
| No SNMP budget | minor | §3 budget. |
| AES-256 isn't on every release | minor | AES-128 default. |
| The view was wider than needed | minor | Six subtrees. |
| A replaced or impersonating switch goes unnoticed | minor | Engine id pinned; `snmp_engine_changed`. |
| Several RADIUS nodes would each poll | minor | One collector per switch (§2). |

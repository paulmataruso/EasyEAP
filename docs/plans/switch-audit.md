# Plan: switch visibility and audit (SNMP, then syslog)

Status: revised after critique (2026-11-07), then revised again with the user's decisions and a check of the MIB
text (§0). Request: "a way for EasyEAP to see into the switch to see if port security
is working as it should / audit — maybe SNMP + a syslog from each device."

## 0. Revision 3 (2026-11-07): implementation decisions

Supersedes §2 and the library, migration and table names below where they differ.

- **The collector runs from the API image, not the RADIUS image.** `easyeap-collector` (`entrypoint.sh collector`) is
  attached to the networks the worker uses (data, pki, egress), reads the switches to poll from the database and writes
  the polled state and the findings itself, in one transaction per poll. That removes the collector token, the two
  collector endpoints and the decrypted keys in transit between containers (§2), and it still never shares a process
  with FreeRADIUS or the job worker: a hung walk can't delay a directory sync or a RADIUS answer. It pauses during a
  restore like the worker and writes a heartbeat (`platform_settings.collector_heartbeat`).
- **SNMP client written in-house** (`app/switchaudit/snmp.py`): EasyEAP needs GET and GETBULK only, and pysnmp's API has
  changed with every major version and maintainer. BER, v2c, and v3 USM: HMAC-SHA-1-96 or HMAC-SHA-256-192 (RFC 7860,
  the default), AES-128-CFB (RFC 3826, the default) or AES-256 only together with SHA-256 (a 32-byte localized key, so
  no key extension, whose two variants vendors disagree on). Tested against the RFC 3414 key-localization vectors and,
  end to end, against net-snmp's independent implementation.
- **Test connection runs in the API** (it's on the egress network too), bounded to about 10 s, and saves nothing but the
  capability probe's answer.
- **Migration `0009_switch_audit`**; tables `switch_states` and `switch_findings` (not `audit_findings`, which reads as
  the admin audit trail). Credentials in one Transit-encrypted column `radius_clients.snmp_secret_ct` (a JSON object:
  the community, or the v3 keys).
- **`switch_changed` replaces `snmp_engine_changed`**: the v3 engine id *or* the chassis serial differs from the one
  pinned at the first successful poll. It stays open until acknowledged; acknowledging pins the new values.
- **Findings are evaluated per kind only when their evidence was read**: a failed poll touches only the `snmp_*`
  findings, and a switch without the CAF tables gets none of the session or port findings.
- **The generated block has no secrets in it** (placeholders, like the RADIUS configuration); the community or keys are
  shown once when monitoring is set up or the credentials are regenerated, and the console fills them in then.
- **Lab switch for the end-to-end test**: net-snmp's snmpd with a `pass_persist` script serving a Catalyst-like dataset
  (CAF port and session tables, err-disable), on v2c and v3 SHA-256/AES-128, instead of snmpsim.

## 0b. Revision 2 (2026-11-07): user decisions and MIB corrections

- **SNMPv2c is the default** (the user's call), SNMPv3 authPriv an option. With v2c the community travels in clear, so
  EasyEAP generates a random 24-character community, the generated switch configuration binds it to the read-only view
  (§6) and to an ACL that permits only EasyEAP's address, and it's stored Transit-encrypted like every other secret. The
  console says what v3 adds (no community on the wire) next to the choice.
- **OIDs checked against CISCO-AUTH-FRAMEWORK-MIB (2013-08-23) and CISCO-ERR-DISABLE-MIB.** The first table below had
  wrong column numbers; the corrected ones are in §3.
- **Capability probe**: CAF is supported when cafAuthMethodRegTable (.656.1.1.2) returns rows (it lists the registered
  methods, dot1x and mab, on every switch that runs the framework); err-disable when cErrDisableRecoveryInterval.0 answers.
- **Collector token**: the API writes a random token on first start to a small volume shared only with the collector
  (`easyeap-collector`), so upgrades need no new file under `deploy/secrets` (`docker compose build && up -d` keeps
  working).

## 1. Goal

For every Cisco switch with monitoring on, EasyEAP reads what the switch itself reports (which ports run 802.1X/MAB,
whether they're closed, who is authorized by what method and in which VLAN) and **compares it with what EasyEAP decided
and sent**. Differences become audit findings with a severity, a plain-language meaning and a fix. When it's set up, the
polled session list replaces the manual "paste `show access-session`" readiness step.

Evidence only: nothing here changes a switch or a RADIUS decision.

v1 is Cisco Catalyst over SNMPv2c (default) or SNMPv3. UniFi has no documented 802.1X MIB (and Flex/Ultra switches have no SNMP), so it waits
for phase 2 (the UniFi Network application's API, after a hardware check). Syslog is v1.1 (§9).

## 2. Where polling runs: a collector next to RADIUS (superseded by §0, revision 3)

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

## 3. What is read (SNMPv2c by default, SNMPv3 authPriv optional)

| Data | MIB / OID | Notes |
|---|---|---|
| Ports: name, alias, type, admin/oper status | IF-MIB ifName 1.3.6.1.2.1.31.1.1.1.1, ifAlias …31.1.1.1.18, ifType 1.3.6.1.2.1.2.2.1.3, ifAdminStatus …2.2.1.7, ifOperStatus …2.2.1.8 | |
| Port control, host mode, **pre-auth open access** | CISCO-AUTH-FRAMEWORK-MIB cafPortConfigTable 1.3.6.1.4.1.9.9.656.1.2.1.1 (INDEX ifIndex): .1 controlled direction, .3 cafPortAuthHostMode (singleHost 1, multiHost 2, multiAuth 3, multiDomain 4), .4 cafPortPreAuthOpenAccess (TruthValue), .5 cafPortAuthorizeControl (forceUnauthorized 1, auto 2, forceAuthorized 3) | `.4 = true` on an enforcing switch means `access-session closed` is missing: the port is open |
| Sessions | cafSessionTable …656.1.4.1.1 (INDEX ifIndex, IMPLIED cafSessionId): .2 MAC, .5 status (authorizationSuccess 6, …), .6 domain (data 2, voice 3), .10 user name, .12 authorized by (text), .13 critical time left, .14 authorized VLAN (0 = none), .22 VLAN group name | |
| Method per session | cafSessionMethodsInfoTable …656.1.4.2.1.2 (INDEX ifIndex, cafSessionId length-prefixed, cafSessionMethod: dot1x 2, macAuthBypass 3, webAuth 4): state (authcSuccess 4, authcFailed 5, …) | |
| CAF present | cafAuthMethodRegTable …656.1.1.2 | capability probe |
| Err-disabled ports | CISCO-ERR-DISABLE-MIB cErrDisableIfStatusCause 1.3.6.1.4.1.9.9.548.1.3.1.1.2 (INDEX ifIndex, VLAN) | cause enum (bpduGuard 2, dot1xSecurityViolation 8, portSecurityViolation 9, …) |
| Facts | sysDescr, sysName, ENTITY-MIB entPhysicalModelName …47.1.1.1.1.13 / SerialNum …11, snmpEngineID (v3) | engine id tracked for v3 (§5) |

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

## 5. Data model (migration `0009_switch_audit`; table names per §0)

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
! SNMPv2c (default):
snmp-server community <community> view EASYEAP-RO RO EASYEAP-SNMP
! or SNMPv3:
snmp-server user <user> EASYEAP v3 auth sha-2 256 <auth> priv aes 128 <priv> access EASYEAP-SNMP
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

SNMPv2c by default (the user's decision, §0): a generated community bound to the view and the ACL, Transit-encrypted at rest; SNMPv3 authPriv when chosen; read-only view narrowed to the six
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

### Revision 3: critique of the implementation

| Finding | Severity | Change |
|---|---|---|
| `radius:write` could point the switch's monitoring at another address, and the v2c community would follow it | major | Changing the address or port needs `radius:secrets`, like seeing the credentials. |
| An error that isn't an SNMP error (an out-of-range engine boots, an odd index) escaped the poll: Test connection gave a 500, and the collector re-polled the switch every minute without recording anything | major | Engine boots/time validated; a poll always ends with a result; a result that can't be stored is recorded as such and waits an interval. |
| A MAB accept and a later 802.1X reject (or the reverse) were compared as one device | medium | EasyEAP's answers are compared per method family (802.1X, MAB), as the switch keeps them as separate sessions. |
| Two polls of one switch (the service and `--once`, or Test connection) could write at once | medium | The switch's row is locked while a result is written. |
| A poll that ended during a restore could write into the database being replaced | medium | The result is dropped when a restore is running. |
| The "slow switch" threshold could never be reached, sessions over the limit failed the whole poll, and findings past a cut list were resolved | low | Slow after a minute; long session lists are cut short and marked; findings past the cut are left as they were; only the three port-configuration columns are walked. |
| SNMPv3 responses: no time-window check, predictable request ids, an authenticated but unencrypted response accepted | low | RFC 3414 §3.2 step 7 checks; independent random ids; responses must be encrypted. |
| A switch moved from v2c to v3 never had its engine ID pinned | low | Serial and engine ID are pinned one by one. |
| Secrets in object reprs; one-time credentials kept in the page after the dialog closed; the collector held secrets it doesn't use | low | `repr=False`; the dialog clears them; the collector gets only the application role's password. |
| Test connection had no rate limit, and a sealed OpenBao gave a 500 | low | Six tests a minute per switch; 503 with a message. |
| The `auth_events` index is built without `CONCURRENTLY` | low | Not changed: events reach the database only through the API, which applies the migration before it serves, and RADIUS resends what it couldn't deliver. |

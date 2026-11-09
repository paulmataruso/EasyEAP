# Plan: device administration (TACACS+) with AD and local accounts

Status: built (2026-11-07), not yet verified on Cisco hardware. User guide: [docs/device-administration.md](../device-administration.md).
Request: network admins log into Cisco switches and Catalyst 9800 controllers with their **AD accounts**, and EasyEAP
also keeps its **own local account database** for this.

*As built*, where it differs from the plan below:
- The agent keeps the admin data in `admin.json` (0600, written atomically), not SQLite; the TACACS+ process reloads it
  when it changes. It carries its own validity (`admin_valid_until`, the tenant's snapshot age limit), so expired data
  answers ERROR. The role cache is in memory (12 h).
- TCP 49 is always mapped, but to `127.0.0.1` unless `EASYEAP_TACACS_BIND` names another address: off the network by
  default, as planned, without a compose profile.
- The configuration's address placeholder is `<easyeap-radius-ip>` (the same address as RADIUS), filled in by the
  console when the server has no `EASYEAP_RADIUS_ADDRESS`.
- Event kinds are `login`, `enable`, `authz`, `session` and `command`.
- After the code review (2026-11-07):
  - The AD bind cap is checked and reserved in one step under the throttle lock; binds in flight count, and a login
    whose cap is full only because of binds in flight waits (asyncio, no thread held) instead of failing. The cap is
    `(threshold − 1) // 2` per lockout observation window (at least 30 minutes), 1 while the threshold is unknown,
    5 when the domain has no lockout. The sync reads `lockoutThreshold` and `lockOutObservationWindow` from the
    domain root (RootDSE `defaultNamingContext`), not the sync base DN (`directory_configs.lockout_window`, 0006).
  - Exec and command authorization answer only for sessions EasyEAP authenticated: `authen_method` TACACS+ (or not
    set) and a login by that account to that device on this node within the role cache time. Anything else is ERROR
    (`admin_not_easyeap_login`), so the device's `local` method decides. The role is re-derived from current data
    (the groups the DC gave at login, the current mappings; for EasyEAP accounts enabled, expiry, sites, role).
  - Password hashing and AD binds use separate thread pools (4 and 16); each tenant has at most 2 binds in flight,
    so one tenant's slow DCs can't hold up other tenants or local accounts.
  - A directory that can't be used for admin logins (plain LDAP, verification off) is still sent to the agent as
    `{"usable": false}`, so mapped users get ERROR rather than FAIL "unknown user".
  - TOTP codes are checked and marked used in one step; logins and enable track used codes separately.
  - ERROR paths log the account's name or the keyed hash, never the typed name.
  - Masking: `password`/`secret` take the rest of the line, `snmp-server host` communities, numeric SNMPv3
    passphrases, IKEv2 `pre-shared-key local|remote`, HSRP/VRRP `authentication text`, IS-IS area/domain passwords.
  - `radius:write` alone can't change the address, type or site of an admin-enabled device or delete it.
- Tests: `backend/tests/test_device_admin.py` (codec, fuzz, decisions, throttles, masking corpus, real-socket sessions),
  `tests/radius/run.sh` step 11 (the service in the RADIUS image), `tests/e2e/run.sh` step 11b (AD logins through the
  lab Samba DC with nested groups, from a lab container as the switch) and the console smoke test.

## 1. Findings that shape the design

- **TACACS+, not RADIUS, for logins.** RADIUS PAP logins are what Blast-RADIUS attacks, and EasyEAP drops any request
  without Message-Authenticator; Cisco adds it to every Access-Request only from IOS XE 26.2.1, and what 17.x and 15.2
  send on logins is unverified. TACACS+ separates authentication, authorization and accounting.
  RFC 8907 (TACACS+) only obfuscates with an MD5 keystream: no integrity, so it must run on a management network.
  RFC 9887 (TACACS+ over TLS 1.3) is supported from IOS XE 17.18.1 and is phase 2 (§9).
- **UniFi has no RADIUS, TACACS+ or LDAP administrator login.** Documented as not supported.
- **Passwords**: IOS exec logins over TACACS+ are ASCII (the password reaches the server), so a slow hash works; CHAP and
  MS-CHAP need recoverable passwords and are refused.
- **AD lockout**: failed binds count towards the domain's lockout threshold.
- **v1 is Cisco only** (IOS 15.2, IOS XE, Catalyst 9800). FortiGate, PAN-OS, Junos and NX-OS need their own services and
  attribute names (`service=fortigate`, `PaloAlto`, `junos-exec`, `shell:roles`): phase 2.

## 2. Server: EasyEAP's own TACACS+ service

A small asyncio TACACS+ server (`services/radius/agent/tacacs.py`, Python stdlib plus Ubuntu's `python3-ldap3`) in the
RADIUS container, a second process supervised by the agent like FreeRADIUS. It reads the synced snapshot (SQLite) and
writes events to the agent's spool, so logins keep working while the API is down.

Build or buy: tac_plus-ng (C, mature, audited, has TLS) with a Python MAVIS external backend would also keep all policy in
Python. We build instead because the subset IOS needs is small; a Python parser is memory-safe on the network; there is no
official tac_plus-ng image (a pinned C build Dependabot can't track) and no second configuration language to render with
multi-tenant routing. The risk moves to protocol behaviour and vendor quirks, so: v1 limited to Cisco, single-connection
declined, the codec fuzzed, every RFC 8907 rule below unit-tested, and **real hardware is a release gate** before the
feature is called supported (the console says "not yet verified on hardware" until then). tac_plus-ng + MAVIS stays the
documented fallback if interop fails.

Protocol (RFC 8907), each rule tested:
- Header: version 0xC (major) with minor 0 (ASCII) or 1 (PAP); session keyed by (connection, session_id); client
  sequence numbers odd and strictly increasing, session ends at 255; unencrypted flag → drop and log; single-connection
  flag → not echoed (declined, §4.3); body length ≠ header length or bad internal lengths → ERROR; framing errors
  close the connection; a packet whose type can't be determined gets the zero-length error.
- Authentication START `action LOGIN`, ASCII: username in START (SSH) or empty (telnet) → GETUSER; GETPASS with NOECHO;
  CONTINUE with the ABORT flag ends the session without counting a failure; per-session timer 60 s. PAP: user + data in
  START. Service LOGIN and ENABLE. CHAP/MS-CHAP/ARAP → FAIL with "Set the device to ASCII or PAP".
- **FAIL vs ERROR** (IOS treats FAIL as final and ERROR as "try the next method"): FAIL only for a real denial (wrong
  password, unknown user, disabled, expired, outside scope, locked). ERROR for: DCs unreachable or timed out, tenant
  snapshot expired, internal exception, a key that doesn't decrypt the packet (§4.5), and **local-only usernames**
  (break-glass names the tenant lists, so the device falls back to its local account while EasyEAP is up).
- Authorization `service=shell` with `cmd*` (exec): PASS_ADD `priv-lvl=N` (mandatory pair for IOS). Command
  authorization is **not** in v1 (the generated configuration doesn't enable it). If a device sends command
  authorization anyway (`cmd=` non-empty, configured by hand), it gets PASS_ADD when the user's role is level 15 and FAIL
  otherwise, and the request is logged. Role at authorization time: cached from the login per
  (tenant, identity) in SQLite (TTL 12 h), else the identity's synced groups from the snapshot.
- Accounting START/STOP/WATCHDOG → SUCCESS; invalid flag combinations → ERROR. Command records: IOS sends one
  `cmd=… <cr>`; arguments that are secrets are masked before the spool (§6).
- Limits: body ≤ 64 KiB, 20 connections per source address, 300 total, idle timeout 120 s; only registered addresses are
  answered (TCP: not spoofable). Listens on 4949 in the container, published as TCP 49 **only when
  `EASYEAP_TACACS_BIND` is set** (no default bind).
- Slow work off the event loop: LDAP and hashing in a bounded thread pool (4 workers, per-tenant cap 2); total LDAP
  budget 3 s per login, else ERROR.
- Every failure is answered after the same minimum delay (1 s, like FreeRADIUS `reject_delay`), with a dummy hash for
  unknown users, so timing doesn't reveal admin usernames.

## 3. Data model (migration `0006_device_admin`)

- `radius_clients`: `admin_enabled` (bool, default false), `tacacs_key_ct` (encrypted like `secret_ct`), `tacacs_key_set_at`,
  `tacacs_prev_key_ct` + `tacacs_prev_until` (rotation grace, 24 h). Admin-enabled addresses must not overlap another
  tenant's admin-enabled addresses, whatever the RADIUS ports; within a tenant the longest prefix wins.
- `admin_roles`: id, tenant_id, name, `priv_lvl` (0-15), builtin flag. Built-in per tenant: **Network administrator**
  (15), **Read-only** (1; the guide explains what priv 1 can and can't show, and how to make a custom level with
  `privilege exec level 7 show running-config`).
- `admin_users` (local): id, tenant_id, username (`[a-z0-9._-]{1,64}`, unique, case-folded), display name, email,
  `password_hash` (stdlib scrypt N=2^15 r=8 p=1, `scrypt$...` format), `password_set_at`, `totp_secret_ct` (optional,
  encrypted), role_id, `sites` (empty = all), enabled, `expires_at`, last_login_at, created_by.
- `admin_group_maps` (AD): id, tenant_id, directory group (SID), role_id, `sites`, `position` (first match wins).
- `admin_settings` per tenant: `local_only_usernames` (default `[]`), log retention days (180, 30-730).
- `admin_events`: id, tenant_id, at, client_id, username (verbatim for known accounts; a short keyed hash for unknown
  ones), source (`local|directory`), kind (`login|enable|exec|accounting`), result, reason, priv_lvl, command (masked),
  rem_addr, port, task_id.

## 4. Who may log in

The snapshot gains `admin`: roles, local users (username, scrypt hash, TOTP secret, role, sites, enabled, expires),
directory candidates (enabled, not deleted/locked synced users who are members of at least one mapped group: GUID,
sAMAccountName, UPN, mapped-group SIDs), the group maps, local-only usernames, the domain's `lockoutThreshold` (read at
sync), and per-device `{address, site, admin_enabled}`. TOTP secrets and hashes make this section sensitive: the agent
keeps it in its 0600 SQLite only. TACACS keys go to the TACACS process in their own 0600 file (reloaded on change, no
FreeRADIUS restart; a rejected FreeRADIUS configuration can't block a key rotation).

Login for typed name `u` from device `d` (tenant from `d`'s address; `d.admin_enabled` required):
1. `u` in local-only usernames → ERROR (device uses its local account).
2. Resolve `u` (case-folded; `DOMAIN\user`, `user@upn` and `user` forms) to a local user, else a directory candidate.
   Neither → FAIL `admin_unknown_user` (after the uniform delay).
3. Throttles, keyed by the resolved identity: per (identity, rem_addr) exponential backoff (1, 2, 4 … 60 s after 3
   failures); per identity a cap on **AD binds** of `max(1, floor((lockoutThreshold − 1) / 2))` per 30 minutes per node
   (5 when the domain has no lockout). An identical repeated wrong password (keyed hash, 10 min) is refused without
   another bind. ABORT doesn't count. Local accounts: 10 failures in 15 minutes → locked 15 minutes (`admin_locked`),
   shown in the console with Unlock.
4. Local user → scrypt check (+ TOTP when set: the last 6 digits of the password field are the code; a code can't be
   reused within its window); disabled, expired, wrong site → FAIL with the reason.
5. Directory candidate → refused unless the tenant's directory uses LDAPS or StartTLS **with certificate verification**
   (otherwise passwords could go to an impostor DC). LDAPS simple bind as the stored UPN (else `sAMAccountName@domain`),
   WhoAmI to confirm the bound account, then RootDSE `tokenGroups` (MS-ADTS 3.1.1.3.2.41: the bound connection's SIDs, no
   DN or ACL needed) ∩ mapped SIDs → first matching map gives the role; none → FAIL `admin_not_permitted`.
Local takes precedence over directory for the same name (the console warns on a clash).

ENABLE: allowed when the requested priv_lvl ≤ the role's level; the password is checked again.

## 5. Device configuration (generated per device, Cisco)

Two parts, pasted with `reload in 15` and tested from a new session:
```
aaa new-model
tacacs server EASYEAP-ADMIN-<TENANT>
 address ipv4 <easyeap-tacacs-ip>
 key 0 <tacacs-key>
 timeout 5
aaa group server tacacs+ EASYEAP-ADMIN
 server name EASYEAP-ADMIN-<TENANT>
 [ip tacacs source-interface <if>] [ip vrf forwarding <vrf>]
aaa authentication login default group EASYEAP-ADMIN local
aaa authentication login EASYEAP-CONSOLE local
aaa authentication enable default group EASYEAP-ADMIN enable
aaa authorization exec default group EASYEAP-ADMIN local if-authenticated
aaa accounting exec default start-stop group EASYEAP-ADMIN
aaa accounting commands 1 default start-stop group EASYEAP-ADMIN
aaa accounting commands 15 default start-stop group EASYEAP-ADMIN
line con 0
 login authentication EASYEAP-CONSOLE
```
Preflight (like the wired guide): a privilege-15 local user exists (`show running-config | include ^username`), `enable
secret` is set, and no existing `tacacs`/`aaa` lists from ISE or ACS (stop and merge by hand). On switches that also run
EasyEAP wired 802.1X, the wired configuration stops emitting its `aaa authentication login default local` / `aaa
authorization exec default local` lines once admin logins are on, so regenerating it can't silently undo TACACS. Catalyst
9800: adds `ip http authentication aaa login-authentication default` and `exec-authorization default`, `ip http
secure-server` (26.2+), and the HTTP restart; marked not verified. Classic 15.2: images without `tacacs server` get the
legacy `tacacs-server host … key …` form, chosen by the configuration style the wired wizard already asks for.

## 6. Console

- **Device administration** (new screen, Configure section; `admin:read`, `admin:write`; RBAC like `radius:*`):
  - Devices: registered Cisco switches and controllers with an "Admin logins" switch, the TACACS key (shown once, rotate
    with grace), the configuration and preflight. UniFi and other vendors: what's supported and why not.
  - Accounts: local accounts (add, set password with the NIST SP 800-63B-4 policy — at least 15 characters or 8 with
    TOTP, up to 64+, no composition rules, a common-password blocklist — enable TOTP with a QR code, disable, unlock,
    delete).
  - Directory access: AD group → role, ordered, optional site scope; who that admits now; a notice when certificate
    verification is off for the directory.
  - Roles: the built-ins plus custom privilege levels.
  - Local-only usernames (break-glass).
  - Admin log: logins, enables, exec sessions and command accounting by device, user, result. Masking covers `secret`,
    `password`, `key`, `key-string`, `pre-shared-key`, `md5`, `community`, `auth`/`priv` passphrases, `wpa-psk`,
    `server-key`; tested against a corpus.
- Audit for every change. Global search: admin accounts.

## 7. Security summary

Listener off unless bound explicitly; registered addresses only; per-device keys (≥ 32 characters) with rotation grace;
FAIL/ERROR semantics keep local fallback during outages; AD only over verified TLS, bind as the user, no service-account
password in the agent; throttles keyed by identity and derived from the domain's lockout threshold; uniform failure
timing; hashes and TOTP secrets only in 0600 files; secrets masked before logging; local console and break-glass account
in every configuration.

## 8. Testing

Unit: codec (header, MD5 pad round-trip, lengths, sequence rules, unencrypted/single-connect flags) and a fuzz test;
ASCII/PAP/ENABLE state machine incl. ABORT and timeouts; FAIL vs ERROR cases; authorization (priv, role cache, snapshot
fallback); accounting; throttles; masking corpus; snapshot `admin` section; configuration generation and the wired
interaction. Integration (real container): a TACACS+ client driving ASCII like IOS (empty user → GETUSER → GETPASS),
PAP, ENABLE, wrong password, local-only name → ERROR, expired snapshot → ERROR, CHAP refused, unregistered source dropped,
exec authorization, accounting; AD against the lab Samba DC (UPN bind, RootDSE tokenGroups, nested group, DC down →
ERROR). E2E through the published port. Console smoke. Real Cisco hardware: release gate, listed as not verified.

## 9. Phase 2

TACACS+ over TLS 1.3 (IOS XE 17.18+, port 300; needs device certificates from EasyEAP's PKI and a trustpoint flow);
command authorization (token-prefix sets, a second paste from an EasyEAP session, `config-commands`, no
`if-authenticated`); TOTP for AD users; other vendors' AV profiles; RADIUS admin logins once Message-Authenticator on
logins is common; per-tenant ports.

## 10. Critique and revisions

| Finding | Severity | Change |
|---|---|---|
| `aaa authorization commands 15` blocks the paste itself, `write mem`, `reload cancel`, and break-glass users (FAIL is final) | blocker | No command authorization in v1; two-step design moved to phase 2. |
| Only FAIL specified: a DC outage or expired snapshot locks every admin out | blocker | ERROR (fall back to local) for outages, expired snapshot, internal errors, key mismatch; FAIL only for denials (§2). |
| No role for AD users at authorization time (no password in exec authorization) | blocker | Role cached per identity from the login (12 h), else synced groups (§2). |
| Lockout by typed name lets anyone lock an admin out; variants multiply binds; fixed threshold | major | Keyed by resolved identity; per-source backoff; AD bind cap from the domain's `lockoutThreshold`; repeated identical password not re-bound; ABORT not counted (§4). |
| Blocking LDAP/bcrypt inside asyncio | major | Bounded thread pool, 3 s LDAP budget → ERROR (§2). |
| MD5 obfuscation has no integrity; RADIUS binds 0.0.0.0 by default | major | TACACS published only with an explicit bind; management-network requirement in the guide. TLS stays phase 2 (kept, below). |
| Passwords sent to an unverified DC when certificate checks are off | major | AD admin logins require verified LDAPS/StartTLS (§4). |
| User-object `tokenGroups` needs the DN and is fragile | major | WhoAmI + RootDSE `tokenGroups` of the bound connection (§4). |
| Shared TCP 49 vs overlapping tenant addresses | major | No overlap across tenants for admin-enabled clients; longest prefix within a tenant (§3). |
| Protocol details missing | major | Specified and tested (§2). Single-connection declined. |
| Roles don't match IOS privilege; regex rules over-built (ReDoS) | major | Roles are privilege levels; accounting `commands 1` and `15`; command rules phase 2. |
| Non-Cisco services would FAIL | major | v1 Cisco only; others phase 2. |
| No MFA | major | Optional password+TOTP for local accounts with replay protection in v1; AD in phase 2. |
| bcrypt's 72-byte limit vs the length policy; agent stdlib-only | minor | stdlib scrypt. |
| Timing reveals usernames; passwords typed at "Username:" stored | minor | Uniform failure delay + dummy hash; unknown names stored as a keyed hash. |
| Masking too narrow | minor | Wider list, masked before spooling, tested on a corpus (§6). |
| Agent plumbing: spool routing, snapshot bumps, keys tied to FreeRADIUS config | minor | `admin-` spool prefix and route; admin changes bump the snapshot; keys in their own file; rotation grace. |
| Wired guide re-emits `login default local`; enable rules; name clash; missing preflight | minor | Wired config skips those lines when admin logins are on; ENABLE ≤ role level; `EASYEAP-ADMIN-<TENANT>`; preflight (§5). |
| 9800 GUI behaviour unverified | minor | Marked not verified. |
| Port 49 as non-root; one device can exhaust connections | minor | Listen on 4949, publish 49; per-source cap. |
| Test claims (no RFC vectors; client library ≠ IOS) | minor | Round-trip and fuzz tests; a client driving the IOS ASCII sequence; hardware as a release gate. |
| *Kept despite the critique*: TLS in v1 | — | IOS XE 17.18.1 (Dec 2025) is the first release with it, and it needs a device certificate and trustpoint flow; v1 makes the plain listener opt-in instead, with the TLS design ready for phase 2. |

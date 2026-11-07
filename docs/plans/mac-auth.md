# Plan: MAC authentication on switch ports

Status: built (2026-11-07), not yet verified on switch hardware; "As built" notes below where it differs. Scope set by the user: **switch ports only** (Cisco Catalyst and UniFi
switches), for devices that can't do 802.1X (printers, cameras, phones, badge readers, IoT). Not Wi-Fi.

## 1. What exists today

- Wired 802.1X (docs/plans/wired-8021x.md): switches with a port plan, monitor → enforce, VLAN mapping per VLAN
  (`same | port | vlan`), `authz` + `authz_wired` snapshot tables, readiness by port.
- A MAB request (`Service-Type = Call-Check`) is rejected as `mab_unsupported`; the generated configuration never enables
  `mab`. Devices without 802.1X can only be blocked or put in one VLAN (`no_supplicant`).
- FreeRADIUS requires Message-Authenticator on every request (Blast-RADIUS). Cisco IOS/IOS-XE MAB requests carried it in
  every capture found (15.0(2)SE7, 17.15.04); UniFi's MAC mode is EAP-MD5, where it's mandatory. So it stays required;
  `auto` is rejected (never upgrades CIDR clients, downgradable by a spoofed packet). Because a dropped request makes the
  switch mark EasyEAP dead (§6.5), MAB must prove itself in monitor mode before it's enforced.

## 2. Goals and non-goals

Goals: a tenant's **MAC allow list** (devices in groups, each group with an explicit switch VLAN); MAB opt-in per switch;
learning in monitor mode (unknown MACs per switch/port, approve in one step or in bulk); Cisco (IBNS 2.0, classic) and
UniFi configuration; decisions logged and explained; changes take effect on live sessions through CoA where enabled.

Non-goals (v1): Wi-Fi MAC filtering; profiling; automatic approval; dACLs; MAB-first ports; Cisco `mab eap`.

## 3. Data model (migration `0005_mac_auth`)

- `device_groups` (RLS): id, tenant_id, name (unique), description, `vlan_ref` (FK `vlans.id`, **required**,
  `ON DELETE RESTRICT`) or the explicit choice `port_vlan = true` ("port's own VLAN, not recommended"), enabled,
  created_at. The console shows the effective switch VLAN (after the VLAN's wired mapping).
- `mac_devices` (RLS): id, tenant_id, mac (`char(12)`, uppercase hex, unique per tenant), name, notes, group_id,
  enabled (false = blocked), expires_at, source (`manual|import|learned`), created_at, created_by, `last_seen_at`,
  `last_seen_client_id`, `last_seen_port` (updated at ingest; **not** versioned data).
- `mac_sightings` (RLS): tenant_id, mac, client_id, port, first_seen, last_seen, count, last_reason; unique
  (tenant, mac, client, port); upserted at ingest for MAB rejects; capped at 50,000 rows per tenant (oldest dropped).
- `auth_events.mac`, `accounting_sessions.mac`: the normalised device MAC (from Calling-Station-Id, or the MAB
  User-Name), indexed with tenant; `auth_events.method` (`eap-tls|mab|mab-eap`, NULL = certificate on old rows) and
  `mac_device_id`.
- `radius_settings.mac_version` (bigint): bumped by admin edits to devices or groups only.
- Switch opt-in: `WiredProfile.mab: bool = False` in `radius_clients.wired_profile`. Limits: 20,000 devices and 100 groups
  per tenant; import ≤ 1,000 lines per request.

## 4. Snapshot

Separate MAC part with its own version: the snapshot response carries `mac_version` and, when it differs from what the
agent has, `mac_entries` (`{mac, outcome, reason, vlan, device_id, group_id, expires_at}`; `vlan` after the wired mapping,
`null` = none). The agent writes `authz_mac (tenant, mac, version, outcome, reason, vlan, device_id, group_id, expires_at)`
and `meta_mac (tenant, version)`; certificate recomputes don't resend MACs. Expiry is evaluated in the RADIUS lookup
(`expires_at > now`), so a version's content is the same on every agent and expiry needs no new version.
`drop_removed_tenants` clears `authz_mac`/`meta_mac`.

Version skew:
| API | Agent | Result |
|---|---|---|
| new | old (wired-era or 1.0.1) | Ignores `mac_*`, renders `mab_unsupported`. The agent doesn't report the `mab` feature, so the console doesn't offer MAB. |
| old | new | No `mac_*`, no client has MAB on → `mab_not_enabled`. |
| new | new | MAB on switches with `mab` on, once the agent reports `features: ["mab"]`. |

## 5. RADIUS

### 5.1 Recognising a MAC request

Client attribute `easyeap_mab` = `pap` (Cisco switches with `mab`), `eap` (UniFi switches with `mab`: EAP-MD5 or PAP), or
`no`. A request is MAB only when the client allows it **and** there is positive wired evidence (Cisco: `NAS-Port-Type ==
Ethernet`; UniFi: the network decision is wired):
- `pap`: `Service-Type == Call-Check`, no EAP-Message, User-Name is a MAC.
- `eap`: EAP-Message with a MAC User-Name, or PAP as above.
Anything else follows the EAP-TLS path unchanged: a certificate with a MAC-looking identity on Wi-Fi or on a switch without
MAB still works. A `Call-Check` request from a client without MAB → `mab_not_enabled` (Wi-Fi controllers included).

`control:EasyEAP-Mac` := the User-Name normalised (anchored regex); every SQL lookup uses only it. Then:
- Cisco (`pap`): Calling-Station-Id must normalise to the same MAC → else `mab_mismatch`. UniFi: not checked (its
  Calling-Station-Id is unverified).
- Snapshot fresh → else `snapshot_stale`.
- `authz_mac` for the current version: none → `mac_unknown`; expired → `mac_expired`; deny → its reason
  (`mac_disabled`, `mac_group_disabled`); allow → VLAN as for certificates (withheld in monitor mode, still logged).
- PAP: `User-Password` normalised must equal the MAC → else `mab_password`; then `Auth-Type := Accept`.
- EAP (UniFi): `control:Cleartext-Password := User-Name` and the request goes to **`eapmd5_<t>`** (EAP-MD5 only; listed
  in `authenticate` and in `Post-Auth-Type REJECT`). `eap_<t>` stays TLS-only. VLAN attributes go out in post-auth on
  the Access-Accept only, never on challenges.

### 5.2 Events and sightings

`linelog_auth` adds `method`, `mac` (EasyEAP-Mac), `mac_device`, `mac_group`, `service_type`. Ingest fills `auth_events.mac`
and `method`; MAB rejects upsert `mac_sightings`, and a repeated `mac_unknown` for the same (MAC, switch, port) is stored as
an event at most once per hour (the sighting counts the rest), so unknown devices retrying every few minutes can't flood
the log. Accepts update `last_seen_*` without touching versions. New reasons with explanations: `mab_not_enabled`,
`mab_mismatch`, `mab_password`, `mac_unknown`, `mac_disabled`, `mac_expired`, `mac_group_disabled`. `mab_unsupported` stays
for old events.

*As built:* the plan was for the agent to count FreeRADIUS's "no Message-Authenticator" drops per client. FreeRADIUS
3.2.10 discards such a request without logging anything at its normal level (verified in the RADIUS integration test with
a hand-built packet), so there is nothing to count. The safeguard is evidence by absence instead: Enforce with MAB needs
an answered MAB request (§6.5), and the switch's readiness says, when there is none, that the switch may be sending MAC
requests without Message-Authenticator and how to check (`debug radius`).

### 5.3 CoA

Sessions are found by the normalised `mac` column. Block, delete, expiry (worker sweep) or group disable → Disconnect.
Approve/unblock of a MAC whose session sits in the unknown-device VLAN, or a group VLAN change → Cisco CoA-Request
`subscriber:command=reauthenticate` (VLAN change: `subscriber:command=bounce-host-port`, documented as disruptive on
multi-host ports). The agent learns to send CoA-Request besides Disconnect-Request.

*As built:* CoA kinds are `disconnect` (Disconnect-Request), `reauthenticate` and `bounce` (CoA-Request with the Cisco
AV-pair; a switch from another vendor gets a disconnect instead, which also makes it authenticate again). Without an open
accounting session, the target is the switch of the device's last accept in the past two days. A group change queues at
most 500; the rest update at their next re-authentication. The agent reports `features: ["wired", "mab", "coa-request"]`
in its status; the console offers MAB only when an agent seen in the last 10 minutes reports `mab`.

## 6. Switch configuration

### 6.1 Policy maps are never edited in place

IOS merges a re-pasted policy-map into the attached one, so stale lines survive (e.g. `30 authorize` under
`DOT1X_NO_RESP` — the port fails open). This affects today's re-Enforce after a `no_supplicant` change too. From now on
every policy-map name carries a hash of its content (`EASYEAP_MONITOR_<h>`, `EASYEAP_CLOSED_<h>`); any change defines the
new map, swaps `service-policy` on every range (`no service-policy … OLD`, `service-policy … NEW`) and then removes the old
map. The previous state comes from the saved profile (`policy`, `policy_prev`, `last_change`).

*As built:* the wired feature was on `dev` (and the demo) with the fixed names `EASYEAP_MONITOR` / `EASYEAP_CLOSED`, so
migration 0005 records that name as the attached `policy` of every Cisco IBNS 2.0 switch with a port plan; the next
change swaps it out like any other.

### 6.2 Cisco IBNS 2.0 (`mab` on)

`event session-started` unchanged (`authenticate using dot1x priority 10`). `event authentication-failure match-first`:
```
  5 class AAA_SVR_DOWN_AUTHD_HOST ...                  (unchanged)
  10 class AAA_SVR_DOWN_UNAUTHD_HOST ...               (enforce, unchanged)
  20 class DOT1X_NO_RESP do-until-failure
   10 terminate dot1x
   20 authenticate using mab priority 20
  30 class MAB_FAILED do-until-failure
   10 terminate mab
   20 activate service-template EASYEAP_NO_8021X        (enforce + unknown devices → VLAN)
   30 authorize
   — or — 20 authentication-restart 300                 (block)
  40 class always do-until-failure
   10 terminate dot1x
   20 terminate mab
   30 authentication-restart 300
 event agent-found match-all
  10 class always do-until-failure
   10 terminate mab
   20 authenticate using dot1x priority 10
```
A device that answers 802.1X and fails never reaches MAB (class 40). Ports add `mab` and `dot1x max-reauth-req 2` (MAB ≈
30 s after link-up with `tx-period 10`; to be measured on hardware).

### 6.3 Cisco classic

`authentication order dot1x mab`, `authentication priority dot1x mab`, `mab`, `dot1x max-reauth-req 2`,
`authentication timer restart 300`. `authentication event fail` is not configured (an 802.1X failure must not move to
MAB; hardware check listed). Unknown devices: block, or the existing `authentication event no-response action authorize
vlan` as the unknown-device VLAN (the same choice as IBNS 2.0). The "turn on" change states that line explicitly.

### 6.4 UniFi

Guide: a port profile with 802.1X Control **MAC Address** for ports with devices that can't do 802.1X (it also accepts
802.1X), Credentials/Multiple Credentials elsewhere; RADIUS profile with "RADIUS assigned VLAN" for wired; MACs sent as
`AABBCCDDEEFF`. Not verified on hardware: request attributes, CoA.

### 6.5 Turning MAB on, and enforcing with it

- "Turn on MAC authentication" produces the change (§6.1 swap), shown once RADIUS runs the new client attribute **and** the
  agent reports the `mab` feature.
- On an enforced switch, turning MAB on is allowed only after MAB requests from that switch were answered while it was in
  monitor mode; otherwise the console says to go back to monitor mode first. Enforce on a switch with MAB on requires at
  least one answered MAB request from that switch in the last 14 days (409, field `mab`, otherwise). This prevents a
  switch that sends MAB without Message-Authenticator from marking EasyEAP dead for every 802.1X device on it.
  *As built:* MAB is turned on or off only in monitor mode (409 while enforcing), so the first rule reduces to "go back to
  monitor mode first".
- Readiness adds, per port: MAB accepts, unknown MACs ("would get the unknown-device VLAN" / "would lose access"), and MAB
  health.

## 7. Console

- **MAC allow list** (new screen under Configure; `mac:read`/`mac:write`, held by the roles that hold `radius:*`):
  - Devices: MAC (`AA:BB:CC:DD:EE:FF`), name, group, effective switch VLAN, last seen (switch · port · when), status.
    Search any MAC format or name; filters: group, status, "not seen in 90 days". Export CSV.
  - **Seen, not allowed** (from sightings): MAC, switch, port, first/last seen, attempts. **Allow…** prefilled; multi-select
    → **Allow in group…**. MACs seen in certificate (EAP-TLS) accepts, or matching an enrolled device's last-seen MAC, are
    flagged "This device uses a certificate" and need an explicit confirmation; locally administered (randomised) MACs are
    flagged.
  - Groups: name, VLAN (required: a VLAN from Access policy, or explicitly "port's own VLAN"), device count, enabled; a
    warning when the VLAN is also assigned to certificate users.
  - Add (MAC, name, group, expiry, notes); bulk import of `MAC[,name[,group]]` lines with per-line errors.
  - Device sheet: details, recent authentications, "answered 802.1X and failed, so MAB wasn't tried" when EAP rejects come
    from this MAC, edit, block/unblock (the dialog says that with "unknown devices → VLAN" a blocked device lands in that
    VLAN), delete.
- Switch wizard and panel: "MAC authentication" option with the restricted-VLAN warning, MAB health, readiness additions,
  the turn-on change. The switch guide no longer says printers can't be supported.
- Authentication log: method chip (Certificate / MAC), device name, filter; explanations for the new codes.
- Search and command palette: MAC allow-list entries ("MAC" type, distinct from enrolled devices).
- Audit: `mac_device.*`, `device_group.*`, `mac_device.imported`.

## 8. Security

MAB is an allow-list, not a credential: off by default per switch; restricted VLANs pushed; an 802.1X failure never
falls back to MAB; certificate devices' MACs flagged before they're allowed; EAP-MD5 only in `eapmd5_<t>` for UniFi MAC
identities on MAB switches; Cisco PAP MAB only with Call-Check, Ethernet and matching Calling-Station-Id;
Message-Authenticator stays required (requests without it are dropped, and Enforce waits for an answered MAB request);
unknown MACs only logged (coalesced).

## 9. Testing

Unit: MAC parsing; models/validation; snapshot MAC part and versions; agent `authz_mac`/`meta_mac`; render (detection per
client mode, positive wired evidence, mismatch, password, md5 routing, monitor, VLAN only on accept); policy-map naming and
swap (including today's re-Enforce); IBNS 2.0 and classic with `mab`; ingest (mac column, sightings, coalescing);
CoA targets by MAC. RADIUS integration (real FreeRADIUS): Cisco-style PAP MAB accepted with the group VLAN; unknown,
blocked, expired (by time, same version), group disabled; switch without MAB → `mab_not_enabled`; MAC-identity certificate
on Wi-Fi and on a non-MAB switch still authenticates; Call-Check from a Wi-Fi client refused; mismatch; wrong password;
monitor withholds VLAN; UniFi-mode EAP-MD5 accepted (eapol_test), EAP-MD5 with a user identity refused; no
Message-Authenticator dropped (no answer). E2E: learn in monitor mode → approve → accepted with VLAN → block → rejected;
skew with the wired-era agent. Frontend unit tests and console smoke.

## 10. Critique and revisions

| Finding | Severity | Change |
|---|---|---|
| Turning MAB on re-pastes an attached policy-map; IOS merges, leaving `30 authorize` (fail open). Same latent bug in today's re-Enforce | blocker | Content-hashed policy names and a swap on every change; old map removed (§6.1). Fixes re-Enforce too. |
| A switch that sends MAB without Message-Authenticator gets EasyEAP marked dead (all 802.1X affected); the drop is silent | blocker | MAB changes only in monitor mode, and Enforce with MAB needs an answered MAB request (§6.5). (Counting drops was dropped: FreeRADIUS doesn't log them, §5.2.) |
| EAP with a MAC-shaped identity treated as MAB everywhere: regression for MAC-named certificates; 802.1X EAP-MD5 on Cisco | major | MAB only on clients with MAB and wired evidence; Cisco PAP only; EAP-MD5 only for UniFi (§5.1). |
| UniFi's Calling-Station-Id may be bogus → every request `mab_mismatch` | major | Mismatch check for Cisco only; everything keyed on the normalised User-Name. |
| Expiry computed at serve time, never re-versioned | major | `expires_at` in `authz_mac`, checked in the lookup. |
| Block doesn't block with "unknown → VLAN"; approved devices stay in that VLAN | major | Stated in the Block dialog; reauthenticate CoA on approve/unblock (§5.3). |
| CoA can't find MAB sessions (format mismatch); group move strands DHCP | major | Normalised `mac` columns; reauthenticate / bounce-host-port CoA. |
| The real bypass is a certificate device's MAC on the list | major | Flag and confirm such MACs in Seen and Add (§7). |
| Unknown MACs flood `auth_events` | major | Sightings table, hourly coalescing, classic restart 300. |
| Last-seen updates would re-version the snapshot | major | Last-seen not versioned; only admin edits bump `mac_version`. |
| Config-in-sync doesn't prove the renderer supports MAB | major | Agent reports features; console gates on `mab`. |
| Classic enforced `no-response` VLAN contradicts "blocked" | major | Offered as classic's unknown-device VLAN; stated explicitly in the change. |
| Default group VLAN = the port's (user) VLAN | minor | VLAN required; port VLAN only as an explicit choice; effective VLAN shown; RESTRICT. |
| `retries 2 retry-time 0` changes 802.1X; class 25 redundant; class 40 lacks `terminate mab` | minor | Session-started unchanged; class 25 dropped; `terminate mab` added. |
| A listed device that tries 802.1X and fails is locked out silently | minor | Shown on the device sheet. |
| FreeRADIUS details (VLAN on challenges, REJECT section, SQL from User-Name, anchoring, logging, PAP mismatch, wired evidence) | minor | All adopted (§5.1, §5.2). |
| MAC entries resent on every certificate recompute; table cleanup; NULL method | minor | Separate `mac_version`; cleanup; NULL = certificate. |
| UX: name clash with enrolled Devices, stale guide text, readiness, import/export, randomised MACs | minor | "MAC allow list"; guide updated; readiness extended; per-line group, CSV export; randomised flag. |

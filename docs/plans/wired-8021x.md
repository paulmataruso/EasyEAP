# Plan: wired 802.1X (switch ports), Cisco- and UniFi-first

Requested 2026-11-07: add wired 802.1X to EasyEAP, driven by a simple wizard in the same way as the wireless
workflow, centred on Cisco and UniFi. A first draft was critiqued by two independent reviewers (a network-access
engineer and a product/architecture reviewer) before it was built. This document is the revised plan; §10 lists
what the critique found and what changed because of it.

## 1. What exists today

1. **RADIUS settings** (`radius_settings`): server hostname and certificate, SSID, WPA3, ports, TLS, session timeout.
2. **Controllers** (`radius_clients`): name, vendor (`cisco-9800`, `cisco-aireos`, `unifi`, `other`), source address or
   CIDR, site, CoA. *Add controller* generates the shared secret, shows it once, and shows the vendor guide filled
   with it (`app/radius/guides.py` → `GET /radius/guide/{vendor}` → `GuideBody`).
3. **FreeRADIUS** (`services/radius/agent/render.py`): each client is bound to its tenant's virtual server; EAP-TLS
   only; one indexed lookup of the certificate serial in the local SQLite snapshot (`authz`).
4. **Policy**: one decision per certificate (`decisions`), published as the snapshot.
5. **Events**: linelog JSON → agent → `auth_events` / `accounting_sessions`.
6. **Enrollment**: one certificate per device; packages carry Wi-Fi profiles.

Nothing distinguishes a switch from a wireless controller. A Catalyst switch registered as "Cisco Catalyst 9800"
(the only option that says Catalyst) authenticates today with the Wi-Fi decision and VLAN.

## 2. Goals and non-goals

**Goals**
- Register switches and get a configuration that is **safe to paste**: Cisco Catalyst IOS-XE (IBNS 2.0) and Cisco IOS
  / IOS-XE classic (2960-X, 3650, 3850), and UniFi switches. "Other" gets generic steps.
- A wizard the same shape as *Add controller*: switch → ports → secret and configuration → first request.
- **Safe rollout**: monitor mode first, really passive; enforce only after looking at switch-side evidence.
- Wired ports may get a different VLAN from Wi-Fi, or keep their own.
- The same device certificate works on both. Enrollment packages can add wired settings (macOS, Linux); IT gets a
  Windows wired kit.
- The authentication log says which network and which switch port.
- Upgrading changes nothing for existing customers, including RADIUS with the API down and agent/API version skew.

**Non-goals (phase 2, §9)**: MAB, IP-phone voice domain, Windows machine certificates (pre-logon wired), network-scoped
rules (Wi-Fi-only or wired-only *access*), wired-only tenants (no SSID), downloadable ACLs, dead-server probes.

## 3. Data model (migration `0004_wired`)

| Change | Why |
|---|---|
| `radius_clients.networks text[]` — **every existing client gets `{wireless,wired}`** | Nothing that works today stops. New registrations default by type (controllers Wi-Fi, switches wired, UniFi both); editable. |
| `radius_clients.vendor` gains `cisco-switch` | Catalyst / IOS switches. |
| `radius_clients.wired_profile jsonb` | The port plan from the wizard, rollout mode, who set it and when. No secrets. |
| `radius_settings.wired_enabled boolean` | Whether enrollment packages include wired settings. A separate switch: adding a test switch doesn't change what every new device gets. |
| `vlans.wired_mode` (`same` default \| `port` \| `vlan`), `vlans.wired_vlan_id` | What a wired port gets when a rule assigns this VLAN: the same VLAN ID, the port's own VLAN, or a different one. The default is `same`: an upgrade must not change what a switch already registered as "Other" receives, and monitor mode already withholds VLANs from new switches, so nothing moves before Enforce. The Enforce dialog and the guide's checks list the VLANs that must exist on the switch. |
| `decisions.wired_vlan_id` | The decision's VLAN on wired ports, resolved from the VLAN's mapping (null = don't assign). One decision per certificate, so every reader, count, preview and revision fingerprint is unchanged. |
| `auth_events.network`, `.nas_port_id`, `.monitor`; `accounting_sessions.network`, `.nas_port_id` | Log and filter by network; show the switch port; mark VLANs withheld in monitor mode. |

## 4. Policy

Unchanged precedence and one decision per certificate. The decision gains `wired_vlan_id`; the snapshot entry gains
`wired_vlan` (`null` = assign none). The console shows "VLAN 20 · on switch ports: the port's own VLAN" (or "VLAN 120")
wherever it shows a VLAN, and the VLAN editor has the mapping. Rules that *allow on Wi-Fi but not on wired* are phase
2; the per-client network registration already stops a device from authenticating on a network a switch or
controller isn't registered for.

## 5. RADIUS

### 5.1 Which network a request came from

Set as `control:EasyEAP-Network` in the tenant server's `authorize` and `preacct`:

1. `Called-Station-Id` of the form `MAC:` (empty SSID): **wired**. That's what hostapd's wired authenticator sends,
   and hostapd also hard-codes `NAS-Port-Type = Wireless-802.11`, so this rule has to come first.
2. `NAS-Port-Type == Ethernet` → wired; `== Wireless-802.11` → Wi-Fi.
3. Otherwise the client's networks, if it has exactly one (`%{client:easyeap_networks}`, a custom client item).
4. Otherwise Wi-Fi when `Called-Station-Id` names an SSID (`MAC:SSID`), else wired.

If the network isn't one the client is registered for, reject as **`network_not_enabled`**. A `Service-Type =
Call-Check` request (a switch trying MAC Authentication Bypass) is rejected as **`mab_unsupported`**. Nested
registrations are allowed within a tenant (FreeRADIUS picks the longest prefix), and EasyEAP attributes events by
longest prefix too, so a `/32` switch can sit inside a UniFi `/24`.

### 5.2 Lookup and version skew

`authz` is untouched. Wired VLANs go into a new table, `authz_wired (tenant, serial, vlan)`, where `vlan = ''` means
assign none. The check server picks the Wi-Fi VLAN from `authz`, or for wired
`COALESCE((SELECT vlan FROM authz_wired …), <the Wi-Fi VLAN>)`. Every combination degrades to today's behaviour, never
to another decision:

| Agent | API / config | Result |
|---|---|---|
| new | new | wired VLAN per mapping |
| new | old API (no `wired_vlan` in entries) | no `authz_wired` rows → Wi-Fi VLAN on wired (today) |
| new agent, old config still running (new config rejected) | new | old config ignores `authz_wired` → today |
| old (rollback) | new | old agent ignores unknown keys and the new table → today |

### 5.3 Monitor mode is passive

A switch in monitor mode is rendered with `easyeap_monitor = "yes"`. For its wired requests the check server still
decides (and logs the VLAN it *would* assign, with `monitor = true`) but sends no Tunnel or extra attributes: an
Accept leaves the port on its own VLAN. The monitor configuration has no no-supplicant or critical VLAN actions;
those come with Enforce.

### 5.4 Cisco configuration (generated)

**Preflight** (shown before the configuration, with what to look for): `show run | include aaa new-model`,
`show run | include port-control|policy-map type control|access-session` (stop if 802.1X already exists),
`show interfaces trunk`, `show cdp neighbors` / `show lldp neighbors` (uplinks and APs), `show users` and
`show mac address-table address <your-mac>` (don't enforce your own port).

**Safe paste**: `reload in 15` → paste → open a *new* SSH session → `reload cancel` → `write memory`.

**Global**
- `aaa new-model` only if the switch doesn't use AAA yet, then `aaa authentication login default local` with a
  reminder to have a local user. Existing login and exec lists are never touched.
- `radius server EASYEAP-<SLUG>` (address, ports, key, timeout 5, retransmit 2);
  `aaa group server radius EASYEAP` (`server name`, `deadtime 3`, `ip radius source-interface` and `ip vrf forwarding`
  inside the group, so other RADIUS traffic keeps its source).
- `aaa authentication dot1x default group EASYEAP`, `aaa authorization network default group EASYEAP`,
  accounting `identity` (IBNS 2.0) or `dot1x` (classic) `default start-stop group EASYEAP`.
- `aaa server radius dynamic-author` with `client <radius-ip> [vrf …] server-key …` (CoA, UDP 1700).
- `radius-server dead-criteria time 5 tries 3`, `radius-server attribute 31 mac format ietf upper-case`,
  `radius-server vsa send authentication|accounting`, `dot1x system-auth-control`, `dot1x critical eapol` (when
  critical access is used). No `automate-tester`: EasyEAP drops requests without Message-Authenticator, so a probe
  might never be answered and the server would stay dead.

**IBNS 2.0 control policy** `EASYEAP_DOT1X`: session-started → dot1x; authentication-failure →
`AAA_SVR_DOWN_UNAUTHD_HOST` (critical service template + authorize, or nothing, per choice),
`AAA_SVR_DOWN_AUTHD_HOST` (always: pause reauthentication, authorize — connected devices keep working through a VPN
blip), `DOT1X_NO_RESP` (no-supplicant VLAN, enforce only), otherwise terminate and restart after 300 s;
agent-found → dot1x; aaa-available → clear critical sessions / resume reauthentication; inactivity → clear; violation
→ restrict.

**Interfaces**: `switchport mode access`, `[switchport access vlan]`, host mode, `access-session port-control auto`,
`[access-session closed]`, `authentication periodic`, `authentication timer reauthenticate server`, `dot1x pae
authenticator`, `dot1x timeout tx-period 10`, `spanning-tree portfast`, `spanning-tree bpduguard enable`, the service
policy. Classic: the `authentication` equivalents, `authentication violation restrict`, `authentication open` in
monitor, `authentication event server dead action authorize [vlan]` + `server alive action reinitialize`,
`authentication event no-response action authorize vlan` (enforce only).

**Validation**: interface ranges must name physical ports (no `Port-channel`, `Vlan`, `Gi0/0`, `AppGigabitEthernet`,
`Loopback`, `Tunnel`), at most five ranges per `interface range` line, and must not overlap the ports listed as
"leave alone" (uplinks, APs, printers, phones). Every string that reaches the configuration is validated.

**Defaults**: multi-auth, monitor first, devices without 802.1X stay blocked (when enforced), and when EasyEAP is
unreachable new devices wait while connected devices keep working. Critical access ("open on the port's VLAN" or
"VLAN N") is a choice, explained.

### 5.5 UniFi

UniFi switches have no monitor mode. The guide uses the Wi-Fi RADIUS profile with *RADIUS assigned VLAN* for wired,
Global Switch Settings → 802.1X Control, and per-port 802.1X Control = Auto on one test port first. Fallback VLAN
catches rejected devices too, so it must be a restricted network. It registers the switches' management addresses
(each switch sends from its own), and "Turn on wired for <UniFi registration>" is offered only when that range is a
range, not a single gateway address. CoA, re-authentication and NAS-Port-Type behaviour are unverified on hardware; the
console says so.

## 6. Wizard and console

### 6.1 *Add switch* (dialog, mirrors *Add controller*)

1. **Switch**: platform (Cisco Catalyst IOS / IOS-XE, UniFi, Other, with a note that Catalyst 1200/1300, Cisco
   Business and Meraki MS use other configuration), name, source address, site, CoA. UniFi: "Turn on wired for
   <existing UniFi registration>" when one exists.
2. **Ports** (Cisco): access ports (required), ports to leave alone, configuration style, "already uses AAA?". The rest
   (host mode, devices without 802.1X, RADIUS unreachable, access VLAN, source interface, VRF) shows its defaults with
   **Change**. Says plainly that IP-phone ports aren't supported yet. UniFi: fallback VLAN.
3. **Configure**: preflight, the one-time secret and the configuration filled with it, the safe-paste steps.
   "Waiting for the first request" turns into the first result, and explains the two silent failures (requests from
   an unregistered address, a wrong secret) from FreeRADIUS's own log lines.

### 6.2 Enforce and back

A monitor-mode switch shows "Monitor mode · set in EasyEAP on <date> by <who>" (EasyEAP can't read the switch) and
**Enforce**. The dialog shows the last 24 hours from that switch by port, asks the admin to paste
`show access-session` (classic: `show authentication sessions`) and lists every session that isn't authorized, by
port and MAC (these lose access), then the exact change: `access-session closed` (classic `no authentication open`),
the no-supplicant and critical actions, and `clear access-session interface …` so withheld VLANs apply. *Back to
monitor* is the reverse. A switch left in monitor mode for 14 days becomes a needs-action item.

### 6.3 Elsewhere

- RADIUS page: one **Controllers and switches** table with a *Serves* column (Wi-Fi · Wired), an Add menu (wireless
  controller / switch), and guides for switches.
- RADIUS settings: "Include wired settings in enrollment packages", with the note that earlier enrollments don't have
  them (Windows and Linux can use the IT kit; Macs need a new link).
- Access policy: each VLAN's *On switch ports* mapping; wired VLAN shown next to the Wi-Fi VLAN where relevant.
- Tenant setup → RADIUS step: "Switches (optional)". Command palette: *Add switch*. Intent `?add=switch`.
- Authentication log: Network, switch port, "VLAN withheld (monitor mode)", filter by network.
- Explanations: `network_not_enabled`, `mab_unsupported`.

## 7. Enrollment

- **Windows: IT-deployed.** End users can't approve the elevation that wired needs (Wired AutoConfig and
  `netsh lan`). The console offers a **Windows wired kit** per tenant: the LAN profile (EAP-TLS, server name and root
  pinned, `OneXEnforced=false`) and an install script for an admin, Intune or an RMM, plus the Group Policy
  equivalent. It reuses each user's existing certificate. The kit warns that with user certificates there's no
  network at the sign-in screen, so domain-joined PCs need cached credentials (machine certificates are phase 2).
- **macOS**: when wired is included, the profile adds `com.apple.globalethernet.managed` with the same identity and
  trust. Only for macOS links.
- **Linux**: NetworkManager `type=ethernet` with `802-1x.optional=yes`, and a wpa_supplicant wired block.
- iOS, Android: unchanged.

## 8. Testing

1. **Unit**: VLAN mapping and decisions; snapshot `wired_vlan`; render (detection order, gate, monitor stripping,
   wired lookup); guides (style × mode × options), validation (injection, forbidden interfaces, overlaps, more than
   five ranges); readiness parsing of `show access-session` output; profiles (LAN XML, mobileconfig, NM); events.
2. **RADIUS integration** (`tests/radius/run.sh`): real FreeRADIUS 3.2.10 and EAP-TLS: detection paths including the
   hostapd form, VLAN per network, port VLAN kept, monitor withholding, gate, MAB, events, and the skew matrix of
   §5.2.
3. **End-to-end** (`tests/e2e/run.sh`): wired scenarios through the full lab stack.
4. **Upgrade**: a 1.0.1 lab provisioned with data, upgraded to this build: migration, RLS, the e2e suite.
5. **Frontend**: typecheck, lint, unit tests, production build, console smoke test with the wizard.

Results (2026-11-07): backend 138 unit and 35 integration tests; frontend 65 unit tests, typecheck, lint, build;
`tests/radius/run.sh` 35/35; `tests/e2e/run.sh` 48/48 on this build; upgrade from a fresh 1.0.1 lab provisioned
by the 1.0.1 suite (13/13 there), with the same database (migration, controllers serve both networks, VLANs "same", decisions keep their VLAN, Wi-Fi and
wired authentication unchanged) 9/9; console smoke test 28/28, including the wizard, Enforce and the log.

What can't be tested here and is said so in PROGRESS.md: the generated IOS configuration on a physical Catalyst,
UniFi switch behaviour, Windows `netsh lan` import, macOS Ethernet payload install.

## 9. Phase 2

MAB with an allow-list on restricted VLANs (confirm Message-Authenticator on target IOS-XE releases first); voice
domain; Windows machine certificates (LocalMachine store, `machineOrUser`); network-scoped rules; wired-only tenants;
dead-server probes with a tagged probe user; per-port batches for Enforce.

## 10. Critique and revisions

| Finding | Severity | Change |
|---|---|---|
| Decisions per network: every reader breaks, counts double, the preview multiplies, and admins must duplicate every rule when wired VLANs differ | major | One decision per certificate; VLANs carry a wired mapping (§3, §4). Network-scoped rules moved to phase 2. |
| In-place `authz` migration can serve the wired decision to Wi-Fi (old config + new rows sort `wired` first), and an old agent chokes on duplicate serials | blocker | `authz` untouched; wired VLANs in `authz_wired`; every skew combination degrades to today (§5.2). |
| Monitor mode isn't passive: Accepts move VLANs; no-response and critical actions move printers and APs | blocker | VLANs withheld for monitor-mode switches; fallback actions only on Enforce; the Enforce dialog lists the VLANs ports will be moved to, and any VLAN can be set to keep the port's own (§5.3, §3). |
| Monitor mode can't see devices that never speak 802.1X, so Enforce looks clean exactly when it would cut most ports | blocker | Enforce works from pasted `show access-session` output plus the log by port (§6.2). MAB-for-visibility rejected: if a release omits Message-Authenticator, dropped requests mark EasyEAP dead. |
| Pasting can lock the admin out (`aaa new-model`), convert legacy 802.1X one way, or turn an uplink into an access port | blocker | Preflight, AAA guard, style guidance, forbidden and "leave alone" interfaces with overlap checks, `reload in 15` (§5.4). |
| Migrating 9800/AireOS clients to Wi-Fi only blacks out switches registered as "9800", EWC and Remote-LAN | blocker | Every existing client gets both networks (§3). |
| Dead-server handling: hosts re-authenticating during a VPN blip are dropped; `dead-criteria` without `deadtime` never marks dead | blocker | Always `AAA_SVR_DOWN_AUTHD_HOST`, `deadtime 3`, `dot1x critical eapol`; critical access offered and explained. New devices wait by default (fail securely). |
| hostapd sends `NAS-Port-Type = Wireless-802.11` even for wired | major | Empty-SSID `Called-Station-Id` rule first (§5.1); real captures listed as untested. |
| Overlapping ranges refused within a tenant; first-match attribution | major | Nested ranges allowed; longest-prefix attribution (§5.1). |
| Two panels with UniFi in both: Delete on a "switch" row kills Wi-Fi | major | One table with a Serves column (§6.3). |
| Seven Cisco choices in step 2 | major | Required fields only; defaults behind Change (§6.1). |
| Windows wired needs elevation end users can't give | major | IT-deployed kit; user-certificate pre-logon limitation stated (§7). |
| Adding a test switch would change every later package | major | Separate "include wired settings" switch (§3). |
| Wired-only tenants touch ~45 portal strings | major | Cut to phase 2. |
| Classic `violation shutdown` err-disables docks and VMs | major | `violation restrict` / `event violation → restrict`. |
| Global `ip radius source-interface` re-sources existing RADIUS | major | Inside the server group; VRF option (§5.4). |
| Restart after reject every 60 s floods the log | minor | 300 s. |
| `PUT /clients` would wipe networks and the plan | minor | Omitted fields keep their values. |
| NetworkManager wired profile breaks on networks without 802.1X | minor | `802-1x.optional=yes`. |
| An empty network would be logged as `cert_unknown` | minor | Its own reason, `network_unknown`. |
| *Found in testing:* Enforce showed the closed-mode change at once, but RADIUS applies configuration on its next poll (up to ~15 s). Pasted in that window, `clear access-session` re-authenticates devices while VLANs are still withheld; they stay on the port's VLAN until the next re-authentication (hours) | major | The agent reports the change counter it runs per tenant; the API exposes `tenant_config_in_sync`; the Enforce dialog shows the change only once RADIUS runs it (20 s fallback for an older agent, a notice after 90 s, and a rejected configuration says don't paste). Found by the e2e suite, whose own wait had the same blind spot. |
| *Found in testing:* "Ports to leave alone" inside the access-port range was refused, though the preflight tells admins to put uplinks there | minor | Left-alone ports are subtracted from the ranges (`Gi1/0/1-48` leaving 48 alone configures `1 - 47`); refused only if nothing is left. |
| Kept despite the critique | — | Classic IOS stays in v1 (2960-X/3650/3850 are common in MSP estates); UniFi stays in v1 (the request is Cisco- and UniFi-centric) with its unverified points stated in the console; default-list AAA rather than named lists (more widely verified syntax, and the preflight stops when 802.1X already exists); fail-closed for new devices by default, per the product's "fail securely" principle, with connected devices protected. |

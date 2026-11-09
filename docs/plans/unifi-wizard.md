# Plan: set up a UniFi controller from EasyEAP (the UniFi wizard)

Status: **planned, not built.** Revision 2 (2026-11-08) follows the critique in §13; every change it made is listed
there. Building starts with the spike (§11), which needs a real UniFi console.

The user's request:

> Modern UniFi controllers have a full API to configure the controller. Let's set up a simple wizard that will
> configure their UniFi controller using that API for wireless and wired auth (either/or, they pick). If there are no
> wireless networks to pick from, we will create one (after prompting).

## 1. What exists today

- **The manual UniFi guide.** [docs/controllers/unifi.md](../controllers/unifi.md), the console's guide, and the UniFi
  branch of `app/radius/wired.py` list the steps the admin clicks through by hand:
  - a RADIUS profile, with the RADIUS-assigned VLAN turned on;
  - the SSID set to WPA2/WPA3-Enterprise with that profile;
  - for wired, 802.1X Control in Global Switch Settings with a fallback VLAN, then one test port on Auto.
- **A UniFi registration is an ordinary RADIUS client.** It is a `radius_clients` row with `vendor = "unifi"` and:
  - `networks` set to wireless and/or wired;
  - an address or CIDR;
  - the shared secret, encrypted with the tenant's Transit key;
  - CoA off;
  - the wired plan in `wired_profile`. Monitor mode on UniFi means a fallback VLAN set to the ports' current VLAN.
- **Address rules** (`check_address_unique`, `radius/state.py`). An address must not overlap another tenant's on
  the same RADIUS ports. Within a tenant, the longest prefix wins.
- **Enrollment follows the tenant's settings.** Enrollment packages are built from `radius_settings.ssid` and
  `wpa3` (`routers/enrollments.py`). Windows profiles say `WPA3ENT` when `wpa3` is on, `WPA2` otherwise
  (`enrollment/profiles.py`). The network the wizard sets up must therefore match those settings (§4.4).
- **How a change reaches FreeRADIUS.** The agent fetches configuration about every 15 s. `config_sync()` reports
  whether FreeRADIUS runs the tenant's latest change (`tenant_config_in_sync`).
- **Checking a new registration.** `FirstRequest` watches for its first request. `unattributed()`, readiness and the
  silent-failure diagnosis show requests from addresses EasyEAP doesn't know.
- **Network reach.** The API container is on `egress`, so it can reach a controller on a customer network over the
  site-to-site VPN that RADIUS already needs. It is also on the internal `app`, `data`, `pki` and `radius` networks,
  which is why addresses typed by admins need a guard (§7.3).
- **Request timeout.** nginx cuts `/api/` requests at 120 s (`deploy/proxy/proxy-params.conf`).

## 2. What UniFi offers (vendor facts)

Research passes on 2026-11-08 read three kinds of source:

- **Ubiquiti's published OpenAPI files** for every version of the official API (9.1.120–11.0.97), and the Site
  Manager API file.
- **The controller's own field definitions.** These are the `api/fields/*.json` files shipped in the Network
  application, as go-unifi extracted them for 9.5.21 and 10.6.109.
- **Libraries that drive UniFi controllers in production:** go-unifi (ubiquiti-community and filipowm) and their
  Terraform providers, Art of WiFi's PHP client, aiounifi (Home Assistant) and unpoller.

Sources are in §15. Items marked **(spike)** are unconfirmed and go to §11.

### 2.1 Three ways in

| | Official "UniFi Network API" | Classic internal API | Site Manager cloud connector |
|---|---|---|---|
| Base | `https://<console>/proxy/network/integration/v1/…` | `https://<console>/proxy/network/api/s/{site}/…` and `…/v2/api/site/{site}/…` | `https://api.ui.com/v1/connector/consoles/{id}/…`, forwarded to the console's `/proxy/…` |
| Documented | yes, versioned OpenAPI | no; fields come from the controller's definitions | yes |
| Since | Network 9.0.108 (API keys too); UniFi OS 4.1.9 | stable for these objects since 6.x | console firmware 5.0.3 |
| Auth | local API key, `X-API-KEY` | the same local key on UniFi OS (go-unifi, Terraform provider and unpoller do this; Ubiquiti doesn't document it), or a local admin login | Site Manager API key (unifi.ui.com) |
| Limits | none documented | login throttled (429) | 100 requests/min per console, 25 s timeout |

- **Connector paths.** The connector forwards GET, POST, PUT, PATCH and DELETE. The Site Manager and Network specs
  write the forwarded path differently (with and without `/proxy`) **(spike S0)**. Site Manager's getting-started page
  still says its key "is currently read-only" **(spike S0)**.
- **Self-hosted Network Application (`:8443`).** It has no API keys, and Network 11.0.97 removed it ("Upgrade to
  UniFi OS Server"). UniFi OS Server is UniFi OS, so it has the same paths and keys, on port 11443.

**The official API, for this feature (11.0.97, 73 operations):**
- `GET /v1/info` returns `applicationVersion`.
- `GET /v1/sites` returns `id` (UUID), `name`, and `internalReference`, the classic site name such as `default`.
- Devices are listed with their ports (`idx`, `state`, `connector`, PoE). It has no port configuration.
- **Wi-Fi networks** (`/v1/sites/{siteId}/wifi/broadcasts`, from 10.0.162):
  - full create, read, update and delete;
  - security types include `WPA2_ENTERPRISE`, `WPA3_ENTERPRISE` and `WPA2_WPA3_ENTERPRISE`;
  - `radiusConfiguration {profileId, nasId}`;
  - update is a **PUT of the whole object**, and its required fields grew from 11 (10.0.162) to 12 (10.1.68,
    `advertiseDeviceName`) to 14 (10.4.57, `channel2gLockedTo6` and `dtimPeriod2gLockedTo3`).
- **RADIUS profiles: list only** (`id`, `name`, `metadata`). No servers, secrets, create or update.
- **802.1X: nothing.** No port profile, port 802.1X or global switch setting.

**The classic API does all of it.** Field names are from the controller's definitions:

- **RADIUS profile** (`rest/radiusprofile`):
  - `name`, `auth_servers[{ip, port, x_secret}]`, `acct_servers[…]`, `accounting_enabled`;
  - `interim_update_*`, `use_usg_auth_server`/`use_usg_acct_server`;
  - **`vlan_enabled`** (RADIUS-assigned VLAN for wired);
  - **`vlan_wlan_mode`** (`disabled|optional|required`, for Wi-Fi);
  - RadSec fields since 8.x.

  `ip` must be a **dotted IPv4 literal**. `x_secret` comes back **in plain text** on a GET.
- **Wi-Fi network** (`rest/wlanconf`):
  - `security` (`open|wpapsk|wep|wpaeap|osen`), `wpa_mode` (`auto|wpa1|wpa2`), `wpa_enc`;
  - `wpa3_support`, `wpa3_transition`, `wpa3_enhanced_192`, `wpa3_fast_roaming`, `pmf_mode`;
  - `radiusprofile_id`, `radius_mac_auth_enabled`, `radius_das_enabled`, `fast_roaming_enabled`;
  - `networkconf_id`, `ap_group_ids[]`, `ap_group_mode` (`all|groups|devices`), `usergroup_id`;
  - `wlan_band` (`2g|5g|both`) with `wlan_bands[]` (`2g|5g|6g`);
  - `is_guest`, `hotspot2conf_enabled`, `x_passphrase`, `enabled`, `name` (1–32), `hide_ssid`.

  It also holds secrets **not** named `x_*`: `private_preshared_keys[].password` and `sae_psk[].psk`.
- **Site switch setting** (`get/setting/global_switch`, written with `PUT set/setting/global_switch`, whose body
  carries `key: "global_switch"`):
  - `dot1x_portctrl_enabled`, `radiusprofile_id`, `dot1x_fallback_networkconf_id`;
  - `switch_exclusions[]` (switch MACs);
  - other site settings (`dhcp_snoop`, `jumboframe_enabled`, `stp_version`, …) that a full write would reset.
- **Per switch** (`rest/device/{_id}`):
  - its own `dot1x_portctrl_enabled`, `radiusprofile_id` and `dot1x_fallback_networkconf_id` **(spike S6: which
    wins)**;
  - `setting_preference` (`auto|manual`);
  - `port_overrides[{port_idx, portconf_id, dot1x_ctrl, dot1x_idle_timeout, native_networkconf_id, op_mode,
    aggregated_by, …}]`, with `dot1x_ctrl` one of `auto|force_authorized|force_unauthorized|mac_based|multi_host`.

  Stacked switches number their members with `unit_id`. Gateways refuse `op_mode` in `port_overrides`.

  It also holds secrets not named `x_*`: `lte_password`, `nut_server.password`, `mbb_overrides.sim[].current_apn.password`.
- **Reading state:**
  - `stat/device`: `ip` and `type` (`uap`/`usw`/`ugw`/`udm`/`uck`…); each switch's `port_table[]` (`port_idx`,
    `is_uplink`, `portconf_id`, `dot1x_mode`, `dot1x_status`, `lldp_table[]`, `op_mode`); each access point's
    `uplink.uplink_mac` and `uplink_remote_port`; the gateway's `wan1` and `last_wan_ip`.
  - `stat/sta`: clients, with `essid`, `is_wired`, `sw_mac` and `sw_port`. It includes every client's MAC address
    and hostname, which **never** leave the server.
  - `rest/networkconf`: networks and VLANs. It contains secrets too (for example `wireguard_client_preshared_key`).
  - `v2/api/site/{site}/apgroups`: the default group has `attr_hidden_id == "default"`.
  - `rest/usergroup`: the default group is named `Default`.
  - `api/s/{site}/self`: the caller's `site_role`, which tells an admin key from a read-only one.
- **Write semantics.** A PUT is merged **one top-level key at a time**; nested objects and lists are replaced whole.
  Related keys are validated together, so they're sent as groups:
  - {`wpa_mode`, `wpa_enc`}
  - {`wpa3_support`, `wpa3_transition`, `wpa3_fast_roaming`, `wpa3_enhanced_192`}
  - {`radiusprofile_id`, `radius_mac_auth_enabled`}
  - {`ap_group_mode`, `ap_group_ids`}
  - {`wlan_band`, `wlan_bands`}

  Known traps:
  - `port_overrides` is replaced whole. A Terraform user lost four of five overrides.
  - `null` there is refused on gateways.
  - `wlangroup_id: ""` is refused (the field was removed in 6.x).
  - `ap_group_ids` is required to create a network.
- **Login (not used in v1).** UniFi OS uses `POST /api/auth/login`, then the `TOKEN` cookie plus `X-CSRF-Token`. It's
  throttled for about 45 s on a UDM-Pro. MFA and UI.com accounts can't use it, and consoles in a UniFi Fabric have no
  local login at all.

### 2.2 Versions that matter

| Network version | What changed for us |
|---|---|
| 8.x | `ap_group_mode`, RadSec fields, PPSK |
| 9.0.108 | Official API and API keys. API-key clients of the classic API require 9.0.114 or later (filipowm/go-unifi v2) |
| 9.5.21 | "Ethernet Port Profiles"; profiles moved in the UI; endpoints unchanged |
| 10.0.162 | Official Wi-Fi networks, RADIUS profile list, networks |
| 10.x | RADIUS and port profiles moved under Settings → Networks in the UI; endpoints unchanged through 10.6.109 |
| 11.0.97 | Self-hosted Network Application removed |

The latest release is 11.0.99.

### 2.3 Limits worth knowing

- **SSIDs per band.** 4 while wireless meshing is on, 8 when it's off.
- **6 GHz needs WPA3 with PMF required.** A 6 GHz band can be silently dropped on create.
- **Re-provisioning.** Creating a network or changing its security re-provisions the access points: every SSID on
  them drops briefly. Turning on 802.1X for the site re-provisions every switch.
- **The Dream Router has no wired 802.1X.**
- **The fallback VLAN.** The existing guide relies on it taking rejected devices as well as those without 802.1X
  **(spike S5)**.
- **CoA.** `radius_das_enabled` exists on Wi-Fi networks only, nothing for switches. EasyEAP keeps CoA off for UniFi.

## 3. Decisions

1. **The classic API makes the changes.** The official API is used for the version (`/v1/info`) and the site list
   (`/v1/sites`).
   - *Why not the official Wi-Fi API.* It can't create RADIUS profiles or touch 802.1X, so the classic API is needed
     anyway. Using both would mean two id spaces joined by name, and updates that must PUT the whole network, whose
     required fields keep growing. A stale copy resets settings the admin chose.
   - *What the classic API costs.* It's undocumented. Its PUT merges only the keys sent, so a security change touches
     only the security keys. The objects used here haven't changed shape since 6.x, and field changes are tracked per
     version in go-unifi.
   - *How it's protected.* Every write is read back, and a field contract is checked per version (§9).
   - *Revisit when Ubiquiti adds writes for RADIUS profiles and 802.1X to the official API.* The client is written
     per object, so one object can move by itself.
2. **Two ways to connect, both with an API key, no username and password in v1.**
   - **Directly.** A local API key from the console (*Settings → Control Plane → Integrations*). The console must be
     reachable from EasyEAP, which is the normal case: RADIUS already needs the site-to-site VPN.
   - **Through UniFi's cloud** (the Site Manager connector). A Site Manager API key; the admin picks the console from
     its list. It works behind NAT and EasyEAP talks only to `api.ui.com`. **Enabled only once spike S0 confirms
     classic writes through it.**
   - *Why no login.* Local admin logins can't be used with MFA or Fabric, are throttled, and served mainly the
     self-hosted application, which UniFi has retired. The self-hosted application keeps the manual guide, or moves to
     UniFi OS Server.
3. **Supported controllers.**
   - UniFi OS consoles and UniFi OS Server, with **Network 9.0.114 or later**. Tested on 9.5, 10.x and 11.x.
   - Anything older, or a self-hosted application, gets a message naming what was found and the manual guide.
4. **Credentials are never stored.**
   - The browser holds the key for the life of the dialog and sends it with each wizard call over HTTPS. The server
     uses it for that call only.
   - Undo asks for it again.
   - A saved, encrypted connection is phase 5, with the UniFi switch audit, which needs one.
5. **Secrets stay on the server.**
   - EasyEAP writes the registration's shared secret into the UniFi RADIUS profile itself; the browser never sees it.
   - Everything returned to the browser or stored is built from an **allow-list** of fields, never by removing
     secrets from what UniFi sent.
   - Clients appear only as counts.
6. **Who may run it.** Admins with `radius:write` **and** `radius:secrets`: Tenant Administrator, MSP Operator,
   Super Administrator. A new `require_all()` dependency checks both. The wizard moves a shared secret, and the
   controller hands back other secrets on every read.
7. **The Wi-Fi network matches the tenant's settings.** Enrolled devices look for the tenant's SSID with its WPA
   mode.
   - **The name.** The network must have the tenant's SSID name. Picking or creating one with another name changes
     the tenant's SSID setting too. Review says so, and says how many Wi-Fi enrollments use the old name: those devices
     need a new profile.
   - **The security follows `wpa3`.** Off: WPA2-Enterprise. On: the UniFi mode that spike S4 shows Windows'
     `WPA3ENT` profiles join. Phase 2 waits for S4.
   - **Which networks are listed.** Enterprise, passphrase and open networks only. Guest, hotspot (Hotspot 2.0), PPSK
     and `osen` networks aren't listed.
   - **Creating one.** When none qualify, the step says so and offers to create one (after prompting, as asked).
     Creating a new network is also offered next to the list.
8. **EasyEAP uses its own RADIUS profile.**
   - The wizard creates **"EasyEAP"** and, on later runs, updates only that one (by its stored id).
   - It never changes a profile it didn't create.
   - A profile that already points at EasyEAP is reused, untouched, when its secret matches one of the tenant's
     registrations (compared on the server). That registration is then the one used.
9. **Wired, conservatively.**
   - The site's 802.1X setting is turned on with EasyEAP's profile and a fallback VLAN.
   - **One test port by default** (Auto, or MAC-Based for MAC authentication).
   - It starts in monitor mode, with the fallback VLAN equal to the test ports' current VLAN. Enforcing stays a
     separate step.
   - v1 offers only ports on UniFi switches (`usw`). It refuses: uplinks; trunks; LAG members; stacked switches;
     mirror ports; ports feeding a UniFi device; ports carrying the console, the gateway or EasyEAP's own path; and
     ports where more than one MAC address is seen.
   - It stops when the site already runs 802.1X with another profile, or a switch has its own 802.1X settings.
10. **Either or both.** The admin picks Wi-Fi, wired, or both in one run. Running it again adds the other or more
    ports, and changes only what differs.
11. **The registration's address follows the path.**
    - If UniFi reaches EasyEAP by routing (VPN), the proposal is the smallest range covering the access points' and
      chosen switches' addresses.
    - If it reaches EasyEAP across NAT, the proposal is the site's WAN address.
    - The admin confirms either way. After applying, a request from an unregistered address that looks like this
      site's is offered as a one-click fix (§4.8).
12. **Apply in two calls, with checks in between.**
    1. The registration first, then wait until FreeRADIUS runs it.
    2. Then the UniFi changes, in order, each read back, all put back if one fails.

    Undo restores the latest change per site. Before values hold only non-secret keys, so they're kept as plain JSON.

## 4. The wizard, step by step

**Where it starts.**
- **RADIUS → Add → UniFi (set up through the API).**
- Add controller with type UniFi offers "Let EasyEAP set it up".
- A UniFi registration's panel has **Set up through the UniFi API** (run again) and **Undo the last UniFi change**.

The dialog has step dots, like Add switch.

### 4.1 Connect

**Two tabs:**
- **Directly.** Controller address (`https://192.168.1.1`, `https://unifi.example.net`, or `https://host:11443` for
  UniFi OS Server) and the API key. Directions: *UniFi Network → Settings → Control Plane → Integrations → Create API
  Key*, made by an admin with full access to the site.
- **Through UniFi's cloud** (after S0). The Site Manager API key, then the console picked from `GET /v1/hosts`.

**What EasyEAP does on Connect** (`POST …/unifi/probe`):
1. **Direct only: checks the address** (§7.3).
2. **Direct only: opens TLS and checks the certificate** (§7.1).
   - A publicly trusted certificate is verified normally.
   - Otherwise the dialog shows the subject, issuer, validity and the SHA-256 of its public key. The admin ticks *This
     is my controller*. The fingerprint can be compared in a browser. Nothing else is sent before that.
   - Later runs for the same site compare the pin and stop if it changed, offering to re-pin.
3. **Version.** `GET …/integration/v1/info`. Older than 9.0.114 → stop, with the manual guide.
4. **Sites.** `GET …/integration/v1/sites`.
5. **The key's rights**, per chosen site: `GET …/api/s/{site}/self` must say `site_role: admin`. Otherwise: "This key
   can only read. Create it with an admin that has full access."
6. **Each probe is audited** (deduplicated per admin, address and day) and rate-limited (10 a minute per admin).

### 4.2 Site and scope

1. **Pick the site.** Skipped when there's one. A site already linked to **another tenant** is refused (§5.2).
2. **Choose what to set up:** **Wi-Fi**, **Wired** or **Both**. Wired is disabled, with the reason, when the site has
   no UniFi switch or the tenant hasn't turned on wired 802.1X.
3. **Discovery** (`POST …/unifi/discover`) reads, server-side:
   - RADIUS profiles, Wi-Fi networks, networks, devices and clients;
   - the site switch setting, AP groups and user groups;
   - the tenant's VLANs.

   It returns an allow-listed summary: names, ids, security type, VLANs, device names, models, ports with their
   reasons, and client counts per network and per port.

### 4.3 RADIUS profile (shown on Review)

**Which profile.** The stored one from an earlier run; else a matching one as in §3.8; else a new **"EasyEAP"**,
numbered if the name is taken.

**A new profile's contents:**
- `auth_servers: [{ip, port: 1812 or the tenant's dedicated port, x_secret}]`
- `acct_servers` likewise (1813 or dedicated)
- `accounting_enabled: true`
- `vlan_enabled: true`
- `vlan_wlan_mode: "optional"` (an Accept without a VLAN still connects)
- `use_usg_auth_server: false`

**The server address** is "EasyEAP's address as this site reaches it", prefilled with `EASYEAP_RADIUS_ADDRESS`. It
must be an IPv4 literal, which is what UniFi accepts.

### 4.4 Wi-Fi network

**The list.** Eligible networks with name, security (with *which* RADIUS profile for Enterprise), VLAN, bands,
enabled, and devices connected now. Plus **Create a new Wi-Fi network**.

**When nothing qualifies:**

> This site has no Wi-Fi network EasyEAP can use. Create one?

- Name: the tenant's SSID.
- Network: the site's default.
- Bands: 2.4 and 5 GHz.

It's created only on Review.

**What a choice means:**
- **Another name than the tenant's SSID.** The SSID setting changes to it (§3.7), with the count of enrollments to
  redo.
- **Already Enterprise with EasyEAP's profile.** Nothing to do.
- **Enterprise with another profile.** "Its N devices will authenticate against EasyEAP; devices without an EasyEAP
  certificate will be refused."
- **Passphrase or open, with N devices.** A warning: "all N disconnect and can't reconnect until they have an EasyEAP
  certificate; consider a new network". Applying needs the name typed.
- **6 GHz.** With WPA2-Enterprise, 6 GHz is removed from that network (Review says so). With WPA3, it stays if S4
  shows it can.

**The change** is a sparse PUT of the grouped keys:
- `security: "wpaeap"`;
- `{wpa_mode: "wpa2", wpa_enc: "ccmp"}`;
- the four `wpa3_*` keys and `pmf_mode` per §3.7;
- `{radiusprofile_id, radius_mac_auth_enabled: false}`;
- and, for 6 GHz, `{wlan_band, wlan_bands}`.

It doesn't touch the passphrase, VLAN, fast roaming (a note explains the effect on revocation) or
`radius_das_enabled`.

**A new network** gets:
- `name`, `enabled: true`, `hide_ssid: false`;
- the security keys;
- `networkconf_id`;
- `{ap_group_mode: "all", ap_group_ids: [default]}`;
- `usergroup_id: default`;
- `{wlan_band: "both", wlan_bands: ["2g", "5g"]}`.

It never gets `wlangroup_id`. The exact minimal set is confirmed by spike S8.

### 4.5 Wired

**Switches.** Each UniFi switch (`usw`, not stacked) gets a port grid: index, name, link, PoE, current network,
802.1X control, devices seen.

**Ports that can't be chosen show the reason:**
- the uplink (`is_uplink`);
- feeding a UniFi device (`uplink_remote_port`, LLDP);
- carrying the console, the gateway, or EasyEAP's path (`stat/sta` `sw_mac`/`sw_port` for those MACs);
- more than one MAC seen (an unmanaged switch, a hypervisor or a phone with a PC);
- a trunk (a port profile forwarding tagged VLANs);
- a LAG member (`aggregated_by`), mirror or aggregate;
- already on 802.1X.

Switches listed but not selectable: stacks, gateways' built-in ports, and a Dream Router.

**Ports.** None are chosen at first ("Choose one test port to start"). Each chosen port gets Auto, or MAC-Based when
MAC authentication is available for this registration.

**The fallback network.** Prefilled with the chosen ports' current network. If they differ, the step warns that
rejected devices on the other ports would land on it.

**It stops when:**
- the site's 802.1X setting is on with another RADIUS profile (merging with an existing 802.1X setup is a known gap
  for every switch family);
- or a chosen switch has its own 802.1X settings (S6).

**The changes:**
1. `PUT set/setting/global_switch` with only
   `{key: "global_switch", dot1x_portctrl_enabled: true, radiusprofile_id, dot1x_fallback_networkconf_id}`. S6
   confirms the path, or the `/{_id}` form.
2. Per switch: read `rest/device/{_id}` **just before** writing, merge by `port_idx`, and PUT the whole
   `port_overrides` array:
   - an existing entry has only `dot1x_ctrl` changed, every other key kept;
   - a new entry carries the port's `portconf_id` from `port_table` or, on a site without port profiles (§11.4), its
     `forward` and `native_networkconf_id`;
   - `null` is never sent;
   - if the array changed since discovery, stop and show it.
3. **Effect check after provisioning.** The chosen ports' `port_table` `dot1x_mode`/`dot1x_status`, because a port
   profile or `setting_preference` can win over an override (S6).

### 4.6 EasyEAP's registration

**How UniFi reaches EasyEAP.** The step asks, with the answer guessed from the server address: a private address
means routed, a public one means NAT.

**The proposed address:**
- **Routed:** the smallest CIDR covering the access points' (Wi-Fi) and chosen switches' (wired) addresses.
- **NAT:** the gateway's WAN address (`wan1`/`last_wan_ip`).
- The admin can edit it. The usual rules apply (/16 or narrower, no overlap with another tenant on the same ports).
  On overlap, the existing message suggests dedicated ports.

**New or reused.**
- An existing `unifi` registration covering the address (or matched through §3.8) is reused. Its networks gain Wi-Fi
  or wired, with the same checks as editing it.
- Otherwise a new one is made: "UniFi – <site>", CoA off, wired plan `{mode: monitor, fallback_vlan}`.

### 4.7 Review

**The list.** Steps marked *create*, *change* or *no change*, EasyEAP's own first:
- **EasyEAP:** register **UniFi – Office** (10.0.10.0/24, Wi-Fi and wired). Wi-Fi name setting: "Corp-WiFi" →
  "Office" (⚠ 6 enrolled devices need a new profile).
- **UniFi:** create the RADIUS profile **EasyEAP** (10.9.0.5:1812/1813, RADIUS-assigned VLAN on).
- **UniFi:** change **Office** from passphrase to WPA2-Enterprise (⚠ 14 devices connected now).
- **UniFi:** turn on 802.1X for the site's switches, fallback **LAN (1)**.
- **UniFi:** **USW-24-PoE port 5** → Auto.

**Warnings:**
- Access points and switches re-provision: "every Wi-Fi network drops for a few seconds; choose a quiet time".
- Tenant VLANs with no matching UniFi network: "EasyEAP can assign VLAN 30, but this site has none".
- Fast roaming is on.
- SSID count per band (4 with meshing, 8 without).

**Confirmations:**
- typing a busy network's name;
- ticking "ports set to Auto refuse devices EasyEAP rejects once I enforce".

### 4.8 Apply, check, undo

**Call 1: `POST …/unifi/apply/registration`.**
- Creates or updates the registration and records the change row (`applying`).
- Returns at once. The console then polls the RADIUS status until `tenant_config_in_sync` (at most 60 s; past that,
  "FreeRADIUS hasn't loaded it yet; apply anyway?").

**Call 2: `POST …/unifi/apply/controller`.** Same plan, an idempotency key, and an internal deadline of 90 s
(under nginx's 120 s).
1. **Lock and re-read.** Take a Postgres advisory lock on (tenant, site): a second apply is refused while one runs.
   Re-read every object to change; if anything differs from discovery, stop and show it.
2. **Write in order, reading each object back:**
   1. RADIUS profile;
   2. Wi-Fi network;
   3. site switch setting;
   4. each switch's port overrides.

   The change row records each step as it completes (its own commit). The before values are only the non-secret
   keys being changed, plus the whole object for anything this run creates.
3. **On a failure or the deadline:**
   - re-read the failed step's object (a timed-out write may have landed);
   - put back what was written, in reverse order;
   - restore the registration's previous fields, or remove it if this run created it and nothing used it;
   - mark the change *failed*.

   If putting something back fails too, the change is *rollback_incomplete*. The page lists the changes still in
   place, with the UniFi UI steps to undo each one. That's likely when the change itself cut the path to the
   controller, which §4.5's exclusions exist to prevent.
4. **Success.** Mark it *applied* and audit it. If the browser timed out, the console finds the outcome with
   `GET changes/{id}`.

**Check (the last screen):**
- The devices' state through provisioning.
- `FirstRequest` for Wi-Fi and wired.
- For wired, the effect check (§4.5).
- If requests arrive from an unregistered address that matches this site (the gateway, an access point), **Register
  this address instead**.

**Undo** (the registration's panel; the latest change per site; asks for the key again):
- Re-read each object and compare it with the values written. If someone changed it since, show what changed and
  continue only on confirmation.
- Put back the before values in reverse order. Delete what the run created (a network, or the RADIUS profile when
  nothing else uses it). Restore the SSID setting if it changed.
- Leave the registration, with an offer to remove it.
- Audit it.

## 5. Backend

### 5.1 `app/unifi/` (new)

**`client.py`: `UnifiClient`.**
- Base URL and headers per connection: direct, or the connector.
- httpx with the pinned TLS context (§7.1) and `follow_redirects=False`.
- Timeouts: 5 s to connect, 15 s to read; on the connector, 25 s overall and at most 100 calls a minute.
- No request or response logging.
- Methods per object. Writes take a sparse dict, never a full object.
- Errors become `UnifiError(step, status, code)`, where `code` is UniFi's `meta.msg` (`api.err.*`), mapped to an
  EasyEAP message. An unknown code is shown as the code alone.

**`discovery.py`.** Turns UniFi's objects into `Discovery`, an **allow-listed** typed snapshot, and holds the
port-reason rules.

**`plan.py`.** Pure functions, tested without a network:
- `build(discovery, choices, tenant) → Plan`
- `covering_cidr()`
- `wlan_keys(security, bands)`
- `merge_port_overrides()`
- `vlan_gaps()`
- `ssid_change()`

**`apply.py`.** Runs the steps, reads back, rolls back; `undo(change)`.

**`netguard.py`.** §7.3.

### 5.2 Data model (migration `0016_unifi`)

**`unifi_sites`**, one row per linked UniFi site:

| Column | Notes |
|---|---|
| `id` | |
| `tenant_id` | RLS |
| `client_id` | FK to `radius_clients` |
| `site_id` | the official site UUID, **unique across all tenants** |
| `site_ref` | the classic name |
| `site_name` | |
| `connection` | `direct` or `cloud` |
| `url` | direct only |
| `console_id` | cloud only |
| `spki_sha256` | direct, self-signed only |
| `version` | |
| `radiusprofile_id` | |
| `wlan_ids[]` | |
| `switch_macs[]` | |
| `created_at`, `updated_at` | |

Uniqueness across tenants is checked platform-scoped, as `check_address_unique` does, and enforced by the unique
index.

**`unifi_changes`:**

| Column | Notes |
|---|---|
| `id` | |
| `tenant_id` | |
| `unifi_site_id` | |
| `created_at` | |
| `actor` | |
| `idempotency_key` | |
| `status` | `applying\|applied\|failed\|rollback_incomplete\|undone` |
| `steps` | JSONB, per step: object, id, name, action, keys, done or failed |
| `before` | JSONB: non-secret keys only |
| `written` | JSONB: non-secret keys only, for the undo drift check |
| `registration_before` | JSONB: the registration's fields if this run changed them |
| `undone_at`, `undone_by` | |

No secrets are stored anywhere: the RADIUS secret is never part of `before` or `written`, because a profile EasyEAP
updates always gets the registration's current secret.

### 5.3 API (`/api/tenants/{tid}/radius/unifi/…`, all `require_all("radius:write", "radius:secrets")`)

| Call | Body | Returns |
|---|---|---|
| `POST probe` | `{connection, url\|console_id, key, pin?}` | certificate, version, sites |
| `POST discover` | `{…, site}` | allow-listed Discovery |
| `POST preview` | `{…, choices}` | plan and warnings |
| `POST apply/registration` | `{…, choices, confirmations, idempotency_key}` | change id, registration |
| `POST apply/controller` | `{…, change_id, idempotency_key}` | step results |
| `GET changes/{id}` and `GET changes?site=` | | status and steps |
| `POST changes/{id}/undo` | `{…, force?}` | drift, or the result |

The key is a `SecretStr`, and request-validation errors never echo it.

## 6. Console

- **`screens/radius/UnifiWizard.tsx`.**
  - Steps: Connect → Site & scope → Wi-Fi → Wired → Review → Apply & check. Wi-Fi and Wired are skipped by scope.
  - The key lives in a `useRef` cleared on close. All calls are mutations, never cached queries.
- **A port grid component:** keyboard-selectable, reasons on disabled cells, a legend.
- **A UniFi card on the registration's panel:** site, connection, version, last change and its status, *Run again*,
  *Undo*.
- **Copy** in the plain style of the other wizards, with UniFi's own menu names in bold.

## 7. Security

### 7.1 TLS (direct)

- **A publicly trusted certificate.** Normal verification with hostname, and no pin, so an ACME renewal doesn't break
  anything.
- **Otherwise, the leaf's public key (SPKI SHA-256) is pinned.**
  - The context does the handshake without CA verification. An `SSLSocket` subclass (`ctx.sslsocket_class`) checks the
    peer's SPKI right after `do_handshake()` and closes the connection on a mismatch, before any HTTP bytes are sent.
  - Every connection is checked, so there's no window between the probe and later calls.
  - Expiry isn't checked: UniFi's self-signed certificates can be expired, and the pinned key is what's trusted.
  - The hostname isn't checked: consoles are reached by IP.

### 7.2 Secrets

- **The key** is used per call and never stored, logged, audited or returned.
- **The shared secret** is decrypted server-side for the RADIUS profile write and the §3.8 comparison.
- **UniFi's objects** are reduced to allow-listed fields before anything leaves `app/unifi/`. Tests feed objects that
  carry every known secret field (`x_*`, `private_preshared_keys`, `sae_psk`, `lte_password`, `nut_server`,
  `mbb_overrides`, `wireguard_*`) and assert that none appears in any response, change row or log line.
- **Logging.** httpx and h11 loggers stay at WARNING.

### 7.3 Direct connections to an address an admin typed

- **Ports:** 443 and 11443, plus 8443 only for a console behind a reverse proxy.
- **Resolution:** the name is resolved once per call, the guard runs on that IP, and the connection goes to it. A
  hostname is sent as SNI/Host only.
- **Refused addresses:**
  - loopback, link-local, multicast and unspecified;
  - IPv4-mapped, 6to4 and NAT64 forms (normalised first);
  - every subnet of the API container's interfaces;
  - the host's own addresses (`EASYEAP_RADIUS_ADDRESS` and the bind addresses in settings).
- **Who may reach what.**
  - A tenant-role admin may connect only inside the tenant's **UniFi management networks**. These are CIDRs set by an
    MSP Operator in the tenant's settings, so customer staff can't scan other tenants' networks over the MSP's VPNs.
  - Platform-role admins may connect anywhere the guard allows.
- **Errors are coarse:** "couldn't connect", "not a UniFi console", "certificate shown". There's no timing or
  body detail, and only expected JSON is parsed.
- **Audit and limits:** probes are audited and rate-limited (§4.1).

The cloud connection talks only to `api.ui.com` with normal TLS verification.

### 7.4 Audit

| Event | Detail |
|---|---|
| `unifi.probe` | address or console, result (deduplicated) |
| `radius.client_created` / `radius.client_updated` | actor suffix "(UniFi wizard)" |
| `radius.settings_updated` | when the SSID setting changes |
| `unifi.change_applied` / `unifi.change_failed` / `unifi.change_rollback_incomplete` / `unifi.change_undone` | site, version, objects and actions by name, ports by switch |

No values.

## 8. Docs

- **`docs/controllers/unifi.md`:** "Let EasyEAP set it up": the API key, what changes, undo, and the "tested on"
  versions. The manual steps stay below.
- **CHANGELOG.**
- **`TODO.md`:** the real-console checks.

## 9. Tests

**Unit**
- `discovery.py`:
  - port reasons: uplink, UniFi device feed, console/gateway path, several MACs, trunk, LAG, mirror;
  - the allow-list against objects full of secret fields;
  - network eligibility.
- `plan.py`:
  - WPA key groups;
  - 6 GHz removal;
  - SSID change and enrollment count;
  - covering CIDR and NAT address;
  - VLAN gaps;
  - port override merge (unknown keys kept, new entry with `portconf_id`, no `null`);
  - the `global_switch` body (sparse, with `key`).
- `netguard.py`: every refused form, plus the tenant management networks.
- `client.py` with `httpx.MockTransport`:
  - the pinned context accepts the pinned self-signed certificate, expired or not, and refuses another key before
    sending;
  - error code mapping;
  - connector paths.
- `apply.py`:
  - rollback at each step;
  - a timed-out write that landed;
  - rollback failure → `rollback_incomplete`;
  - the deadline;
  - the advisory lock;
  - idempotency;
  - undo drift.

**Field contract.** A fixture lists every key EasyEAP sends, per object, with the controller's validation pattern
from its field definitions (9.5.21 and 10.6.109, with links). Every payload is checked against it. Ubiquiti's
definitions aren't copied into the repo.

**Recorded responses.** From the spike's console, redacted, replayed in the tests.

**Frontend.**
- the no-eligible-network prompt;
- the SSID change warning;
- busy network confirmation;
- port reasons;
- Review;
- apply progress and a timed-out browser call;
- undo.

**On real UniFi.** §11.

## 10. Risks

| Risk | Mitigation |
|---|---|
| A release changes the classic API | Read back each write, effect check, field contract, "tested on" versions, stop on an unknown version family |
| The key is refused on the classic endpoints | Connect checks `self` and a read; the message names the fix |
| Converting a busy network locks people out | New network suggested; typed confirmation; undo |
| Enrolled devices look for another SSID or WPA mode | The network must match the tenant's settings (§3.7) |
| A port override PUT drops other overrides | Re-read just before; merge; compare; read back |
| A wrong port cuts off an AP, uplink, the console or EasyEAP's path | Refusal rules (§4.5), one test port, monitor fallback, `rollback_incomplete` with manual steps |
| A wrong registration address under NAT | Ask the path; propose the WAN address; one-click fix from what arrives |
| Customer staff scan networks through EasyEAP | Tenant management networks, ports, audit, rate limit, coarse errors |
| Secrets leak | Allow-lists, nothing secret stored, tests with every secret field |
| Slow controller or browser timeout | Two calls, 90 s deadline, progress committed per step, outcome readable afterwards |
| No UniFi hardware to test | Spike before building; go/no-go (§11.3) |

## 11. Testing on real UniFi

### 11.1 Spike (on a real console, before phase 2)

Each item is checked in UniFi's UI and read back through the API. The responses are kept, redacted, as test fixtures.
S3 (login) and S9 (official vs classic ids) were dropped with the login path and the official Wi-Fi API.

- **S0.** The cloud connector: Site Manager key, `GET /v1/hosts`, the forwarded path form, a classic read and a
  harmless write.
- **S1.** A local key on the classic endpoints: reads, `self`, and a harmless write (rename a test RADIUS profile).
- **S2.** `x_secret` read back. What a read-only admin's key sees.
- **S4.** WPA3:
  - Make WPA2-Enterprise, WPA2/WPA3-Enterprise and WPA3-Enterprise networks in the UI, and read back `security`,
    `wpa_mode`, the `wpa3_*` keys and `pmf_mode`.
  - 6 GHz behaviour.
  - Which of them a Windows 11 `WPA3ENT` profile and a `WPA2` profile join.
- **S5.** The fallback VLAN: rejected devices, devices without 802.1X, or both.
- **S6.** The site setting:
  - the `set/setting/global_switch` path (or `/{_id}`);
  - site setting vs a switch's own settings;
  - what `switch_exclusions` does;
  - `setting_preference`;
  - a port profile's `dot1x_ctrl` vs an override's;
  - which switch models support 802.1X.
- **S7.** Where RADIUS comes from over a VPN and across NAT: each AP, each switch, or the gateway. The
  `NAS-Port-Type` and `Called-Station-Id` on wired requests.
- **S8.** A new network with the minimal keys of §4.4, on 9.5, 10.x and 11.x.

### 11.2 Where

None of these is a second EasyEAP install.

1. **The user's UniFi console, with a new test site.** Preferred.
2. **With the user's OK, UniFi OS Server on the demo host.** It needs podman and systemd, and it takes ports 8080,
   3478, 10001 and 11443 on the host. It has real UniFi OS and API keys but no devices: the RADIUS profile, Wi-Fi
   networks and the site setting can be tested, ports can't.
3. **End to end on the demo.** The wizard against 1 or 2, then a real device through a UniFi AP and a switch port.

### 11.3 Go/no-go

Phase 2 isn't built until S1, S2, S4 and S8 have run on a real console. Wired needs S5–S7 too. Without a console,
the plan waits and the manual guide stays the way.

### 11.4 Results so far (2026-11-09)

Run on UniFi OS Server (port 11443, a publicly trusted certificate) with Network 10.6.109, on one site of a console
that has many. The calls went through a helper that refused every other site and replaced secret values before
printing.

- **S1: done.**
  - The local API key works on the classic endpoints (`/proxy/network/api/s/{site}/…`) with `X-API-KEY`. No login
    is needed.
  - `self` answers `site_role: admin` and `is_super: true`.
  - A test RADIUS profile was created (`POST rest/radiusprofile`), renamed, then deleted:
    - the rename's body was only `{name}`, and the servers were kept, which confirms the top-level merge;
    - the official API listed it with `id` equal to the classic `external_id`.
  - The official list also has a "UID" profile (`origin: DERIVED`) that the classic list doesn't.
  - `GET /v1/sites` lists every site the key reaches. `internalReference` is the classic site name (`default`).
- **S2: half done.**
  - `x_secret` comes back whole and unmasked, both in the POST answer and on a later GET.
  - What a read-only admin's key sees: not tried, as no such key was available.
- **S6: reads only.**
  - `get/setting` includes `global_switch` with the keys of §2.1.
  - **`rest/portconf` was empty, and ports carry their settings directly.** `port_overrides[]` entries have
    `forward`, `native_networkconf_id`, `dot1x_ctrl` and `dot1x_idle_timeout`, and no `portconf_id`. `port_table[]`
    has no `portconf_id` either. §4.5 step 2 now covers this.
  - With 802.1X off, the switch (US-24-PoE-250W, firmware 7.5.15):
    - has `dot1x_portctrl_enabled: false` on the device, and no `radiusprofile_id` or
      `dot1x_fallback_networkconf_id`;
    - its ports show `dot1x_mode: unknown` and `dot1x_status: disabled`.
- **S8: done.** Tested on a network created disabled, then deleted:
  - **The §4.4 set is accepted for a new network.** The controller adds its own `dtim_*`, `iapp_enabled`,
    `minrate_*`, `setting_preference`, `short_id` and an `x_iapp_key`.
  - **Only `ap_group_ids` is required** (`api.err.ApGroupMissing`). Left out, the others default as follows:
    - `usergroup_id` and `networkconf_id` take the site's defaults;
    - `ap_group_mode` becomes `all`;
    - `wlan_band` and `wlan_bands` become `both` and `["2g","5g"]`;
    - without the `wpa3_*` keys, `pmf_mode` becomes `disabled`;
    - without `wpa_mode` and `wpa_enc`, the network is stored without them.

    So the wizard keeps sending them all.
  - **Disabled networks count against the per-band limit.** A fifth network on a band was refused with
    `api.err.TooManyWirelessNetwork`. The answer carries `max_wlan` (4 with wireless meshing on), `wlan_count`, the
    band and the access point's MAC. The wizard counts every network on the chosen access point groups, enabled or
    not, before offering to create one.
- **S4: the settings side.** Sparse PUTs of the grouped keys worked:
  - WPA3-Enterprise: `wpa3_support: true`, `wpa3_transition: false`, `pmf_mode: required`;
  - WPA2/WPA3-Enterprise: `wpa3_transition: true`, `pmf_mode: optional`;
  - WPA3-Enterprise 192-bit: `wpa3_enhanced_192: true`, with `wpa_enc` read back as `ccmp`.

  Bad combinations are refused, not quietly changed:
  - WPA2 with 6 GHz: `api.err.Wpa3MandatoryFor6GHzBand`;
  - WPA3 transition with PMF off: `api.err.InvalidSecurityPmfModeCombination`.

  WPA3 with 6 GHz was accepted. That was with no 6 GHz access point on the site, so whether 6 GHz is dropped on
  real hardware is still open.
- **Not run yet:**
  - S4's joins (which networks Windows 11 `WPA3ENT` and `WPA2` profiles join) need an access point online.
  - S5, the S6 writes and S7 turn 802.1X on for the site, which re-provisions the switch. They wait for the owner's
    go-ahead.
  - S0 needs a Site Manager key.

## 12. Phases

1. **Spike** (§11.1): needs a console from the user.
2. **Wi-Fi:**
   - direct connection (pin, guard, management networks), site, the RADIUS profile;
   - the network (pick or create, SSID and WPA mode matching the tenant);
   - the registration, two-call apply, rollback, undo;
   - audit, docs.
3. **Wired:** the port grid with its refusal rules, Auto/MAC-Based, the monitor fallback, the effect check.
4. **The cloud connection** (after S0), and **Enforce / back to monitor through the API** (the fallback VLAN), from the
   existing Enforce dialog.
5. **A saved connection (opt-in, encrypted) and the UniFi switch audit:** ports, sessions and findings, like the Cisco
   audit (switch-audit.md §11), plus warnings when someone changes what the wizard set.

## 13. Critique (revision 1) and what changed

A critic read revision 1 against Ubiquiti's specs, the controller's field definitions, the libraries' code and
EasyEAP's code. All 21 findings were accepted. The version and path claims were re-checked against the specs before
changing them.

| # | Sev | Finding | Change |
|---|---|---|---|
| 1 | critical | Hosted MSPs often can't reach consoles behind NAT. The plan called Site Manager keys read-only, but the connector forwards writes (Site Manager OpenAPI; go-unifi uses it). | Cloud connection designed in (§3.2), enabled after spike S0. |
| 2 | critical | The covering CIDR is right only over a VPN. Under NAT, requests come from the site's public address, and private ranges repeat across tenants. | Ask the path; propose the WAN address under NAT; one-click fix from requests that arrive; S7 moved into the spike (§3.11, §4.6, §4.8). |
| 3 | major | Enrollment uses the tenant's SSID and `wpa3`. A network with another name or WPA mode gives devices profiles that never match. | The network must match; a different name changes the setting, with the count of enrollments to redo; security follows `wpa3`, after S4 (§3.7). |
| 4 | major | Removing `x_*` keys misses secrets with other names (PPSK, SAE, LTE, NUT, WireGuard). `stat/sta` hands out every client's MAC and hostname. | Allow-lists only; client counts only; error codes mapped, not passed through (§3.5, §7.2). |
| 5 | major | The probe could be used to scan other tenants' networks over the MSP's VPNs. The host's LAN address wasn't refused. Probes weren't audited. | Ports limited; tenant management networks set by the MSP; the host's addresses and mapped forms refused; probes audited and rate-limited; coarse errors (§7.3). |
| 6 | major | The login path re-logs in on each call into a throttled endpoint, and only serves the retired self-hosted application. | v1 is API keys only (§3.2). |
| 7 | major | Missing exclusions: the console's, the gateway's and EasyEAP's path, unmanaged switches, LAG members, stacks (`unit_id`). Gateways refuse `op_mode`. | Refusal rules extended; only `usw`, no stacks (§4.5). |
| 8 | major | `set/setting/global_switch` takes `key` in the body. A typed struct resets every other site setting. | Sparse body with `key`; the path confirmed in S6 (§4.5). |
| 9 | major | About 20 calls of up to 20 s each can outlast nginx's 120 s; a retry after a 504 runs two applies at once. | Two calls, a 90 s deadline, advisory lock, idempotency key, progress committed per step (§4.8). |
| 10 | major | Rollback ignored a timed-out write that landed, had no state for its own failure, and didn't restore an updated registration. | Re-read the failed step; `rollback_incomplete` with manual steps; `registration_before` (§4.8). |
| 11 | major | FreeRADIUS loads a new registration within about 15 s, but access points re-provision within seconds: the first requests would be dropped. | Wait for `tenant_config_in_sync` between the two calls (§4.8). |
| 12 | major | Adopting any profile that points at EasyEAP and overwriting its servers could break a working setup. | Own profile only; reuse a matching one untouched, when its secret matches a registration (§3.8). |
| 13 | minor | Re-provisioning drops every SSID briefly. | A Review warning (§4.7). |
| 14 | minor | Undo was over-built: Transit, a purge job, 30 days. | Before values are non-secret plain JSON; the latest change per site (§3.12, §5.2). |
| 15 | minor | Wrong version claims for the official PUT's required fields; `wlan_band` has no `6g`; the WPA3 group is four keys; UniFi OS Server is on :11443; two facts lacked a source. | Corrected against the specs; sources added (§2). |
| 16 | minor | Guest, hotspot, PPSK and `osen` networks were offered. The prompt appeared only with zero networks. | Filtered; the prompt fires when nothing qualifies (§3.7, §4.4). |
| 17 | minor | Read-back checks the stored configuration, not its effect. | An effect check on `port_table`; `setting_preference` in S6 (§4.5). |
| 18 | minor | One console holds many sites. A single link per registration gets overwritten, and a site could be linked to two tenants. | `unifi_sites` table, site id unique across tenants (§5.2). |
| 19 | minor | Reading `rest/radiusprofile` proves only read access (and pulls secrets). | `api/s/{site}/self` → `site_role` (§4.1). |
| 20 | minor | Pinning details: expired self-signed certificates, ACME renewals, connecting by IP, re-checking across connections. | SPKI pin checked on every connection before any byte, expiry and hostname ignored for pinned keys; public certificates verified normally (§7.1). |
| 21 | minor | Testing wasn't realistic without hardware; `require()` takes one permission. | Go/no-go (§11.3); recorded fixtures; S9 cut; `require_all()` (§3.6). |

Kept from revision 1, as the critic advised: sparse grouped PUTs and the read-just-before merge of `port_overrides`;
the shared secret never reaching the browser; no stored credentials; one test port with a monitor fallback; stopping
on an existing 802.1X setup; "Create a new network" beside the list, with a typed confirmation for a busy one; the
spike before wired; the IPv4-literal check; no redirects.

## 14. Not in this plan

- Creating networks or VLANs on the controller (Review lists the missing ones).
- UniFi's own RADIUS server, guest portals, PPSK.
- RadSec to EasyEAP (EasyEAP has none).
- The self-hosted Network Application and local admin logins.
- Network versions before 9.0.114.
- Stacked switches and gateways' built-in ports (after S6, on request).

## 15. Sources

**Official API (Ubiquiti)**
- OpenAPI files 9.1.120–11.0.97: https://developer.ui.com/api/services/network/versions (for example
  https://developer.ui.com/network/v11.0.97/openapi.json).
- Getting started: https://developer.ui.com/network/v11.0.97/gettingstarted.
- Errors: https://developer.ui.com/network/v11.0.97/error-handling.
- `GET /v1/info`: https://developer.ui.com/network/v11.0.97/getinfo.
- Site Manager API and the connector: https://developer.ui.com/site-manager/v1.0.0/openapi.json and
  https://developer.ui.com/site-manager/v1.0.0/gettingstarted.

**Release notes and help**
- 9.0.108: https://community.ui.com/releases/UniFi-Network-Application-9-0-108/4e4c885a-311f-41b1-ad5d-9b6afcee77f7.
- 10.0.160: https://community.ui.com/releases/UniFi-Network-Application-10-0-160/ce7adc5c-4b42-49d3-8447-971992c0bced.
- 11.0.97: https://community.ui.com/releases/UniFi-Network-Application-11-0-97/15662d06-8122-44e2-a1ba-af5d71b8a045.
- 11.0.99: https://community.ui.com/releases/r/network/11.0.99.
- UniFi OS 4.1.9: https://community.ui.com/releases/UniFi-OS-Dream-Machines-4-1-9/bb11c52d-50c6-45a2-b0e2-fd7e844a68d6.
- UniFi OS Server: https://help.ui.com/hc/en-us/articles/34210126298775.

**Field definitions (extracted from the Network application)**
- go-unifi at 10.6.109: https://github.com/ubiquiti-community/go-unifi. Files: `unifi/radius_profile.generated.go`,
  `unifi/settings/global_switch.generated.go`, `unifi/device.generated.go`, `unifi/port_profile.generated.go`;
  `unifi/patch.go` (the PUT merge rule); `unifi/setting.go` (`set/setting/{key}` with `key`); `unifi/unifi.go`
  (login, CSRF, `X-Api-Key`, the cloud connector, login throttling).
- The raw 9.5.21 JSON: https://github.com/filipowm/go-unifi/tree/main/codegen/v9.5.21 (`RadiusProfile.json`,
  `WlanConf.json`, `SettingGlobalSwitch.json`, `Device.json`, `PortConf.json`, `NetworkConf.json`).
- Field history 6.4.54–9.0.114: https://github.com/paultyng/go-unifi.
- filipowm/go-unifi v2 migration guide (API keys, 9.0.114+): https://github.com/filipowm/go-unifi/blob/main/docs/2.0.0/migration_guide.md.

**Libraries**
- Terraform provider: https://github.com/ubiquiti-community/terraform-provider-unifi. Covers the WLAN key groups,
  `port_overrides` (issue #266), `wlangroup_id` (#176), 6 GHz (#406), gateway `op_mode` (#213), and the SSID budget
  per band in `docs/resources/setting.md`.
- Art of WiFi PHP client: https://github.com/Art-of-WiFi/UniFi-API-client (`create_wlan` keys, ports 443/8443/11443).
  Authentication notes: https://artofwifi.net/blog/unifi-api-authentication-local-admin-vs-api-key-vs-site-manager.
- aiounifi: https://github.com/Kane610/aiounifi (`port_table`, `uplink_remote_port`, `wan1`, client `sw_mac`/`sw_port`,
  PR #1096).
- unpoller: https://github.com/unpoller/unifi (API keys on classic paths; `server_version` gone in 10.x).

**Other**
- Portnox UniFi guide (Global Switch Settings in 10.x; no wired 802.1X on the Dream Router):
  https://docs.portnox.com/topics/nas_switches_ubiquiti.html.
- RFC 5176 (Dynamic Authorization).

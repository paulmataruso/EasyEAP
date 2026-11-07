# EasyEAP Architecture

EasyEAP is a multi-tenant platform: one deployment, operated by an MSP, serves many customer organisations ("tenants"). Each tenant has its own PKI, directory connection, access policy, RADIUS configuration and audit trail. The design goal is that **authentication keeps working when anything above RADIUS is down**, and that **every failure denies rather than permits**.

## 1. Services

```mermaid
flowchart LR
  subgraph edge["edge network"]
    proxy["easyeap-proxy<br/>nginx (TLS 443, HTTP 80)"]
  end
  subgraph app["app network (internal)"]
    api["easyeap-api<br/>FastAPI"]
    worker["easyeap-worker<br/>Postgres-backed jobs"]
  end
  subgraph data["data network (internal)"]
    db[("easyeap-db<br/>PostgreSQL 18")]
  end
  subgraph pki["pki network (internal)"]
    bao["easyeap-pki<br/>OpenBao 2.4 PKI + Transit"]
  end
  subgraph rad["radius network (internal)"]
    radius["easyeap-radius<br/>FreeRADIUS 3.2 + radius-agent"]
  end
  admin(("Admins /<br/>enrolling users")) -->|HTTPS| proxy
  nas(("Wireless controllers")) -->|"UDP 1812/1813"| radius
  radius -->|"CoA UDP 3799/1700"| nas
  proxy --> api
  api --> db
  worker --> db
  api --> bao
  worker --> bao
  radius -->|"pull snapshot / push events (HTTPS, agent token)"| api
  api -.->|"LDAPS 636"| ad(("Customer AD"))
  worker -.->|"LDAPS 636"| ad
```

| Container | Image base | Runs as | Purpose |
|---|---|---|---|
| `easyeap-proxy` | nginx-unprivileged 1.31 | uid 101 | Serves the console SPA and the enrollment portal, terminates TLS, proxies `/api`, serves CRLs and OCSP on plain HTTP (clients fetch them without TLS by design). |
| `easyeap-api` | python 3.13-slim | uid 10001 | REST API (OpenAPI at `/api/docs`), authentication, RBAC, policy engine, PKI orchestration, enrollment, snapshot publisher, event ingestion. |
| `easyeap-worker` | same image as api | uid 10001 | Background jobs: directory sync, hourly policy recomputation (which keeps the snapshot fresh while the directory is healthy), CRL rotation, enrollment-link expiry, purge of undelivered server-generated keys, event retention, OpenBao token renewal. |
| `easyeap-db` | postgres 18-alpine | postgres | Application database. Row-level security isolates tenants. |
| `easyeap-pki` | openbao 2.4.1 | openbao | One PKI secrets-engine mount per tenant (issuing CA), one Transit key per tenant (envelope encryption of tenant secrets). Static auto-unseal from a key file. Raft/file storage on its own volume. |
| `easyeap-radius` | freeradius 3.2.10 | freerad | FreeRADIUS plus `radius-agent` (Python) under a small supervisor. Renders and validates its own configuration from the API's desired state, keeps a local authorization snapshot, ships events. |

Only `easyeap-proxy` (TCP 80/443) and `easyeap-radius` (UDP 1812/1813) publish ports. The API is never published directly. RADIUS has **no route** to the database or to OpenBao; it only talks to the API over an authenticated channel, and it keeps working without it.

## 2. Multi-tenancy

- Every tenant-scoped table has `tenant_id`. PostgreSQL **row-level security** policies compare it with `current_setting('easyeap.tenant_id')`, which the API sets per transaction after authorising the caller for that tenant. Platform tables (tenants, admins, platform audit) have no RLS and are only reachable through platform-scoped endpoints. The application connects as a non-owner role so RLS cannot be bypassed accidentally.
- **PKI isolation:** each tenant gets its own Root CA (kept offline) and Issuing CA (OpenBao mount `pki-t-<tenant_id>`). A certificate from one tenant never chains to another tenant's trust anchor, so it cannot authenticate on another tenant's Wi-Fi even with shared RADIUS infrastructure.
- **RADIUS isolation:** each RADIUS client (wireless controller) belongs to exactly one tenant. Requests are routed by client to the tenant's own virtual server, with its own EAP instance, server certificate, trusted CA chain, CRL and authorization snapshot. Controller source addresses must be unique across tenants; when two tenants' controllers share an address range (overlapping RFC 1918 over VPNs), the tenant is given a dedicated authentication/accounting port pair.
- **Secrets:** AD bind passwords, RADIUS shared secrets and escrowed PKCS#12 blobs are encrypted with the tenant's OpenBao Transit key (envelope encryption). Deleting a tenant deletes its Transit key and PKI mount, so its ciphertext becomes unrecoverable (crypto-shredding).
- **RBAC:** platform roles (`platform_owner`, `platform_operator`, `platform_auditor`) apply to all tenants; tenant roles (`tenant_admin`, `pki_admin`, `wifi_admin`, `auditor`) are granted per tenant. Issuing certificates (`certificates:issue`) is a separate permission from managing CAs (`ca:manage`). See SECURITY.md for the permission matrix.

## 3. PKI

### Engine evaluation

| Option | Verdict |
|---|---|
| OpenSSL CLI (`openssl ca`) | Rejected. Text `index.txt` database, shell-out parsing, no concurrency, no API. |
| Smallstep step-ca | Excellent single-CA server (ACME, SCEP, templates, CRL). One authority per process, so per-tenant CAs would need a process or container per tenant and orchestration with Docker-socket access. No OCSP responder. |
| EJBCA CE | Mature but heavyweight (Java/WildFly), complex to automate, more than this product needs. |
| Custom CA on pyca/cryptography | Maximum control, but EasyEAP would own CA correctness, CRL/OCSP generation and key storage. Rejected per the "no custom PKI" rule. |
| **OpenBao PKI (chosen)** | Open-source (MPL-2.0, Linux Foundation) Vault fork. Unlimited PKI mounts (one per tenant), roles as certificate templates, keys generated and held inside OpenBao (`internal`), CRL + delta CRL with auto-rebuild, built-in OCSP responder, ACME, tidy, audit devices, policies per mount. Transit engine reused for envelope encryption. Static seal gives unattended restarts. |

### CA hierarchy per tenant

```mermaid
flowchart TB
  root["Tenant Root CA<br/>(offline — key exported once, encrypted, then destroyed online)"]
  iss["Tenant Issuing CA<br/>OpenBao mount pki-t-&lt;id&gt; (key never leaves OpenBao)"]
  user["User Wi-Fi certs<br/>EKU clientAuth"]
  dev["Device Wi-Fi certs<br/>EKU clientAuth"]
  srv["RADIUS server cert<br/>EKU serverAuth"]
  root --> iss --> user & dev & srv
```

**Root ceremony** (setup wizard, step "Initialize PKI"): EasyEAP mounts a temporary engine, generates the root with `type=exported`, generates the issuing CA's CSR inside the tenant mount (`intermediate/generate/internal`), signs it with the root, sets the signed certificate, issues the root CRL, then **unmounts the temporary engine (destroying the online copy of the root key)**. The root private key is returned to the administrator exactly once, encrypted (PKCS#8, AES-256, PBKDF2) under a passphrase they choose, for offline storage. Later root operations (renewing the issuing CA, re-issuing the root CRL) reopen a ceremony by uploading that file. A lab-only "keep root online" option exists and is labelled insecure.

**Templates** map to OpenBao roles (`ext_key_usage`, `key_usage`, `ttl`/`max_ttl`, key type/bits, `allowed_*` names). The EasyEAP API is the registration authority: it builds subjects and SANs from directory data and the template's patterns, never accepting client-chosen subjects.

**Revocation:** `revoke` by serial → OpenBao rebuilds the CRL (auto-rebuild + delta) and OCSP answers immediately → EasyEAP marks the certificate revoked, recomputes the tenant snapshot and pushes it to RADIUS (seconds), and if the certificate's device has an active session on a CoA-capable controller, sends a Disconnect-Request. See §5 for honest latency.

**CRL/OCSP distribution:** the proxy serves `http://<pki-host>/pki/<tenant>/crl` and `/ocsp` (plain HTTP, as RFC 5280 clients expect). CRL distribution point and AIA URLs are set on each mount.

## 4. Enrollment and key custody

Every device gets its own certificate. Methods, in order of preference:

| Method | Where the key is generated | Platforms |
|---|---|---|
| Windows helper (PowerShell, `certreq` with the Microsoft Platform Crypto Provider when a TPM exists) | Device (TPM / non-exportable when available) | Windows |
| Browser enrollment (WebCrypto P-256 key, CSR built in-page, PKCS#12 assembled in-page) | Device browser; the private key never leaves the page | Android, Linux, macOS, Windows, iOS/iPadOS (profile assembled in-page) |
| CSR upload | Wherever the user generated it (e.g. `openssl` / NetworkManager) | Linux, advanced users |
| Server-generated (admin mode, opt-in per tenant) | OpenBao `issue` endpoint; EasyEAP immediately wraps the key in a password-protected PKCS#12 (AES-256-CBC, PBKDF2-SHA256, 600k iterations), encrypts it with the tenant Transit key, and allows **one** download before the escrow row is purged (or 72h expiry) | All |

One-time enrollment links carry a random 256-bit token (stored hashed), bound to tenant + identity + device name, single use, 72h default expiry. Platform packages include the issuing chain, the Root CA, a Wi-Fi profile (Windows WLAN XML, Apple `.mobileconfig` with EAP-TLS + `TLSTrustedServerNames`, NetworkManager keyfile, wpa_supplicant block) and step-by-step instructions. Apple SCEP/ACME device-key enrollment is planned (see PROGRESS.md).

## 5. RADIUS authentication flow

```mermaid
sequenceDiagram
  participant D as Device
  participant N as Controller or switch (NAS)
  participant R as FreeRADIUS (tenant virtual server)
  participant S as Local authz snapshot (SQLite)
  participant A as radius-agent
  participant API as EasyEAP API
  D->>N: EAPOL start
  N->>R: Access-Request (EAP, Message-Authenticator)
  R->>D: EAP-TLS: server cert (tenant), request client cert
  D->>R: client cert + proof of key
  R->>R: verify chain to tenant issuing CA, expiry, CRL
  R->>S: SELECT decision WHERE issuer AND serial
  S-->>R: allow + VLAN + attributes (or deny + reason)
  R->>N: Access-Accept (Tunnel-Type=13, Tunnel-Medium-Type=6, Tunnel-Private-Group-ID=VLAN) or Access-Reject
  R->>A: event line (JSON) appended to spool
  A->>API: batch events (when API reachable)
  API-->>A: snapshot updates (pulled every 15 s)
```

- **Authorization data is precomputed.** The policy engine evaluates every certificate's holder against the tenant's rules whenever directory data, rules, certificates or account state change, and publishes a per-tenant snapshot: `serial → {decision, vlan, reply attributes, rule id, reason, valid_until}`. RADIUS performs one indexed lookup on a local SQLite file. There is **no synchronous call to the API, the database, AD or OpenBao during authentication**.
- **Fail closed:** unknown serial → reject (`cert_unknown`); snapshot missing or older than the tenant's `max_snapshot_age` (default 24h) → reject (`snapshot_stale`); decision deny → reject with reason. AD unreachable → the last successfully synced state continues to apply until it ages past the limit; accounts AD reports as disabled/locked/deleted are denied at the next sync.
- **Freshness:** directory sync every 15 min (configurable) and on demand; certificate, rule and revocation changes republish immediately. The agent pulls every 15 seconds (and on SIGHUP), so a change reaches RADIUS within about 15 seconds. Snapshot age is shown on the dashboard and enforced by RADIUS.
- **Revocation latency, honestly:** new authentications are rejected within seconds of revocation (snapshot + CRL). A device **already connected** keeps its session until it re-authenticates: controllers re-authenticate on `Session-Timeout` (default 8h, tenant-configurable) and may skip full EAP on roaming (PMK caching / OKC / 802.11r). For controllers with CoA enabled, EasyEAP sends a Disconnect-Request immediately to end the session (UDP 3799; Catalyst 9800 defaults to 1700). TLS session resumption is disabled by default so a resumed session cannot bypass the snapshot check.
- **Blast-RADIUS (CVE-2024-3596):** `require_message_authenticator = yes` and `limit_proxy_state = yes` on every client. RADIUS/UDP must not cross untrusted networks; use a site-to-site VPN, or RadSec where the controller supports it (planned).
- **Wired 802.1X** ([plan and critique](docs/plans/wired-8021x.md)). Each RADIUS client is registered for Wi-Fi, wired or both (`radius_clients.networks`). FreeRADIUS decides which network a request is, in this order: a `Called-Station-Id` of the form `MAC:` with an empty SSID (hostapd's wired form) → wired; `NAS-Port-Type` Ethernet → wired, Wireless-802.11 → Wi-Fi; the client's only registered network; an SSID in `Called-Station-Id` → Wi-Fi, otherwise wired. A request for a network the client isn't registered for is rejected (`network_not_enabled`) before EAP; `Service-Type = Call-Check` (MAB) is rejected as `mab_unsupported`. Nested registrations (a switch inside a controller's range) resolve to the longest prefix, in FreeRADIUS and in EasyEAP's event attribution and CoA.
- **VLANs on switch ports.** Each decision has a Wi-Fi VLAN and a wired VLAN (`decisions.wired_vlan_id`), from each VLAN's `wired_mode`: the same VLAN, none (the port keeps its own), or another ID. The snapshot carries both; the agent stores the wired VLAN in `authz_wired`, tied to the snapshot version, so any mix of agent, configuration and API versions falls back to the Wi-Fi VLAN (1.0.1 behaviour) and never to another decision.
- **Monitor mode.** A switch whose port plan is in monitor mode is rendered with `easyeap_monitor = yes`: FreeRADIUS still decides and logs, but sends no Tunnel or extra attributes, and the event records the VLAN it would have assigned. The switch's own configuration keeps its ports open. Enforce is an explicit, audited step; the console asks for the switch's session list first.
- **Configuration management:** the agent fetches the desired state (tenants, clients, virtual servers, certificates) from the API, renders FreeRADIUS configuration from templates, validates it with `freeradius -C` in a staging directory, swaps it atomically and restarts FreeRADIUS; on validation failure it keeps the running configuration and reports the error to the API (shown in System Health). Shared secrets reach the agent over the authenticated channel and live only on the RADIUS volume (mode 0600).

## 6. Access-policy precedence

Deterministic, documented in the UI, identical in the backend engine and the UI preview:

1. **Account gate:** directory account disabled, locked out or deleted → deny (not overridable).
2. **Certificate gate:** revoked or expired → deny.
3. **Explicit deny:** any enabled Deny rule matching any of the identity's groups (transitive, including the primary group via `tokenGroups`) → deny. Deny always wins.
4. **First allow:** the enabled Allow rule with the lowest priority number wins (ties broken by rule id; the UI prevents ties). Its VLAN and extra attributes are returned.
5. **Default:** the tenant default (deny unless an administrator configures allow + default VLAN).

Every decision stores its full trace (`steps`), shown as "why this VLAN" on the user page and in authentication logs.

**Staged changes.** The console never edits live rules one at a time. An administrator edits a draft (rules in order plus the tenant default), asks for an impact preview, and publishes:

- `POST /api/tenants/{id}/policy/preview` evaluates both the live policy and the draft for every user (per certificate purpose they hold) against the current directory data and returns who is newly allowed, newly denied or moves VLAN, with the draft's decision trace. It never writes.
- `POST /api/tenants/{id}/policy/publish` replaces the rules, their order and the default in one transaction, recomputes decisions and republishes the snapshot. Each draft carries the `revision` (a fingerprint of the live policy) it started from; a stale draft is refused with 409, so two administrators can't silently overwrite each other. The impact summary is written to the audit log.

**Posture and the needs-action queue** (`app/posture.py`). For each tenant the API reports whether RADIUS can enforce it (CA, server certificate, at least one controller, tenant active), when its local snapshot would fail closed (`snapshot_built_at + max_snapshot_age`), whether the worker is still refreshing it, and whether the agent has applied the latest version. The dashboard's queue lists what needs action, ranked by severity, then time until users are affected, then how many people are affected; every item names one action and the screen that performs it.

## 7. Directory (Active Directory)

LDAPS (636) or LDAP + StartTLS with certificate verification against an uploaded CA bundle; plain LDAP is refused unless explicitly enabled in Advanced settings. Read-only service account. Users are keyed by `objectGUID`; transitive group membership comes from `tokenGroups` (resolving the primary group such as *Domain Users*, which `memberOf` omits); account state from `userAccountControl` (disabled) and `msDS-User-Account-Control-Computed` (locked out). Users missing from a full sync are marked deleted and denied. Library: `ldap3` (pure Python) with explicit TLS context.

## 8. Data model (summary)

| Domain | Tables |
|---|---|
| Platform | `tenants`, `admins` (Argon2id hash, TOTP secret ciphertext), `admin_sessions` (token hash), `role_grants`, `platform_settings`, `jobs`, `audit_events` (hash-chained: each row stores `sha256(prev_hash ‖ canonical_row)`; UPDATE and DELETE revoked from the application role) |
| PKI | `certificate_authorities` (metadata + PEM, never private keys), `certificate_templates`, `certificates` |
| Identity | `directory_configs` (bind secret ciphertext, last sync status and stats), `directory_groups`, `identities`, `identity_groups`, `devices` |
| Policy | `vlans` (with what switch ports get), `access_rules`, `access_rule_groups`, `policy_settings`, `decisions` (per certificate, with trace and the wired VLAN) |
| RADIUS | `radius_settings` (snapshot version and build time, server key ciphertext, wired enrollment on/off), `radius_clients` (secret ciphertext, networks served, the switch's port plan and rollout mode), `auth_events` (network, switch port, monitor), `accounting_sessions`, `coa_requests`, `agent_status` |
| Enrollment | `enrollments` (token hash, method, status, expiry), `key_escrow` (ciphertext, one-time) |

Migrations: Alembic, run automatically by the api container on start (`alembic upgrade head`) under an advisory lock.

## 9. Frontend

React 19 + TypeScript + Tailwind CSS v4 + Radix primitives, React Router (hash routes) and TanStack Query. Two production entries:

- **Console** (`index.html`, `src/app/`): the design direction chosen in `design/CONCEPTS.md`, Concept F ("Modern Security Management") with Concept D's needs-action queue and Concept E's command palette. A search-first sidebar is scoped to the current tenant (`/`), and a command palette (Ctrl/Cmd+K) starts entity actions such as issue, revoke, rotate secret and test a user. The decision ledger renders the backend's decision trace on the user page, in Test a user and in the policy preview. Each status carries the age of its source data, and "allowed by policy" is shown separately from "can connect".
- **Enrollment portal** (`enroll.html`, `src/enroll/`): the end-user flow behind a one-time link. The default path generates the key pair on the device with WebCrypto, builds the CSR and PKCS#12 in the page with PKI.js, and never sends or stores the private key.

The design prototypes (`design.html`, `src/concepts/`, `src/prototype/`) are a separate entry that only `vite build --mode design` emits; their synthetic data never ships in the production bundle. Mutations carry the CSRF header; no secret reaches the browser except one-time displays (a new shared secret, an enrollment link, a server-generated package password, the encrypted root-key file from the CA ceremony).

## 10. Technology decisions

| Decision | Choice | Why |
|---|---|---|
| Backend | Python 3.13, FastAPI, SQLAlchemy 2, Alembic, Pydantic v2, psycopg 3 | Mature ecosystem for LDAP, X.509 (pyca/cryptography for packaging and parsing only), RADIUS tooling; typed OpenAPI. |
| Jobs | In-database job table + worker loop (`SELECT … FOR UPDATE SKIP LOCKED`) | No extra broker container; jobs survive restarts; simple to back up. |
| PKI | OpenBao PKI + Transit | See §3. |
| RADIUS | FreeRADIUS 3.2.10 | Stable branch with Blast-RADIUS mitigations, `rlm_sql_sqlite`, `linelog`, CRL reload. |
| Passwords | Argon2id (argon2-cffi) | Memory-hard, current OWASP recommendation. |
| MFA | TOTP (RFC 6238) | Works offline, no external dependency. |
| Proxy | nginx-unprivileged | Non-root, small, well understood. |

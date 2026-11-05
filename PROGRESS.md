# Progress

Status as of 2026-11-05 (release 1.0.0).

## Complete

### Platform and deployment
- [x] Compose stack: proxy, API, worker, PostgreSQL 18, OpenBao 2.4.1, FreeRADIUS 3.2.7 + radius-agent
- [x] Segmented internal networks; RADIUS has no route to the database or OpenBao
- [x] `install.sh` (secrets generated once, `.env`, temporary TLS), encrypted `backup.sh`, `restore.sh` with audit verification
- [x] Lab profile: Samba AD domain controller and `eapol_test` Wi-Fi client
- [x] Development override with a hot-reloading API

### Security
- [x] No default account; one-time setup token
- [x] Argon2id, TOTP, server-side sessions, CSRF, lockout and rate limits
- [x] RBAC: platform and per-tenant roles; issuing separate from CA management
- [x] PostgreSQL row-level security with a non-owner, NOBYPASSRLS application role
- [x] Per-tenant Transit envelope encryption for shared secrets, bind passwords, escrowed keys
- [x] Hash-chained audit trail, verifiable from the console and the CLI
- [x] Log redaction; strict CSP and security headers; non-root containers

### PKI
- [x] Offline Root CA ceremony (encrypted root key returned once, online copy destroyed)
- [x] Issuing CA inside OpenBao (never exported); templates; RADIUS server certificate
- [x] CRL and OCSP on plain HTTP; revocation with RFC 5280 reasons (permanent; no hold)

### Directory
- [x] LDAPS sync with a read-only account: users, nested groups via `tokenGroups`, account state
- [x] Scheduled sync; failures surface in the needs-action queue

### Policy
- [x] Precedence engine with full decision traces (backend authoritative; frontend mirror for prototypes, shared fixtures)
- [x] Staged drafts: impact preview against every real user; atomic publish with optimistic concurrency
- [x] Tenant posture: enforceability, fail-closed deadline, needs-action queue

### RADIUS
- [x] Per-tenant virtual servers, EAP-TLS, trust anchors and CRL checks
- [x] Local SQLite authorization snapshot; fails closed when stale; keeps working with the API down
- [x] Dynamic VLANs (Tunnel-Type 13, Tunnel-Medium-Type 6, Tunnel-Private-Group-ID)
- [x] CoA Disconnect on revoke; Blast-RADIUS mitigations; dedicated port pairs for overlapping addresses
- [x] Controller guides for Cisco Catalyst 9800, AireOS and UniFi (console and `docs/controllers/`)

### Enrollment
- [x] One-time, device-bound links (72-hour default)
- [x] On-device keys by default (browser WebCrypto + PKI.js; TPM-aware Windows helper)
- [x] Opt-in server-generated PKCS#12, one download, purged when undelivered

### Console and portal
- [x] Foundation: theme, API client, session, tenant scope, search-first shell, command palette
- [ ] Screens: see "In progress"
- [ ] Enrollment portal: see "In progress"

### Tests
- [x] Backend unit tests; RLS and policy-draft integration tests; RADIUS renderer tests
- [x] Shared policy fixtures for the backend and frontend engines
- [x] End-to-end EAP-TLS through FreeRADIUS against a real domain controller (`tests/e2e/run.sh`)
- [x] Frontend unit tests (formatting, routes, decision ledger)
- [ ] Console browser smoke test against the full stack

## In progress

- Console screens and the enrollment portal (being integrated)

## Not done / known limitations

- **SCEP and MDM enrollment** (Intune, Jamf) are not implemented. Apple devices enroll with a configuration profile
  from the portal.
- **RadSec** (RADIUS over TLS) between controllers and EasyEAP is not implemented. Use a site-to-site VPN.
- **Email delivery** of enrollment links is not built in. Administrators copy the one-time link and send it.
- **High availability.** There is one RADIUS node per deployment. Running a second node against the same API is
  designed for (agent node IDs) but not tested.
- **Directory sources** other than Active Directory over LDAPS (Entra ID, Google Workspace) are not supported.

## Planned

- SCEP for MDM-managed devices
- RadSec
- Additional RADIUS nodes with health in System
- Email notifications for expiring certificates and failing directory syncs

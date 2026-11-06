# Progress

Status as of 2026-11-06 (release 1.0.0).

## Complete

### Platform and deployment
- [x] Compose stack: proxy, API, worker, PostgreSQL 18, OpenBao 2.4.1, FreeRADIUS 3.2.10 + radius-agent
- [x] Segmented internal networks; RADIUS has no route to the database or OpenBao
- [x] `install.sh` (secrets generated once, `.env`, temporary TLS)
- [x] Full backup and restore from the console and the first-run page (age-encrypted `.easyeap`, step-by-step
      progress, automatic rollback); `backup.sh` / `restore.sh` wrap the same engine for scheduling
- [x] System log (30 days) and remote syslog (TLS/TCP/UDP, RFC 5424/3164, text/JSON, at-least-once with catch-up)
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
- [x] Screens: MSP tenants overview, system health, tenant dashboard, users and decision ledger, certificates and
  revocation, authentication log, access policy (draft, preview, publish, Test a user), RADIUS, directory, certificate
  authority, audit (tenant and platform), administrators, tenant setup wizard, tenant settings, account security
- [x] Enrollment portal: platform detection, on-device keys, per-platform packages and instructions, clear states for
  used, cancelled and expired links

### Tests
- [x] Backend unit tests; RLS and policy-draft integration tests; RADIUS renderer tests
- [x] Shared policy fixtures for the backend and frontend engines
- [x] End-to-end EAP-TLS through FreeRADIUS against a real domain controller (`tests/e2e/run.sh`)
- [x] Frontend unit tests (formatting, routes, decision ledger)
- [x] Console browser smoke test of every screen against the production build behind the proxy and CSP
- [x] GitHub Actions CI: backend lint and unit tests, frontend checks and build, image builds
- [x] Verified with a live Cisco Catalyst 9800 and an iPhone enrolled through the portal

## Not done / known limitations

- **SCEP and MDM enrollment** (Intune, Jamf) are not implemented. Apple devices enroll with a configuration profile
  from the portal.
- **RadSec** (RADIUS over TLS) between controllers and EasyEAP is not implemented. Use a site-to-site VPN.
- **Email delivery** of enrollment links is not built in. Administrators copy the one-time link and send it.
- **High availability.** There is one RADIUS node per deployment. Running a second node against the same API is
  designed for (agent node IDs) but not tested.
- **Directory sources** other than Active Directory over LDAPS (Entra ID, Google Workspace) are not supported.
- **Real-device installs** are confirmed on an iPhone: it enrolled through the portal with its key made on the
  device, and authenticated through a live Cisco Catalyst 9800 onto its VLAN. Windows, macOS and Android packages are
  checked by format and by the end-to-end EAP-TLS test, not yet by installing them on physical devices.
- **iOS profile hand-off.** A profile built on the device (the default) reaches Safari's profile installer through a
  blob URL, because the key never leaves the page. This worked on the iPhone above; other iOS versions aren't
  confirmed. Server-generated packages (opt-in) are served as a regular download.
- **New administrators** are not forced to change the password they were given, and two-factor authentication is
  not mandatory. Each administrator turns on TOTP under Account; the Administrators screen flags anyone without it.
- **PKCS#12 MAC.** Packages use PBES2 (PBKDF2-SHA256, 600,000 iterations) with AES-256-CBC, but the integrity MAC
  uses 2,048 iterations (the OpenSSL default, kept for device compatibility). The generated passwords are strong
  enough that this is not the weak point; see SECURITY.md.

- **Root CRL renewal.** The root CA's revocation list is signed at the ceremony and valid for a year. RADIUS
  doesn't check it, but clients that check the whole chain may refuse the RADIUS server once it lapses. Renewing it
  needs the offline root key, and the console can't do that yet; the dashboard warns 60 days ahead.
- **Backups of installations made with a preview build before 1.0.0** can regain CA access only within 32 days of being made (no OpenBao
  recovery keys were kept). The console shows each backup's restore-by date.

## Planned

- SCEP for MDM-managed devices
- RadSec
- Additional RADIUS nodes with health in System
- Email notifications for expiring certificates and failing directory syncs

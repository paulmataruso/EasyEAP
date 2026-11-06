# Changelog

All notable changes to EasyEAP. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Backup and restore in the console.** System health → Backup and restore makes a complete, encrypted backup
  (database, every CA key, secrets) as one `.easyeap` file, and restores one with a step-by-step progress screen and
  automatic rollback on failure. A new installation's first-run page offers **Set up new** or **Restore a backup**.
  `deploy/backup.sh` and `restore.sh` now drive the same engine, for scheduling only.
- **System log and remote syslog.** The console keeps 30 days of messages from the API, worker, RADIUS agent and
  FreeRADIUS (System health → System log), and forwards them, the audit trail and every authentication to up to four
  syslog servers over TLS, TCP or UDP (RFC 5424 or 3164, text or JSON), with a test message, delivery status and
  catch-up after outages.
- **Base DN detection.** Directory settings read the base DN and AD domain from the domain controller's RootDSE with
  "Detect from domain controller". It needs only the controller's name and TLS settings and tries without signing
  in first. The base DN also follows the AD domain as you type, and Test connection names the directory's real base
  DN when the one entered is outside it.

### Changed

- **One enforcement status everywhere.** The dashboard, Tenants page, tenant switcher and users' "Can connect" now
  show the same status, computed once on the server. It accounts for FreeRADIUS actually running, the tenant being in
  RADIUS's running configuration, an expired snapshot, and a short grace while a change is applied.
- **Truthful status chips.** The root CA reads "Key held offline" (neutral: it's by design) instead of "Offline". The
  issuing CA chip reflects its validity and whether the CA service answers. System health labels each service by what
  it does (Reachable, Ready, Running, Idle, Delivering) and checks EasyEAP's OpenBao token, not only the seal. Renewed
  certificates show "Renewed" instead of "Active", and the certificate counts add up.
- **New needs-action items:** FreeRADIUS stopped, tenant missing from RADIUS's configuration, snapshot expired,
  directory stale or never synced, revocation list expiring, issuing CA expired, root revocation list expiring, and
  tenant suspended. Backup reminders point at the console instead of `backup.sh`.
- **Directory sync interval** must now be at most half the fail-closed limit, so one missed sync can't make RADIUS
  deny everyone.
- **New logo.** The sign-in and setup screens, sidebar, mobile top bar, enrollment page and favicon use the new EasyEAP mark: an amber E and wireless signal with a security key, on a charcoal tile. The source is `design/brand/mark.svg`.

### Fixed

- Signing out returns to the sign-in screen at once.
- OpenBao recovery keys were discarded at install (`recovery_keys_base64`). New installations keep them, so backups
  can always regain CA access.
- The audit verification no longer claims to detect deleted entries at the end of the chain.
- "Enrolled" now means holding a valid certificate, so it clears when the last one is revoked or expires.
- Disconnect (CoA) requests that stall show "No reply recorded" instead of waiting forever.
- Saving a new directory connection blanked the console until the first sync finished. A configuration that hasn't
  synced yet now reports no statistics, and the page checks for complete statistics before showing them.
- A screen that hits a rendering error now shows what happened inside the console, with a reload button, instead of
  a blank page.
- The RADIUS status no longer reads "Not running" in red before any tenant is active. It shows "Idle" until a tenant
  is activated and "Starting" while the agent loads it. The RADIUS screen, dashboard and system overview check every
  5 seconds during that time instead of every 30.
- `install.sh` puts an IP address in the temporary TLS certificate as an IP subjectAltName. A DNS entry made browsers
  reject the certificate when the console hostname is an IP address.

## [1.0.0] - 2026-11-05

The first complete release: multi-tenant EAP-TLS with PKI, Active Directory, RADIUS, enrollment and the console.

### Added

- **Deployment.** One Docker Compose project with proxy, API, worker, PostgreSQL 18, OpenBao 2.4.1 and FreeRADIUS
  3.2.7, on segmented internal networks. Also:
  - `install.sh` generates every secret once;
  - encrypted `backup.sh` and `restore.sh`;
  - a lab profile with a Samba AD domain controller and an `eapol_test` Wi-Fi client;
  - a development override with a hot-reloading API.
- **Multi-tenancy.**
  - PostgreSQL row-level security on every tenant table, applied by a non-owner application role.
  - Per-tenant OpenBao PKI mounts and Transit keys.
  - Platform roles (Super Administrator, MSP Operator, MSP Auditor) and per-tenant roles (Tenant Admin, PKI Admin,
    Wi-Fi Admin, Auditor).
- **PKI.**
  - Offline Root CA ceremony: the encrypted root key is returned once, then destroyed online.
  - Issuing CA inside OpenBao.
  - Certificate templates, a RADIUS server certificate, CRL and OCSP over plain HTTP.
  - Revocation with RFC 5280 reasons.
- **Directory.** LDAPS sync with a read-only service account: users, nested groups via `tokenGroups` (including the
  primary group), account state, and a scheduled sync.
- **Access policy.**
  - Precedence: account gate, then certificate gate, then deny wins, then the lowest-priority Allow, then the tenant
    default (Deny).
  - Full decision traces.
  - Staged drafts with an impact preview against every real user.
  - Atomic publish with optimistic concurrency.
- **RADIUS.**
  - The radius-agent renders and validates FreeRADIUS configuration per tenant and keeps a local SQLite
    authorization snapshot.
  - Fails closed when the snapshot is stale.
  - Dynamic VLANs (`Tunnel-Type` 13, `Tunnel-Medium-Type` 6, `Tunnel-Private-Group-ID`).
  - CoA Disconnect on revoke.
  - Blast-RADIUS mitigations; dedicated per-tenant port pairs for overlapping controller addresses.
- **Enrollment.**
  - One-time, device-bound links.
  - Keys generated on the device: in the browser for macOS/iOS/Android/Linux, and with a TPM-aware PowerShell helper
    on Windows.
  - Opt-in server-generated PKCS#12 with a single download.
- **Monitoring.**
  - Authentication events in plain language, with fixes.
  - Tenant posture: enforceability, the fail-closed deadline, a needs-action queue.
  - A platform needs-action queue for backups and administrator two-factor.
  - Controller attribution by packet source, so last-request times and CoA targets are right when a controller
    reports a different NAS-IP-Address.
  - The issuing CA's revocation list: publish time, revoked count and validity.
  - Dashboard trends.
- **Console.**
  - React 19 with a search-first shell and a tenant-scoped search.
  - A command palette that starts actions.
  - The MSP tenants overview, the tenant dashboard, users with "can connect" status, certificates with revocation,
    the authentication log, the access policy editor with preview and publish, RADIUS, directory, certificate
    authority, audit, administrators, the tenant setup wizard, tenant settings and account security (TOTP).
- **Enrollment portal.** Detects the platform, generates keys in the browser and assembles the certificate package,
  with per-platform instructions.
- **Security.**
  - Argon2id passwords, TOTP, server-side sessions, CSRF tokens and rate limits.
  - A hash-chained audit trail (`easyeap verify-audit`).
  - Log redaction, a strict CSP, non-root containers.
- **Documentation.** README, ARCHITECTURE, SECURITY, DEPLOYMENT, DEVELOPMENT, DESIGN, controller guides,
  enrollment and troubleshooting.
- **Tests.**
  - Backend unit and integration tests (RLS, policy drafts).
  - Shared policy fixtures for both engines.
  - The RADIUS config renderer.
  - Frontend unit tests.
  - End-to-end EAP-TLS through FreeRADIUS against a real domain controller.
  - A browser smoke test of every console screen.
- **Design.** Six design concepts, a critique of each, and the chosen direction (`design/CONCEPTS.md`).

### Security

- Revocation is permanent. The certificate-hold state was removed from the domain model.
- Enrollment links stay single-use after they are used, cancelled or expire: the token hash is kept, the portal says
  which of those happened, and every action on a spent link returns 410. Per-address and per-token rate limits apply.
- One-time secrets (new RADIUS shared secrets, the offline root key bundle and its passphrase) are never stored in the
  console's query cache.
- The tenant default action changes only through a published policy draft. The settings endpoint rejects unknown fields.
- Tenant posture treats a stopped worker as a blocked refresh: the needs-action queue reports an offline worker, a
  missing snapshot and an overdue refresh before RADIUS starts failing closed.
- Fonts are served as files rather than inlined, so the strict CSP (`font-src 'self'`) holds without exceptions.

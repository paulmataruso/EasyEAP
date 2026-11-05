# Changelog

All notable changes to EasyEAP. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

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

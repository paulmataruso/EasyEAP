# Progress

Status as of 2026-11-06 (release 1.0.1).

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
- [x] Wired 802.1X for Cisco Catalyst (IBNS 2.0 and classic) and UniFi switches: Add switch wizard, monitor mode,
      readiness, Enforce, VLANs on switch ports, wired/Wi-Fi detection and refusal, MAB named, wrong-secret and
      unregistered-address diagnosis, wired enrollment (macOS, Linux) and the Windows wired kit
- [x] MAC authentication on switch ports (Cisco MAB, UniFi MAC-Based): the MAC allow list with groups and switch VLANs,
      Seen not allowed, bulk allow, CSV import and export, the Enforce gate, CoA on changes
- [x] Device administration over TACACS+ (Cisco IOS, IOS XE, Catalyst 9800): EasyEAP accounts with optional authenticator
      codes, AD group → role mappings checked in AD at login, per-device keys with rotation grace, break-glass names,
      the Admin log with masked commands

### Enrollment
- [x] One-time, device-bound links (72-hour default)
- [x] On-device keys by default (browser WebCrypto + PKI.js; TPM-aware Windows helper)
- [x] Opt-in server-generated PKCS#12, one download, purged when undelivered
- [x] Windows setup file: user and computer certificates (TPM or non-exportable software key), Wi-Fi and wired
  profiles, automatic renewal signed by the current key
- [x] Group Policy autoenrollment (preview): MS-XCEP and MS-WSTEP with Kerberos and channel binding; computers checked
  in AD (workstation flag, optional group, MachineAccountQuota warning) with their own identities and AD groups; one
  user certificate per user per PC; AD CS-style template OIDs and revisions, Re-enroll everyone; service-account
  scripts for Windows and Samba AD, keytab upload and live test; readiness and the request log

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
- [x] End-to-end EAP-TLS through FreeRADIUS against a real domain controller (`tests/e2e/run.sh`), including wired 802.1X,
      MAC authentication and TACACS+ logins with AD and EasyEAP accounts
- [x] RADIUS integration test on real FreeRADIUS without the API (`tests/radius/run.sh`), with 1.0.1 version skew; in CI
- [x] Upgrade from 1.0.1 to wired 802.1X on the lab stack: migration, existing controllers, VLANs and decisions kept
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
- **Wired 802.1X is not verified on switch hardware.** The generated Catalyst configuration has not been pasted onto a
  real Catalyst switch, and nothing has run against a UniFi switch: the RADIUS side is tested on real FreeRADIUS
  with real EAP-TLS, with the attributes Catalyst and UniFi switches document. Unverified on UniFi: CoA,
  re-authentication timing and the port type it reports. Also unverified on real devices: the Windows wired kit
  (`netsh lan`), and the macOS Ethernet payload.
- **MAC authentication is not verified on switch hardware** (Cisco MAB with IBNS 2.0 or classic, UniFi MAC-Based):
  tested on real FreeRADIUS with the attributes the switches document.
- **Device administration is not verified on Cisco hardware.** EasyEAP's TACACS+ service is tested against a protocol
  client that follows IOS's login sequence and against a Samba domain controller, not a real switch or 9800. No TACACS+
  over TLS (RFC 9887), no command authorization, no authenticator codes for AD accounts, and only Cisco devices.
  Known trade-offs (docs/device-administration.md): the AD bind limit and authenticator-code reuse are tracked per
  RADIUS node; fine-grained password policies aren't read; anyone who can reach a device's SSH can lock a named
  EasyEAP account for 15 minutes; FreeRADIUS and the TACACS+ service share the container user that can read the
  admin data.
- **Windows setup file not run on a real Windows 11 PC.** It's tested under PowerShell 7 with Windows' commands
  replaced by recorders; certreq with the TPM, netsh, the approval prompt and the scheduled tasks are unverified.
- **Group Policy autoenrollment is a preview, not run on a real Windows PC.** It's tested against Samba AD and a
  Kerberos client written from MS-XCEP and MS-WSTEP (channel binding, both request forms, refusals), through the real
  proxy, CA and FreeRADIUS. Windows' own parsing of the policy and of the CMC response, the TPM-or-software provider
  fallback and the sign-in-screen connection are unverified ([docs/autoenrollment.md](docs/autoenrollment.md)).
- **The switch audit is not verified on switch hardware.** It's tested against net-snmp's agent (SNMPv2c and SNMPv3
  SHA-256/AES-128) serving Catalyst-like CISCO-AUTH-FRAMEWORK-MIB and CISCO-ERR-DISABLE-MIB tables. Which IOS-XE
  releases implement those tables, and the cost of walking the session table on large stacks, are unverified
  ([docs/switch-audit.md](docs/switch-audit.md)).
- **Wired 802.1X gaps.** No IP-phone voice domain, no
  merge with an existing 802.1X configuration on a switch, no profiling or automatic approval for MAC authentication.
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
- Switch audit v1.1: syslog from switches (allow-listed messages, shown as "the switch says"), then UniFi through the
  UniFi Network application ([docs/plans/switch-audit.md](docs/plans/switch-audit.md) §9, §11)
- Group Policy autoenrollment: key attestation for TPM keys, and confirming it on real Windows 11 PCs
- Device administration phase 2: TACACS+ over TLS, command authorization, other vendors
- RadSec
- Additional RADIUS nodes with health in System
- Email notifications for expiring certificates and failing directory syncs

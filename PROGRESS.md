# Progress

Status as of 2026-11-09 (release 1.1.0). What's left to build and to test on real gear is in [TODO.md](TODO.md).

## Complete

### Platform and deployment
- [x] Compose stack: proxy, API, worker, switch-audit collector (`easyeap-collector`), syslog receiver
      (`easyeap-syslog`), PostgreSQL 18, OpenBao 2.4.1, FreeRADIUS 3.2.10 + radius-agent and the TACACS+ service; the
      collector and the syslog receiver report their heartbeats in System health
- [x] Segmented internal networks; RADIUS has no route to the database or OpenBao
- [x] `install.sh` (secrets generated once, `.env`, temporary TLS; also publishes syslog on UDP 514 when the host
      doesn't use it)
- [x] Full backup and restore from the console and the first-run page (age-encrypted `.easyeap`, step-by-step
      progress, automatic rollback); `backup.sh` / `restore.sh` wrap the same engine for scheduling
- [x] System log (30 days) and remote syslog (TLS/TCP/UDP, RFC 5424/3164, text/JSON, at-least-once with catch-up)
- [x] Time from the console (`easyeap-time`): the host chrony's NTP servers (server/pool, NTS, prefer, only these,
      with a fallback), clock status, health checks and alerts, an SNTP measurement without chrony; every log view
      shows the date and time to the second with the zone
- [x] Lab profile: Samba AD domain controller, `eapol_test` Wi-Fi client, and a pretend Cisco Catalyst (net-snmp) for
      the switch audit
- [x] Development override with a hot-reloading API

### Security
- [x] No default account; one-time setup token
- [x] Argon2id, TOTP, server-side sessions, CSRF, lockout and rate limits
- [x] RBAC: platform and per-tenant roles; issuing separate from CA management
- [x] PostgreSQL row-level security with a non-owner, NOBYPASSRLS application role
- [x] Per-tenant Transit envelope encryption for shared secrets, bind passwords, escrowed keys, pending enrollment
      links and setup-file codes
- [x] Hash-chained audit trail, verifiable from the console and the CLI
- [x] Log redaction; strict CSP and security headers; non-root containers

### PKI
- [x] Offline Root CA ceremony (encrypted root key returned once, online copy destroyed)
- [x] Issuing CA inside OpenBao (never exported); templates; RADIUS server certificate
- [x] CRL and OCSP on plain HTTP; revocation with RFC 5280 reasons (permanent; no hold)
- [x] No certificate issued past the issuing CA's expiry: lifetimes end an hour before the CA's, and issuance is
      refused with a clear reason when less than a day is left
- [x] Renewal settings (Certificate authority → Renewal): automatic renewal on or off for user, device and RADIUS
      server certificates, starting at 50–90 % of each certificate's own life (80 % by default); templates' renewal
      periods follow it (Group Policy's keep their own); when to prepare and switch to the next issuing CA
- [x] RADIUS server certificate rotation: by itself once due (only when the issuing CA can give the new one 30 days),
      the previous certificate and key kept 14 days for **Put the previous certificate back** (which pauses automatic
      rotation), and a dashboard watch for devices that fail the handshake after a rotation
- [x] Renewal protocol v2: daily check-ins signed with the certificate's key, the renewer saying what it is and which
      roots it trusts; every answer says when renewal starts and carries the tenant's roots (v1 unchanged). Each
      certificate's page shows what renews it, when renewal starts, the last check-in and what it was renewed into; the
      Renewal panel counts certificates that renew by themselves, have gone quiet, are overdue or need the user
- [x] Lost answers and lost keys: a resent renewal gets the certificate issued the first time; an unused renewed
      certificate is replaced (within 14 days, at most 3 times); refusals carry a code and are audited once a day
- [x] Renewed certificates retired (revoked once the device uses the newer one and the old one has been quiet for 7
      days; one still in use is listed on the dashboard instead); renewal conflicts (a certificate renewed with two
      keys) refused, audited and critical on the dashboard; revoking a certificate also revokes what it was renewed
      into, unless unticked

### Directory
- [x] LDAPS sync with a read-only account: users, nested groups via `tokenGroups`, account state
- [x] Scheduled sync; failures surface in the needs-action queue
- [x] Computer accounts for autoenrollment, read again by objectGUID and kept current by the sync (never imported as
      users)

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
- [x] Wired 802.1X for Cisco and UniFi switches: Add switch wizard, monitor mode, readiness, Enforce, VLANs on switch
      ports, wired/Wi-Fi detection and refusal, MAB named, wrong-secret and unregistered-address diagnosis, a
      SPAN-destination preflight, wired enrollment (macOS, Linux) and the Windows wired kit
- [x] Every Cisco switch family, with the configuration for the switch's own release: paste `show version` and
      EasyEAP reads the family, model, release and LAN Lite images, and offers only what that switch can do. IOS-XE
      (IBNS 2.0); classic IOS by release, down to the pre-12.2(50)SE `dot1x` dialect; Nexus 9000, 3000, 3548,
      5000/6000 and 7000 (NX-OS); Cisco Business (Catalyst 1200/1300, CBS220/250/350, SG/SF 200–550X); Meraki MS with
      Dashboard steps. No VLAN for switches that can't apply one
- [x] Monitor mode from EasyEAP's side for switches without an open mode (Nexus, Meraki MS other than MS130/MS150,
      classic IOS before 12.2(50)SE): MAC requests accepted with no VLAN, logged with what EasyEAP would decide;
      plain-PAP MAC requests recognised only with port evidence; Message-Authenticator required per switch (not from
      the families that send MAC requests without it)
- [x] MAC authentication on switch ports (Cisco MAB, UniFi MAC-Based): the MAC allow list with groups and switch VLANs,
      Seen not allowed, bulk allow, CSV import and export, the Enforce gate, CoA on changes
- [x] Device administration over TACACS+ (Cisco IOS, IOS XE, NX-OS, Cisco Business, Catalyst 9800): EasyEAP accounts
      with optional authenticator codes, AD group → role mappings checked in AD at login, per-device keys with rotation
      grace, break-glass names, the Admin log with masked commands
- [x] Switch audit for Cisco Catalyst, Nexus and Cisco Business: SNMPv2c (default) or SNMPv3 polling every minute
      (1 to 60) by the `easyeap-collector` container of ports, 802.1X/MAB sessions and err-disabled ports (as far as
      each family reports them), findings against EasyEAP's own answers with hysteresis and acknowledgement; a failed
      authentication in the switch's syslog brings the next poll forward
- [x] Device syslog: the `easyeap-syslog` container keeps everything switches and controllers send (access messages
      14 days, the rest 3) from Catalyst 9800, AireOS, UniFi, Meraki and other devices, and decodes it into the
      sessions a switch logged (started, authorized or failed and why, VLAN, IP, how it ended) and the clients a
      controller logged; extra source addresses per device; a live view under Investigate → Device syslog
- [x] A switch's or controller's whole configuration again, any time: **Fill in** the shared secret, the TACACS+ key
      and the switch audit's credentials (with the permission that may rotate them; each showing audited)

### Enrollment
- [x] One-time, device-bound links (72-hour default)
- [x] On-device keys by default (browser WebCrypto + PKI.js; TPM-aware Windows helper)
- [x] Opt-in server-generated PKCS#12, one download, purged when undelivered
- [x] Windows setup file: user and computer certificates (TPM or non-exportable software key), Wi-Fi and wired
  profiles, automatic renewal with `renew.ps1` 2.0 (a daily signed check-in, renewal from EasyEAP's date, the pending
  request kept across a lost answer, the old certificate deleted only after the new one checks in, a notice two
  weeks before expiry); the portal's Windows helper renews its certificate the same way
- [x] Windows setup as a program users double-click (`.exe`, not code-signed yet), for the setup file and the portal's
  helper; both accept EasyEAP's web certificate by its pinned key when the PC doesn't trust it
- [x] Linux setup script (`EasyEAP-WiFi-Setup.sh`): finds NetworkManager, iwd, or wpa_supplicant with systemd-networkd
  or dhcpcd, makes the key on the computer, adds the Wi-Fi network and, with NetworkManager, wired 802.1X (one 802.1X
  connection per port, each port's own settings kept, "other ports" for the rest); `--check` and `--remove`; renews by
  itself with renewal protocol v2
- [x] Given again without a new one: a pending link's **Show link**, and **Download setup file** for Windows (the same
  one-time codes, no new certificate), each audited; what's waiting for each person shown in Users, with an
  **Enrollment → Waiting for device** filter
- [x] Hand-over on the platform: a QR code for an iPhone, iPad or Android phone, **Download setup script** for Linux,
  and Issue certificate on Windows pointing to Windows setup
- [x] Group Policy autoenrollment (preview): MS-XCEP and MS-WSTEP with Kerberos and channel binding; computers checked
  in AD (workstation flag, optional group, MachineAccountQuota warning) with their own identities and AD groups; one
  user certificate per user per PC; AD CS-style template OIDs and revisions, Re-enroll everyone; service-account
  scripts for Windows and Samba AD, keytab upload and live test; readiness and the request log

### Console and portal
- [x] Foundation: theme, API client, session, tenant scope, search-first shell, command palette
- [x] Screens: MSP tenants overview, system health, system log, tenant dashboard, users (people and computers) and
  decision ledger, certificates and revocation, authentication log, Device syslog, access policy (draft, preview,
  publish, Test a user), RADIUS (controllers and switches, Add switch, the switch audit, Windows Group Policy), MAC
  allow list, Device administration (devices, EasyEAP accounts, directory access, Admin log), directory, GPO
  autoenrollment, certificate authority (with Renewal), audit (tenant and platform), administrators, tenant setup
  wizard, tenant settings, account security
- [x] Enrollment portal: platform detection, on-device keys, per-platform packages and instructions, clear states for
  used, cancelled and expired links

### Tests
- [x] Backend unit tests (including every Cisco family's configuration, device syslog decoding, renewal, and the Linux
      script's renewal run for real against a local HTTPS server); RLS and policy-draft integration tests; RADIUS
      renderer tests
- [x] Shared policy fixtures for the backend and frontend engines
- [x] End-to-end EAP-TLS through FreeRADIUS against a real domain controller (`tests/e2e/run.sh`), including wired 802.1X,
      MAC authentication, TACACS+ logins with AD and EasyEAP accounts, Group Policy autoenrollment (a Kerberos client
      written from MS-XCEP and MS-WSTEP against Samba AD, then EAP-TLS with the issued computer certificate), and the
      switch audit (SNMP and syslog) against a pretend Catalyst
- [x] RADIUS integration test on real FreeRADIUS without the API (`tests/radius/run.sh`), with 1.0.1 version skew; in CI
- [x] Windows setup without Windows (`tests/windows/run.sh`): PowerShell 7 parses the generated files and runs the
      setup's steps and `renew.ps1`'s decisions with Windows' commands replaced by recorders; v2 renewals and check-ins
      signed by the script's own code verify in EasyEAP
- [x] Kerberos acceptance for autoenrollment against a real MIT KDC (`tests/autoenroll/kerberos.sh`)
- [x] The Linux setup script end to end in containers (enroll, connect with EAP-TLS, get an address, renew, remove) on
      Ubuntu 22.04, 24.04 and 26.04 desktop, Ubuntu Server 24.04, Debian 13 and Fedora 43
- [x] Upgrade from 1.0.1 to wired 802.1X on the lab stack: migration, existing controllers, VLANs and decisions kept
- [x] Frontend unit tests (formatting, routes, decision ledger, port plans, switch audit, secrets filled in, giving a
      link again, renewal, Device syslog, the Linux portal page)
- [x] Console browser smoke test of the screens against the production build behind the proxy and CSP (not yet the
      system log, Device syslog or GPO autoenrollment)
- [x] GitHub Actions CI: backend lint and unit tests, frontend checks and build, image builds

### Verified on real gear
- [x] A live Cisco Catalyst 9800 and an iPhone enrolled through the portal (key made on the device), onto its VLAN
- [x] A Catalyst 3850 (IOS-XE 16.6.1), in monitor mode: the generated configuration taken (after the fixes it prompted
      in this release), an Ubuntu desktop's wired EAP-TLS accepted with the Linux setup script (2026-11-09), SNMP
      polling of its ports and sessions, and its 802.1X and session syslog messages decoded

## Not done / known limitations

- **SCEP and MDM enrollment** (Intune, Jamf) are not implemented. Apple devices enroll with a configuration profile
  from the portal.
- **RadSec** (RADIUS over TLS) between controllers and EasyEAP is not implemented. Use a site-to-site VPN.
- **Email delivery** of enrollment links and expiry notices is not built in. Administrators copy the one-time link
  and send it; certificates that can't renew by themselves (Apple and Android profiles, those installed by hand) are
  listed on the dashboard as they near expiry.
- **High availability.** There is one RADIUS node per deployment. Running a second node against the same API is
  designed for (agent node IDs) but not tested.
- **Wired 802.1X is verified on one switch, in monitor mode.** A Catalyst 3850 (IOS-XE 16.6.1) took the generated
  configuration and accepted an Ubuntu desktop's EAP-TLS with its ports open. Enforce (closed ports, VLANs from
  RADIUS) hasn't run on it, and no other Cisco family or release has run at all (classic IOS, other IOS-XE releases,
  NX-OS, Cisco Business, Meraki MS): their configuration follows Cisco's documentation for each release, and every
  guide says so. No device has authenticated through a UniFi switch yet: the port type it reports, re-authentication
  timing and CoA are unverified. Also unverified on real devices: the Windows wired kit (`netsh lan`) and the macOS
  Ethernet payload.
- **MAC authentication is not verified on switch hardware** (Cisco MAB on any family, UniFi MAC-Based): tested on
  real FreeRADIUS with the attributes the switches document.
- **Meraki has no CoA.** Meraki needs a session ID in each answer that EasyEAP doesn't send yet, so the Meraki steps
  leave RADIUS CoA off: revoking a certificate doesn't end a Meraki port's session, and the device is refused at its
  next authentication. No switch audit or admin logins on Meraki either.
- **Device administration is not verified on Cisco hardware.** EasyEAP's TACACS+ service is tested against a protocol
  client that follows IOS's login sequence and against a Samba domain controller, not a real switch or 9800. No TACACS+
  over TLS (RFC 9887), no command authorization, no authenticator codes for AD accounts, and only Cisco devices.
  Known trade-offs (docs/device-administration.md): the AD bind limit and authenticator-code reuse are tracked per
  RADIUS node; fine-grained password policies aren't read; anyone who can reach a device's SSH can lock a named
  EasyEAP account for 15 minutes; FreeRADIUS and the TACACS+ service share the container user that can read the
  admin data.
- **Windows setup file not fully run on a real Windows 11 PC.** It's tested under PowerShell 7 with Windows' commands
  replaced by recorders. A first real run got through the CA, the profiles and the renewal tasks, then stopped at the
  self-signed web certificate (fixed with the pin); certreq with the TPM, the approval prompt and the scheduled tasks
  running are unverified. The setup program (`.exe`) isn't code-signed: SmartScreen asks once, and Smart App Control,
  where it's on, blocks it (and the `.cmd`). Its
  renewal (`renew.ps1` 2.0) and the portal helper's renewal task are tested the same way and against a running
  EasyEAP's API, never on a PC.
- **Group Policy autoenrollment is a preview, not run on a real Windows PC.** It's tested against Samba AD and a
  Kerberos client written from MS-XCEP and MS-WSTEP (channel binding, both request forms, refusals), through the real
  proxy, CA and FreeRADIUS. Windows' own parsing of the policy and of the CMC response, the TPM-or-software provider
  fallback and the sign-in-screen connection are unverified ([docs/autoenrollment.md](docs/autoenrollment.md)).
- **RADIUS server certificate rotation hasn't run with real clients connected.** Whether devices accept the new
  certificate without a prompt, and whether putting the previous one back works for them, is unverified; the
  dashboard watches for devices that fail the handshake after a rotation.
- **The Linux setup script on real machines.** Besides the containers above, it has run on one Ubuntu desktop
  (wired, monitor mode), before the one-connection-per-port fix: the port then showed two 802.1X connections, and the
  first one tried got no address after the accept. The fix, Wi-Fi, and the renewer v2 (daily check-in, a renewal, a
  lost answer) are unverified on a real machine. The iwd and dhcpcd paths are written from their documentation and
  have never run. The renewer v2 hasn't had its own critic pass (its refusal handling and lost-key recovery were
  matched to Windows'). GNOME Settings' Wired page may list the "other ports" connection on a port bound by name, as
  it doesn't read the rule NetworkManager follows.
- **The switch audit is verified on one switch.** A Catalyst 3850 (IOS-XE 16.6.1) answers the polls (it has no
  cafAuthMethodRegTable; its port and session tables are enough) and its 802.1X and session syslog messages are
  decoded; the newer syslog lines (verbose logging, no discriminator), findings with real sessions and the live view
  aren't checked on it yet. Everything else is tested against net-snmp's agent (SNMPv2c and SNMPv3) serving
  Catalyst-like CISCO-AUTH-FRAMEWORK-MIB and CISCO-ERR-DISABLE-MIB tables, and with syslog formats from Cisco's and
  Ubiquiti's documentation and published logs sent from pretend devices: other IOS-XE releases, classic IOS, NX-OS,
  Cisco Business, the cost of walking the session table on large stacks, and syslog from a 9800, AireOS, UniFi or
  Meraki are unverified ([docs/switch-audit.md](docs/switch-audit.md)).
- **Wired 802.1X gaps.** No IP-phone voice domain, no merge with an existing 802.1X configuration on a switch, no
  profiling or automatic approval for MAC authentication. Not used yet: NX-OS 10.6(3)F's open mode (MDA), IBNS 2.0 on
  classic 15.2E (the classic form is generated), 802.1X session polling on Cisco Business.
- **A PAP request that isn't MAC authentication** is logged with the reason `tls_handshake` instead of saying that PAP
  is accepted only for MAC authentication.
- **The Renewal panel's counts** are worked out in Python for every valid certificate on each load; they need to move
  into SQL before a tenant has tens of thousands of certificates.
- **Directory sources** other than Active Directory over LDAPS (Entra ID, Google Workspace) are not supported.
- **Real-device installs** are confirmed on an iPhone (enrolled through the portal with its key made on the device,
  then onto its VLAN through a live Cisco Catalyst 9800) and an Ubuntu desktop (the Linux setup script, wired, above).
  Windows, macOS and Android packages are checked by format and by the end-to-end EAP-TLS test, not yet by installing
  them on physical devices. The QR hand-over hasn't been tried on a phone.
- **iOS profile hand-off.** A profile built on the device (the default) reaches Safari's profile installer through a
  blob URL, because the key never leaves the page. This worked on the iPhone above; other iOS versions aren't
  confirmed. Server-generated packages (opt-in) are served as a regular download.
- **Macs join after sign-in.** Mac profiles are installed for the user, so a Mac joins Wi-Fi only once someone signs
  in; there is no login-window profile yet.
- **New administrators** are not forced to change the password they were given, and two-factor authentication is
  not mandatory. Each administrator turns on TOTP under Account; the Administrators screen flags anyone without it.
- **PKCS#12 MAC.** Packages use PBES2 (PBKDF2-SHA256, 600,000 iterations) with AES-256-CBC, but the integrity MAC
  uses 2,048 iterations (the OpenSSL default, kept for device compatibility). The generated passwords are strong
  enough that this is not the weak point; see SECURITY.md.
- **Root CRL renewal.** The root CA's revocation list is signed at the ceremony and valid for a year. RADIUS
  doesn't check it, but clients that check the whole chain may refuse the RADIUS server once it lapses. Renewing it
  needs the offline root key, and the console can't do that yet (renewal phase 4); the dashboard warns 60 days ahead.
- **Backups of installations made with a preview build before 1.0.0** can regain CA access only within 32 days of being made (no OpenBao
  recovery keys were kept). The console shows each backup's restore-by date.

## Planned

- UniFi controller wizard: the RADIUS profile, a WPA2/WPA3-Enterprise network and 802.1X on switch ports set up
  through the UniFi Network API; the spike is under way on a real console
  ([docs/plans/unifi-wizard.md](docs/plans/unifi-wizard.md))
- Certificate renewal, phases 3–7 ([docs/plans/cert-renewal.md](docs/plans/cert-renewal.md) §15): assisted renewal
  for Apple, Android and hand-configured Linux (renewal links, email reminders, profile replacement); the root
  ceremony from the console (root CRL, the next issuing CA); switching to a new issuing CA; root rollover; spikes
  (Windows key-based renewal outside the domain, Apple ACME with device attestation, an Android app)
- SCEP for MDM-managed devices
- Switch audit: UniFi switches through the UniFi Network application ([docs/plans/switch-audit.md](docs/plans/switch-audit.md) §11)
- Switch audit extras: SNMP traps to trigger polls, CDP/LLDP neighbours to suggest ports to leave alone, a scheduled
  audit report
- Meraki: CoA and the Meraki Dashboard API
- Group Policy objects created from the console (the Wi-Fi and wired profiles, and autoenrollment)
- Group Policy autoenrollment: key attestation for TPM keys, and confirming it on real Windows 11 PCs
- Windows setup as a signed `.exe`
- A computer-wide Mac profile (login window), so a Mac joins Wi-Fi before anyone signs in
- Device administration phase 2: TACACS+ over TLS, command authorization, other vendors
- RadSec
- Additional RADIUS nodes with health in System
- Email notifications for expiring certificates and failing directory syncs, and email delivery of enrollment links

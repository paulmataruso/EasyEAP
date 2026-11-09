# Changelog

All notable changes to EasyEAP. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Windows setup as a program.** **Download setup** in the console and the portal's Windows helper now give a `.exe`
  users double-click, instead of a `.cmd` file or a PowerShell script to right-click and run. It carries the same setup
  and runs it the same way, in the same window. **Download the .cmd instead** still gives the file. The program isn't
  code-signed yet: SmartScreen asks once (**More info**, then **Run anyway**), and Smart App Control, where it's on,
  blocks it as it blocks the `.cmd`.

### Fixed

- Windows setup files, the portal's Windows helper and their renewal tasks couldn't reach EasyEAP when the PC didn't
  trust its web certificate, such as the temporary self-signed one `install.sh` makes: each request failed with "Could
  not establish trust relationship for the SSL/TLS secure channel". They now accept that certificate when its public
  key is the one the file was made with, as the Linux script does. Files made before this fix still fail that way:
  download them again.

## [1.1.0] - 2026-11-09

Wired 802.1X and MAC authentication on Cisco, Meraki MS and UniFi switches; switch logins over TACACS+; a switch
audit over SNMP and syslog; device syslog from switches, controllers and access points; a Windows setup file, a Linux
setup script and Group Policy autoenrollment (preview); and certificates that renew themselves, with renewal
settings, renewal protocol v2 and retirement of renewed certificates.

### Upgrading from 1.0.x

- Back up first (System → Backup and restore, or `deploy/backup.sh`). Database migrations `0004` to `0015` run by
  themselves when the API starts. A 1.0.x API can't start on the migrated database, so to go back, restore that
  backup into a fresh 1.0.x installation.
- Two new containers, **`easyeap-collector`** (the switch audit's poller) and **`easyeap-syslog`** (UDP 5514), start
  with the stack. New settings in `deploy/.env.example`: `EASYEAP_TACACS_BIND` (TCP 49, device administration),
  and `EASYEAP_SYSLOG_BIND` and `EASYEAP_SYSLOG_PORT` (syslog, UDP 5514). Both listen on 127.0.0.1 only until you set
  the address switches reach EasyEAP on.
- Migration `0014` recalculates the renewal period of every certificate template except Group Policy's from the new
  renewal settings (from 80 % of the certificate's life by default); check Certificate authority → Renewal after
  upgrading.
- Windows setup files and Linux setup scripts made before 1.1.0 keep renewing with renewal protocol v1, on the days
  they were made with. Make new ones (or have users download theirs again) for the daily check-in and renewal from
  EasyEAP's date.

### Added

- **Certificate renewal settings** (Certificate authority → Renewal; [plan](docs/plans/cert-renewal.md) §15a): turn
  automatic renewal on or off for user certificates, device certificates and the RADIUS server certificate, and choose
  when it starts: 50 to 90 % of each certificate's own life (80 % by default). Templates' renewal periods follow the
  percentage (shown read-only in the template dialog); Group Policy templates keep their own. The panel also shows
  when to prepare and switch to the next issuing CA.
- **The RADIUS server certificate rotates by itself** once due (checked every 6 hours, only when the issuing CA can
  give the new one 30 days or more). The previous certificate and key are kept 14 days: **Put the previous
  certificate back** on the RADIUS page undoes a rotation (manual or automatic) and pauses automatic rotation. The
  dashboard watches for devices that connected the week before a rotation and have failed the handshake since.
- **Refused renewals are audited** (Certificate renewal refused, with the reason), once a day per certificate and
  reason.
- **How each certificate renews** ([plan](docs/plans/cert-renewal.md) §15b): its page shows what renews it (Windows
  setup file, Linux script, Group Policy, or a new link), when renewal starts, the renewal task's last check-in and what
  it was renewed into. The Renewal panel counts certificates that renew by themselves, have gone quiet, are overdue or
  need the user.
- **Renewal protocol v2** on the server: renewal tasks can check in daily without renewing (signed with the
  certificate's key) and report what they are and which roots they trust; every answer says when renewal starts and
  carries the tenant's root certificates. v1 is unchanged.
- **The Linux setup script's renewal uses it** (scripts made from now on): it checks in daily, renews from the date
  EasyEAP gives instead of the days it was made with (those are the fallback when EasyEAP can't be reached), and says
  which roots it trusts.
- **The Windows setup file's renewal uses it too** (`renew.ps1` 2.0, files made from now on;
  [plan](docs/plans/cert-renewal.md) §15c): a daily signed check-in, renewal from EasyEAP's date, the new key and
  request kept until the new certificate is in (a lost answer is asked again with the same request), the new
  certificate confirmed by a check-in with its own key before the old one is deleted, and only the certificate it
  renewed deleted (never Group Policy's or another EasyEAP one in the same store). Users are notified once a day when
  their certificate is two weeks from expiry and didn't renew. The shared user task also runs daily, and two minutes
  after sign-in and unlock.
- **The portal's Windows helper renews its certificate**: it leaves a task for its user that runs the same script,
  unless a setup file already renews everyone's certificate on that PC. The certificate's page says "Windows enrollment
  helper".
- **Retire renewed certificates** (on by default): a superseded certificate is revoked once its device uses the newer
  one and the old one hasn't connected for 7 days. A device still presenting the old one is listed on the dashboard
  instead (**A renewed certificate is still in use**).
- **Renewal conflicts** (critical on the dashboard): a renewal signed by a certificate that another key already renewed,
  when that newer certificate is in use, is refused and audited (**Certificate renewed with two keys**).
- **Revoking a renewed certificate revokes what it was renewed into**, unless you untick it in the dialog.
- **Device syslog, live** (Investigate → Device syslog; [plan and critique](docs/plans/syslog-full.md)): everything
  this tenant's switches and controllers send, as it arrives (checked every second while the page is open). A message
  repeated within the minute moves to the top with its count. Filter by device, access messages, warnings and errors,
  or any text; pause, clear and load earlier messages. Today's received, kept and over-the-limit counts per device.
  MSP operators also see the addresses syslog comes from that aren't a device with syslog on, with an example message.
- **The whole log, decoded**: EasyEAP keeps every message (access messages 14 days, the rest 3) instead of only the
  access ones, and puts sessions together from them: **Sessions the switch logged** on the switch audit (started,
  authenticated, authorized or failed and why, VLAN, IP, ended by link down or a MAC move), and the clients a
  controller logged. The switch configuration adds `authentication logging verbose`, `dot1x logging verbose` and
  `mab logging verbose` (session start and success messages, off by default), and drops the logging discriminator; a
  switch set up earlier gets `no logging discriminator EASYEAP` in its block.
- **Syslog from controllers and other devices**: Catalyst 9800, AireOS and the vWLC, UniFi (access points' `hostapd`
  and the console's client events), Meraki and others. In RADIUS, select the device, then **Keep syslog from this
  device**: the panel has the lines to paste or the steps, the extra addresses it sends from (up to 8), its counters,
  what it said about access and the clients its log describes. An address that overlaps another tenant's device is
  refused.
- **UDP 514 for syslog** (`deploy/docker-compose.syslog514.yml`): `install.sh` publishes it when the host doesn't use
  it, for AireOS controllers and switches that send only there.
- **The switch audit polls every minute by default** (1 to 60 minutes; a poll takes about 0.1 s), and a failed
  authentication in the switch's syslog brings the next poll forward to within seconds (30 s after the last poll at
  the earliest).
- **A switch's or controller's whole configuration, any time, with its secrets**: **Fill in the shared secret** (and
  **Fill in the TACACS+ key**, **Fill in the credentials** for the switch audit) puts the secret EasyEAP already keeps
  into the configuration on screen, so pasting it again no longer means generating a new secret. It needs the
  permission that may rotate that secret, and each showing is in the audit log. Removing the switch audit gives the
  removal lines with the community filled in.
- **Show an enrollment link again**: a pending link's **Show link** on the user's page, until the device enrolls, the
  link is cancelled or it expires, so a lost link no longer means cancelling it and sending a new one. The link is
  kept encrypted with the tenant's key and cleared once it can't be used; each showing is audited. Links created
  before this version can't be shown again.
- **Download a Windows setup file again**: **Download setup file** on the user's page makes the same file with the
  same one-time codes (only those not used yet), its original choices and today's RADIUS settings; no new
  certificate. The codes are kept encrypted like links (migration 0013) and each download is audited.
- **What's waiting, in Users**: each person's waiting links and setup files by platform (**iPhone/iPad link
  waiting**, **Linux link waiting**, **Windows setup file waiting** and so on: show it, or download it again) right
  in the list, and an **Enrollment → Waiting for device** filter.
- **Hand a link over on its platform**: a new or shown-again link comes with a QR code for an iPhone, iPad or Android
  phone to scan, **Download setup script** for a Linux link (the script its page gives, same one-time code, audited)
  and that platform's next steps. **Issue certificate** on Windows points to **Windows setup**, which installs the
  computer's certificate too ([User and computer certificates](docs/enrollment.md#user-and-computer-certificates)).
- **Every Cisco switch family** for wired 802.1X, with the configuration for the switch's own release
  ([plan and critique](docs/plans/cisco-platforms.md)). Not verified on Cisco hardware; every guide says so.
  - **Paste `show version`** in Add switch: EasyEAP reads the family, model, release and LAN Lite images, and the port
    plan offers only what that switch can do (host modes, VLAN for devices without 802.1X, what happens while EasyEAP
    is unreachable), with what it can't do and what EasyEAP assumed shown above the plan.
  - **Classic IOS by release**: `radius-server host` before 15.2(3)E, `dot1x critical` before 12.2(55)SE, no CoA before
    12.2(52)SE, LAN Lite limits, and the pre-12.2(50)SE `dot1x` dialect (`show dot1x all summary`,
    `dot1x re-authenticate interface`). An unknown release keeps the named RADIUS server already deployed.
  - **Nexus (NX-OS)**: Nexus 9000, 3000, 3548, 5000/6000 and 7000, by model and release
    ([docs/controllers/cisco-nexus.md](docs/controllers/cisco-nexus.md)). The Nexus 3600 is refused (no 802.1X).
  - **Cisco Business**: Catalyst 1200/1300, CBS220/250/350 and the SG/SF 200–550X
    ([docs/controllers/cisco-business.md](docs/controllers/cisco-business.md)). Models without an open mode start
    with one test port; the SG200 gets web interface steps.
  - **Meraki MS** as its own switch type, with Dashboard steps ([docs/controllers/meraki-ms.md](docs/controllers/meraki-ms.md)).
  - **Monitor mode from EasyEAP's side** for switches without an open mode (Nexus, Meraki MS other than MS130/MS150,
    classic IOS before 12.2(50)SE): EasyEAP accepts their MAC requests with no VLAN and a 30-minute session, and logs
    what it would decide. MAC authentication requests sent as plain PAP (Nexus, Meraki) are recognised only with port
    evidence and never when they look like an admin login.
  - **Message-Authenticator per switch**: not required from Nexus, Cisco Business, Meraki and pre-12.2(50)SE switches,
    which send MAC requests without it; Proxy-State without it is still dropped.
  - **Admin logins (TACACS+)** on NX-OS (`shell:roles` network-admin / network-operator, VDC roles on the Nexus 7000)
    and Cisco Business; the release picks the IOS form, and the "older IOS" choice appears only when it's unknown.
  - **Switch audit** on NX-OS and Cisco Business (ports, and err-disabled ports where the switch reports them), with
    each family's own SNMP and syslog block; NX-OS and Cisco Business syslog (letter severities) is parsed.

- **Linux setup script.** Linux enrollment links now offer `EasyEAP-WiFi-Setup.sh`: one command in Terminal finds
  NetworkManager, iwd, or wpa_supplicant with systemd-networkd or dhcpcd, creates the key on the computer, adds the
  Wi-Fi network (and wired 802.1X with NetworkManager, keeping each existing wired profile's own settings) for all
  users, and renews the certificate by itself. `--check` and `--remove`. Tested on Ubuntu 22.04, 24.04 and 26.04, Ubuntu Server 24.04, Debian 13 and Fedora 43
  ([docs/enrollment.md](docs/enrollment.md#linux-computers-the-setup-script)). `POST /api/enroll/{token}/csr` and
  `/renew` take `?format=pem`.
- **Renewal survives a lost answer.** A renewal request for an already-renewed certificate, signed by its key and
  carrying the same new key, gets the certificate issued the first time instead of "already renewed" (the Linux
  renewal and, from `renew.ps1` 2.0, the Windows renewal keep their pending request for this).

- **Wired 802.1X for Cisco Catalyst and UniFi switches**, with the same device certificates as Wi-Fi
  ([docs/controllers/cisco-catalyst-switch.md](docs/controllers/cisco-catalyst-switch.md),
  [plan and critique](docs/plans/wired-8021x.md)).
  - **Add switch** wizard on the RADIUS screen: the switch and its shared secret, a port plan (access ports, ports to
    leave alone, server-down and no-802.1X behaviour), then the configuration for that switch's ports with preflight
    commands, safe-paste steps (`reload in 15`) and a live wait for the first request. UniFi: steps, or "turn on wired
    for an existing registration".
  - **Monitor mode first.** A new switch's ports stay open and EasyEAP sends it no VLAN; the log shows the VLAN it
    would assign. The switch panel shows readiness by port, checks a pasted `show access-session`, and asks for
    confirmation before **Enforce**, then shows the change to paste only once RADIUS is sending VLANs (the agent now
    reports which configuration change it runs for each tenant). Back to monitor mode at any time. Switches in monitor mode for 14 days appear in
    the needs-action queue.
  - **VLANs on switch ports**: each VLAN gives switch ports the same VLAN, the port's own VLAN, or another VLAN ID.
    The policy simulator says when ports get something different from Wi-Fi.
  - **Which network**: each controller or switch is registered for Wi-Fi, wired or both. Requests are counted as
    wired or Wi-Fi from the port type, the SSID and the registration; a request for a network the client isn't
    registered for is refused (`network_not_enabled`), and MAC Authentication Bypass attempts are named
    (`mab_unsupported`).
  - **Authentication log**: a Network filter, the switch port, and monitor-mode attempts marked as such. Sessions show
    the port.
  - **Diagnosis while waiting for a switch**: FreeRADIUS's own log lines for an unregistered source address or a wrong
    shared secret, shown in the wizard.
  - **Enrollment**: "Wired settings in enrollment packages" (off by default) adds an Ethernet payload to macOS
    profiles and wired NetworkManager and `wpa_supplicant` files for Linux. Windows: the **Windows wired kit** (LAN
    profile, install script, Group Policy steps) for IT.
  - Nested registrations: a switch can be registered inside a controller's range; the longest prefix wins, as in
    FreeRADIUS. Events and CoA now match the same way.
- **MAC authentication on switch ports** for devices without 802.1X (printers, cameras, phones): Cisco MAB (IBNS 2.0
  and classic) and UniFi MAC-Based, opt-in per switch ([plan and critique](docs/plans/mac-auth.md)).
  - The **MAC allow list** screen: devices in groups, and each group gives its devices a VLAN on switch ports (or the
    port's own VLAN). Import and export as CSV, block and unblock, expiry dates, randomised addresses flagged.
  - **Seen, not allowed**: the MACs switches asked about, by switch and port, to allow one at a time or in bulk. While
    a switch is in monitor mode its ports stay open, so you can build the list before you enforce; Enforce warns about
    MACs still waiting.
  - A MAC that also signs in with a certificate needs an explicit confirmation to be listed.
  - Decisions are logged and explained (`mac_unknown`, `mac_disabled`, `mac_expired`, `mac_group_disabled`,
    `mab_not_enabled`, `mab_mismatch`, `mab_password`), and changes reach live sessions through CoA where it's on.
  - Wi-Fi doesn't use the list.
- **Device administration**: administrators log in to Cisco switches and Catalyst 9800 controllers with their AD
  account or an EasyEAP account, over TACACS+ to the RADIUS node
  ([docs/device-administration.md](docs/device-administration.md), [plan and critique](docs/plans/device-admin.md)).
  - EasyEAP's own TACACS+ service (RFC 8907) in the RADIUS container: ASCII and PAP logins, enable, exec
    authorization with the role's privilege level (only for sessions EasyEAP authenticated on that device, re-checked
    against the current accounts and mappings), session and command accounting. FAIL only for real denials and ERROR
    when EasyEAP can't decide (domain controllers down or slow, stale data, key mismatch, break-glass names), so
    devices fall back to their local accounts. One tenant's slow domain controllers can't hold up other tenants'
    logins or local accounts.
  - **EasyEAP accounts**: a local account database with the NIST SP 800-63B password rule, optional authenticator
    codes (typed after the password), sites, expiry, and lockout after 10 failures with Unlock.
  - **Directory access**: ordered AD group → role mappings, checked in AD at each login (nested groups included) over
    verified LDAPS or StartTLS, binding as the administrator. Failed binds stay under half the domain's lockout
    threshold within its observation window (both read from the domain's password policy at each sync), counting
    binds still in flight.
  - Per-device TACACS+ keys, shown once when created or rotated (later only by **Fill in the TACACS+ key**, audited),
    with a 24-hour grace on rotation; the generated configuration keeps the
    console port and local accounts as fallback, with preflight checks, `reload in 15` and a rollback.
  - The **Admin log**: logins, enables, sessions and commands, with secrets in commands masked; names that match no
    account are logged as a keyed hash.
  - Changing the address, type or site of a device with admin logins, or deleting it, needs a tenant administrator.
  - TCP 49 is published only when `EASYEAP_TACACS_BIND` is set to a reachable address.
  - Not yet verified on Cisco hardware: tested against a protocol client that follows IOS's login sequence.
- **Windows setup file**: one download per user that sets up a Windows 11 PC
  ([docs/windows-setup.md](docs/windows-setup.md), [plan and review](docs/plans/windows-setup.md)).
  - A user's page → **Windows setup**: the user's certificate, the **computer's certificate** (so the sign-in screen
    has network and people who never signed in on the PC can, without cached credentials), Wi-Fi, wired 802.1X, and a
    shared-PC mode. The file carries one-time codes that expire, never a key.
  - Keys are made on the PC, non-exportable: in the TPM (ECDSA, then RSA), or with the Microsoft Software Key Storage
    Provider on PCs without one, such as Windows 11 installed with the TPM bypass. The console shows **TPM** or
    **Software key** for each certificate.
  - Profiles use **User or computer authentication** and pick the EasyEAP certificate by its issuer.
  - **Automatic renewal**: scheduled tasks renew both certificates inside the template's renewal window; the current
    certificate's key signs the request (`POST /api/enroll/renew`), and the console shows "Renewed automatically".
  - Each step stands alone, the user part covers what the administrator part couldn't do, and the summary lists both.
  - `tests/windows/run.sh`: PowerShell parses the generated files and runs the setup's steps with Windows' commands
    replaced by recorders; renewals signed by the script's own code verify in EasyEAP. Not yet run on a real Windows 11 PC.
- **Windows Group Policy guide** ([docs/windows-group-policy.md](docs/windows-group-policy.md)) and a Windows Group
  Policy dialog on the RADIUS screen with the CA certificates and the Wi-Fi and wired profiles to import.
- **Switch audit (SNMP)**: EasyEAP reads a Cisco Catalyst's own view of its ports and 802.1X/MAB sessions and
  compares it with what EasyEAP decided and sent ([docs/switch-audit.md](docs/switch-audit.md),
  [plan and critique](docs/plans/switch-audit.md)).
  - **Findings**: planned ports not protected or open before authentication when enforcing, devices authorized without
    or despite EasyEAP, devices still connected after EasyEAP denied them (CoA missing), sessions outside the VLAN
    EasyEAP sent, MAB EasyEAP has off, critical authentication, err-disabled ports, a replaced switch, and SNMP failures.
    Two polls to open and two to resolve; acknowledge with a note; open ones in the needs-action queue.
  - **SNMPv2c by default** with a generated community bound to a read-only view and an ACL, or **SNMPv3** (SHA-256 or
    SHA-1, AES-128 or AES-256). The configuration block is generated; the credentials are stored encrypted and shown
    again only on request (**Fill in the credentials**). Test connection checks which tables the switch answers
    before monitoring turns on.
  - A new **`easyeap-collector`** container polls the switches (at most eight at once, every minute by default,
    "Poll now"), with its own heartbeat in System health and its own source in the system log.
  - **Enforce** uses the switch's polled session list instead of a pasted `show access-session` when it's recent.
  - **Syslog** ("what the switch says"): a new **`easyeap-syslog`** container receives the switches' messages on UDP
    5514 (and 514, above), published when `EASYEAP_SYSLOG_BIND` is set. Messages count from a switch's polled
    management address, once a poll there has succeeded, and from the extra addresses added for it; an address two
    switches claim is ignored. The 802.1X, MAB, err-disable, RADIUS server and configuration messages show on the
    switch's audit and under the matching findings, never as a finding on their own. An err-disable, a security
    violation, a configuration change or a failed authentication brings the next poll forward (30 seconds after the
    last at the earliest). Each RADIUS server the switch says is dead is shown until it's alive again or the switch's
    requests reach EasyEAP. Redacted, coalesced per minute, rate-limited per switch and per tenant; access messages
    are kept 14 days and the rest 3 (above). Heartbeat in System health. Migration `0010`.
- **Group Policy autoenrollment (preview)**: domain PCs and the users who sign in to them get certificates from
  EasyEAP through Group Policy, as from AD CS, and Windows renews them
  ([docs/autoenrollment.md](docs/autoenrollment.md), [plan and critique](docs/plans/gpo-autoenrollment.md)).
  - EasyEAP answers MS-XCEP (`/cep/<tenant>`) and MS-WSTEP (`/ces/<tenant>`) with Kerberos (SPNEGO, both Kerberos
    OIDs), channel binding to the proxy's TLS certificate required by default, NTLM refused and named.
  - **Computers are identities**: `NAME$` is checked in AD (computer account, workstation flag, enabled, optional
    computer group) and read again by objectGUID before every certificate, kept current by the directory sync, and
    listed under **Users → Computers**. Its `dNSHostName` must be its own (first label, AD domain, unique). A computer's
    certificate carries its `dNSHostName` and is decided with its own AD groups; access rules gain the certificate
    type **Domain computers**. On a PC that autoenrolls, the setup file's computer certificate is replaced.
  - Callers it isn't for get an empty policy, as from AD CS. The keytab keeps only EasyEAP's own keys; a
    whole-domain export is refused.
  - Users get one certificate per PC (UPN from the directory). Subject names come from the directory, never the
    request; RSA 2048 in the TPM or, on PCs without one, in software; ROCA keys refused; daily limits.
  - Two templates per tenant with AD CS-style OIDs and revisions, issued through OpenBao CEL roles that fix key usage,
    client authentication and the validity cap; **Re-enroll everyone** publishes a new major revision.
  - The **GPO autoenrollment** screen: readiness (DNS name, directory, CA, keytab, test, channel binding, an access
    rule for computers, MachineAccountQuota), **Create the service account…**, settings, and a request log with
    reasons. EasyEAP creates the Kerberos service account itself with a Domain Admin's credentials, typed once and
    never kept or logged: over LDAPS or StartTLS it checks that `HTTP/<name>` (and `HOST/<name>`) isn't another
    account's anywhere in the forest, creates or resets `easyeap-cep` (AES only, not delegable, only an account
    EasyEAP made), derives its keys with the salt the domain controller reports (MIT `ktutil`), keeps them encrypted
    and runs a live Kerberos test against the domain controller. Scripts for Windows AD (`ktpass`) and Samba AD with a
    keytab upload remain for administrators who won't type credentials into EasyEAP.
  - Upgrading: the new `docker-compose.yml` mounts the proxy's certificate into the API for channel binding (restart
    `easyeap-api` too when you replace that certificate); the proxy accepts the larger Kerberos headers on `/cep` and
    `/ces`, with its own per-address limit.
  - The directory sync never imports computer accounts as users, even with a user filter like `(objectClass=user)`.
- `tests/radius/run.sh`: the rendered FreeRADIUS configuration and the agent's store on real FreeRADIUS with real
  EAP-TLS, including every version-skew combination with the 1.0.1 agent and configuration, MAC authentication, and
  the TACACS+ service. Runs in CI.
- `tests/e2e/run.sh` covers wired 802.1X, MAC authentication, device administration (switch logins with AD groups
  and EasyEAP accounts) and Group Policy autoenrollment (a Kerberos client written from the specifications against
  Samba AD, through the proxy, then EAP-TLS with the issued computer certificate) end to end, and can drive another
  deployment (`E2E_DEPLOY_DIR`). `tests/autoenroll/kerberos.sh` checks Kerberos acceptance against a real MIT KDC.

### Fixed

- **Linux: one 802.1X connection per network port.** With wired 802.1X, the setup script's copy of a port's own
  connection (Ubuntu's "Wired connection 1") and its generic "Wired 802.1X" connection were both offered on that port.
  The generic one, now "Wired 802.1X (<organization>): other ports", leaves out the ports that have a copy (by name,
  and by address for connections bound by address), and isn't added when a copy that connects by itself already fits
  every port. `--remove` gives a port left without any connection a plain one back: NetworkManager's own "Wired
  connection 1" lives in memory and isn't made again after a restart while the copy fits its port. Run the new script
  to tidy a computer set up before.
- **A lost renewal answer no longer strands a Windows PC.** The setup file's renewal task deletes its new key when
  the answer doesn't arrive, and EasyEAP refused the next day's request with another key ("already renewed"), so the
  PC kept its old certificate until it expired. EasyEAP now replaces the unused certificate (within 14 days, at most 3
  times), and refuses as a conflict when that certificate has been used.
- **An expired enrollment link stayed stored, encrypted**: the expiry job (every 10 minutes) didn't clear it, though
  it could never be shown (the expiry is checked first). It's cleared now, and migration 0013 clears those left over.
- **The user's page said a lost link can't be shown again**, though **Show link** could since the previous change.
- **A switch port that's a SPAN destination never authenticates** (the switch runs no 802.1X on it), and nothing said
  so: the preflight now asks for `show monitor session all`, and the troubleshooting table explains it.
- **"Sessions aren't readable over SNMP" on a Catalyst 3850 with IOS-XE 16.6**: the switch has no
  cafAuthMethodRegTable, which was all EasyEAP checked; it answers the port and session tables, which are now enough.
- **A switch audit poll took 13 seconds on a Catalyst 3850** with no 802.1X sessions: stepping past the end of an
  empty session table costs the switch about 2 s a column. EasyEAP reads the client MAC column first and stops there
  when it's empty (about 3 s in all).
- **IOS-XE 16.6.1 and other releases rejected parts of the classic and IOS-XE configuration**: commands now follow
  the switch's release (see above). `DEFAULT_CRITICAL_DATA_TEMPLATE` is replaced by EasyEAP's own critical template,
  except on switches already enforcing with it, whose policy name stays the same.
- **The switch audit's syslog line was refused on IOS-XE** (`% Invalid input` at `transport`): the line is now
  `logging host <EasyEAP> transport udp port 5514`, with no discriminator (EasyEAP keeps the whole log, above). A
  switch that refused it needs only the syslog part of the block; the rest was accepted.
- **IOS-XE asks a yes/no question before its first control policy** (converting to the new-style configuration), and
  inside a paste it took the next pasted line as the answer. The safe-paste steps now run
  `authentication convert-to new-style` first.
- **Switches that can't apply a VLAN from RADIUS** (Nexus 3000 and 7000, some Cisco Business models) no longer get
  one, whatever the method. A plan or type change that would orphan the switch audit's SNMP lines is refused until
  the audit is removed, and a switch's family can't keep a release number from another family.

### Changed

- **A renewal task that lost its new key gets a replacement** (v2 as well as v1): EasyEAP replaces the unused
  certificate it issued, within 14 days and at most 3 times, as it did for the older tasks. A renewal refusal now
  carries a `code`; renewal tasks keep their waiting request after a refusal that may change (a wrong clock, renewal
  turned off) and drop it only after a final one. The Linux script asks again with a new key when EasyEAP says the
  certificate was renewed but nothing reached the computer.
- Renewal by the Windows setup file and the Linux script starts at the tenant's percentage of the certificate's own
  life instead of the template's fixed days, so a certificate shortened by an expiring CA renews in proportion.
  Existing templates' renewal periods are recalculated for 80 % (User Wi-Fi 30 → 73 days, Device Wi-Fi 45 → 146).
- No certificate is issued past the issuing CA's expiry: its lifetime is cut to end an hour before the CA's, and
  issuance is refused with a clear reason when less than a day is left (before, OpenBao's refusal surfaced as a server
  error).
- The dashboard's "certificates expire soon" item counts only certificates that don't renew by themselves (Apple and
  Android profiles, certificates installed by hand, or renewal turned off); those that should have renewed by
  themselves and haven't, two weeks into their window, get their own item.
- Group Policy autoenrollment: a template's renewal period must be under a fifth of its validity (it was three
  quarters): at a fifth or more, Windows enrolls afresh instead of renewing. The policy caps an older value at 19 %.
- Nexus switches send syslog at severity 6 (informational) so the session and address-learning messages arrive.
- A live page that refreshes itself (Device syslog) no longer keeps an idle console session signed in.
- System health's "Switch syslog" check is now "Device syslog" and counts every device address it receives from.
- **Linux Wi-Fi steps without the script** now work with GNOME: forget the network saved by an earlier try (GNOME
  never shows the form again and keeps Tunneled TLS, which then asks for a user name and password), choose
  **TLS**, and store the key password for all users. The "For IT staff" section's unexplained NetworkManager and
  `wpa_supplicant` cards are replaced by complete `nmcli` and `wpa_supplicant` steps, and the Linux CA file lists the
  root CA first (NetworkManager 1.54 only trusts the first certificate of a per-user profile's CA file).
- Upgrading keeps behaviour: existing controllers serve both Wi-Fi and wired (a switch registered as "Other" keeps
  working), every VLAN is the same VLAN on switch ports, and enrollment packages stay Wi-Fi only.
- "Wireless controllers" is now "Controllers and switches" on the RADIUS screen; Add offers a wireless controller or
  a switch.
- On a switch with admin logins on, the wired 802.1X configuration no longer sets `aaa authentication login default
  local` and `aaa authorization exec default local`, so re-pasting it doesn't undo TACACS+.
- Cisco wired 802.1X: the configuration always starts with `aaa new-model`, which `radius server` and every `aaa`
  command need. On a switch whose `show running-config | include aaa new-model` printed `no aaa new-model`, ticking
  "Already uses AAA" left it out and IOS-XE answered "radius server" isn't a command (seen on a 3850 with 16.6.1). The
  preflight now looks for `^aaa new-model`, `aaa accounting identity` comes after the first control policy (it needs
  IBNS 2.0 policy mode), and the platform advice no longer sends 3650/3850 to classic configuration.
- Switch audit: SNMPv3 defaults to SHA-1 with AES-128 (`auth sha`), which every IOS-XE Catalyst accepts; `auth sha-2
  256` is documented only from IOS XE 17.10.1a. Removal deletes each view subtree as it was added (IOS XE 17.12 and
  17.15 require it) and only the ACL that was created.

## [1.0.1] - 2026-11-06

### Changed

- FreeRADIUS 3.2.10 (was 3.2.7) and nginx 1.31 (was 1.29) as the RADIUS and proxy base images. Verified with the
  end-to-end EAP-TLS suite, the console smoke test, and with an iPhone on a live Cisco Catalyst 9800.
- Dependabot proposes monthly, grouped minor and patch updates; major versions are upgraded by hand.

### Security

- The frontend's lint tooling no longer uses a minimatch version affected by GHSA-g3hv-75wg-m249 (denial of service).
  It was never part of the console or enrollment portal.

## [1.0.0] - 2026-11-06

The first public release: multi-tenant EAP-TLS with PKI, Active Directory, RADIUS, enrollment and the console.
Verified end to end with a live Cisco Catalyst 9800 and an iPhone enrolled through the portal.

### Added

- **Deployment.** One Docker Compose project with proxy, API, worker, PostgreSQL 18, OpenBao 2.4.1 and FreeRADIUS
  3.2.7, on segmented internal networks. Also:
  - `install.sh` generates every secret once;
  - `backup.sh` and `restore.sh` for scheduled backups (the same engine and files as the console);
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

### Changed since the preview build (2026-11-05)

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

### Fixed since the preview build

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

### Upgrading a preview installation

- Installations made with the preview have no OpenBao recovery keys, so their backups can regain CA access only
  if restored within 32 days of being made. The console shows each backup's restore-by date.
- Backups made by the preview (`.tar.gz.enc` or `.tar.gz.gpg`) can't be restored. Make a new backup from the
  console after upgrading.

[Unreleased]: https://github.com/paulmataruso/EasyEAP/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/paulmataruso/EasyEAP/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/paulmataruso/EasyEAP/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/paulmataruso/EasyEAP/releases/tag/v1.0.0

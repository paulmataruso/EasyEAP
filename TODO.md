# What's left to do

Started 2026-11-08. This is the working list: features not built yet, and what still needs testing on real gear. What's
already done is in [CHANGELOG.md](CHANGELOG.md) and [PROGRESS.md](PROGRESS.md). PROGRESS.md was last refreshed at
release 1.0.1 and is behind. Plans live in [docs/plans/](docs/plans/).

Tick items off here when they're done or verified, and say where (commit, or the device and version it was tried on).

## Next up, in order

1. **UniFi controller wizard.** EasyEAP sets up a UniFi Network controller through its API: the RADIUS profile, a
   WPA2/WPA3-Enterprise Wi-Fi network (an existing one, or a new one if the admin agrees), and/or 802.1X on UniFi
   switch ports. Planned and critiqued in [docs/plans/unifi-wizard.md](docs/plans/unifi-wizard.md), not built.
   - [ ] **Blocked on a UniFi console for the spike** (§11): a test site on a real console, or UniFi OS Server on the
     demo host with the owner's OK. Phase 2 (Wi-Fi) isn't built until S1, S2, S4 and S8 have run.
   - [ ] Phase 2: Wi-Fi. Phase 3: wired. Phase 4: the cloud connection and Enforce through the API. Phase 5: saved
     connection and the UniFi switch audit.
2. **Certificate renewal, phase 2b (Windows).** `renew.ps1` v2 does what the Linux script's renewer v2 already does:
   a daily signed check-in, keeping the pending request when an answer is lost, reporting the roots it trusts, and a
   notice to the user near expiry. The portal's Windows helper gains the same renewal task.
   [docs/plans/cert-renewal.md](docs/plans/cert-renewal.md) §4.3, §4.5.
3. **A critic pass on the Linux renewer v2** (committed in 153adc2/5d1eba7, demo e2e only).
4. **Certificate renewal, phases 3–7** ([cert-renewal.md](docs/plans/cert-renewal.md) §15):
   - [ ] 3. Assisted renewal for Apple, Android and hand-configured Linux: renewal links, the queue, email (SMTP) and
     reminders, portal renewal pages, profile replacement in place.
   - [ ] 4. Root ceremony from the console: check the root key file, renew the root CRL, prepare the next issuing CA.
   - [ ] 5. Switching to a new issuing CA: several issuing CAs at once, per-issuer CRLs, the server chain, watch and
     rollback.
   - [ ] 6. Root rollover: new root, cross-certificate, publishing the new trust, retiring the old root.
   - [ ] 7. Spikes: Windows key-based renewal outside the domain, Apple ACME with device attestation, an Android app,
     EST/SCEP for Intune and Jamf, TPM key attestation.

## Features not built yet

### Network gear
- [ ] **UniFi switch audit**: ports and 802.1X sessions read through the UniFi Network API, the same findings as
  the Cisco audit ([switch-audit.md](docs/plans/switch-audit.md) §11). It can reuse the wizard's controller
  connection.
- [ ] Switch audit extras: SNMP traps (cafAuthFail, MAC notification) to trigger polls, CDP/LLDP neighbours to
  suggest "leave alone" ports, a scheduled audit report.
- [ ] Wired 802.1X: an IP-phone voice domain; merging with an 802.1X configuration a switch already has.
- [ ] MAC authentication: profiling or automatic approval.
- [ ] Meraki: CoA (needs `audit-session-id` kept per session) and the Meraki Dashboard API.
- [ ] Cisco leftovers ([cisco-platforms.md](docs/plans/cisco-platforms.md) §13): NX-OS 10.6(3)F MDA open mode,
  Cisco Business 802.1X session polling, IBNS 2.0 on classic 15.2E.
- [ ] Device administration phase 2: TACACS+ over TLS, command authorization, vendors other than Cisco.
- [ ] RadSec (RADIUS over TLS) between controllers and EasyEAP.

### RADIUS
- [ ] A PAP request that isn't MAC authentication is logged with the reason `tls_handshake`. It should say what
  actually happened (PAP isn't accepted outside MAC authentication).
- [ ] A second RADIUS node against the same API, with its health on the System page.

### Certificates and enrollment
- [ ] Windows setup as a signed `.exe` (needs a code-signing certificate so SmartScreen doesn't block it).
- [ ] A computer-wide Mac profile (login window), so a Mac joins Wi-Fi before anyone signs in.
- [ ] SCEP / MDM enrollment (Intune, Jamf).
- [ ] Email delivery of enrollment links and expiry notices (overlaps renewal phase 3).
- [ ] The Renewal panel's counts are worked out in Python for every valid certificate on each load. Move them into
  SQL before a tenant has tens of thousands of certificates (cert-renewal.md §15b item 10).

### Windows and Active Directory
- [ ] Create the Group Policy objects from the console (the Wi-Fi/wired profiles and autoenrollment). This writes
  to the customer's AD, so it needs that customer's OK.
- [ ] Group Policy autoenrollment: TPM key attestation.
- [ ] The demo needs a DNS name for autoenrollment (Kerberos needs a name, not an IP). Adding the record to the
  demo's AD needs the owner's OK.

### Directory
- [ ] Directory sources other than Active Directory over LDAPS (Entra ID, Google Workspace).

### Housekeeping
- [ ] Refresh PROGRESS.md (it stops at 1.0.1).

## Things to test on real gear

Nothing below has run on the real thing yet. Each was tested against stand-ins (FreeRADIUS with real EAP-TLS, Samba
AD, net-snmp pretending to be a Catalyst, PowerShell 7 with Windows' commands recorded, Linux containers). The guide
named in each item says what to check.

### Windows
- [ ] **Windows setup file, end to end on a Windows 11 PC**: TPM key through certreq, user and computer certificates,
  Wi-Fi and wired profiles, the approval prompt, the scheduled tasks ([docs/windows-setup.md](docs/windows-setup.md)).
- [ ] Its **renewal**: let a test certificate reach its renewal point (use a short template) and watch the task renew
  it. Once phase 2b ships: the daily check-in shows on the certificate's page.
- [ ] The **lost-answer re-issue** with the current `renew.ps1` (v1): drop the answer once, then confirm the next
  run gets a replacement and the unused one is revoked as "replaced".
- [ ] **Group Policy autoenrollment on a real domain PC**: the first-PC checklist in
  [docs/autoenrollment.md](docs/autoenrollment.md). The open question is whether Windows accepts EasyEAP's unsigned
  CMC response.
- [ ] The Windows wired kit (`netsh lan`) on a real 802.1X port.

### Linux
- [ ] **Linux script on a real machine** (not a container): Wi-Fi, then wired on a real switch port
  (`802-1x.optional`, the copied wired profiles, `--remove` puts the originals back).
- [ ] The **iwd** and **dhcpcd** paths (written, never run).
- [ ] **Renewer v2 on a real machine**: the daily check-in, a renewal, and a pending request kept across a lost answer.

### Apple and Android
- [ ] The QR hand-over on an iPhone and an Android phone; the Linux script download from the console.
- [ ] Profiles installed on macOS (including its Ethernet payload) and Android (only an iPhone has been confirmed).
- [ ] Other iOS versions with the on-device key (blob URL hand-off).

### Switches and controllers
- [ ] **Generated Catalyst configuration pasted on a real Catalyst**, monitor mode, then enforce
  ([docs/controllers/cisco-catalyst-switch.md](docs/controllers/cisco-catalyst-switch.md)).
- [ ] The other Cisco families on real hardware: classic IOS, IOS-XE 3.x/16/17, NX-OS, Cisco Business, Meraki MS.
- [ ] **Switch audit on a real Catalyst 3850 (IOS-XE 16.6)**: paste the newer syslog lines (verbose logging, without
  the old discriminator) and check sessions, findings and the live syslog view
  ([docs/switch-audit.md](docs/switch-audit.md)).
- [ ] **MAC authentication** on a real Catalyst (MAB) and a UniFi switch (MAC-Based).
- [ ] **TACACS+ logins** on a real Cisco switch and a Catalyst 9800 ([docs/device-administration.md](docs/device-administration.md)).
- [ ] **CoA disconnect** on each controller that claims it (9800, AireOS, Catalyst); confirm UniFi and Meraki stay off.
- [ ] **UniFi**: wired 802.1X and MAC-Based on a UniFi switch: the port type it sends, re-authentication timing,
  whether it accepts CoA.
- [ ] **UniFi wizard spike** on a real console ([unifi-wizard.md](docs/plans/unifi-wizard.md) §11.1, S0–S8): API key on
  the classic endpoints, the WPA3 field mapping (and which mode a Windows 11 `WPA3ENT` profile joins), the fallback
  VLAN, site vs switch 802.1X settings, where RADIUS comes from over a VPN and across NAT, the cloud connector.
- [ ] Syslog from a 9800, AireOS, UniFi and Meraki (decoded lines show up under Investigate → Device syslog).

### Server side
- [ ] **RADIUS server certificate rotation and rollback** with real clients connected: do they accept the new
  certificate without a prompt? Does rolling back work for them?
- [ ] **Restoring a backup** from the console onto a fresh install.

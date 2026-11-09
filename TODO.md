# What's left to do

Started 2026-11-08. This is the working list: features not built yet, and what still needs testing on real gear. What's
already done is in [CHANGELOG.md](CHANGELOG.md) and [PROGRESS.md](PROGRESS.md). PROGRESS.md was last refreshed at
release 1.1.0. Plans live in [docs/plans/](docs/plans/).

Tick items off here when they're done or verified, and say where (commit, or the device and version it was tried on).

## Next up, in order

1. **UniFi controller wizard.** EasyEAP sets up a UniFi Network controller through its API: the RADIUS profile, a
   WPA2/WPA3-Enterprise Wi-Fi network (an existing one, or a new one if the admin agrees), and/or 802.1X on UniFi
   switch ports. Planned and critiqued in [docs/plans/unifi-wizard.md](docs/plans/unifi-wizard.md), not built.
   - [ ] **The spike** (§11) on the owner's console, one site only. Phase 2 (Wi-Fi) isn't built until S1, S2, S4 and
     S8 have run. S1 and S8 done, S2 half done, S4's settings side done, 2026-11-09 (§11.4). S4's joins wait for an access
     point; S5–S7 wait for the owner's go-ahead to turn on 802.1X on the site's switch.
   - [ ] Phase 2: Wi-Fi. Phase 3: wired. Phase 4: the cloud connection and Enforce through the API. Phase 5: saved
     connection and the UniFi switch audit.
2. ~~Certificate renewal, phase 2b (Windows)~~: done 2026-11-09 (`renew.ps1` 2.0 and the portal helper's renewal;
   [cert-renewal.md](docs/plans/cert-renewal.md) §15c). Tested without Windows and on the demo's API; the real-PC
   items are below.
3. **A critic pass on the Linux renewer v2** (committed in 153adc2/5d1eba7, demo e2e only). Its refusal handling and
   lost-key recovery were brought in line with Windows in phase 2b; the rest hasn't had its own critic.
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
- [x] Refresh PROGRESS.md: done 2026-11-09 (1.1.0).

## Things to test on real gear

Nothing below has run on the real thing yet. Each was tested against stand-ins (FreeRADIUS with real EAP-TLS, Samba
AD, net-snmp pretending to be a Catalyst, PowerShell 7 with Windows' commands recorded, Linux containers). The guide
named in each item says what to check.

### Windows
- [ ] **Windows setup file, end to end on a Windows 11 PC**: TPM key through certreq, user and computer certificates,
  Wi-Fi and wired profiles, the approval prompt, the scheduled tasks ([docs/windows-setup.md](docs/windows-setup.md)).
- [ ] Its **renewal** (`renew.ps1` 2.0): let a test certificate reach its renewal point (use a short template) and
  watch the task renew it: the daily check-in on the certificate's page, the new certificate in the store, the old one
  gone only after the confirming check-in. Then:
  - which certificates it takes, with a Group Policy certificate, a certificate from another CA and an EasyEAP one
    without its key in the same store (the chain test only ran under PowerShell 7 on Linux);
  - a lost answer (block the API once mid-renewal): the next run sends the same request and gets the same
    certificate; a cleared REQUEST entry: the next run gets a replacement;
  - the two-minute sign-in/unlock delay and the daily trigger of the shared user task on a PC with two signed-in
    users;
  - the expiry notification (shows as "*Organization* network"; logged when notifications are off);
  - the computer task as SYSTEM behind a proxy (the log says which way it went);
  - a PC whose TPM refuses the key: certreq's error output doesn't stop the script, and the software key is used;
  - an organization or network name with non-ASCII letters and a curly apostrophe, through the setup file and the
    portal helper.
- [ ] The **portal's Windows helper** on a PC without the setup file: its own task, the certificate's page says
  "Windows enrollment helper", and on a PC with the setup file no second task (even when a standard user can't list
  the shared task).
- [ ] An **older PC** (v1 `renew.ps1`) next to a new setup file run: the old per-user tasks are removed.
- [ ] **Group Policy autoenrollment on a real domain PC**: the first-PC checklist in
  [docs/autoenrollment.md](docs/autoenrollment.md). The open question is whether Windows accepts EasyEAP's unsigned
  CMC response.
- [ ] The Windows wired kit (`netsh lan`) on a real 802.1X port.

### Linux
- [ ] **Linux script on a real machine** (not a container): Wi-Fi, then wired on a real switch port
  (`802-1x.optional`, the copied wired profiles, `--remove` puts the originals back).
  - [x] Wired on Ubuntu desktop, Catalyst port in monitor mode: EAP-TLS accepted (2026-11-09). It showed two 802.1X
    connections on the port (the copy of "Wired connection 1" and the generic one); the first one tried got no
    address after the accept.
  - [ ] Again with the one-profile-per-port fix: one 802.1X connection offered on the port (quick settings menu,
    GNOME Settings' Wired page), an address by DHCP, a dock or USB adapter getting "other ports" (and a dock with MAC
    pass-through), `--remove` before and after a restart.
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

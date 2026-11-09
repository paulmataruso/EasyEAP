# Enrolling devices

Every device gets its own certificate. EasyEAP never shares one certificate between devices.

## How an administrator starts it

1. Open the user (search with `/`, or press ⌘K / Ctrl+K and type their name).
2. Choose **Issue Wi-Fi certificate**, pick the device platform and name the device ("Jordan's laptop").
3. EasyEAP creates a **one-time enrollment link**. It's bound to that user and device, works once, and expires after
   72 hours (configurable per tenant). Send it to the user through a channel you trust. If it's lost, the user's page
   shows it again (**Enrollment links → Show link**) until it's used, cancelled or expires: EasyEAP keeps it encrypted
   with the tenant's key until then, and each showing is in the audit log. No new link or certificate is made.

**Users** shows what's still waiting for each person, by platform: **iPhone/iPad link waiting**, **Mac link
waiting**, **Linux link waiting** and so on show the link, **Windows setup file waiting** downloads the Windows setup
file again, and **Package waiting** opens the user's page. **Enrollment → Waiting for device** lists only the people
with something waiting. Showing a link also gives what its platform needs:

- **iPhone, iPad and Android**: a QR code. The person scans it with the device's camera and the link opens in Safari
  or Chrome on the device itself, so nobody has to email it.
- **Linux**: **Download setup script**, the same `EasyEAP-WiFi-Setup.sh` the link's page gives, with the same
  one-time code. Hand it over, or copy it to a computer that has no browser.
- **Windows**: the link installs the user's certificate only (and a task that renews it); **Windows setup** (below)
  does more.

A server-generated package is the exception: its password is shown once and never stored, so a lost one means
cancelling the package and making a new one.

### User and computer certificates

A computer certificate is what lets a PC join the network before anyone signs in: at the Windows sign-in screen, so
people who never used that PC can sign in with their directory password, and for startup scripts and Group Policy.

- **Windows**: the **Windows setup** file installs both, the user's certificate and the computer's, by default, and
  **Issue certificate** points to it when you choose Windows. A link (the browser route) can only install the user's
  certificate: the computer's store needs administrator rights, which a web page doesn't get. Reasons to use a link
  anyway: a personal PC you don't manage (no administrator approval, and no credential on it that works without the
  person), or when Group Policy autoenrollment already gives the domain PC its own computer certificate.
- **Linux**: there's nothing extra to install. The setup script keeps the key for the whole computer (root only, in
  `/etc/easyeap`), makes a system-wide connection that comes up at boot before anyone signs in, and renews it as
  root, which is what a computer certificate does on Windows. A Linux computer shared by several people uses the
  access of the person it was set up for.
- **Mac**: the profile from the link is a user profile (Apple's default for a profile someone installs), so the Mac
  joins after that person signs in, not at the login window.
- **iPhone and iPad**: the profile is for the whole device; there's no sign-in screen to cover.

The user opens the link **on the device being enrolled**. By default the device generates its own private key and
sends only a certificate signing request. The key never leaves the device.

### Windows PCs: the setup file

For a Windows 11 PC, **Windows setup** on the user's page makes one file that does everything: trust in the CA, the
Wi-Fi and wired 802.1X profiles, the user's certificate and the computer's certificate (so the sign-in screen has
network), and their automatic renewal. Keys stay in the TPM, or in a non-exportable software key on PCs without one.
See [windows-setup.md](windows-setup.md).

### Linux computers: the setup script

On Linux the portal offers a **setup script** (`EasyEAP-WiFi-Setup.sh`) made for the link. The user downloads it and
runs one command in Terminal, `bash ~/Downloads/EasyEAP-WiFi-Setup.sh`, and types their password once. The script:

- finds what the computer uses for networks and sets up that: **NetworkManager** (Ubuntu and Debian desktops, Fedora,
  Linux Mint, Raspberry Pi OS Bookworm and later), **iwd**, **wpa_supplicant with systemd-networkd** (Ubuntu Server
  with netplan, minimal Debian) or **wpa_supplicant with dhcpcd** (Raspberry Pi OS Bullseye). It says so and stops
  without changing anything if it finds none of them;
- creates the private key on the computer (ECDSA P-256; RSA 3072 for iwd, which can't sign with ECDSA), sends only
  the certificate request, and keeps the key in `/etc/easyeap/<tenant>/`, readable by root only;
- adds the Wi-Fi network for all users of the computer with the root CA and the RADIUS server name pinned, and no
  password stored or asked for. It replaces earlier settings for the same SSID, including the half-finished ones
  GNOME's Wi-Fi dialog saves. With wired 802.1X on and NetworkManager, it also adds a wired connection (802.1X is
  optional on it: a port that doesn't ask for it connects after up to 15 seconds). Wired settings the computer already
  has (a fixed address, DNS, one port) are kept: 802.1X goes on a copy of each, which NetworkManager prefers, so
  `--remove` brings the originals back unchanged. Nothing is reconnected while the script runs;
- installs a daily systemd timer (or a cron job) that renews the certificate before it expires, signed with the
  current key like the Windows renewal. Each run checks in with EasyEAP (signed with the key; the certificate's page
  shows the last check-in) and renews once EasyEAP says renewal has started; when EasyEAP can't be reached, the
  renewal period the script was made with decides. The new key and request wait in `/etc/easyeap/<tenant>/` until
  the new certificate is in: if the answer gets lost, the next run asks again with the same request, and EasyEAP
  sends the certificate it already issued for it;
- checks the connection to EasyEAP: when the computer doesn't trust EasyEAP's certificate (a self-signed one), it
  accepts the public key EasyEAP had when it made the script. The link never appears on a command line, where other
  users of the computer could read it.

`--check` shows what it found and would do, without using the link. `--remove` undoes everything. Running it again
with a spent link keeps the current certificate and redoes the network settings. It works with `curl` or, when that's
missing (Ubuntu Desktop), Python 3, and with bash 4 and later, GNU or uutils coreutils (Ubuntu 25.10 and later) and
`sudo`, `sudo-rs` or `pkexec`.

Tested end to end (enroll, connect with EAP-TLS, get an address, renew, remove) on Ubuntu 22.04, 24.04 and 26.04
desktop, Ubuntu Server 24.04, Debian 13 and Fedora 43. The iwd and dhcpcd paths are written from their documentation
but not yet tested.

If the user can't run scripts, **Create the certificate in this browser instead** gives a `.p12` and the GNOME steps;
its "For IT staff" section has the `nmcli` and `wpa_supplicant` equivalents.

### Server-generated keys (opt-in)

A Tenant Administrator can allow server-generated keys for devices that can't run the portal. It must be allowed
both in tenant settings and on the certificate template. EasyEAP then generates the key and wraps it in a
password-protected PKCS#12 file (AES-256, PBKDF2-SHA256, 600,000 iterations), encrypted at rest with the tenant's
Transit key. The file can be downloaded once, and the password is shown once to the issuing administrator: send the
link and the password through different channels. On iPhone, iPad and Mac the download is a configuration profile
that also installs the CA chain and the Wi-Fi network; on Windows the portal adds the Wi-Fi profile. An undelivered
package expires, and its certificate is revoked.

## What the user does

The portal detects the platform and shows only that platform's steps.

| Platform | Steps |
|---|---|
| **Windows 10/11** | Download the enrollment helper and run it in PowerShell. It needs no administrator rights. It creates a non-exportable key in the TPM when there is one (otherwise in the Windows software key store), requests the certificate, trusts the organisation's Root CA once the user approves the Windows prompt, and adds the Wi-Fi profile. Then connect to the SSID; no password is needed. |
| **macOS, iPhone, iPad** | The browser generates the key and inserts it, password-protected, into a configuration profile. Download it, then install it: on iPhone/iPad in Settings → Profile Downloaded; on a Mac in System Settings → General → Device Management (Privacy & Security → Profiles before macOS 15). Enter the certificate password shown on the page. Then join the SSID. |
| **Android** | The browser generates the key and builds a certificate file. Install it from Settings → Security → More security settings → Install from device storage → Wi-Fi certificate. Then open the SSID with EAP method TLS, the installed CA certificate, Domain = the RADIUS server name shown on the page, and Identity = the user's sign-in name shown on the page. |
| **Linux** | Download the setup script and run `bash ~/Downloads/EasyEAP-WiFi-Setup.sh` in Terminal (see above). Without the script: create the certificate in the browser, forget any earlier saved network, then in Settings → Wi-Fi choose Authentication **TLS** (GNOME preselects Tunneled TLS), the CA file, Domain = the RADIUS server name, the `.p12` as the user certificate, and its password stored for all users. |

The certificate password the portal shows protects the file on its way to the device's certificate store; the
browser makes it up and never sends it to EasyEAP.

A link that has been used, cancelled or has expired says so when opened again and can't be used. Issue a new one.

## Wired 802.1X

The certificate a device enrolls with works on switch ports too. What sets the Ethernet port up for 802.1X:

| Platform | Wired 802.1X |
|---|---|
| **macOS** | With **Wired settings in enrollment packages** on (RADIUS settings), the configuration profile also contains an Ethernet payload (`com.apple.globalethernet.managed`) using the same certificate and server name. |
| **Linux** | With that setting on, the setup script adds a wired NetworkManager connection (802.1X only where the port asks for it). Without NetworkManager, or with `--no-wired`, it doesn't. The browser route's "For IT staff" section has the `nmcli` command. |
| **Windows 10/11** | Set up by IT, not the portal. The [Windows setup file](windows-setup.md) adds the wired profile with the computer's certificate, so the port opens at the sign-in screen. Or **RADIUS → Windows wired kit**: a LAN profile, an install script (run as administrator or SYSTEM, for example from Intune or a startup script) and Group Policy steps, using the certificate each user already has; it connects after sign-in. |
| **iPhone, iPad, Android** | Not applicable. |

The setting is off by default, so adding a test switch doesn't change what new devices get. Devices enrolled before
it was turned on don't have the wired settings until they enroll again (or IT installs them).

## Renewal

**Certificate authority → Renewal** sets what renews by itself (docs/plans/cert-renewal.md §15a):

- **User certificates** and **Device certificates**: renewed by the Windows setup file's tasks, the task the portal's
  Windows helper leaves for its user (from 2026-11-09 on; skipped where a setup file already renews everyone's
  certificate), and the Linux script's timer, each signing the request with the certificate's current key, so nobody
  signs in and nothing is downloaded again. Group Policy certificates renew on Windows' own schedule (see
  [autoenrollment.md](autoenrollment.md)). Apple and Android profiles can't renew themselves: the dashboard lists
  those certificates as they near expiry, and the user needs a new link.
- **RADIUS server certificate**: EasyEAP issues a new one by itself (checked every 6 hours). Devices accept it because
  they trust the CA and the server's name, not the certificate. The previous one is kept for 14 days: if devices
  stop connecting after the change (the dashboard watches for devices that connected the week before and have failed
  the handshake since), **Put the previous certificate back** on the RADIUS page. That pauses automatic rotation until
  you turn it on again. A new certificate is only issued when the issuing CA can give it at least 30 days.
- **Renew once this much of a certificate's life has passed**: 50 to 90 %, 80 % by default (where Windows'
  autoenrollment starts too). A 365-day certificate renews from day 292, so a device that's off or away has 73 days
  to come back. A certificate that's shorter than its template (because the issuing CA expires first) renews at the
  same share of its own life. Templates show their renewal period in days from this setting; setup files and scripts
  made afterwards carry it.

Certificates can't outlive the issuing CA: one issued when the CA has less time left than the template's lifetime
ends with the CA, and the panel shows when to prepare and switch to the next issuing CA. Refused renewals are in the
audit log (**Certificate renewal refused**, with the reason, once a day per certificate and reason).

What each certificate's page shows under **Renewal** (docs/plans/cert-renewal.md §15b): what renews it (the Windows
setup file, the Linux script, Group Policy, or nothing: a new link), when renewal starts, the renewal task's last
check-in, and what it was renewed into. The panel counts the tenant's valid certificates: renew by themselves,
haven't checked in for a week, overdue, need the user. On the dashboard:

- **Devices haven't checked in for renewal in a week**: renewal tasks that check in daily (setup files and Windows
  helpers made since 2026-11-09, Linux scripts since 2026-11-08) and have gone quiet while their certificate is due.
- **Certificates should have renewed by themselves**: two weeks into the renewal period (older tasks that ask only
  when due: once 14 days are left). Critical when one has 14 days or less.
- **A certificate was renewed with two keys** (critical): a renewal signed by a certificate another key already
  renewed, when that newer certificate is in use. The key may have been copied: revoke the certificate with the ones
  renewed from it, and enroll the device again.
- **A renewed certificate is still in use** (warning): RADIUS accepted it more than a day after its successor was
  first used.

**Retire renewed certificates** (on by default) revokes a superseded certificate once its device has shown it holds
the newer one (RADIUS accepted it, or the renewal task checked in with its key) and the old one hasn't connected for 7
days. Revoking a certificate by hand also revokes the certificates renewed from it (the dialog lists them), unless
you untick that (to revoke only an old certificate a device kept). A certificate that merely replaced it (Group
Policy's after a setup file's, or one from another PC) isn't revoked with it.

## Revoking

Revoke from the certificate or the user page. Revocation is permanent. New connections with that certificate are
refused once RADIUS applies the update, normally within about 15 seconds. A device already connected stays
connected until EasyEAP disconnects it with CoA (when the controller supports it and you choose to), or until its
session reaches the tenant's `Session-Timeout`. See [controllers/README.md](controllers/README.md#change-of-authorization-coa).

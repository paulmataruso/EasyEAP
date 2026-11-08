# Enrolling devices

Every device gets its own certificate. EasyEAP never shares one certificate between devices.

## How an administrator starts it

1. Open the user (search with `/`, or press ⌘K / Ctrl+K and type their name).
2. Choose **Issue Wi-Fi certificate**, pick the device platform and name the device ("Jordan's laptop").
3. EasyEAP creates a **one-time enrollment link**. It's bound to that user and device, works once, and expires after
   72 hours (configurable per tenant). Send it to the user through a channel you trust. If it's lost, the user's page
   shows it again (**Enrollment links → Show link**) until it's used, cancelled or expires: EasyEAP keeps it encrypted
   with the tenant's key until then, and each showing is in the audit log. No new link or certificate is made.

**Users** shows what's still waiting for each person: **Link waiting** shows the link, **Setup file waiting**
downloads the Windows setup file again, and **Package waiting** opens the user's page. **Enrollment → Waiting for
device** lists only the people with something waiting. A server-generated package is the exception: its password is
shown once and never stored, so a lost one means cancelling the package and making a new one.

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
  current key like the Windows renewal. The new key and request wait in `/etc/easyeap/<tenant>/` until the new
  certificate is in: if the answer gets lost, the next run asks again with the same request, and EasyEAP sends the
  certificate it already issued for it;
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

## Revoking

Revoke from the certificate or the user page. Revocation is permanent. New connections with that certificate are
refused once RADIUS applies the update, normally within about 15 seconds. A device already connected stays
connected until EasyEAP disconnects it with CoA (when the controller supports it and you choose to), or until its
session reaches the tenant's `Session-Timeout`. See [controllers/README.md](controllers/README.md#change-of-authorization-coa).

# Enrolling devices

Every device gets its own certificate. EasyEAP never shares one certificate between devices.

## How an administrator starts it

1. Open the user (search with `/`, or press ⌘K / Ctrl+K and type their name).
2. Choose **Issue Wi-Fi certificate**, pick the device platform and name the device ("Jordan's laptop").
3. EasyEAP creates a **one-time enrollment link**. It's bound to that user and device, works once, and expires after
   72 hours (configurable per tenant). Send it to the user through a channel you trust. EasyEAP shows the link only
   once.

The user opens the link **on the device being enrolled**. By default the device generates its own private key and
sends only a certificate signing request. The key never leaves the device.

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
| **Linux** | Save the certificate, key and CA chain under `/etc/easyeap/` (key mode 600) and install the NetworkManager profile or the `wpa_supplicant` block shown. The profile checks the server name. |

The certificate password the portal shows protects the file on its way to the device's certificate store; the
browser makes it up and never sends it to EasyEAP.

A link that has been used, cancelled or has expired says so when opened again and can't be used. Issue a new one.

## Wired 802.1X

The certificate a device enrolls with works on switch ports too. What sets the Ethernet port up for 802.1X:

| Platform | Wired 802.1X |
|---|---|
| **macOS** | With **Wired settings in enrollment packages** on (RADIUS settings), the configuration profile also contains an Ethernet payload (`com.apple.globalethernet.managed`) using the same certificate and server name. |
| **Linux** | With that setting on, the portal's "For IT staff" section adds a wired NetworkManager profile and a wired `wpa_supplicant` file, using the same files in `/etc/easyeap/`. |
| **Windows 10/11** | Set up by IT, not the portal: **RADIUS → Windows wired kit** has a LAN profile, an install script (run as administrator or SYSTEM, for example from Intune or a startup script) and Group Policy steps. It uses the certificate each user already has, so enroll users for Wi-Fi first. User certificates connect after sign-in, so domain-joined PCs need cached credentials. |
| **iPhone, iPad, Android** | Not applicable. |

The setting is off by default, so adding a test switch doesn't change what new devices get. Devices enrolled before
it was turned on don't have the wired settings until they enroll again (or IT installs them).

## Revoking

Revoke from the certificate or the user page. Revocation is permanent. New connections with that certificate are
refused once RADIUS applies the update, normally within about 15 seconds. A device already connected stays
connected until EasyEAP disconnects it with CoA (when the controller supports it and you choose to), or until its
session reaches the tenant's `Session-Timeout`. See [controllers/README.md](controllers/README.md#change-of-authorization-coa).

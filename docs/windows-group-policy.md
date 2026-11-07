# Windows Group Policy for EasyEAP

How to set up domain-joined Windows PCs for EasyEAP's Wi-Fi and wired 802.1X with Group Policy. The console shows the
same steps with your tenant's values filled in, and the files to import: **RADIUS → Controllers and switches → Windows
Group Policy**. This page is the long form; where they differ, the console is current.

## Can Group Policy enroll certificates from EasyEAP automatically?

No, not today. Windows certificate autoenrollment only talks to a Microsoft Enterprise CA (over DCOM), or to a Microsoft
Certificate Enrollment Policy and Enrollment Web Service pair. No Group Policy setting points it at another CA, and every
third-party product that plugs into autoenrollment needs certificate templates in Active Directory, a service account and
usually an on-site agent. SCEP on Windows is available only through an MDM such as Intune.

So users enroll each device from the EasyEAP portal (the Windows helper creates the key in the TPM where it can), and
Group Policy sets up everything around it: trust in the EasyEAP CA, the 802.1X services, and the Wi-Fi and wired
policies. Automatic machine certificates through a Group Policy startup task are planned (see
[docs/plans/windows-gpo.md](plans/windows-gpo.md) §3).

## Before you start

- You need: RADIUS settings saved in EasyEAP (server name and SSID), and the files from the console's Windows Group Policy
  dialog: `<tenant>-root.cer`, `<tenant>-issuing.cer`, `<tenant>-wifi.xml` and `<tenant>-wired.xml`. None of them is
  secret.
- Create one GPO for the network (for example "EasyEAP 802.1X") and link it to the OUs that hold the computers.
- Everything below is under **Computer Configuration → Policies → Windows Settings → Security Settings**.
- Import `<tenant>-root.cer` into the Trusted Root Certification Authorities of the PC you run Group Policy Management
  on, too: the EAP settings dialogs only list roots installed on that PC.

## 1. Trust the EasyEAP CA

1. **Public Key Policies → Trusted Root Certification Authorities → Import** → `<tenant>-root.cer`. Check that the SHA-1
   thumbprint matches the one in the console. Every computer in the GPO's scope then trusts certificates from this CA.
2. **Public Key Policies → Intermediate Certification Authorities → Import** → `<tenant>-issuing.cer`.
3. Don't add either to **NTAuth** (the Enterprise NTAuth store). That would let this CA's certificates sign in to the
   domain with smart-card logon, which EasyEAP doesn't need.

## 2. Start the 802.1X services

1. **System Services → WLAN AutoConfig** → Define this policy setting → **Automatic** (Wi-Fi).
2. **System Services → Wired AutoConfig** → Define this policy setting → **Automatic**. It's off by default, and wired
   802.1X never starts without it.

## 3. Wi-Fi policy

1. **Wireless Network (IEEE 802.11) Policies → Create A New Wireless Network Policy for Windows Vista and Later
   Releases.**
2. **General → Import…** → `<tenant>-wifi.xml`. That adds your SSID with every setting below already made, including
   WPA3-Enterprise, which the Group Policy editor can't select. If you import it, skip to step 6.
3. Or **Add → Infrastructure**: network name = your SSID; security WPA2-Enterprise (or WPA3-Enterprise), AES.
4. **Network authentication method: Microsoft: Smart Card or other certificate → Properties**:
   - When connecting: **Use a certificate on this computer**, with **Use simple certificate selection** on.
   - **Advanced**: Certificate Issuer → tick your EasyEAP root; Extended Key Usage → Client Authentication. With several
     client certificates on a PC, this is what makes Windows pick the EasyEAP one.
   - **Verify the server's identity by validating the certificate**: on. **Connect to these servers**: the RADIUS server
     name from the console.
   - **Trusted Root Certification Authorities**: tick your EasyEAP root only.
   - **Don't prompt user to authorize new servers or trusted CAs**: on (newer Group Policy Management: Notifications
     before connecting → Don't ask user). Without it, a user can accept an impostor's certificate.
5. **Advanced → Specify authentication mode: User authentication** (see [Sign-in and machine
   certificates](#sign-in-and-machine-certificates)).
6. OK, and close the policy.

## 4. Wired policy

1. **Wired Network (IEEE 802.3) Policies → Create A New Wired Network Policy for Windows Vista and Later Releases.**
2. **Security**: Enable use of IEEE 802.1X authentication for network access.
3. The same method settings as step 3.4 (certificate on this computer, issuer filter, server name, root, don't prompt).
4. **Advanced → Specify authentication mode: User authentication.** Cache user information for subsequent connections:
   on. **Enforce use of IEEE 802.1X authentication: off**, so the PC still works on ports without 802.1X.
5. Or deploy `<tenant>-wired.xml` with the script from the Windows wired kit (RADIUS → Windows wired kit) instead of this
   policy, but never both on the same PCs: a Group Policy wired profile disables the Settings toggle and replaces the
   script's profile.

## Sign-in and machine certificates

EasyEAP certificates belong to users, so the network starts after a user signs in.

- On a switch port that enforces 802.1X, the sign-in screen has no network. A user who has never signed in on that PC
  can't, and computer Group Policy doesn't refresh before sign-in. Domain users need cached credentials on wired-only PCs,
  or a first sign-in over Wi-Fi or on a port in monitor mode.
- Keep **User authentication** for now. **User or computer authentication** needs a machine certificate; without one,
  the sign-in screen still has no network.
- Machine certificates are planned and will fix this; this guide will then recommend User or computer authentication.

## Check it

1. On a PC: `gpupdate /force`, then `netsh wlan show profiles` (your SSID appears under "Group policy profiles") and
   `netsh lan show profiles`.
2. `certlm.msc` → Trusted Root Certification Authorities shows your EasyEAP root.
3. The user enrolls from the EasyEAP portal, then connects. EasyEAP's Authentication log shows the result and, if it
   fails, why (for example "Secure handshake failed" when the PC doesn't trust the server).
4. A Group Policy profile wins over a profile with the same name installed by the EasyEAP helper. Remove one of them so
   users see one network.
5. Several client certificates on one PC: the issuer filter (step 3.4) makes Windows pick the EasyEAP one.

## Not verified here

These steps follow Microsoft's documentation for Windows 10 and 11 and current Group Policy Management. They weren't run
against a real Active Directory domain in EasyEAP's test lab (which uses Samba AD and no Windows clients). Menu names
vary slightly between GPMC versions.

# Windows setup file

One file per user that sets up a Windows 11 PC for EasyEAP: trust in your certificate authority, the Wi-Fi and wired
802.1X networks, the user's certificate, the computer's certificate, and their renewal. Run it once on the PC and the
PC connects by itself from then on, including at the sign-in screen.

It's the quickest way to set up a PC that isn't managed by Group Policy, or a domain PC before Group Policy is in place.
For the Group Policy side, see [windows-group-policy.md](windows-group-policy.md).

## Make the file

1. Open the user in the console and choose **Windows setup** (needs a role that can issue certificates and manage
   enrollment; the button appears only for enabled accounts).
2. Choose what it sets up:
   - **The user's certificate** and **the computer's certificate** (both on by default). The computer's certificate is
     what gives the sign-in screen network, so people who have never signed in on that PC can, without cached
     credentials. It belongs to the same user (a device certificate, named `<PC name>.<username>`), so the PC gets that
     user's access.
   - **Shared PC**: the PC always connects with the computer's certificate, so anyone who signs in keeps the network.
   - **Wi-Fi** (needs the network name in RADIUS settings) and **Wired 802.1X** (on by default when wired enrollment is
     on).
   - How long the codes last: 24 hours to 14 days (3 days by default).
3. **Download setup** saves `EasyEAP-Setup-<username>.cmd`.

The file contains one-time codes, never a private key. Each code works once, for that user only, and expires. The
console lists them under the user's **Enrollment links** ("Windows setup file") until they're used, and you can cancel
them there. A file that was used or has expired does nothing; make a new one.

## Run it on the PC

1. Copy the file to the PC, or send it to the user.
2. The user signs in **as themselves** and double-clicks the file. Windows warns that it came from the internet:
   choose **More info → Run anyway** if SmartScreen asks.
3. Windows asks for administrator approval for the computer part. A standard user needs IT to type an administrator's
   name and password there. Don't start the file with "Run as administrator" from another account: the user's
   certificate would end up in the wrong account, so the setup skips it and says so.
4. The window lists every step with `[ok]` or `[!!]`, then waits for Enter.

| Network sign-in | When | What Windows does |
|---|---|---|
| Computer, then user | Both certificates (default) | The computer's certificate at the sign-in screen, the user's after sign-in |
| Computer only | Shared PC, or no user certificate | The computer's certificate, always |
| User only | No computer certificate | The user's certificate after sign-in; no network at the sign-in screen on 802.1X ports |

## What it does

As administrator (the computer part):

- Adds your root CA to the computer's Trusted Root Certification Authorities and the issuing CA to Intermediate
  Certification Authorities.
- Creates the computer's key and certificate in the computer's store (`certlm.msc` → Personal).
- Starts Wired AutoConfig (set to Automatic) and adds the wired profile to every physical Ethernet adapter.
- Adds the Wi-Fi network for every user on the PC.
- Installs `C:\Program Files\EasyEAP\renew.ps1` and two scheduled tasks under **Task Scheduler → EasyEAP**: *Renew
  computer certificate* (as SYSTEM, daily and at startup) and *Renew user certificate* (as each user, at sign-in and
  unlock).

As the user:

- Creates the user's key and certificate in their own store (`certmgr.msc` → Personal).

Each step stands on its own: a PC without Wi-Fi, or an adapter Windows refuses, doesn't stop the others. Without
administrator approval, the user part still installs the user's certificate, trusts the CA for that user (Windows asks
them to confirm), adds the Wi-Fi network for them and a renewal task for them only; wired 802.1X and the computer's
certificate need the administrator part.

The profiles check the RADIUS server's name and certificate authority, and pick the EasyEAP certificate even when the PC
has other client certificates (they match the issuer).

## Where the keys are

Keys are created on the PC and can't be exported. The setup tries, in order:

1. The **TPM** (Microsoft Platform Crypto Provider), ECDSA P-256.
2. The TPM with RSA 2048, for TPMs without elliptic curves.
3. **Software**: the Microsoft Software Key Storage Provider, ECDSA P-256, non-exportable. This is for PCs without a
   usable TPM, such as Windows 11 installed with the TPM requirement bypassed.

The console shows which one each certificate got: **TPM** or **Software key** next to the key's origin on the user's
page and on the certificate.

## Renewal

The renewal tasks run `renew.ps1`. When a certificate is inside its template's renewal window, the script makes a new
key (the same order as above), and the current certificate's key signs the request; EasyEAP checks that signature,
issues the new certificate and marks the old one superseded (it stays valid until it expires, so nothing drops). The
script installs the new certificate and deletes the old one with its key. The console shows "Renewed automatically"
on the new certificate.

Renewal needs nobody to sign in to the console and no new file. It stops working for a certificate that was revoked,
has expired, or whose user was disabled: run a new setup file then.

Logs: `C:\Program Files\EasyEAP\renew.log` (computer), `%LOCALAPPDATA%\EasyEAP\renew.log` (user), and the Application
event log, source **EasyEAP**.

## Check it

1. `certlm.msc` → Personal → Certificates: the computer's certificate, issued by your EasyEAP issuing CA.
   `certmgr.msc` → Personal: the user's.
2. `netsh lan show profiles` and `netsh wlan show profiles`.
3. Sign out: the sign-in screen shows the network connected (wired or Wi-Fi). EasyEAP's Authentication log shows the
   computer's certificate (`<PC name>.<username>`), then the user's after sign-in.
4. Run `Get-ScheduledTask -TaskPath \EasyEAP\` to see the renewal tasks, and
   `Start-ScheduledTask -TaskPath \EasyEAP\ -TaskName 'Renew computer certificate'` to run one now (it does nothing
   until the renewal window).

## Remove it

- Delete the certificates in `certlm.msc` and `certmgr.msc` (issued by your EasyEAP issuing CA), and revoke them in the
  console.
- `netsh lan delete profile interface="Ethernet"`, `netsh wlan delete profile name="<SSID>"`.
- Task Scheduler → EasyEAP: delete both tasks; delete `C:\Program Files\EasyEAP`.

## Not verified here

The setup is tested without Windows: PowerShell parses every generated file, the setup's steps run with Windows'
commands replaced by recorders (success, partial failure, no administrator), and its own signing code signs renewals
that EasyEAP verifies. It hasn't run on a real Windows 11 PC in EasyEAP's lab, so certreq with the TPM, netsh, the
approval prompt and the scheduled tasks are unverified. Windows 10 usually works; the setup says when it runs there.

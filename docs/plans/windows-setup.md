# Plan: Windows 11 setup and machine certificates

Status: built (2026-11-07); §8 is the review and what it changed. Requests, in the user's words: "build the machine certificates thing too, so users can log
in without cred caching"; "an .exe or a script that will automatically set up the Windows wired and the Wi-Fi profile,
import all the certs … and the user's cert too, if you select a username before you download"; "Windows 11 is the
default to build for"; "support PCs on Windows 11 with TPM bypass".

## 1. Goals

1. **One download per user does everything** on a Windows 11 PC: trust the tenant CA, the Wired AutoConfig service,
   the wired and Wi-Fi profiles, the user's certificate and the computer's certificate.
2. **The sign-in screen has network**: the computer authenticates with its own certificate before anyone signs in, so
   a user who has never signed in on that PC can (no cached credentials needed), and computer Group Policy refreshes.
3. **Certificates renew themselves** before they expire, with no one running anything again.
4. **TPM when there is one, a software key otherwise.** Windows 11 requires TPM 2.0, but PCs installed with the TPM
   bypass have none: keys then go to the Microsoft Software Key Storage Provider, never exportable. The console shows
   which one each certificate has.
5. Domain PCs through Group Policy: §7.

Nothing secret is in the download: it carries one-time enrollment codes that expire, and every private key is created
on the PC. A copied file is useless once used or expired.

## 2. Script, not .exe (for now)

An unsigned .exe triggers SmartScreen ("Windows protected your PC") and antivirus heuristics; a per-user .exe can't be
code-signed once and reused without tagging tricks. A script is transparent and needs no build toolchain.

The download is one file, `EasyEAP-Setup-<user>.cmd`: a batch/PowerShell polyglot. Double-clicking runs Windows
PowerShell 5.1 (on every Windows 11) with `-ExecutionPolicy Bypass` for that process only. A `.ps1` would open in Notepad
on double-click. Windows shows its "downloaded file" warning once; the guide says so. An .exe (Go, cross-compiled, signed
with the organisation's own code-signing certificate, the per-user codes in its file name) is a later option.

## 3. What the setup does

Run by the person who'll use the PC, signed in as themselves. It asks for administrator approval (UAC) for the
computer part; a standard user gets the UAC credential prompt for IT to fill in.

As the signed-in user:

1. Check Windows: build ≥ 22000 is Windows 11; Windows 10 works but the setup says it isn't the tested target.
2. **User certificate**: key in the TPM (Microsoft Platform Crypto Provider), ECDSA P-256 → TPM RSA 2048 → software
   ECDSA P-256 (TPM bypass); non-exportable; CSR → `POST /api/enroll/{code}/csr` (existing endpoint) with
   `key_storage` = `tpm` | `software`; `certreq -accept -user`.
3. Start the computer part elevated (`Start-Process -Verb RunAs`), handing it a file with the computer code.

Elevated (administrator):

4. Root CA → LocalMachine\Root, issuing CA → LocalMachine\CA.
5. **Computer certificate**: the same key order with `MachineKeySet = TRUE`; `certreq -accept -machine`.
6. Wired AutoConfig (dot3svc) Automatic and started; the LAN profile on every physical wired adapter.
7. The Wi-Fi profile for all users (`netsh wlan add profile … user=all`).
8. Sign-in mode in both profiles:
   - **One person uses this PC** (default): `machineOrUser`. The computer certificate at the sign-in screen, the user's
     certificate after sign-in.
   - **Shared PC**: `machine`. The computer certificate always, so people without an EasyEAP certificate can sign in
     and keep the network.
9. **Renewal**: `%ProgramFiles%\EasyEAP\renew.ps1` (only administrators can write there), a scheduled task
   `\EasyEAP\Renew computer certificate` as SYSTEM (daily with jitter, and at startup) and
   `\EasyEAP\Renew user certificate` for the Users group (at sign-in and at unlock; runs as each user, finds nothing to
   do for users without an EasyEAP certificate). Logs: `%ProgramFiles%\EasyEAP\renew.log` (computer),
   `%LOCALAPPDATA%\EasyEAP\renew.log` (user), and the Application event log, source `EasyEAP`.
10. A summary of what worked and what didn't. Each step stands alone (§8). Without administrator approval the user
    part trusts the CA for the user, adds Wi-Fi for the user and registers a renewal task for that user only, with
    the script in `%LOCALAPPDATA%\EasyEAP` (it runs as them, so a folder they can write is fine).

Everything is idempotent: running it again replaces EasyEAP's own profiles and removes EasyEAP certificates it
supersedes (matched by issuer = the tenant's issuing CA), never anything else.

## 4. Server side

- **Console**: Identities → a user → **Windows setup** (`enrollment:manage`). Options: Wi-Fi, wired (when wired
  enrollment is on), computer certificate (on), sign-in mode, how long the codes last (default 72 h, the enrollment link
  setting). It creates two enrollments (method `windows-setup`), user template + device template, and returns the file.
  Audit: `enrollment.windows_setup_created`.
- **The computer certificate is a device certificate of that user** (the existing "Device Wi-Fi" template, CN =
  `<pc>.<username>`, the PC's name reported by the setup), so access policy treats it like the user's devices: the
  user's groups, rules for the "device" purpose. Both certificates point at one Device row (the PC). Domain computer
  accounts are §7.
- **Key storage** recorded: `certificates.key_storage` (`tpm` | `software` | NULL = not reported).
- **Renewal endpoint** `POST /api/enroll/renew` (no token; the current certificate is the credential):
  body = the current certificate (DER, base64), the new CSR, `signed_at` (Unix seconds), `key_storage`, and a
  signature by the current certificate's key over
  `easyeap-renew-v1|<sha256 hex of the certificate DER>|<signed_at>|<sha256 hex of the CSR DER>`. The server checks:
  the certificate is one EasyEAP issued (looked up by its exact DER), active, not superseded or renewed already, not
  expired, purpose user or device, its identity enabled and tenant active; `signed_at` within ±10 minutes; the
  signature (ECDSA in IEEE P1363 as .NET produces, or DER; RSA PKCS#1 v1.5; SHA-256); the CSR's key differs from the
  current one; inside the template's renew window (else `{"renewed": false, "renew_from": …}`, nothing issued). It issues a certificate with the
  same template, identity, device and names, marks the old one superseded (still valid until it expires, as today) and
  logs `certificate.renewed`. One renewal per certificate (a superseded certificate can't renew). Rate limits per
  address and per serial.
- The Device row and the user's identity are unchanged; revoking either certificate in the console works as today.

## 5. Windows 11 details

- PowerShell 5.1, TLS 1.2 forced (`[Net.ServicePointManager]::SecurityProtocol`), `Invoke-RestMethod` with
  `-UseBasicParsing` where needed; the API URL is the console's public URL, which must have a certificate the PC trusts.
- certreq INF per key: `ProviderName`, `KeyAlgorithm`, `KeyLength`, `MachineKeySet`, `Exportable = FALSE`,
  `KeyUsage = 0x80` (digital signature), `RequestType = PKCS10`.
- Signing for renewal: `ECDsaCertificateExtensions.GetECDsaPrivateKey($cert).SignData(bytes, SHA256)` (P1363) or
  `RSACertificateExtensions.GetRSAPrivateKey($cert).SignData(bytes, SHA256, Pkcs1)`; both work for TPM keys.
- WPA3-Enterprise profiles (`WPA3ENT`) are supported on Windows 11.

## 6. Tests

Unit: setup generation (options, both enrollments, expiry, audit), every renewal check (signature formats, replay window,
wrong key, superseded, revoked, disabled account, outside the window), key storage recorded. The generated script is
parsed by PowerShell's own parser (`pwsh` in a container) so syntax errors fail the build, and the renewal signing code
runs under `pwsh` against the real endpoint with a software certificate. Not verified here: certreq, TPM providers,
netsh, UAC and scheduled tasks on a real Windows 11 PC (manual checklist in the guide).

## 7. Domain PCs through Group Policy

Windows' own certificate autoenrollment can use a non-Microsoft enrollment service that speaks MS-XCEP (policy) and
MS-WSTEP (enrollment) with Kerberos. That is a separate piece of work with its own plan: docs/plans/gpo-autoenrollment.md.
The setup file stays the way for PCs that aren't in a domain, or before Group Policy is set up.

## 8. Review (2026-11-07) and what it changed

Read the generated script as an attacker on the PC, as a user with no rights, and as a PC that only half works:

1. **Privilege escalation through the renewal script (fixed before release).** The first draft put `renew.ps1` in
   `%ProgramData%\EasyEAP`, run by a SYSTEM task. Users can create folders in ProgramData, so one could pre-create
   `EasyEAP` (or a junction) before the setup and own the script SYSTEM runs. It lives in `%ProgramFiles%\EasyEAP` now.
2. **A stale result from an earlier run.** The elevated copy hands its result back in `setup-result.json`, which a
   user can't delete. Each run tags it with a fresh run ID, and the result of another run is ignored.
3. **Comment injection.** The organisation and user names are in the file's header comment; `<#`/`#>`, CR and LF are
   removed there, and every value in code is a single-quoted literal or a here-string that can't be closed early.
4. **One failure took the rest down.** A wired adapter Windows refused, or a PC without the Wi-Fi service, ended the
   whole computer part, and its one-time code was already spent. Each step (trust, computer certificate, wired, Wi-Fi,
   renewal) now succeeds or fails on its own and the summary lists both.
5. **No renewal without an administrator.** A user-only, Wi-Fi-only setup never asked for approval, so nothing renewed
   the certificate. The user part registers a task for that user when the shared one wasn't registered, and removes it
   when a later run registers the shared one (two tasks would race over the same certificate).
6. **The wrong user's store.** Started with "Run as administrator" by an IT account, the user part would put the
   certificate in the IT account's store. It compares the process owner with the owner of the desktop (explorer) and
   skips the user part with a message when they differ, or when it runs as SYSTEM.
7. **Folders for everyone.** The renewal task runs for every user who signs in; the script created
   `%LOCALAPPDATA%\EasyEAP` for each. It now creates the folder only when it has something to log.
8. **Issuing CA after renewal.** The renewal response carries the issuing CA; the script adds it to the intermediate
   store, so a renewed certificate still chains if the CA certificate changed.

Accepted: the file can be read by anyone it's sent to, and its codes work for whoever runs them first, like an
enrollment link; they're one-time, expire (24 h to 14 days) and are tied to the user who was chosen. A copied file
can't produce a certificate for anyone else.

Not verifiable without a Windows 11 PC (no KVM on the build host): certreq with the TPM provider, netsh, UAC and the
scheduled tasks themselves. tests/windows/run.sh runs everything else under PowerShell 7 with those commands replaced
by recorders: it parses every generated file, checks the embedded profiles, runs the computer and user parts in the
success, partial-failure and no-administrator cases, and has the script's own signing code sign renewals that EasyEAP
verifies (ECDSA and RSA).

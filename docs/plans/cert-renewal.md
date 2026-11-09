# Plan: automatic renewal of client certificates, the RADIUS server certificate and the CA

Status: plan (2026-11-08); phase 1 built (§15a). Request, in the user's words: "I think we should give the admin the option to
enable auto-renew on the main CA, and user and machines certs, so users dont have to install a new cert when the time
comes." §1 is what exists, §2 what each platform allows (vendor sources in §16), §3–§11 the design, §12 tests, §13
risks, §14 the critique of this plan and what it changed, §15 the order of work.

"Main CA" is read here as the tenant's CA hierarchy: the **issuing CA** (online in OpenBao, 8 years by default, signs
every certificate and is the first to expire) and the **root CA** (offline, 20 years by default). The RADIUS server
certificate is in scope too: it is the certificate that lapses first (397 days) and nothing renews it today.

## 1. What exists today

### 1.1 Client certificates, per enrollment path

| Path (code) | Platforms | Key | Renews by itself today? |
|---|---|---|---|
| Windows setup file (`enrollment/windows_setup.py`, method `windows-setup`) | Windows 10/11, joined or not | TPM, else non-exportable software key, made on the PC | **Yes**: `renew.ps1` from `%ProgramFiles%\EasyEAP`, task *Renew computer certificate* as SYSTEM (daily with up to 8 h jitter, and at startup) and *Renew user certificate* for the Users group (sign-in and unlock); without an administrator, one per-user task (daily and at sign-in) |
| Linux setup script (`enrollment/linux_setup.py`) | Linux with NetworkManager, iwd, systemd-networkd or dhcpcd + wpa_supplicant | software key in `/etc/easyeap/<slug>/`, root only | **Yes**: `renew.sh` from a systemd timer (`OnBootSec=15min`, daily, `Persistent=true`) or `cron.daily` |
| Group Policy autoenrollment (`autoenroll/`, MS-XCEP/MS-WSTEP) | domain computers and users | Windows decides (TPM or software provider listed in the policy) | **Yes, by Windows**, see §1.3 |
| Portal, Windows helper (`profiles.windows_powershell`, method `link`) | Windows | TPM or software | **No**: certificate, root (CurrentUser, with Windows' prompt) and Wi-Fi profile only; no task |
| Portal, Apple (`profiles.apple_mobileconfig`; key made in the browser and wrapped in a PKCS#12 on the page, or server-generated) | macOS, iOS, iPadOS | keychain, from the PKCS#12 | **No** |
| Portal, Android (`.p12`, installed under Settings → Wi-Fi certificate) | Android | from the PKCS#12 | **No** |
| Portal, Linux by hand (NetworkManager / wpa_supplicant snippets) | Linux | | **No** (the portal says "won't renew itself") |
| Server-generated PKCS#12 (admin mode, opt-in) | any | made by OpenBao, one download | **No** |

Manual renewal for the "No" rows: an administrator creates a new enrollment link with `renewal_of` (the old
certificate's id) from the user's record; when it completes, `_finish` marks the old certificate `superseded`. The
dashboard's `certs_expiring` item says "Create a renewal link from each user's record" and counts every active client
certificate inside `expiry_warning_days` (30), including ones a renewal task will renew anyway.

### 1.2 The renewal endpoint (`POST /api/enroll/renew`, `enrollment/service.py:renew`)

Built with the Windows setup (docs/plans/windows-setup.md §4) and reused by the Linux script. The client sends the
current certificate (DER), a CSR for a **new** key, `signed_at`, `key_storage` and a signature by the current key over
`easyeap-renew-v1|sha256(cert DER)|signed_at|sha256(CSR DER)` (ECDSA P1363 or DER, RSA PKCS#1 v1.5, SHA-256). The
server, in a platform-scoped session (no tenant in the request):

- finds the certificate by the SHA-256 of its exact DER (so it must be one EasyEAP issued), checks the clock (±10 min),
  the signature, then: not revoked; not already renewed (a superseded certificate gets the certificate an earlier
  renewal issued **for the same new key** again, so a lost answer is recoverable; any other key is refused); not
  expired; purpose `user` or `device`; identity enabled; tenant active; template not an autoenroll one;
- returns `{"renewed": false, "renew_from": …}` (or 204 for `format=pem`) until `now ≥ not_after − template.renew_before_days`;
- checks the CSR (its own signature, key type) and that its key differs from the current one, then signs it through the
  template's OpenBao role with names rebuilt from the directory (the CSR's subject is ignored), records `renewal_of`,
  marks the old certificate `superseded` (still accepted by RADIUS until it expires) and audits `certificate.renewed`.

Rate limits: 60/min per address, 10/min per certificate. Not there: an on/off switch, any record of refusals (a
refused renewal leaves a line in the device's log and nothing in EasyEAP), any record that a renewer is alive, and
any way to hand a device new trust anchors. The scripts bake the template's `renew_before_days` in at download time
and do not call the server before that point.

### 1.3 Group Policy autoenrollment renewals

The XCEP policy advertises the template's validity and `renewalPeriodSeconds` (`renew_before_days`, 42 of 365 days by
default, at most ¾ of the validity) with `ENROLL_AUTOENROLLMENT | ENROLL_REMOVE_INVALID`. Windows renews by itself
inside that period: it sends a PKCS#10 inside a CMS SignedData signed by the old certificate. EasyEAP parses that form
(`cms.parse_request`, form `pkcs7`) but **does not verify the outer signature or tie the request to the old
certificate**: the request is authenticated by Kerberos (the computer or user account, re-checked in AD) exactly like a
first enrollment, rate-limited, and `_supersede` marks the account's earlier certificates of that template superseded
and sets `renewal_of` to the newest one. So renewal works whenever the PC can get a Kerberos ticket and reach the CES
URL. There is no key-based renewal (CES with X.509 authentication) for laptops that stay off the domain network.
`_ttl` shortens a certificate to the issuing CA's expiry and refuses one that would already be due for renewal. The
Autoenroll screen accepts a renewal period up to ¾ of the validity; Windows only supports less than 20 % (§2.1).

### 1.4 The RADIUS server certificate

`radius/state.py:ensure_server_certificate` issues it from the "RADIUS Server" template (397 days, `renew_before_days`
30) with a key made by OpenBao and kept Transit-encrypted in `radius_settings.server_key_ct`, when RADIUS settings are
first saved, when the host name changes, and on **Rotate** (`POST …/radius/server-certificate/rotate`). The previous
certificate is marked superseded, not revoked. **Nothing rotates it automatically**; the dashboard warns 30 days
before it lapses ("Rotating it is seamless: devices trust the CA, not the certificate"). The agent renders
`server.pem` = server certificate + the first certificate of `ca_pem` (the issuing CA), `ca.pem` = issuing CA + root +
the issuing CA's CRL + the root CRL, with `check_crl = yes`, `check_all_crl = no` (`services/radius/agent/render.py`).

### 1.5 The CA hierarchy

- Root: generated with `type=exported` in a temporary mount `pki-root-<tenant>-<hex>`, 20 years by default (5–30),
  `max_path_length 1`; the key is returned once as an encrypted PKCS#8 file (passphrase ≥ 12 characters) and the mount
  is deleted. Lab mode can keep that mount (root online). The root CRL is signed once, at the ceremony, valid one year.
- Issuing CA: key generated inside the tenant mount `pki-t-<tenant>` (`intermediate/generate/internal`), signed by the
  root, 8 years by default (1–15, capped at the root's expiry − 24 h), imported with `intermediate/set-signed`. CRLs
  72 h, rebuilt daily by the worker; OCSP on.
- **No renewal of either.** There is no issuing-CA renewal, no root renewal, and no way to re-sign the root CRL
  (PROGRESS.md "Root CRL renewal"; the console warns 60 days before the root CRL lapses and the issuing CA 180 days
  before it expires). ARCHITECTURE.md describes "later root operations … reopen a ceremony by uploading that file";
  that upload doesn't exist yet.
- The code assumes exactly one issuing CA: `pki.issuing_ca()` returns *the* active one, `chain_pem()` one issuing and one
  root, `crl_pem()` the mount's default CRL, the RADIUS desired state one `ca_pem`, the XCEP policy one CA certificate,
  `/pki/<tenant>/ca.crt` and `/crl` one each (and every certificate's AIA/CDP points at those two URLs).
- Leaf lifetimes are not capped at the issuer's expiry except in autoenrollment (`_ttl`). `sign_csr` and
  `issue_with_server_key` ask OpenBao for the full template TTL, and OpenBao 2.4.1 refuses a leaf that would outlive
  its issuer (`leaf_not_after_behavior = err`, §2.6); the routes don't catch `OpenBaoError`, so the user gets an HTTP
  500. With the defaults (8-year CA, 730-day device template) that starts about six years in; a tenant created with a
  1-year issuing CA (allowed) hits it on day one for device certificates, and a RADIUS server rotation fails once the
  CA has less than 397 days left.

### 1.6 Trust in the generated profiles

| Platform | Server validation | Client certificate selection |
|---|---|---|
| Windows WLAN/LAN XML (`profiles._eap_config`) | `ServerNames` = RADIUS host; **one** `TrustedRootCA` (root SHA-1 thumbprint); `DisableUserPromptForServerValidation` | setup file: `CAHashList` with root and issuing CA thumbprints |
| Windows Group Policy guide | the admin ticks the root in the wireless/wired policy; root to Trusted Root, issuing CA to Intermediate (not NTAuth) | "Certificate Issuer" = the root |
| Apple `.mobileconfig` (`com.easyeap.<slug>.wifi`) | `TLSTrustedServerNames` = host; `PayloadCertificateAnchorUUID` = [root, issuing]; `TLSAllowTrustExceptions` false | the PKCS#12 payload |
| Android | the user picks the installed CA and types the domain | the installed Wi-Fi certificate |
| Linux script | `ca.pem` = root + issuing; `domain-suffix-match` / `EAP-TLS-ServerDomainMask` = host | fixed file paths |

Every client trusts the **root** (Apple and Linux also the issuing CA) and the server **name**, never the server
certificate itself. That is why the server certificate and the issuing CA can change under the same root without
touching a single device, and why only a new **root** needs anything on devices.

### 1.7 Gaps this plan closes

1. The RADIUS server certificate lapses after 397 days unless someone clicks Rotate: every device stops connecting.
2. The root CRL lapses after a year and can't be renewed; the issuing CA can't be renewed at all.
3. No admin control over renewal; one window per template, baked into scripts at download.
4. Renewal failures are invisible to EasyEAP; refused renewals aren't audited; "expiring" counts certificates that will
   renew themselves.
5. The portal's Windows helper, Apple, Android and hand-configured Linux never renew; renewal links are manual.
6. A superseded certificate (and its key) keeps working until it expires; a stolen key can renew itself forever and the
   legitimate device only learns of it when its own renewal is refused.
7. Nothing can carry a new trust anchor to devices, so a root rollover would mean re-enrolling everything.

## 2. What each platform allows (vendor facts)

EasyEAP enrolls `windows`, `macos`, `ios`, `android` and `linux` (`enrollment/service.py:PLATFORMS`); there is no
ChromeOS path. Numbers in brackets are §16's sources, read on 2026-11-08.

| Platform | Silent renewal without MDM? | With management | What EasyEAP does (§4) |
|---|---|---|---|
| Windows, domain | **Yes**: Windows' autoenrollment renews by itself [1][2] | (it is the management) | Group Policy autoenrollment (exists) |
| Windows, not in a domain | **Yes, if something on the PC renews**: a scheduled task (EasyEAP's, exists), or Windows' own autoenrollment pointed at a certificate-authenticated policy server with key-based renewal [5][6] | Intune renews at a renewal threshold, a percentage of the lifetime left [15] | setup file's task (exists); the portal helper gets one; native autoenrollment later |
| macOS | **No** (auto-renewal exists only for AD-bound Macs against Microsoft AD CS [18][20]) | MDM re-sends the profile before expiry [19] | assisted renewal: link, one install |
| iOS, iPadOS | **No** [18][19] | MDM | assisted renewal |
| Android | **No** for certificates installed from Settings [32]; only an app of ours using Wi-Fi suggestions with a software key [26][27][28] | Android Enterprise device policy controller [29] | assisted renewal; an app later |
| Linux | **Yes, with a root timer** (EasyEAP's, exists) | (certmonger, for SCEP/IPA [37]) | setup script's timer (exists) |

### 2.1 Windows

- **Autoenrollment** runs every eight hours, and renews a certificate that has completed 80 % of its validity **and** is
  inside the template's renewal period; Microsoft says to set the renewal period above 8 hours and **below 20 % of the
  validity**, and when the values aren't supported "the renewal is skipped and the client triggers new enrollment
  requests instead" [1]. The Group Policy box "Renew expired certificates, update pending certificates, and remove
  revoked certificates" is `-EnableMyStoreManagement` [2]. The renewal request is signed with the old certificate's key
  and carries that certificate [3]. A new key is made by default; the "Renew with the same key" template option
  (`CT_FLAG_REQUIRE_SAME_KEY_RENEWAL`) keeps a TPM key [50]. Expired certificates can't be renewed [7].
  *For EasyEAP*: the Autoenroll screen accepts a renewal period up to ¾ of the validity. The 42-of-365-day default is
  fine (11.5 %); anything at or above 20 % makes Windows enroll afresh instead of renewing (which still works, because
  the request is authenticated by Kerberos, but isn't a renewal). Phase 1 caps it.
- **Key-based renewal.** A CES in renewal-only mode authenticates the client with its existing certificate's key [5];
  in the policy that is a `CAURI` with `clientAuthentication` 8 (message X.509) and `renewalOnly` true [4]. A PC that
  isn't in a domain can be pointed at such a policy server (`Add-CertificateEnrollmentPolicyServer -Credential
  <certificate> -AutoEnrollmentEnabled` with `Set-CertificateAutoEnrollmentPolicy -PolicyState Enabled
  -EnableMyStoreManagement`), and Windows' autoenrollment then renews at restart and every eight hours; Microsoft
  documents this for workgroup computers against AD CS [5][6]. Not confirmed against a non-Microsoft server.
- **Wi-Fi/wired profile trust.** `TrustedRootCA` may repeat (`maxOccurs="unbounded"`), each the SHA-1 hash of a
  certificate (so a root re-issued with the same key still has a new thumbprint); with
  `DisableUserPromptForServerValidation` a failed validation fails the authentication [8]. Windows 11 trusts the
  server only if the server certificate's thumbprint is in the profile, or the chain is trusted by the machine or user
  root store **and** its root's thumbprint is in the profile **and** the name matches [10]. So a new root must be in
  the store and in the profile before the server presents a chain to it. The client-certificate filter `CAHashList`
  holds "issuer hashes" [9]; whether a root's hash selects certificates issued by an intermediate under it isn't
  stated. The Group Policy editor's "Certificate Issuer" lists root CAs, which suggests chain matching. That gets
  checked on a real PC before any issuing CA switch (§13).
- **NTAuth.** KB 814394 says the client accepts a third-party root "in an Active Directory domain that has an
  NTAuthCertificates store that contains the published root certificate" [11]; the Windows 11 page doesn't mention it
  [10]. The sources conflict. This matters for EasyEAP on domain PCs whether or not anything renews (the Group Policy
  guide says to keep the CA out of NTAuth), so it goes on the real-PC checklist (§12).

### 2.2 macOS, iOS and iPadOS

- **No silent renewal for a profile installed by hand.** Apple: renew certificates deployed by a device management
  service before they expire by issuing a new profile [19]; certificates in SCEP payloads aren't eligible for automatic
  renewal [18]. The Active Directory Certificate payload can auto-renew, but only on macOS, as a device profile, on a
  Mac bound to AD, from Microsoft AD CS over DCE/RPC or AD CS web enrollment [18][20], so not from EasyEAP's CA.
- **ACME payload** (`com.apple.security.acme`): iOS/iPadOS 16 and macOS 13.1, **manual install allowed**; the key is
  made on the device, optionally hardware-bound (Secure Enclave, EC P-256/384; Macs need macOS 14 with Apple silicon
  or a T2 chip), and the server must use the `device-attest-01` challenge; the page says nothing about renewal [16].
  The declarative ACME credential is MDM only [24]. So ACME would replace the PKCS#12 with a key the device makes and
  can't export, but renewal would still be a new profile. OpenBao 2.4.1 has ACME, without `device-attest-01` [43][46].
- **Replacing a profile.** `PayloadIdentifier` decides whether a profile replaces an installed one or is added
  beside it [22]. Installing still needs the user: iOS, Settings → Profile Downloaded → Install, within 8 minutes of
  the download [23]; macOS, System Settings → General → Device Management [53].
- **Trust.** `PayloadCertificateAnchorUUID` is an array (several anchors); `TLSTrustedServerNames` is an array and
  turns off the certificate prompt [21][51].

### 2.3 Android

- Certificates installed from Settings are installed by hand each time [32]. Since Android 11, apps on unmanaged
  devices can't install CA certificates; users install them in Settings [30].
- The only silent path without a device policy controller is an **app of ours** that adds a Wi-Fi network suggestion
  with `WifiEnterpriseConfig.setClientKeyEntry` and `setCaCertificates`, and updates it in place (`CHANGE_WIFI_STATE`,
  one user approval; on Android 11+ a TLS suggestion must set a root CA and a server domain) [26][27][28]. The key
  must be exportable (`setClientKeyEntry` encodes it, so a hardware keystore key is refused, per the AOSP source [33]);
  `setClientKeyPairAlias` with a keystore key needs `grantKeyPairToWifiAuth`, which only a device owner, profile owner
  or delegated certificate installer can call [29].
- With Android Enterprise, a device policy controller generates or installs the key pair and grants it to Wi-Fi [29].
- Passpoint online sign-up is deprecated (Wi-Fi Alliance, June 2023) and provisioned EAP-TTLS only [31];
  `addOrUpdatePasspointConfiguration` fails for ordinary apps targeting Android 11+ [27].
- `setCaCertificates` takes several CAs (the limit isn't documented); `setDomainSuffixMatch` several names [26].

### 2.4 Linux

- wpa_supplicant's `ca_cert` file "can have one or more trusted CA certificates" [35] and is read into a fresh store
  at each TLS connection setup [36], so replaced files are used at the next authentication. NetworkManager's
  `802-1x.ca-cert` is a path, with `ca-path` for a directory [34]; EasyEAP's script already writes a two-certificate
  bundle there and is tested on Ubuntu 22.04–26.04 (docs/enrollment.md).
- certmonger renews by itself through SCEP (RenewalReq), IPA or Dogtag, not EST [37]. Not used: EasyEAP's script needs
  no extra package, and EasyEAP doesn't speak SCEP.

### 2.5 Standard protocols

- **EST** (RFC 7030): re-enrollment authenticates with the existing certificate in TLS (§3.3.2); `/simplereenroll`
  keeps subject and SAN identical (§4.2.2); tls-unique in `challengePassword` links the request to the TLS session
  (§3.5) [38].
- **SCEP** (RFC 8894): `RenewalReq` is signed with the key of the previously issued certificate (§2.3, §3.2.1.2) [39].
- **ACME** (RFC 8555): no renewal operation, a renewal is a new order (§7.4); RFC 9773 (ARI) lets the server suggest
  windows; `device-attest-01` is an IETF draft [40].
- **CMP**: RFC 4210 is obsoleted by RFC 9810; key update (`kur`) is for non-revoked, non-expired certificates [41].
- No Windows or Linux distribution ships any of these as a renewal client for Wi-Fi certificates, and OpenBao 2.4.1 has
  ACME only (EST and SCEP are open requests) [43][46][47]. EasyEAP's own renewal (a signature by the old key over the
  old certificate, the time and the new request, §1.2) is SCEP's RenewalReq idea without CMS, and is already on every
  device that renews. It stays.

### 2.6 OpenBao 2.4.1, FreeRADIUS, and CA practice

From OpenBao's documentation [43][44][45] and the v2.4.1 source [46] (EasyEAP pins `openbao/openbao:2.4.1`):

- One mount holds several issuers; requests that name none use the **default issuer** (`/config/issuers`).
  `default_follows_latest_issuer` is false by default, and importing (`intermediate/set-signed`,
  `issuers/import/bundle`) or generating a root into a mount that already has a default **doesn't move it**.
- `leaf_not_after_behavior` is per issuer and **defaults to `err`** (the import path sets it, so EasyEAP's issuing
  CAs have it): a leaf whose requested expiry passes the issuer's is refused. *For EasyEAP* this is an `OpenBaoError`,
  which the enrollment and renewal routes don't catch: HTTP 500 (§1.5).
- `issuer/:ref/sign-intermediate` **always lets an intermediate outlive its signer** in 2.4.1 (a warning only), and
  `root/sign-self-issued` checks nothing: EasyEAP must cap CA lifetimes itself (`run_ceremony` does).
- `crl/rotate` rebuilds **every** issuer's CRL; issuers that share a key and subject share one CRL; each issuer's CRL
  is at `issuer/:ref/crl`.
- `issuer/:ref` takes its own `issuing_certificates`, `crl_distribution_points` and `ocsp_servers`, which override
  `config/urls`; setting any one cuts that issuer off from all the global values, so set all three.
- Rotation primitives: cross-signing (`intermediate/cross-sign`, `issuer/:ref/sign-intermediate`,
  `issuers/import/cert`, `manual_chain`), reissuance with an existing key (`issuers/generate/intermediate/existing`,
  `issuers/generate/root/existing`, `key_ref`), and "forward" (the old certificate vouches for the new key) and
  "backward" links. The suggested root rotation: a new root with a new common name, cross-sign the intermediates, move
  leaves onto them, add the new trust, then remove the old [44].
- `issuers/import/bundle` takes a certificate with its private key (how a ceremony brings the offline root back).
  `tidy_expired_issuers` removes expired issuers after `issuer_safety_buffer` (8760 h); `issuer/:ref/revoke` can't
  be undone.

FreeRADIUS 3.2: every CA in `ca_file` is trusted to issue client certificates [48]; since 3.0.24 the server
certificate can be chosen per request (`TLS-Session-Cert-File` with `realm_dir`) [49].

Practice: Microsoft recommends renewing a CA certificate at half its validity; a same-key renewal keeps old
certificates chaining to the new CA certificate and one CRL, a new-key renewal makes cross-certificates and a new CRL
[12][13]. RFC 9810 §4.4 describes the root key update certificates (old-with-new, new-with-old) [41]. NIST SP 800-57
puts a signature key's cryptoperiod at one to three years, ending at the last certificate's expiry, and allows several
certificates for one key [42]. None of these sets an overlap length for 802.1X; this plan's is §6.1.

## 3. Admin settings (per tenant)

A **Renewal** section on the Certificate authority page (permission `ca:manage`: PKI Administrator, Tenant
Administrator). New table `renewal_settings`, one row per tenant, created by the migration with these defaults:

| Setting | Default | Meaning |
|---|---|---|
| `user_certs` | on | User certificates renew with their own key (setup file, Linux script, Windows helper), and certificates on platforms that can't renew silently get a renewal link at the start of their window (§4.6). Off: `/api/enroll/renew` refuses user certificates with a clear message, and no links are made. |
| `machine_certs` | on | The same for device/computer certificates made by the setup file (LocalMachine store) and the Linux script. Group Policy autoenrollment keeps its own on/off on the Autoenroll screen (Windows renews those itself; EasyEAP can't tell a renewal from a first enrollment there), and the card says so. |
| `server_cert` | on | The RADIUS server certificate rotates by itself (§5). |
| `renew_at_percent` | 80 | Renewal starts when this share of a certificate's own lifetime has passed (50–90). A 365-day certificate renews from 73 days before expiry, a 730-day one from 146. |
| `ca_rollover` | `guided` | `off`: warnings only (today). `guided`: EasyEAP computes the schedule, asks for the root key file when it needs it (§6.2), and does everything else itself. `automatic`: the root key is held in OpenBao so nobody has to bring it (§6.8; opt-in, step-up, labelled). |
| `retire_superseded` | on | Revoke a renewed certificate once its successor has been used, or 30 days after renewal for automatic renewers that delete the old key (§4.8). |
| `notify_users` | off | Email the certificate's holder their renewal link and reminders (needs the platform's SMTP settings, §4.6). |

Why a percentage: it holds for certificates that were shortened (by an expiring issuing CA, or autoenrollment's
`_ttl`), where "N days before expiry" can exceed the whole lifetime and make a device renew at every run. The
templates keep `renew_before_days` because Windows needs days in the XCEP policy and the scripts read it: saving the
setting rewrites every template's `renew_before_days = ceil((100 − p)% × validity_days)` (autoenroll templates get a
minor revision bump, as editing them does today), and the template dialog shows the derived value read-only
("73 days, from Renewal settings"). The server's own test is per certificate:
`renew_from = not_before + p% × (not_after − not_before)`.

80 % is where Windows' own autoenrollment starts renewing (§2.1 [1]), and leaves a laptop that's switched off for two
months inside the window; the current templates sit at 88–94 %. Domain PCs never renew before 80 %, whatever the
setting: their templates' renewal period is capped below 20 % of the validity, as Microsoft requires [1].

## 4. Client certificates

### 4.1 The rule

A certificate renews when: its tenant is active, the setting for its purpose is on, it is active (not revoked, not
superseded, not expired), its identity is enabled, `now ≥ renew_from`, the request proves possession of the current
key and of the new key, and the new key differs. The new certificate gets the same template, identity, device and
directory-built names, and is capped at the issuing CA's expiry (§6.1); if the cap would leave it already due, the
request is refused with "the issuing CA must be renewed first" and a critical dashboard item, instead of issuing a
certificate that would renew again every day.

### 4.2 Renewal protocol v2 (`POST /api/enroll/renew`, backward compatible)

v1 requests keep working unchanged (every PC and Linux computer set up so far runs v1). v2 adds:

- **Check-in.** A request without `csr` and with `easyeap-check-v2|sha256(cert)|signed_at|sha256(client)` signed by
  the current key records `certificates.renewal_checked_at`, the renewer kind and version, and answers
  `{"renewed": false, "renew_from": …, "trust": …}`. v2 renewers call daily whether or not they're due, so EasyEAP
  knows which renewers are alive (§10).
- **Client block**, covered by the signature (`easyeap-renew-v2|…|sha256(client)`): `{"kind": "windows-setup" |
  "windows-helper" | "linux", "version": "2", "scope": "computer" | "user", "roots": [sha256 of the EasyEAP roots the
  device trusts], "profile_roots": [the thumbprints in its Wi-Fi/wired profiles]}`. Telemetry only; it never changes
  what is issued, but it is what tells EasyEAP a device can take a new root (§6.6).
- **Trust block** in every answer: the tenant's current anchors and, during a root rollover, the new root and the
  cross-certificate that proves the old root vouches for it (§6.6). The issuing CA chain of the new certificate comes
  with it, as today.
- **Settings and audit.** The tenant's switches are honoured; every refusal is audited as `certificate.renewal_refused`
  with the reason (at most once a day per certificate and reason), so "renewal stopped" is visible.
- **Tenant scope.** The platform-scoped session is used only to find the certificate by its fingerprint; the handler
  then switches to the certificate's tenant (`set_tenant`) before anything is read or written, so row-level security
  covers issuance (today the whole renewal runs platform-scoped).

### 4.3 Windows setup file, renewer v2

`SCRIPT_VERSION = "2"`. `renew.ps1`:

- checks in daily (computer task) and at sign-in/unlock at most once a day (user task), and uses the server's
  `renew_from` instead of the baked-in days (kept only as a fallback when EasyEAP can't be reached);
- finds its certificate by issuer **and** chain to a trusted EasyEAP root, not by the issuing CA's subject alone (v1
  matches `Issuer -eq <issuing CA subject>`, which is why §6.3 keeps that subject unchanged);
- installs a new root only when the answer carries a cross-certificate that verifies under a root it already trusts
  (§6.6), then rewrites EasyEAP's own Wi-Fi and wired profiles from the templates it was installed with, adding the
  thumbprint to `TrustedRootCA` and `CAHashList` (`netsh wlan add profile … user=all`, `netsh lan add profile`). Only
  the SYSTEM task does this; it can't change the SSID, the server name or anything else in the profile;
- when a **user** certificate is within 14 days of expiry and renewal keeps failing, shows a Windows notification to
  the signed-in user ("Your network certificate expires on … Contact IT") once a day; SYSTEM can't show UI, so the
  computer certificate relies on the dashboard (§10).

The setup file installs v2; a PC set up with v1 keeps renewing with v1 (and is listed as "renewer v1: can't take a new
root" until someone runs a new setup file).

### 4.4 Linux script, renewer v2

Same changes: daily check-in, server-provided window, `ca.pem` extended only with a new root whose cross-certificate
verifies against the bundle (`openssl verify -CAfile`), atomically replaced. `renew.sh` is regenerated by a new setup
script only; v1 keeps working.

### 4.5 The portal's Windows helper

Today it installs nothing that renews. It gains the setup file's user-only renewal (a per-user task with
`%LOCALAPPDATA%\EasyEAP\renew.ps1`, as `Invoke-UserPart` registers when no administrator ran the computer part), so a
user certificate from the portal renews like one from the setup file. The portal points Windows users to the setup file
first, as it does now.

### 4.6 Platforms that can't renew silently (Apple, Android, Linux by hand, server-generated packages)

No zero-touch path exists without MDM (§2). The least effort EasyEAP can offer is to do everything up to the tap:

- **Renewal links made automatically.** A daily job makes a renewal link (`renewal_of` = the certificate; same
  identity, device name, platform and template; one live link per certificate, 7 days, remade weekly until the
  certificate is renewed or expires) when a certificate without a renewer reaches `renew_from`.
- **Delivery.** With `notify_users` on and SMTP configured (new platform settings: host, port, STARTTLS/TLS, from,
  optional credentials, tested from the console), the holder's directory email gets the link, then reminders at 14, 7
  and 1 days. Without SMTP, the console's **Renewals to send** queue lists them with a copy button, which is what admins
  do today by hand. Every link sent is audited.
- **One tap on the device.** The renewal page says what it replaces ("the certificate on Paul's iPhone that expires on
  12 March"). Apple: the new profile keeps the identifier `com.easyeap.<slug>.wifi`, so it replaces the old one
  in place (§2.2); the user taps Install and enters the device passcode. Android: install the new Wi-Fi certificate and
  pick it in the saved network (Android has no way to swap it underneath). Server-generated packages are renewed as a
  new server-generated package and need an administrator, as today.
- Completing the link supersedes the old certificate (`_finish`, as today) and §4.8 retires it.

### 4.7 Group Policy autoenrollment

Windows keeps renewing. Changes: `renew_at_percent` drives the templates' renewal period (§3), capped at 19 % of the
validity because Windows skips renewal and enrolls afresh at 20 % or more [1] (the Autoenroll screen's limit drops
from ¾ to that); a renewal request's
SignedData signature is verified and, when it verifies, `renewal_of` points at that exact certificate (today it is "the
newest earlier one"); a renewal signed by a **revoked** certificate is logged as a renewal of a revoked certificate
(the account still gets a certificate, because Kerberos and AD are the authority here: disable the account or remove it
from the computer group to stop it, as docs/autoenrollment.md says). Key-based renewal for PCs off the domain network
(a second CES URL with X.509 authentication, `renewalOnly`) is §15 phase 7.

### 4.8 Retiring superseded certificates

Today a renewed certificate stays valid until it expires, so a copied key keeps working for the whole window. With
`retire_superseded` on, a daily job revokes (reason `superseded`) a superseded certificate when its successor has been
accepted by RADIUS (`auth_events.cert_serial`), or 30 days after renewal when the renewer deletes the old key itself
(setup file, Linux script, Group Policy with `ENROLL_REMOVE_INVALID`): a connected device re-authenticates every
`Session-Timeout` (8 hours by default) and reads the new files then [36], so 30 days only catches devices that were
off. Manual platforms are retired only once the successor has been seen. A superseded certificate that is still
presented after its successor was used is a security event (`certificate.superseded_used`, critical on the dashboard):
two devices hold copies of one key.

Revoking a certificate in the console also revokes its active successors (`renewal_of` chain): renewal continues the
same credential, so "revoke this certificate" must not leave its renewed copy working.

## 5. RADIUS server certificate rotation

- Daily job `renewal.server_cert` per tenant: when `server_cert` is on and `now ≥ not_before + p% × lifetime` (80 %:
  about 80 days before a 397-day certificate expires), call `ensure_server_certificate` (same template, host name,
  key type), bump `config_version`, audit `radius.server_certificate_rotated` as the system. The agent picks it up
  within its poll interval; FreeRADIUS reloads.
- Before switching: the new certificate must chain to the tenant root with the current issuer, carry the host name, and
  be valid for at least 30 days (capped by the issuing CA, §6.1).
- Rollback: `radius_settings` keeps `previous_server_certificate_id` and `previous_server_key_ct` for 14 days.
  `POST …/radius/server-certificate/rollback` puts the previous one back.
- Watch: for two hours after a rotation (and after any CA switch, §6), the job compares the rate of `tls_handshake` and
  `client_timeout` rejects (the reasons RADIUS records when a device abandons the handshake because it doesn't like the
  server's certificate, `radius/explain.py`) with the previous day's same hours, per device. Devices that succeeded
  before and fail now raise a critical item "Devices refuse the new server certificate" with the rollback button.
- The manual Rotate button stays. The dashboard item `server_cert_expiring` stays as the safety net (it fires only if
  rotation failed).

## 6. CA rollover

### 6.1 The arithmetic

A CA can't issue certificates that outlive it (§2.6). With `L` the longest validity among the tenant's templates
(730 days for "Device Wi-Fi", 397 for the server) and a 90-day margin `M`, for an issuing CA `I1` expiring at `E1`:

- **Switch** `S = E1 − L − M`: from then on the next issuing CA `I2` issues. Everything `I1` issued before `S` expires
  before `E1`.
- **Prepare** `P = min(S − 180 days, half of I1's validity)`: `I2` should exist (signed by the root) by then; half
  the validity is Microsoft's recommendation for renewing a CA [12], and with the defaults it is the earlier of the
  two (year 4), which leaves the admin almost two years to bring the key file before `S`. In `guided` mode the
  dashboard asks for it from `P`, and turns critical 90 days before `S`.
- **Retire** at `E1 + 1 day`: `I1` leaves the trust bundles and CRL sets.

Defaults (root 20 y, issuing 8 y, L = 730 d): `S` ≈ 5 years 9 months after the ceremony; `I2` runs to year 13.75,
`I3` is capped at the root's expiry, and the root rollover (§6.6) starts 5 years before the root expires. A template
change that moves `S` into the past is refused with the date by which the CA must be renewed. The schedule is
recomputed whenever templates or CAs change and shown on the CA page (§11).

### 6.2 The root ceremony from the console

`POST /api/tenants/{tid}/pki/ceremony` (multipart: the encrypted root key file, the passphrase, the operations).
The server decrypts the PKCS#8 in memory, checks that the key matches the active root certificate, imports it with its
certificate into a temporary mount `pki-root-<tenant>-<hex>` (`issuers/import/bundle`, §2.6), runs the operations,
and deletes the mount in `finally`, as `run_ceremony` does today. The key is never written to the database, a log or a
backup; the passphrase field is redacted in request logging. Step-up: the admin's TOTP when they have one.

Operations (any combination; the dialog preselects what's due):

1. **Verify the key file** (nothing signed): proves the file and passphrase still work. Offered every year, because
   a lost root key file turns every later step into "re-enroll every device".
2. **Renew the root CRL** (one year, as today). Closes the PROGRESS.md limitation. Due yearly, so the admin brings the
   key once a year anyway; that's the natural moment for the next steps.
3. **Prepare the next issuing CA** (§6.3) when `now ≥ P`, or when the admin asks.
4. **Prepare a new root** (§6.6) when the root rollover is due.

### 6.3 Issuing CA rollover

A **new key under the same subject name** as the current issuing CA, as AD CS keeps a CA's name when it renews it
[13]. The same name matters because renewer v1 on every PC set up so far finds its certificate by the issuing CA's
subject (§4.3); chain builders and OpenBao's CRL grouping go by key, so two CAs with one name and different keys stay
distinct (proved for FreeRADIUS by the §12 integration test before release; fallback in §13).

Preparing (phase 4, inside the ceremony; all in the tenant mount `pki-t-<tenant>` unless said otherwise):

1. `issuers/generate/intermediate/internal` with the current issuing CA's subject: a new key and its CSR.
2. In the temporary root mount: `issuer/<root>/sign-intermediate` with `use_csr_values=false`, the same subject,
   `max_path_length 0`, and a TTL EasyEAP computes: the tenant's issuing validity, capped at the root's expiry minus
   24 hours, because 2.4.1 won't stop an intermediate from outliving its root (§2.6).
3. `intermediate/set-signed` with that certificate and the root: a new issuer, and the default stays where it is
   (§2.6). Then `issuer/<new>`: name `issuing-g<n>`, `leaf_not_after_behavior = err` kept as a backstop (EasyEAP caps
   leaves itself, §4.1), and all three of its own URL lists (§6.4).
4. A `certificate_authorities` row: `role = issuing`, `generation = n`, `status = next`, `bao_issuer_id`.

`next` is already trusted where it's harmless (RADIUS `ca.pem` and its CRL, so a mistake shows before anything depends
on it) and issues nothing.

Switching (phase 5), at `S` or when the admin presses **Switch now**: `config/issuers` `default = <new id>`. Every
role, and the CEL roles of autoenrollment, use `default`, so every issuance path moves at once. Then the RADIUS server
certificate is re-issued from the new issuer (with §5's watch), XCEP advertises the new CA certificate, and the old row
becomes `retiring`. Rollback sets the default back while the old issuer still has more than `L + M` left.

Retiring, at `E1 + 1 day`: out of every bundle and CRL set, status `retired`. The issuer stays in OpenBao until
auto-tidy's `tidy_expired_issuers` removes it after its one-year safety buffer; `issuer/:ref/revoke` is never used for
this (it can't be undone, and it means compromise).

Why not reissue the same key with a new certificate? Old certificates would chain to it and one CRL would serve both
[13][46], which is simpler, but one signing key would live 16 years and more, against NIST's cryptoperiods [42], and
Windows identifies CAs by certificate thumbprint anyway [8][9]. Reissuance is used only to re-certify the current
issuing key under a new root (§6.6).

### 6.4 EasyEAP with more than one issuing CA

- `certificate_authorities` rows get `generation`, `bao_issuer_id` and a status `next | active | retiring | retired`
  (today only `active`). Helpers replace the single-CA ones: `current_issuer()` (issues), `trusted_issuers()`
  (`active` + `retiring`: RADIUS and client bundles), `chain_for(cert)` (its own issuer + root, for responses),
  `trust_bundle()` (every trusted issuer, every root, cross-certificates).
- **CRLs**: one per issuer, all in RADIUS's `ca.pem`. With `check_crl = yes`, a certificate whose issuer has no CRL in
  the file is rejected, so a missing CRL rejects every certificate of that issuer: `desired_state` refuses to publish a
  tenant whose trusted issuers don't all have a current CRL (the tenant keeps its last good configuration and the
  dashboard says why), and `crl.rotate` rebuilds and records each issuer's CRL (`crl_next_update` per CA row).
- **URLs**: new issuers get their own CA and CRL URLs (`/pki/<tenant>/ca/<generation>.crt`, `/crl/<generation>`), set
  per issuer in OpenBao (§2.6). The existing `/ca.crt` and `/crl` keep serving generation 1, because every certificate
  it issued carries those URLs.
- **RADIUS desired state**: `server_chain_pem` (server certificate + its own issuer + any cross-certificate) next to
  `ca_pem`; `ca_pem` lists the server certificate's issuer **first**, so an older agent that still builds `server.pem`
  from "the first certificate in `ca_pem`" gets the right chain (version skew, as tested in `tests/radius/run.sh`).
- **XCEP** advertises the current issuer's certificate; responses carry the new certificate's own chain.
- **Snapshot**: `authz` rows are keyed by serial; OpenBao serials are random per mount, so two issuers in one mount
  can't collide. Keep the key, add the issuer to the event record for display.
- The certificate list and detail show the issuer generation; "Issuing CA" cards become one card per issuer with its
  status and dates.

### 6.5 What the RADIUS server presents during the overlap

One server certificate per tenant, as rendered today (FreeRADIUS 3.0.24+ can choose one per request [49]; this plan
uses that only for the staged root switch in §6.6). Before the switch it chains to `I1`, after it to
`I2`; both chain to the same root, which is what every device trusts (§1.6), so devices don't notice. RADIUS's
`ca.pem` holds root, `I1`, `I2` and both CRLs from the moment `I2` exists, so client certificates from either are
accepted throughout. The switch re-issues the server certificate from `I2` (§5 rotation path, with the same watch and
rollback); rollback of a switch sets the default issuer back to `I1` while `I1` has more than `L` left.

### 6.6 Root rollover

Rare (the default root lives 20 years) but the only change devices have to take part in. It follows OpenBao's
suggested root rotation [44] and AD CS's new-key renewal [13]. For a root `R1` expiring at `ER`:

1. **Prepare** (a ceremony from `ER − 5 years`, with R1's key file):
   - generate `R2` in a temporary mount (`root/generate/exported`, a new key, a new common name such as
     "<org> Root CA 2", so that Windows' and Group Policy's lists can tell them apart) and hand its key back once,
     encrypted, like the first ceremony;
   - a **cross-certificate** `X`: R2's subject and key signed by R1, valid until `ER` (the "forward" link: the old
     root vouches for the new key [44]; `intermediate/cross-sign` for a CSR of R2's key in R2's mount, signed by
     `issuer/<R1>/sign-intermediate` in R1's). Devices use `X` to decide whether to trust R2 (§4.3, §14 item 7);
   - **re-certify the current issuing key under R2** (reissuance: `issuers/generate/intermediate/existing` with the
     issuing key's `key_ref`, signed by R2, imported with `intermediate/set-signed`): `I'` has the same subject and
     key as `I`, so OpenBao keeps one CRL for both [46], and every certificate `I` has issued also chains to R2;
   - R2's first CRL; both temporary mounts are deleted.
2. **Publish**, from the ceremony for at least `L` plus the renewal window plus six months (3–4 years with the
   defaults): RADIUS trusts R2 and `I'`; every renewal answer and every new package carries R2 and `X` (§4.2, §6.7);
   renewer v2 installs R2 only when `X` verifies under the R1 it trusts; the Group Policy checklist. The CA page shows
   readiness per platform: devices whose check-in reported R2 in store and profile, devices that received a package
   with R2, and devices that can't take it (renewer v1, the Windows helper, Group Policy until the admin confirms it).
3. **Switch** (from `ER − 1 year`, when the admin has confirmed Group Policy and accepts the readiness shown): the
   server keeps its certificate and sends `I'` (by R2) with it instead of `I` (by R1). Only the intermediate copy
   changes. §5's watch and rollback (send `I` again) apply while R1 is valid. Staged if wanted: with
   `TLS-Session-Cert-File` [49], devices whose check-ins reported R2 get the new chain first, everyone else later.
4. **Retire** at `ER`: R1, `X` and `I` (by R1) leave every bundle. Later issuing CAs are signed by R2 only.

Why not keep R1's key and re-issue its certificate? Windows profiles pin the root certificate's thumbprint [8], so it
needs the same profile changes as a new root, and the key's age is what the rollover is for [42].

### 6.7 How each platform gets a new root

| Platform / path | Mechanism | User action |
|---|---|---|
| Windows setup file, renewer v2 | SYSTEM task installs the new root in LocalMachine\Root and adds it to EasyEAP's profiles, only after verifying the cross-certificate (§4.3) | none |
| Windows setup file, renewer v1; Windows helper | can't (v1 only imports issuing CAs; the helper's user task can't write LocalMachine\Root and CurrentUser\Root prompts) | run a new setup file; listed by name in the console |
| Domain PCs (Group Policy) | the admin imports the new root into the GPO's Trusted Root Certification Authorities **and ticks it in the wireless and wired policies at the same time** (§13); the console gives the files and an updated `-wifi.xml`/`-wired.xml` | admin, once; nothing on PCs |
| Apple | every profile made from the start of the rollover carries both roots as anchors; devices get it at their next (manual) renewal | the renewal tap they do anyway |
| Android | the new PKCS#12 carries both roots | the renewal steps they do anyway |
| Linux script, renewer v2 | `ca.pem` extended after verifying the cross-certificate (§4.4) | none |
| Linux by hand / renewer v1 | can't | new setup script |
| RADIUS | `ca.pem` gets the new root, the cross-certificate and the re-certified issuing CA at once | none |

The publish phase lasts at least `L` plus the renewal window, so that every certificate in use has renewed once after
the new root appeared; the server switches only after that (§6.6).

### 6.8 `automatic` mode: the root key in OpenBao

Opt-in per tenant, Tenant Administrator with step-up, explained on screen: "EasyEAP will be able to sign with your root
key at any time. If this server is compromised, your root is too, and recovering means re-enrolling every device."
Turning it on runs a ceremony that imports the root key into a permanent mount `pki-root-<tenant>` as a key OpenBao
won't export (the API policy already covers `pki-root-*`); turning it off deletes that mount (the admin keeps the file
they uploaded). With it, the worker renews the root CRL 60 days before it lapses, prepares the next issuing CA at `P`
and switches at `S` with nobody involved. The root rollover itself stays guided: a new root has to reach Group Policy
and the admin decides when to switch. Lab mode's online root behaves like `automatic`. SECURITY.md's table gets a row
for it.

## 7. Data model (migration `0011_renewal`)

- `renewal_settings` (tenant PK): the §3 settings, `updated_at`, `updated_by`.
- `certificate_authorities`: `generation` (int, 1 for existing rows), `bao_issuer_id`, `parent_id` (the root that
  signed it), `kind` (`self` | `cross`), status values `next | active | retiring | retired`, `switch_at`.
- `certificates`: `renewer` (`windows-setup` | `windows-helper` | `linux` | `gpo` | `link` | NULL), `renewer_version`,
  `renewal_checked_at`, `trust_reported` (JSONB: roots and profile roots from the last check-in), `retired_at`.
- `radius_settings`: `previous_server_certificate_id`, `previous_server_key_ct`, `server_cert_rotated_at`.
- `platform_settings` key `smtp` (secret parts Transit-encrypted with the platform key).
- No new tables for links: renewal links are `enrollments` with `renewal_of`.

## 8. Jobs (worker, per tenant, daily unless noted, deduplicated as today)

`renewal.server_cert` (§5), `renewal.watch` (every 10 minutes for two hours after a rotation or switch),
`renewal.links` (§4.6), `renewal.notify` (§4.6, needs SMTP), `renewal.retire` (§4.8), `ca.schedule` (computes
`P`/`S`/`E`; in `automatic` mode also renews the root CRL, prepares, switches and retires), and `crl.rotate` extended
to every trusted issuer.

## 9. API

| Endpoint | Permission | |
|---|---|---|
| `GET/PUT /api/tenants/{tid}/renewal` | `certificates:read` / `ca:manage` | settings (§3); `ca_rollover = automatic` also needs the Tenant Administrator role and step-up |
| `GET /api/tenants/{tid}/renewal/status` | `certificates:read` | counts by renewer and state (§10), the CA schedule |
| `GET /api/tenants/{tid}/renewal/queue` | `enrollment:manage` | manual renewals: link, sent at, expires |
| `POST /api/tenants/{tid}/pki/ceremony` | `ca:manage` | §6.2 |
| `POST /api/tenants/{tid}/pki/issuers/{id}/switch`, `…/rollback` | `ca:manage` | switch now / back |
| `POST /api/tenants/{tid}/radius/server-certificate/rollback` | `radius:write` | §5 |
| `PUT /api/platform/smtp`, `POST …/test` | platform admin | §4.6 |
| `POST /api/enroll/renew` | the certificate's key | v1 and v2 (§4.2) |
| `GET /pki/{tid}/ca/{gen}.crt`, `/crl/{gen}`, `/root/{gen}.crt`, `/cross/{id}.crt` | public | §6.4 |

## 10. Audit events and dashboard items

Audit: `renewal.settings_updated`, `certificate.renewed` (exists; gains renewer and version),
`certificate.renewal_refused`, `certificate.renewal_conflict` (a second key tried to renew a renewed certificate),
`certificate.superseded_retired`, `certificate.superseded_used`, `certificate.revoked` (gains `successors`),
`renewal.link_created`, `renewal.link_sent`, `radius.server_certificate_rotated` (system actor),
`radius.server_certificate_rolled_back`, `pki.ceremony` (operations, never the key), `pki.root_crl_renewed`,
`pki.issuer_prepared`, `pki.issuer_switched`, `pki.issuer_rolled_back`, `pki.issuer_retired`, `pki.root_prepared`,
`pki.root_switched`, `pki.root_online_enabled` / `_disabled`. Device-side refusals reach syslog forwarding like every
audit event.

Dashboard (posture) items:

| Item | Severity | When |
|---|---|---|
| `renewal_silent` | warning | an automatic renewer (v2) hasn't checked in for 7 days and its certificate is inside the window |
| `renewal_overdue` | warning → critical at 14 days left | `renew_from` + 14 days passed, no successor, renewer automatic |
| `renewals_to_send` | info | manual renewals waiting in the queue (no SMTP) |
| `renewal_conflict`, `superseded_used` | critical | §4.8 |
| `server_cert_rejected` | critical | §5 watch; rollback button |
| `ca_ceremony_due` | warning | root CRL within 60 days, next issuing CA due (`P − 90 d`), key file not verified for a year |
| `issuer_switch` | info | switch scheduled / done, with the date |
| `issuing_ca_cap` | critical | a request was refused because the issuing CA expires too soon (§4.1) |
| `root_rollover` | warning | rollover due; then readiness: devices that can't take the new root yet, by platform |

`certs_expiring` changes to count only certificates that **won't** renew by themselves (no renewer, or renewal
off), plus overdue ones; the rest are healthy and stay off the dashboard.

## 11. Console

- **Certificate authority page**: a **Renewal** section between the CA cards and the templates, with the three
  switches, "Renew at [80] % of each certificate's lifetime" with a worked example, the CA rollover choice (Off /
  Guided / Automatic, the last with its warning), and status tiles: *Renew by themselves* (healthy · silent),
  *Need the user* (links waiting · sent), *Overdue*. Each CA card gets a timeline (issued → prepare by → switch →
  expires) and a **Bring the root key** button that opens the ceremony dialog with the due operations preselected.
- **Templates**: "Renew before" shows the derived days and the percentage.
- **Certificates list and detail**: a "Renewal" column/section: *Automatic (Windows setup, checked 2 h ago)*,
  *Group Policy*, *Needs the user (link sent 3 days ago)*, *Overdue*, *Off*; the predecessor/successor links that
  exist today.
- **RADIUS page**: "Rotates by itself on <date>", and for 14 days after a rotation, **Put the previous certificate back**.
- **Renewals to send** (Users area): the queue with copy and send.
- **Dashboard**: the §10 items.
- **Enrollment portal**: a renewal link says what it replaces and when that expires; Apple and Android get
  renewal-specific steps.
- **Platform settings**: SMTP, with a test message.
- Copy and components follow DESIGN.md and the existing screens (`SectionHeader`, `ESwitch`, `Callout`, `Chip`).

## 12. Tests

Unit (`backend/tests/test_renewal.py`, fake sessions in the style of `test_windows_setup.py`, no network):

- window arithmetic: percentage, shortened certificates, boundaries; templates' derived days; the XCEP renewal period
  and revision bump;
- the renewal rule for every refusal (revoked, superseded, expired, disabled identity, suspended tenant, setting off),
  each audited once a day; v1 and v2 messages; the client block bound by the signature; check-ins; a lost answer
  re-sent; a second key on a renewed certificate → conflict; tenant scope after lookup (a certificate can only ever be
  renewed into its own tenant);
- successors revoked with their predecessor; retirement rules (successor seen; 30 days for automatic renewers; never
  for manual platforms until the successor is seen);
- server-certificate rotation due logic, rollback, the watch's baseline comparison;
- schedule arithmetic for default and edge configurations (1-year issuing CA, a template longer than the CA's
  remainder), and the TTL cap;
- multi-issuer helpers: bundle order (server issuer first), every trusted issuer has a CRL or `desired_state`
  refuses, per-issuer URLs; the ceremony against a fake OpenBao (key/cert mismatch refused, mount always deleted);
- posture items.

Integration, throwaway containers like `tests/radius/run.sh` (not an EasyEAP stack):

- `tests/pki/run.sh` (new): a dev-mode OpenBao of the pinned version (2.4.1) and the real `pki/service.py` code:
  ceremony; root CRL re-sign through `issuers/import/bundle`; next issuer with the same subject; the default not moving
  on import; the switch; `crl/rotate` producing one CRL per issuer and the right serials on each after revoking on the
  old issuer; per-issuer URLs (all three set) in issued certificates; `leaf_not_after_behavior = err` refusing and
  EasyEAP's cap avoiding it; `sign-intermediate` letting an intermediate outlive the root (so the cap is tested);
  root cross-signing and re-certifying the issuing key under a new root (one shared CRL). These facts come from reading
  the 2.4.1 source (§2.6); the test pins them so an OpenBao upgrade can't change them silently.
- `tests/radius/run.sh`, new steps with real FreeRADIUS and `eapol_test`: two issuing CAs with the same subject and
  different keys, both CRLs, one revoked certificate from each (rejected) and one valid from each (accepted); a missing
  CRL for one issuer (rejected: the guard in `desired_state` exists because of this); server chain under `I2` with
  clients whose `ca_cert` is only the root; root rollover with the server presenting `I2'` + cross-certificate to
  clients that trust [R1], [R1, R2] and [R2].
- `tests/windows/run.sh` (pwsh with recorders): renewer v2 check-in, server-provided window, root install only with a
  valid cross-certificate (a forged one is refused), profile rewrite, v1 and v2 side by side.
- `test_linux_setup.py` plus a bash run of `renew.sh` v2 against a stub server.
- Frontend: vitest for the Renewal section and ceremony dialog; the console smoke test covers the new screens.

End to end on the demo (172.16.0.45), run by the main agent per its memory notes: back up the demo (pg_dump, `.env`,
compose), build from a clean worktree, `docker compose up -d --no-build`, check migration, health and heartbeats. Then,
on a **temporary tenant** with local users only (no Active Directory reads or writes, nothing on the user's tenant):

1. Settings: defaults present; turning `user_certs` off makes a renewal refuse with the message and an audit line.
2. Client renewal over HTTP: a temporary template, and its OpenBao role adjusted to `not_before_duration` 22 h and a
   2 h TTL (lifetime 24 h, 92 % elapsed at issue), so the certificate is inside its window at once; enroll it with a
   CSR from a Python client in the API container through a link; check in (v2); renew; verify the new certificate,
   `superseded` and `renewal_of`; repeat the same request (same certificate back); a different key (conflict, audited).
3. Server certificate: run the rotation job with a `now` past the threshold; `config_version` bumped and the agent
   reloaded; `eapol_test` (the lab-client image as a one-off container, against the temporary tenant's dedicated
   RADIUS ports, with a temporary RADIUS client for the container's address) succeeds with a client that trusts only
   the root; rollback works.
4. CA: the temporary tenant's ceremony returns its key file into the scratch directory; renew the root CRL; prepare
   `I2`; switch; `eapol_test` with an `I1` and an `I2` certificate (both accepted), revoke one of each (both
   rejected), server chain under `I2` (client trusting only the root succeeds); retire `I1` early via a test date.
5. Root rollover on the same tenant: prepare `R2`, cross-certificate, `I2'`; publish; switch; clients trusting [R1],
   [R1, R2] succeed.
6. On the user's tenant, read only: settings and schedule shown and plausible; the server certificate's next rotation
   date (if it is already past 80 %, the first job run rotates it: tell the user before deploying); real devices keep
   authenticating in the Authentication log after the rebuild.
7. Clean up: delete the temporary tenant (crypto-shredding), the temporary RADIUS client and the scratch key file;
   confirm the demo is healthy.

Not verifiable here and left as a checklist for a real device: the Windows renewer v2 on a real Windows 11 PC (TPM
signing, the notification, `netsh` profile rewrite, the cross-certificate check); whether `CAHashList` with the root's
hash still selects a certificate from a second issuing CA (needed before any phase-5 switch, §13); whether a domain PC
accepts the RADIUS server without the root in NTAuth (§2.1); Windows' choice of chain when two roots are trusted;
Group Policy with two roots ticked; an iPhone or Mac replacing the profile in place; Android's renewal steps.

## 13. Risks

1. **Windows chooses its own chain.** Windows 11 needs the server's root in its store **and** in the profile [10].
   After a root switch, a PC that trusts both roots in its store but lists only the old one in its profile can build
   the chain to the new root and fail. So: v2 renewers add the root to the store and the profile together; the Group
   Policy checklist says "import and tick in the same change"; the server switch waits for the publish period; the §5
   watch and rollback catch what slips through.
2. **`CAHashList` may match only the direct issuer** [9]. If so, every Windows profile with the setup file's filter
   (root and issuing CA hashes) stops picking the certificate a PC renews from a new issuing CA. Check on a real PC
   before phase 5. If it does match only the issuer: renewer v2 adds the new issuer's hash to EasyEAP's profiles when
   it installs a certificate from it (the issuer chains to a root the PC trusts, so this needs no cross-certificate),
   phase 5 waits until v2 has spread, and v1 PCs are listed for a new setup file before the switch.
3. **Same subject for the next issuing CA** (§6.3) relies on chain builders and CRL lookup using key identifiers.
   OpenSSL (FreeRADIUS, wpa_supplicant), Windows and Apple do; the RADIUS integration test proves it for FreeRADIUS
   before anything ships. Fallback if it fails: a new subject, plus renewer v2 matching by chain (v1 PCs then need a
   new setup file, listed in the console).
4. **A lost root key file** makes every CA step impossible: only a new root and re-enrolling every device remain. The
   yearly "verify the key file" and the early `P − 90 days` reminder exist for this.
5. **OpenBao behaviour** (default issuer, per-issuer CRLs and URLs, `crl/rotate` across issuers) may not match the
   Vault documentation it was forked from; `tests/pki/run.sh` pins it.
6. **Renewal surge.** Lowering the percentage makes every certificate older than the new threshold due at once.
   Renewers jitter (Windows up to 8 h, Linux 1 h) and a refused or rate-limited request is retried the next day; the
   per-address limit (60/min) can bite a large site behind one NAT address, so v2 requests are limited per certificate
   first and the per-address limit is raised for signed requests.
7. **The console's TLS certificate.** Renewers reach EasyEAP over HTTPS: Windows needs a certificate it trusts, the Linux
   script falls back to a pinned public key. Re-keying the console's certificate breaks pinned Linux renewers silently.
   v2 check-ins return the next pin when the proxy's key changes, and the System page warns before a key change.
8. **Backups.** CA state lives in OpenBao and the database, which backups snapshot together; the root key files (old
   and new) are offline by design and not in backups. Restoring a backup from before a switch puts the old default
   issuer back; certificates issued since are unknown to the restored database (as with any restore).
9. **NTAuth.** If domain PCs do need the root in NTAuth to accept the RADIUS server (KB 814394 [11], against the
   Windows 11 page's silence [10]), a new root has a third place to go on domain PCs, and NTAuth also lets the CA issue
   AD logon certificates [52], which EasyEAP's Group Policy guide advises against. Today's deployments work, so either
   the rule doesn't apply or NTAuth already holds the root. The real-PC check (§12) settles it before phase 6, and the
   root rollover checklist (§6.7) gains or drops an NTAuth step accordingly.

## 14. Critique of this plan, and what it changed

Argued against the first draft, as an attacker, as an admin who forgets, and as a device that half works:

1. **Proof of possession.** The renewal is signed by the current key over the certificate, the time and the new CSR,
   and the CSR proves the new key. A replay inside the 10-minute window returns the same certificate for the same new
   key, which is useless to anyone without that key. A replayed check-in could fake "alive" for ten minutes, nothing
   more. Kept; v2 binds the client block into the signature so the trust report can't be altered in transit.
   (Considered EST `simplereenroll`, RFC 7030: standard, but it needs TLS client authentication at the proxy, no
   Windows or Linux client ships one, and every deployed renewer speaks v1. Not now.)
2. **A stolen key renews forever.** v1 lets whoever renews first win and the legitimate device only gets "already
   renewed". Folded in: conflicts audited and critical (§4.8), the successor revoked with its predecessor, superseded
   certificates retired once the successor is used, and `superseded_used` as an alarm. Considered and left optional (not
   in v1 of this work): forcing a fresh enrollment every N years for software keys; it contradicts "no user action".
3. **Key storage is self-reported.** `key_storage = tpm` comes from the client. A renewal that moves from TPM to
   software is shown and audited; real proof needs TPM key attestation (PROGRESS.md "planned").
4. **Revoked and expired certificates.** Refused, as today; no grace period after expiry (an expired certificate is
   no proof of anything current). The 80 % default is the answer to laptops that are away, not a grace period.
5. **Tenant isolation.** The first draft kept today's platform-scoped session through issuance. Folded in: platform
   scope only for the fingerprint lookup, then tenant scope; a unit test that a certificate is only ever renewed into
   its own tenant's mount.
6. **Failing silently.** The first draft had only server-side "overdue". Folded in: daily signed check-ins (so a dead
   renewer shows within a week, not at expiry), audited refusals, a Windows notification to the user, dashboard items
   that separate "will renew" from "needs someone", and email for manual platforms.
7. **The renewal channel now distributes trust.** A compromised online EasyEAP (it holds the issuing CA key) must not
   be able to plant a root on every PC. Folded in: devices accept a new root only with a cross-certificate that verifies
   under a root they already trust, and only the offline root key can make one; profile rewrites can only add root
   thumbprints, never change names or SSIDs.
8. **"Automatic" undermines the offline root.** It does. It stays opt-in, behind step-up, labelled on the CA page and in
   SECURITY.md, and `guided` is the default: the yearly root CRL means the admin brings the key file once a year anyway.
9. **Unwanted noise.** The first draft emailed users at every window. Changed: email is off by default, needs SMTP, and
   only goes to certificates with no automatic renewer.
10. **"No user action" isn't true everywhere.** Apple and Android always need a tap (and Android a settings change).
    The console and portal say so instead of promising it; §2 gives the sources.
11. **Is CA rollover worth building now?** The issuing CA switch is years away for default tenants, but the root CRL
    lapses within a year of each ceremony and a 1-year issuing CA (allowed today) fails sooner. Changed the order: the
    ceremony (root CRL, verify key file, prepare) comes before multi-issuer operation, and multi-issuer before any
    tenant's `P` date; renewer v2 ships early because only v2 devices can take a new root silently, and they need years
    to spread.
12. **Changing the percentage rewrites Windows' policy.** A minor revision bump makes domain PCs re-read the policy, not
    re-enroll; that's what editing the autoenroll templates does today.
13. **Why a scheduled task, when Windows has key-based renewal built in?** Windows' own autoenrollment against a
    renewal-only policy server [4][5][6] would renew PCs outside the domain, and domain laptops away from a domain
    controller, with no EasyEAP code on the PC, and it is what Microsoft supports. Against it: Microsoft documents it
    only against AD CS; EasyEAP would have to accept WS-Security message signatures (XML signature over SOAP, a large
    parsing surface on an unauthenticated endpoint) instead of today's Kerberos-authenticated autoenroll; the setup
    file would still have to register the policy server, so it isn't fewer steps; and it reports nothing back (no
    check-ins, no trust block, so no silent root distribution). Kept the task as the path; native key-based renewal
    is phase 7, behind a feasibility spike against a real Windows 11 PC.
14. **Why not Apple's ACME payload, which a user can install without MDM?** It gives a key made on the device that
    can't be exported, which is better than a PKCS#12 [16]. But it needs `device-attest-01`, which OpenBao 2.4.1 lacks
    [43][46] (EasyEAP would implement the challenge and Apple's attestation checks itself); Apple doesn't say a manually
    installed profile gets an attestation [25]; and renewal is still a new profile the user installs, so it doesn't
    serve the request. Phase 7, for the key, not for renewal.
15. **Why not an Android app, the only silent route on Android?** It is silent after one approval [26][27][28], but
    only with a software key that the app can read [33], an app has to be built, published and kept current, and many
    users won't install it. Assisted renewal ships first; the app is phase 7 if tenants ask for it.

## 15. Phases, smallest useful slice first

1. **Server certificate rotation and the switches.** `renewal_settings` with `user_certs`, `machine_certs`,
   `server_cert`, `renew_at_percent`; the Renewal section (switches and percentage only, plus the computed CA schedule
   read-only); `/api/enroll/renew` honours the switches, uses the percentage and audits refusals; tenant scope after
   lookup; TTL capped at the issuing CA's expiry everywhere (§4.1), which also turns today's latent HTTP 500 into a
   shorter certificate (§1.5); the autoenroll renewal period capped below 20 % of the validity (§4.7);
   `renewal.server_cert` with rollback and the watch; `certs_expiring` split. This alone removes the one outage every
   tenant will hit (day 397) and gives the admin the control asked for.
2. **Automatic renewal you can trust.** Protocol v2 (check-ins, client block, trust block), renewer v2 for Windows and
   Linux, the Windows helper's renewal task, renewal status per certificate, `renewal_silent`/`renewal_overdue`,
   conflicts, successor revocation, retirement of superseded certificates.
3. **Assisted renewal for Apple, Android and hand-configured Linux.** Automatic renewal links, the queue, SMTP and
   reminders, renewal pages in the portal, profile replacement in place.
4. **Root ceremony from the console.** Verify key file, renew the root CRL, prepare the next issuing CA (status `next`,
   not used yet); schedule and `ca_ceremony_due` items.
5. **Issuing CA switch.** Multi-issuer operation (§6.4), per-issuer CRLs and URLs, server chain, XCEP, the switch at
   `S` with watch and rollback, retirement; `automatic` mode.
6. **Root rollover.** New root, cross-certificate, re-certified issuing CA, trust publication (renewer v2, packages,
   Group Policy checklist), readiness, the server switch, retirement of the old root.
7. **Later, each behind a spike.** Windows' native autoenrollment with key-based renewal (a renewal-only policy
   server with X.509 authentication) for PCs outside the domain and domain laptops away from a domain controller
   (§14 item 13); Apple's ACME payload with `device-attest-01`, implemented by EasyEAP since OpenBao lacks it, for a
   device-made key (§14 item 14); an Android app with Wi-Fi suggestions (§14 item 15); EST and SCEP for Intune and
   Jamf; TPM key attestation.

### 15a. Phase 1 as built (2026-11-08)

Decisions taken while building phase 1, where the plan above was open or had to change:

1. **Migration `0014_renewal`** (0011–0013 were taken by other work). It creates `renewal_settings` (one row per
   tenant, made on first read with the §3 defaults; only `user_certs`, `machine_certs`, `server_cert` and
   `renew_at_percent` in this phase), adds `previous_server_certificate_id`, `previous_server_key_ct` and
   `server_cert_rotated_at` to `radius_settings`, and sets every template that isn't Group Policy's to
   `renew_before_days = ceil(20 % × validity)` (the 80 % default).
2. **Group Policy templates keep their own renewal period**, set on the Autoenroll screen, now required to be under a
   fifth of the validity (Windows renews only then, §2.1 [1]; it was ¾), and the XCEP policy clamps an older value to
   19 %. Deriving them from the percentage too would give the setting two owners. The Renewal section says Windows
   renews those itself.
3. **Templates** (user, device, RADIUS server) take `renew_before_days` from the percentage whenever the setting or the
   template is saved; the API still accepts the field and ignores it. The setup file and the Linux script bake that
   value in, as before; the server's own test is per certificate (`renew_from = not_before + p % × lifetime`).
4. **Lifetimes are capped at the issuing CA**: every issuance asks OpenBao for `min(template validity, CA remaining −
   1 h)`, so a short CA gives shorter certificates instead of an HTTP 500. With under a day left it refuses: "renew the
   issuing CA". A warning dashboard item says when new certificates are being shortened.
5. **The watch** (§5) is a dashboard item computed from the authentication log for 14 days after a rotation: devices
   accepted in the week before it that since get only `tls_handshake`/`client_timeout` rejects (two or more, and no
   accept). No timed job. The previous certificate and key are kept 14 days for **Put the previous certificate back**,
   which a manual Rotate now offers too.
6. **The server certificate job** runs every six hours per tenant: it rotates once `p %` of the certificate's lifetime
   has passed, and only if the new certificate would get at least 30 days (§5), else the CA items say why.
7. **Who renews by itself**, until phase 2 records it: a Group Policy template; a Windows setup file enrollment; a
   Linux link completed with a key made on the computer (the script); or a certificate renewed through
   `/api/enroll/renew` before. `certs_expiring` counts only the others (and every certificate whose purpose has
   renewal turned off). Automatic ones past `renew_from` + 14 days, and within 14 days of expiry, are
   `renewal_overdue` (see the critique below).
8. **Refusals** from `/api/enroll/renew` are audited as `certificate.renewal_refused` with a reason code, once a day
   per certificate and reason (looked up in the audit log; no new column). Unknown certificates aren't audited (no
   tenant to put them in).

**Critique of the build (2026-11-08) and what it changed.** A reviewer read the whole change cold:

| Finding | Change |
| --- | --- |
| Editing a template returned 500: the console no longer sends `renew_before_days`, the `None` was set on the row, and reading the renewal settings flushed it into a NOT NULL column | the field is excluded from the update, and the percentage read before the row changes |
| A host name change kept the old-name certificate as "previous": a rollback would present it while every new profile names the new server | kept only when it names the same server; a rollback also checks the name |
| `renewal_overdue` flagged working devices: copies made before 0014 ask only from 30 or 45 days before expiry | overdue = later of `renew_from` + 14 days and 14 days before expiry (item 7 amended) until phase 2 records each device's period |
| Group Policy certificates dropped off the dashboard entirely | they count as overdue like the other automatic renewers |
| Two first reads could both insert the settings row (unique violation, 500) | rows seeded by the migration; the insert is `ON CONFLICT DO NOTHING` |
| The dashboard loaded whole certificate rows (PEM included) for 20–50 % of certificates per tenant | only the columns needed, and only certificates within the warning period or 14 days of expiry |
| `NOT IN (subquery)` in the watch | `EXISTS` / `NOT EXISTS` |
| Clock and signature refusals were audited before the key was proven | the signature is checked first; a bad signature isn't audited, a wrong clock (signed) is |
| The Autoenroll page refused every save while an older period was ≥ 20 % | only a changed value is checked, there and on the server |
| "Rotates within 6 hours" while the CA was too short for a new one | the status carries `ca_too_short` and both pages say it waits for a new issuing CA |
| Rollback paused rotation without saying who; the job and a rollback could overwrite each other | `updated_by`/`updated_at` set; both lock the RADIUS settings row |
| Severities differed from §5 and item 4 | `server_cert_rejected` critical, `issuing_ca_cap` warning |

Not changed: the rollback hook already refreshes the dashboard (through the RADIUS invalidation).

### 15b. Phase 2 as built (2026-11-08)

Split in two: **2a** the server (this list), **2b** the devices (renewer v2 for the Windows setup file, the Linux
script and the portal's Windows helper, §4.3–4.5).

1. **Migration 0015.** `certificates` gains `renewer`, `renewer_version`, `renewal_checked_at`, `trust_reported`
   (JSONB) and `retired_at`; `renewal_settings` gains `retire_superseded` (on). Existing certificates get `renewer`
   from how they were issued (§15a item 7), version `1`; a renewal copies its predecessor's. Group Policy writes
   `gpo` when it issues. The heuristic stays as the fallback for rows without one.
2. **Protocol v2 on the server** (§4.2). A request with a `client` field (the JSON text, at most 4 KB, signed by its
   SHA-256) is v2: without `csr` it's a check-in (`easyeap-check-v2|sha256(cert)|signed_at|sha256(client)`), with one a
   renewal (`easyeap-renew-v2|sha256(cert)|signed_at|sha256(csr)|sha256(client)`). Both record the check-in time, the
   renewer kind and version and the roots reported. Every JSON answer carries `trust` (the tenant's current roots; the
   cross-certificate list is empty until phase 6). v1 is unchanged.
3. **A lost answer, for renewers that throw their key away.** v1 `renew.ps1` deletes its pending key when the answer
   doesn't arrive, then asks again the next day with a new key, which v1 refused for good ("already renewed"): the PC
   kept its old certificate until it expired. Now, when a renewal arrives for a certificate already renewed with
   another key: if the earlier successor (a renewal through this endpoint, same template) has never been accepted by
   RADIUS, it's revoked ("replaced: never received") and the new key gets the certificate, within 14 days of the first
   renewal and at most 3 times per certificate (a copied key can't keep extending itself); if it **has** been used, that's a **conflict**: refused, audited `certificate.renewal_conflict`
   (once a day), critical on the dashboard (two keys claim one certificate: a copied key). Group Policy's successors
   are never replaced this way. *After the critique:* only v1 requests get a replacement (a v2 renewer keeps its
   request until the answer arrives, so another key from it is refused); a successor the device has checked in with
   counts as used (a conflict) like one RADIUS accepted; the certificate row is locked for a renewal, so two requests
   at once can't both replace; "at most 3" counts replacements, not the first renewal.
4. **Revoking a certificate revokes its active successors** (the `renewal_of` chain), in the console; the audit line
   lists them. Only renewals count (same template and device): Group Policy's `_supersede` also links a computer
   certificate that replaced a setup file's, and a user certificate from another PC, which aren't revoked with it. The
   dialog lists exactly what will go, for any status (an expired certificate can have a valid renewal), and sends
   nothing extra unless it showed the list.
5. **Retirement** (`renewal.retire`, daily per tenant, when `retire_superseded` is on): a superseded certificate is
   revoked (`superseded`) once its device has shown it holds the successor (RADIUS accepted the successor, or a v2
   check-in was signed with the successor's key) **and** the old one hasn't been accepted in the last 7 days (a device
   still using it isn't cut off; it expires as before). Audited `certificate.superseded_retired`. *Changed while
   building:* the planned "30 days after renewal, for renewers that delete the old key" rule is dropped. A v1 device
   whose answer was lost and that stayed away past the re-issue limits still holds only the old certificate and key;
   revoking it on a timer would cut that device off, and nothing it buys is worth that.
6. **Superseded certificate used** (`certificate.superseded_used`): one presented more than a day after its successor
   was first accepted. A **warning**, not the plan's critical: a Windows PC that failed to delete the old certificate
   can present it once more, so it is a reason to look, not proof of a copied key.
7. **Dashboard.** `renewal_silent` (warning): a v2 renewer that hasn't checked in for 7 days while its certificate is
   due. `renewal_overdue`: v2 renewers from `renew_from` + 14 days, v1 from 14 days before expiry (§15a); critical
   when any has 14 days or less. `renewal_conflict` (critical), `superseded_used` (warning).
8. **Console.** Certificates show how they renew (Windows setup file, Linux script, Group Policy, needs a new link,
   off) with the last check-in, and their successor; the Renewal panel gets the retirement switch and counts (renew by
   themselves, silent, need the user, overdue). The revoke dialog of a renewed certificate lists its unrevoked
   successors with a box (on) to revoke them too; off revokes only the old one.
9. **Check-ins are what the device signs.** Issuing a successor records its renewer, not a check-in: only a request
   signed with the successor's own key says the device has it (retirement relies on that). A refused v2 request still
   records its check-in (after the rollback), except a wrong clock, which could be a replay. Retirement revokes each
   certificate in its own savepoint and recomputes before auditing.
10. **Known limit:** the Renewal panel's counts classify every valid client certificate in Python on each load; fine
   for thousands, to move into SQL for tenants far larger.
11. **Silent and overdue don't double up.** A v2 renewer that is due and quiet for 7 days is *silent*; one that keeps
   checking in and still hasn't renewed 14 days into its window is *overdue* (it's being refused: the audit log says
   why). Both are critical once a certificate has 14 days or less.

### 15c. Phase 2b plan: the Windows renewer v2 (2026-11-09)

§4.3 and §4.5, narrowed to what a PC can do now. Taking a new root (cross-certificates, rewriting the profiles) waits
for phase 6, as on Linux, because nothing can test it before the server sends one. The trust block is read but not
acted on.

1. **`renew.ps1` v2** (`SCRIPT_VERSION = "2"`, renewer version `2.0`). The same file serves the setup file (kind
   `windows-setup`, computer and user scope) and the portal's helper (kind `windows-helper`, user scope). Baked in:
   - the API address and the kind;
   - the tenant's root certificates (SHA-256 of each) and the issuing CA;
   - the template renewal days, kept only as the fallback when EasyEAP can't be reached.
2. **Which certificate is EasyEAP's.** v1 took every certificate in the store whose issuer matched the issuing CA's
   name, and deleted all but the newest. That deleted Group Policy's certificate from the same EasyEAP CA, when a PC
   had both. v2 takes only certificates that:
   - have their private key;
   - allow client authentication;
   - chain (X509Chain, revocation not checked) to one of the baked roots;
   - **don't** carry the certificate template extension (`1.3.6.1.4.1.311.21.7`), which marks Group Policy's own.
   It deletes only the certificate it just renewed, and its own older leftovers matched by the same test.
3. **Daily check-in.** A signed `easyeap-check-v2` with the client block:
   `{kind, version: "2.0", scope, roots: [the baked roots present in the Root store]}`.
   - The answer's `renew_from`, `renewal_enabled` and `superseded` go into `renew-state.json` beside the log.
   - The computer task runs daily and at startup. The user task runs at sign-in and unlock. Each checks in at most
     once in 20 hours, unless the saved window says it's due.
   - When EasyEAP doesn't answer, the baked days decide.
   - A 404/422 means an EasyEAP from before check-ins: protocol v1 (the v1 message, no client block).
4. **The pending request survives a lost answer.** `certreq -new` puts the key in the store's REQUEST folder.
   `renew-pending.json` keeps:
   - the request (PEM);
   - the thumbprint of its REQUEST entry (the one that appeared when certreq ran);
   - the thumbprint of the certificate it renews.

   The next run sends that same request at once, and EasyEAP answers with the certificate it already issued. It's
   dropped when:
   - EasyEAP refuses it (400);
   - its REQUEST entry is gone;
   - it was made for another certificate;
   - it is older than 30 days.

   v1 deleted every `CN=EasyEAP` request after any failure.
5. **Installing.** `certreq -accept` with the answer.
   - Check the certificate landed in the store with its private key; only then delete the old certificate (and its
     key) and the pending file.
   - The issuing CA from the answer goes to the CA store, as v1 did.
6. **The user's warning.** The user task only, once a day: a Windows notification (a toast, as Windows PowerShell) when
   the certificate expires within 14 days and the run didn't renew it (refused, renewal turned off, EasyEAP
   unreachable), or has expired. The computer certificate relies on the dashboard, as planned: SYSTEM can't show UI.
7. **One run at a time.** A named mutex per scope (and per user) stops the sign-in and unlock triggers, or the
   portal's and the setup file's tasks, from overlapping. A second run exits quietly.
8. **The portal's helper renews too** (§4.5). `windows.ps1` writes the renewal script (kind `windows-helper`) to
   `%LOCALAPPDATA%\EasyEAP\renew.ps1` and registers the per-user task the setup file uses without an administrator:
   the same name, daily and at sign-in. It skips this when the setup file's shared user task exists. Its request says
   `renewer: "windows-helper"`, so EasyEAP records the renewer at issuance.
   - Only the new helper says this. A helper downloaded before the change installs no renewal, and its certificates
     stay "needs the user".
9. **Existing PCs.** A PC keeps its v1 script until someone runs a setup file again; the new file replaces the script
   and the tasks. The certificate's page says "Renewal task version 2.0" after the first check-in.
10. **Tests.**
    - `tests/windows`: the v2 script's decisions with the store, certreq, the network and the notification replaced by
      recorders:
      - which certificate it takes (a Group Policy one, a foreign chain, one without a key);
      - quiet within 20 hours, a check-in that says not yet, due;
      - a lost answer sent again, with the same request and no check-in;
      - a refusal drops the request;
      - an old server gets v1;
      - the warning only for the user, once a day.
    - The check-in and v2 renewal bodies the script signs are verified by EasyEAP's own code. Unit tests cover the
      generated files and the helper's renewer.
    - Not covered without Windows: certreq, the TPM, the toast, the tasks.

**Critique of this plan (2026-11-09), and what it changed.** A critic read the plan and the first draft of the script.

| # | Finding | Change |
|---|---|---|
| 1 | A PC that lost its waiting request after EasyEAP issued the new certificate hit a silent dead end: v2 got no replacement for another key, the check-in said `superseded` and the script stopped quietly until the old certificate expired. The v1/v2 rule wasn't a control anyway: the version is the client's own claim. | v2 gets v1's bounded replacement (unused successor, 14 days, 3 times). A `superseded` check-in with nothing waiting is logged as a warning and asks again with a new key (Linux too). |
| 2 | Any 400 dropped the request, including a wrong clock (refused before the resend check), so the key of an issued certificate could be thrown away. The 30-day age rule did the same. | The 400 body carries `code`. The request is dropped only on final codes (renewed, conflict, revoked, expired, same_key, request, gpo, kind, missing), and a final refusal stops asking for that certificate (`final` in the state file, `renew-refused` on Linux). No age rule. |
| 3 | v1 and the setup file delete every `CN=EasyEAP` REQUEST entry, which would take v2's waiting key. | Each request has its own subject (`CN=EasyEAP renewal <guid>`, `CN=EasyEAP setup <guid>`); clean-up removes only its own. The setup file's computer part removes the old per-user tasks when it installs the shared one. |
| 4 | Finding the REQUEST entry as "the one that appeared" races Group Policy's autoenrollment. | Found by its subject. Installing checks first whether the certificate is already in the store with its key. |
| 5 | Deleting every older EasyEAP certificate at the start of a run could delete the helper's, a console package's, or (on an expiry tie) the new one. | Only the certificate the request was for is deleted, after the new one is confirmed. The newest certificate is the one renewed; NotBefore breaks an expiry tie. |
| 6 | `HasPrivateKey` doesn't prove the key works. | After installing, a check-in signed with the new key; the old certificate goes only after EasyEAP answers. A new key that can't sign: the new certificate goes, the old stays, and EasyEAP's replacement covers the next try. An interrupted run finishes next time (`answered` in the pending file). |
| 7 | Any local user can create a `Global\` mutex first and stop the computer's renewal. | A lock file in the account's own LocalApplicationData (SYSTEM's profile for the computer), which other users can't open. |
| 8 | A user who never locks the PC never checks in. | The shared user task also runs daily; sign-in and unlock wait two minutes. |
| 9 | A request answered "not renewed" was resent on every trigger for up to 30 days. | Nothing was issued for it: it's dropped and the window is saved. |
| 10 | The v1 fallback on 404/405/422 was over-built (a v2 server made the script, and 422 is also a validation error). | Removed. |
| 11 | The toast came from "Windows PowerShell", which users can turn off, and fails silently. | Its own AUMID `EasyEAP.Renewal` (registered under HKCU, as Windows asks of unpackaged apps); a turned-off setting is logged. |
| 12 | A standard user can't always list the shared task, so the helper might add a second one. SYSTEM uses its own proxy settings. | The setup file leaves `renews-users.txt` for the helper to find. An unreachable EasyEAP is logged with the proxy used. |

Kept from the plan: resending the same request (answered by `_earlier_renewal`, matched by key), the 21.7 exclusion,
the chain test, `[int]$_.Exception.Response.StatusCode` (5.1 and 7), a negative check-in age counting as stale.
Not done: a dashboard item for "renewed, never received" (the client now recovers by itself; the certificate still
shows as overdue if it doesn't), warning users about the computer's certificate on shared PCs.

**Critique of the implementation (2026-11-09), and what it changed.** A second critic read the code and ran its own
scenarios.

| # | Finding | Change |
|---|---|---|
| 1 | Linux: a superseded certificate never asked again: EasyEAP's `renew_from` is the moment it answers, a second past the script's start, so the script waited. Its test fixed the time before the script ran. | Superseded skips the time comparison (as on Windows). The test's fake answers with the time it answers at. |
| 2 | The helper is downloaded as UTF-8 without a BOM; Windows PowerShell reads such a file as ANSI, and an organization name with ł, т, Ñ (bytes that decode to curly quotes) broke renew.ps1. | The helper is served with a BOM. renew.ps1 is ASCII: `$Org` is decoded from base64, comments are ASCII. |
| 3 | PowerShell reads ‘ ’ ‚ ‛ as single quotes; a name like "Children’s Hospital" broke the setup file and renew.ps1. | Every one of them is doubled in a quoted string; a here-string refuses a line starting with any of them and @. The helper's message quotes the network name the same way. Tests parse files made with such names. |
| 4 | After a refusal that keeps the request, only the first day was quiet. | Every such refusal sets the check-in time: one resend a day. |
| 5 | An unconfirmed new certificate was finished only if it was the newest; a shorter one was renewed over, and EasyEAP revoked it. | It's found among all of EasyEAP's certificates in the store. |
| 6 | A confirming check-in refused for good (revoked since, a database restored from before) left the run stuck. | Refused (other than a wrong clock): the new certificate goes, the old stays, and the next run starts from a fresh check-in. |
| 7 | The helper skipped its task, and the setup file removed per-user tasks, without checking they were for the same EasyEAP. | The helper skips only when the shared script carries its root; the setup file removes only per-user tasks whose script carries its root (or, for older scripts, its issuing CA). |
| 8 | A request that failed after certreq made a key had no back-off. | Waits a day; a key whose request can't be saved is deleted. |
| 9 | Reading the toast setting could throw and stop the toast. | Its own try. Whether Windows shows a toast for an AUMID registered only in the registry is on the Windows 11 list. |
| 10 | The tests replaced the HTTP client and never ran the certificate selection. | `Invoke-EasyEap` runs against a real HTTP server (codes, details, errors, nothing listening), and `Test-EasyEapCertificate` against real certificates (EasyEAP's, Group Policy's, a server one, another CA's, one without its key). |
| - | Windows PowerShell may turn certreq's error output into a stopping error under `$ErrorActionPreference = 'Stop'`, so the next key provider is never tried (not verified). | certreq runs with `Continue` for that call, in renew.ps1, the setup file and the helper. |

**As built (2026-11-09).** Items 1, 2, 3, 5, 6, 8, 9 as planned with the changes above. Item 4: no age rule, entries
found by subject, the `answered` marker. Item 7: a lock file. Item 10: `tests/windows/renew-decisions.ps1` runs the
generated script's own functions against a stand-in store and EasyEAP (21 decision checks), the real HTTP client
against a local server, and the certificate selection against real certificates; rules broken on purpose made their
checks fail. The selection runs on .NET for Linux (OpenSSL, not CryptoAPI), so the Windows 11 test repeats it with a
real store.

## 16. Sources

Read in November 2026. Numbers 14 and 17 aren't cited in the text; they hold pages read for the research that back
the cited ones.

**Windows**

1. Microsoft, "Approval-required certificate renewals with autoenrollment" (80 % rule, renewal period below 20 %):
   https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/approval-required-certificate-renewals-autoenrollment
2. Microsoft, `Set-CertificateAutoEnrollmentPolicy`:
   https://learn.microsoft.com/en-us/powershell/module/pki/set-certificateautoenrollmentpolicy
3. MS-WCCE §3.1.2.4.2.1, renewal requests signed with the key of the certificate being renewed:
   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/a76aad8d-a918-4975-b17e-b6050a72d4ed
4. MS-XCEP `CAURI` (`clientAuthentication`, `renewalOnly`):
   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/4b1d4164-c653-42a2-8a1d-41d259616219;
   `EnrollmentPermission`: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cc5a0298-fd6b-41f1-a700-dad9f8e95842;
   MS-WSTEP §3.1.4.2.1.1: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/7b30ac73-8df4-4057-94f8-4d291ce3e722
5. Microsoft, "Certificate Enrollment Web Service key-based renewal":
   https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-enrollment-certificate-key-based-renewal
6. Microsoft, `Add-CertificateEnrollmentPolicyServer`:
   https://learn.microsoft.com/en-us/powershell/module/pki/add-certificateenrollmentpolicyserver
7. Microsoft, `certreq` ("Expired certificates can't be renewed"):
   https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1; revoked certificates
   can't sign a renewal: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc784923(v=ws.10)
8. Microsoft, EapTlsConnectionPropertiesV1 `ServerValidationParameters` (`TrustedRootCA`):
   https://learn.microsoft.com/en-us/windows/win32/eaphost/eaptlsconnectionpropertiesv1schema-servervalidationparameters-complextype
9. Microsoft, EapTlsConnectionPropertiesV3 `FilteringInfo` (`CAHashList`):
   https://learn.microsoft.com/en-us/windows/win32/eaphost/eaptlsconnectionpropertiesv3schema-filterinfoparams-complextype
10. Microsoft, "Windows 11 changes to EAP server validation":
    https://learn.microsoft.com/en-us/windows-server/networking/technologies/extensible-authentication-protocol/windows-11-changes
11. Microsoft, KB 814394, "Certificate requirements when you use EAP-TLS or PEAP with EAP-TLS":
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/certificate-requirements-eap-tls-peap
12. Microsoft, "PKI design considerations" (renew a CA at half its validity):
    https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/pki-design-considerations
13. Microsoft, "Renew a root CA certificate" (same key and new key):
    https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/renew-root-ca-certificate; `certutil -renewCert`:
    https://learn.microsoft.com/en-us/windows/win32/seccrypto/certification-authority-renewal
14. Microsoft, "Network access" (EAP settings; a designated certificate that isn't installed fails authentication):
    https://learn.microsoft.com/en-us/windows-server/networking/technologies/extensible-authentication-protocol/network-access;
    distributing a root by Group Policy:
    https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/distribute-certificates-to-client-computers-by-using-group-policy;
    enterprise CA roots on domain members:
    https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/deploy-server-certificates-for-802.1x-wired-and-wireless-deployments
15. Microsoft Intune, SCEP certificate profiles ("Renewal threshold (%)"):
    https://learn.microsoft.com/en-us/intune/device-configuration/certificates/scep-profiles

**Apple**

16. Apple, ACME Certificate payload (`com.apple.security.acme`):
    https://developer.apple.com/documentation/devicemanagement/acmecertificate
17. Apple, Active Directory Certificate payload:
    https://developer.apple.com/documentation/devicemanagement/activedirectorycertificate; SCEP payload:
    https://developer.apple.com/documentation/devicemanagement/scep
18. Apple, certificates eligible for automatic renewal: https://support.apple.com/en-us/101986
19. Apple Platform Deployment, certificate management (renew by issuing a new profile):
    https://support.apple.com/guide/deployment/depcdc9a6a3f/web
20. Apple, Active Directory certificate requirements: https://support.apple.com/en-us/HT204602
21. Apple, `EAPClientConfiguration`:
    https://developer.apple.com/documentation/devicemanagement/wifi/eapclientconfiguration-data.dictionary
22. Apple, top-level profile keys (`PayloadIdentifier`, `PayloadExpirationDate`):
    https://developer.apple.com/documentation/devicemanagement/toplevel
23. Apple, installing a profile on iPhone and iPad (8-minute limit): https://support.apple.com/en-us/102400
24. Apple, declarative ACME credential asset: https://developer.apple.com/documentation/devicemanagement/assetcredentialacme
25. Apple Platform Deployment, Managed Device Attestation:
    https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web

**Android**

26. Android, `WifiEnterpriseConfig`: https://developer.android.com/reference/android/net/wifi/WifiEnterpriseConfig
27. Android, `WifiManager`: https://developer.android.com/reference/android/net/wifi/WifiManager
28. Android, Wi-Fi suggestion API: https://developer.android.com/develop/connectivity/wifi/wifi-suggest
29. Android, `DevicePolicyManager`: https://developer.android.com/reference/android/app/admin/DevicePolicyManager;
    `KeyChain`: https://developer.android.com/reference/android/security/KeyChain
30. Android 11 for enterprise (CA certificates installed in Settings only):
    https://developer.android.com/work/versions/android-11
31. AOSP, Passpoint (online sign-up deprecated): https://source.android.com/docs/core/connect/wifi-passpoint
32. Google, installing certificates on Pixel: https://support.google.com/pixelphone/answer/2844832
33. AOSP source, `WifiEnterpriseConfig.java`:
    https://android.googlesource.com/platform/packages/modules/Wifi/+/refs/heads/main/framework/java/android/net/wifi/WifiEnterpriseConfig.java

**Linux**

34. NetworkManager, `802-1x` settings: https://networkmanager.dev/docs/api/latest/settings-802-1x.html
35. wpa_supplicant, `eap_peer_config` (`ca_cert`): https://mail.w1.fi/wpa_supplicant/devel/structeap__peer__config.html;
    https://w1.fi/cgit/hostap/plain/wpa_supplicant/wpa_supplicant.conf
36. hostap source, `tls_openssl.c` (CA file loaded per connection): https://w1.fi/cgit/hostap/plain/src/crypto/tls_openssl.c
37. certmonger, `getcert-request`: https://www.mankier.com/1/getcert-request; `getcert-add-scep-ca`:
    https://www.mankier.com/1/getcert-add-scep-ca; EST request: https://bugzilla.redhat.com/show_bug.cgi?id=1841055

**Standards and practice**

38. RFC 7030, Enrollment over Secure Transport: https://www.rfc-editor.org/rfc/rfc7030
39. RFC 8894, Simple Certificate Enrolment Protocol: https://www.rfc-editor.org/rfc/rfc8894
40. RFC 8555, ACME: https://www.rfc-editor.org/rfc/rfc8555; RFC 9773, ACME Renewal Information:
    https://www.rfc-editor.org/rfc/rfc9773; draft-ietf-acme-device-attest:
    https://datatracker.ietf.org/doc/draft-ietf-acme-device-attest/
41. RFC 9810, CMP, §4.4 root CA key update: https://www.rfc-editor.org/rfc/rfc9810.html#section-4.4; RFC 4210 §4.4
    (obsoleted): https://www.rfc-editor.org/rfc/rfc4210#section-4.4
42. NIST SP 800-57 Part 1 Rev. 5, key management (cryptoperiods):
    https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf

**OpenBao and FreeRADIUS**

43. OpenBao, PKI secrets engine API: https://openbao.org/docs/api/secret/pki/
44. OpenBao, PKI rotation primitives: https://openbao.org/docs/secrets/pki/rotation-primitives/
45. OpenBao, PKI considerations: https://openbao.org/docs/secrets/pki/considerations/
46. OpenBao v2.4.1 source, `builtin/logical/pki`: https://github.com/openbao/openbao/tree/v2.4.1/builtin/logical/pki
47. OpenBao issues: EST https://github.com/openbao/openbao/issues/1222, SCEP https://github.com/openbao/openbao/issues/1605
48. FreeRADIUS 3.2, `mods-available/eap` (`ca_file`):
    https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/v3.2.x/raddb/mods-available/eap
49. FreeRADIUS 3.2, `certs/realms/README.md` (`TLS-Session-Cert-File`):
    https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/v3.2.x/raddb/certs/realms/README.md

**More Windows and Apple**

50. MS-CRTD, `msPKI-Private-Key-Flag` (`CT_FLAG_REQUIRE_SAME_KEY_RENEWAL`):
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667;
    template options: https://learn.microsoft.com/en-us/archive/technet-wiki/13303.windows-server-2012-certificate-template-versions-and-options
51. Apple device-management schema, `com.apple.wifi.managed`:
    https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.wifi.managed.yaml
52. Microsoft, "Import a third-party CA into the enterprise NTAuth store":
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store
53. Apple, Mac User Guide, profiles in System Settings: https://support.apple.com/guide/mac-help/mh35561/mac

## 17. Not in this plan

- MDM. EasyEAP isn't one; §2 records what an MDM would add.
- Renewing server-generated (escrowed) packages without an administrator.
- Changing the key algorithm of a CA during rollover (possible with the same machinery, not designed here).
- Revoking a compromised issuing CA (an incident procedure, not a renewal).

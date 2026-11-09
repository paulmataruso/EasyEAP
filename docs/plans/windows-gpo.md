# Plan: Windows Group Policy — guide now, automatic machine certificates next

Status: revised after critique (2026-11-07). Request: can Group Policy make domain PCs pull user and device certificates
from EasyEAP automatically? If admins have to configure Group Policy by hand, write a guide.

> **Superseded in part (2026-11-07).** The guide (§2) shipped. §1's "no" was too strong: an enrollment service that
> speaks MS-XCEP and MS-WSTEP with Kerberos works with Windows autoenrollment without AD templates or an on-site agent;
> that's [gpo-autoenrollment.md](gpo-autoenrollment.md). The startup-task enrollment (§3) became the Windows setup
> file ([windows-setup.md](windows-setup.md)): computer and user certificates with renewal, run once per PC.

## 1. Answer to the question

- **No Group Policy setting makes Windows enroll from EasyEAP today.** Windows' own autoenrollment talks only to an AD
  Enterprise CA (MS-WCCE/DCOM) or to a Certificate Enrollment Policy + Enrollment Web Service pair (MS-XCEP + MS-WSTEP,
  SOAP over HTTPS with Kerberos). Every third-party implementation (EJBCA MSAE, Entrust PKIaaS, AppViewX) also needs
  certificate templates in AD, a service account with an SPN and keytab, and often an on-site agent. SCEP on Windows is
  MDM-only.
- **The workable route is a GPO-deployed scheduled task**: a startup task as SYSTEM authenticates to EasyEAP as the
  computer (`PC$`, Kerberos via HTTP Negotiate) and enrolls a TPM-backed machine certificate. No secret goes into SYSVOL.
- **Manual Group Policy is needed either way** (trust anchors, AutoConfig services, 802.1X policies): a guide.

## 2. v1 (now): the Group Policy guide

`docs/windows-group-policy.md`, plus a console page (RADIUS → Windows → Group Policy) that renders the tenant's values
(RADIUS server name, root CA download and thumbprint, SSID). The wired kit links to it; it becomes the single source for
these steps.

Contents:
1. Trust: root CA → Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies →
   Trusted Root Certification Authorities; issuing CA → Intermediate Certification Authorities. Never publish to NTAuth.
   The root becomes trusted on every machine in the GPO's scope.
2. Services: System Services → Wired AutoConfig (and WLAN AutoConfig) → Automatic.
3. Wireless Network (IEEE 802.11) Policies → Vista and later policy (or import the WLAN XML the console generates, which
   also covers WPA3-Enterprise where GPMC lacks it): SSID, WPA2/WPA3-Enterprise AES, "Microsoft: Smart Card or other
   certificate" → "Use a certificate on this computer", simple selection, Advanced → issuer = tenant root, EKU Client
   Authentication; "Verify the server's identity", "Connect to these servers" = the RADIUS server name, the tenant root
   ticked (it must be installed on the GPMC workstation to appear), "Don't prompt user…" (newer GPMC: "Notifications
   before connecting: Don't ask user"). Authentication mode and single sign-on.
4. Wired Network (IEEE 802.3) Policies → the same EAP settings; "Enforce advanced 802.1X settings" defaults.
5. Authentication mode: **User authentication** works with today's EasyEAP user certificates, but there is no network at
   the sign-in screen (new users can't sign in on a wired-only PC, no computer policy refresh before sign-in; SSO doesn't
   help with software user keys). **User or computer** becomes the recommendation once machine certificates exist (§3).
6. Pitfalls: a GPO wired profile disables the Settings toggle and must not be combined with EasyEAP's wired script on the
   same PCs; the per-user Wi-Fi profile from EasyEAP's helper and a GPO profile for the same SSID: GPO wins, remove one;
   several client-auth certificates → the issuer filter; WPA3-Enterprise in GPMC.
7. What isn't verified here (Windows builds, GPMC versions).

The wired kit (`profiles.py`) keeps "User authentication" until machine certificates ship, and links to the guide.

## 3. v2 (after MAB, device administration and switch audit): automatic machine certificates

Users are cut: machine certificates + "User or computer" mode solve the sign-in problem, and users keep the portal
(automatic user certificates would let any domain user mint certificates from any domain machine). Design, with every
critique finding addressed:

- **Tenant from the URL, its own keytab only**: `POST /api/enroll/windows/{tenant_slug}/computer`. The ticket is accepted
  with that tenant's keytab alone (`gssapi.Credentials(usage='accept', store={'keytab': …})`, decrypted per request to
  tmpfs), and client realm = service realm = upper(`DirectoryConfig.domain`); cross-realm and child domains refused in v2.
  No merged keytab, no global realm registry (MSPs' customers reuse realm names).
- **Keytab health**: guide gives the exact steps (dedicated account, `Set-ADUser -KerberosEncryptionType AES256`, password
  never expires, `ktpass … /ptype KRB5_NT_PRINCIPAL /crypto AES256-SHA1`); EasyEAP checks at upload and daily over LDAP that
  the SPN exists once, `msDS-KeyVersionNumber` matches the keytab's kvno, AES is enabled, the account is enabled; drift is
  an alert. The keytab is a domain credential: encrypted with the tenant's Transit key.
- **Server**: SPNEGO restricted to Kerberos; NTLMSSP tokens detected and answered with a 401 naming the likely cause
  (SPN, CNAME, encryption type); `rdns=false`, `dns_canonicalize_hostname=false`; replay cache on tmpfs; skew and
  modified-ticket errors logged distinctly; no channel binding (TLS required, documented). Own nginx location and rate
  zone, `large_client_header_buffers 4 64k`, per-principal limits in the app, Retry-After honoured with jitter.
- **Computers as identities**: `Identity.kind` (`user|computer`), `sid`, `dns_host_name`; every existing query filters
  `kind='user'` by default (counts, posture, links). Computer sync has its own toggle, filter, search base and safety stop;
  principal mapped by sAMAccountName (`PC$`). New "computer" purpose in the engine/recompute/policy UI; a migrated
  "Computer" template (CN and DNS SAN = dNSHostName, no UPN). Unknown principal → live LDAP lookup and add.
- **Issuance at scale**: evaluate only the new certificate under a per-tenant advisory lock; batched snapshot bumps.
- **Renewal is server-driven**: the task POSTs daily with its current serial; the server decides from status and the
  template's `renew_before_days`; the client first tests its key with a signature (TPM cleared → re-enroll). The old
  certificate is superseded, denied through the snapshot after the new serial first authenticates or a grace period —
  never added to the CRL.
- **First certificate**: guide section — enroll while ports are in monitor mode, or via a provisioning VLAN (unknown-device
  VLAN or MAB) that reaches only DNS, the DCs and EasyEAP, or over Wi-Fi; scripts copied locally with GPP Files; triggers
  at startup, on network change (NetworkProfile 10000), daily with jitter.
- **Script**: `CustomTargetNameDictionary` = `HTTP/<host>`, TLS 1.2 forced, Invoke-RestMethod, optional proxy,
  `certreq -q`, key order TPM ECDSA → TPM RSA-2048 → software KSP, chain imported before `-accept`, cleanup of old EasyEAP
  certificates, event-log source registered by the machine task, script version header (console flags old versions),
  script signing documented.
- **Tests**: Samba AD + curl for the server side; a `windows-latest` CI job runs the script in PowerShell 5.1 against a
  mock endpoint; a manual AD checklist must pass before the feature is called supported.

Native XCEP/WSTEP moves to research notes (nothing behind it yet).

## 4. Critique and revisions

| Finding | Severity | Change |
|---|---|---|
| Merged keytab + realm→tenant mapping lets a tenant forge tickets for another tenant (silver ticket); realm uniqueness breaks MSPs | blocker | Tenant from URL, its own keytab only, realm = the tenant's domain (§3). |
| Keytab checks miss AES on the account, kvno drift, ktpass side effects | major | Exact guide steps; LDAP health checks at upload and daily (§3). |
| The real PS 5.1 failure modes are CNAME SPNs, no proxy as SYSTEM, TLS 1.0, IWR parsing | major | Script and server changes (§3). |
| No path to the first certificate on enforced ports; new computers not synced yet | major | "First certificate" guide section, triggers, live lookup (§3). |
| Renewal strands machines (dead keys, revoke-before-accept, CRL growth) | major | Server-driven renewal, key test, supersede without CRL (§3). |
| Mass rollout: O(n²) recompute, PK races, nginx 30/min per IP | major | Per-certificate evaluation under a lock, batched bumps, own rate zone, jittered retries (§3). |
| Automatic user certificates change the trust model; RDS duplication; header size | major | Users cut (§3). |
| Computer identities leak into counts, links, sync safety, purposes, templates | major | `kind` everywhere, separate sync settings, computer purpose and template (§3). |
| Kerberos server details (rcache, rdns, skew, EPA) | minor | Adopted (§3). |
| Script/GPO details (hash sign-off, execution policy, AppLocker, event source, certreq -q, cleanup) | minor | Adopted (§3). |
| Guide gaps (root on GPMC workstation, newer GPMC wording, SSO, NTAuth, WPA3, duplicate profiles, wired kit mode) | minor | Adopted (§2). |
| Samba/curl ≠ AD/SSPI | minor | Windows CI job + manual AD checklist (§3). |
| XCEP phase 2 had nothing behind it | minor | Moved to research notes. |

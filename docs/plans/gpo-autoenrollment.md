# Plan: Group Policy autoenrollment (MS-XCEP and MS-WSTEP with Kerberos)

Status: built as a preview (2026-11-07); not yet run on real Windows (§4). Request: "are you sure it can't be done via GPO automatically, like with SCEP?" and
"you need to build the machine certificates thing too, so users can log in without cred caching". The Windows setup
file ([../windows-setup.md](../windows-setup.md)) covers PCs one at a time; this covers every domain PC and user
through Group Policy, with no file and no one at the PC. §8 is the review of the first draft and what changed.

## 1. How Windows does it

Windows' certificate autoenrollment (the Certificate Services Client) can use an enrollment policy server that isn't
Active Directory: Group Policy → *Certificate Services Client – Certificate Enrollment Policy* names its URL and the
authentication (Windows integrated = Kerberos). Every 8 hours, at startup and sign-in, and on `certutil -pulse`:

1. **Policy (MS-XCEP)**: SOAP 1.2 `GetPolicies` to the policy URL, authenticated with HTTP Negotiate as the computer
   (`PC01$`) or the user. The answer lists templates the caller may enroll for (`permission/autoEnroll`), the key to
   make (providers, algorithm, length, hash), validity and renewal period, and the enrollment services (CES URLs).
2. **Enrollment (MS-WSTEP)**: for each autoenroll template without a valid certificate, Windows makes the key and
   sends a WS-Trust `RequestSecurityToken` with a PKCS#10 or a CMC request (a renewal is signed by the old certificate)
   to the CES URL. The answer is a CMC full PKI response plus the issued certificate.
3. Windows decides "already enrolled" from the **certificate template extension** (1.3.6.1.4.1.311.21.7: template OID
   and major/minor version) of the certificates in its store, compared with the policy's template OID and revision.

Nothing in Active Directory changes except one service account with an SPN: no templates in the configuration
partition, no NTAuth, no agent on site. References: Microsoft's specs (MS-XCEP, MS-WSTEP, MS-CRTD),
tranquilit/adcs_python (MIT, Python), openSUSE/cepces (the client Samba uses on Linux).

## 2. What EasyEAP adds

### 2.1 Endpoints (one pair per tenant)

- `POST https://<console host>/cep/<tenant slug>` — XCEP `GetPolicies`.
- `POST https://<console host>/ces/<tenant slug>` — WSTEP `RequestSecurityToken` (Issue).
- Tenant slugs can't be renamed, so the URLs Group Policy stores ("Validate Server" saves the URL and the policy ID)
  never change. The policy ID is a UUID stored per tenant.
- Both answer `401 WWW-Authenticate: Negotiate` without a ticket, and take a SPNEGO/Kerberos token in
  `Authorization: Negotiate`. **Kerberos only**: an NTLM token gets `401` and an event that says why (the PC couldn't
  get a ticket for `HTTP/<host>`: SPN missing or duplicated, or a CNAME / IP address in the URL).
- The proxy routes `/cep/` and `/ces/` to the API with a 64 KiB body limit and 64 KiB header buffers (a user in many
  groups has a large ticket; nginx's default 8 KiB would answer 400 before the API sees it). No per-IP rate limit
  there: a site behind one NAT address boots all at once. Limits are per caller in the API (§2.6).

### 2.2 Kerberos per tenant

- Each tenant's AD gets a service account with the SPN `HTTP/<console host>` and AES keys; EasyEAP holds its
  **keytab**, encrypted with the tenant's Transit key like the directory password, never returned by the API (the
  console shows principal, KVNO, encryption types, upload time, last success, last error).
- The console generates a PowerShell script for a domain admin: create the account (default `easyeap-cep`, ≤ 20
  characters), `msDS-SupportedEncryptionTypes = 0x18` (AES only), the SPN, and `ktpass` to write the keytab. Samba AD:
  `samba-tool user add` + `samba-tool spn add` + `samba-tool domain exportkeytab --principal`.
- **Test** in the console: with the directory's own bind account, EasyEAP asks the domain controller for a ticket to
  `HTTP/<console host>` (as a PC would) and opens it with the uploaded keytab. That catches a wrong or duplicated SPN,
  a password changed after the keytab was made, and RC4-only accounts, before any PC tries. It needs Kerberos
  (88/tcp) to the directory's host; enrollment itself doesn't talk to a KDC.
- The API accepts with python-gssapi (MIT krb5) using a credential store pointing at that tenant's keytab, written
  0600 to tmpfs. Replay cache in tmpfs.
- Checks after the context completes: the mechanism is Kerberos (the standard OID or Microsoft's 1.2.840.48018.1.2.2);
  the client realm is the tenant's AD domain (upper case). Realms needn't be unique across tenants: another tenant's
  keytab can't decrypt the ticket anyway.
- **Channel binding (EPA)**: the ticket must be bound to the TLS connection (tls-server-end-point, RFC 5929, the hash
  of the proxy's certificate, which the API reads from the same file nginx serves). Without it a ticket captured or
  relayed to another server (the ESC8 class of attacks on AD CS web enrollment) can't be replayed here. On by default;
  the setting exists for a TLS-inspecting proxy in front of EasyEAP, and the request log says when a PC didn't bind.

### 2.3 Who the caller is

- `NAME$@REALM` → looked up in AD by sAMAccountName: it must be a computer (`objectClass=computer`) with
  `userAccountControl` WORKSTATION_TRUST_ACCOUNT (0x1000) and not disabled. A user account whose name ends in `$` is
  refused. The **computer identity** (`identities.kind = 'computer'`, `username = NAME$`, display name `NAME`,
  `dns_name` = dNSHostName, objectGUID) is created on first contact and refreshed by every directory sync (a separate
  search; deletion and the safety stop count users and computers separately). A disabled or deleted computer account
  is disabled or deleted here, so RADIUS refuses its certificate.
- Any domain user may add 10 computer accounts by default (ms-DS-MachineAccountQuota). So the computer template can be
  limited to an AD group (for example a "Corporate PCs" group), and readiness warns when the quota is above 0.
- `user@REALM` → the AD user with that sAMAccountName, matched to the synced identity by objectGUID (a renamed
  account's old identity is `name~guid`). Users outside the sync scope, disabled or deleted get no templates.
- A new purpose, **`computer`**, for computer certificates (`device` already means a user's device certificate, so a
  rule "any group + device" mustn't catch every domain PC). Rules like "Domain Computers + computer → VLAN 20" use the
  computer's AD groups. The policy simulator and People gain a Computers view.

### 2.4 Templates

Two template rows per tenant, created when autoenrollment is first enabled: **Domain computer** (purpose
`computer`) and **Domain user** (purpose `user`). Template OIDs are built like AD CS's: a per-tenant random root under
Microsoft's enterprise OID root `1.3.6.1.4.1.311.21.8` (six random arcs below 2^24, as each AD forest does), plus two
random arcs per template. Every arc fits 32 bits: Windows' ASN.1 encoder has 32-bit arcs, so a `2.25.<UUID>` OID
(128-bit arc) can't be put in a request.

Each template has a revision (major, minor), validity and renewal days, and on/off. XCEP attributes, pinned in
`app/autoenroll/xcep.py` with spec references:

| Attribute | Computer | User |
|---|---|---|
| policySchema | 3 | 3 |
| revision | major, minor from the template | same |
| permission | enroll, autoEnroll true | same |
| privateKeyAttributes | minimalKeyLength 2048, keySpec 1 (AT_KEYEXCHANGE), algorithmOIDReference → RSA, cryptoProviders `Microsoft Platform Crypto Provider`, `Microsoft Software Key Storage Provider` | same |
| hashAlgorithmOIDReference | SHA-256 | SHA-256 |
| privateKeyFlags | 0 (not exportable, no archival; also the client-version bits: 0 = any) | 0 |
| subjectNameFlags | 0x18000000 subject from the DNS name, DNS SAN (built from AD; enrollee-supplied subjects don't autoenroll) | 0x82000000 subject from the directory, UPN SAN |
| enrollmentFlags | 0x20 autoenrollment, 0x400 remove invalid certificates from the store | same |
| generalFlags | 0x40 machine type | 0 |
| validity / renewal | 365 days / 42 days | 365 / 42 |
| policyOIDReference | the template's OID (application policy client authentication is in the extensions) | same |

RSA 2048 rather than ECDSA: every TPM 2.0 has it, and it's the least likely to trip an untested Windows path. Keys
with the ROCA weakness (Infineon TPMs before 2017, CVE-2017-15361) are refused at enrollment with a message that says
to update the TPM's firmware.

The extension EasyEAP writes carries exactly the template's current major and minor revision. Saving a template
bumps the minor revision (no re-enrollment); **Re-enroll everyone** bumps the major revision, and every PC replaces
its certificate at its next refresh. If the CA would cut a certificate's life to less than the renewal period (the
issuing CA expires sooner), the request is refused and the console says to renew the CA: otherwise every PC would
re-enroll at every refresh.

### 2.5 Issuing: OpenBao CEL roles

The normal OpenBao `sign/<role>` can't add the template extension. OpenBao 2.4's **CEL roles**
(`<mount>/cel/roles/<name>`, `<mount>/cel/sign/<name>`) build the certificate from a `CertTemplate` that the role's
program fills; it sees the request fields and can set `ExtraExtensions` by OID (`base64.decode()` is available).
Checked on `openbao/openbao:2.4.1`: a CEL role produced a certificate with the template extension and a SAN taken from
the request, with the issuer's CRL and AIA URLs and stored for revocation.

The role's program fixes what EasyEAP mustn't vary: not a CA, key usage digital signature + key encipherment (RSA),
EKU client authentication, the validity EasyEAP passes capped by the role. The request supplies the subject CN, the
SAN extension (DER) and the template extension (DER); the program accepts only those two OIDs from the request.
Subjects in the CSR are ignored: EasyEAP builds names from the directory (computer: CN = dNSHostName, SAN DNS; user:
CN = UPN, SAN UPN).

### 2.6 Enrollment

1. Parse the SOAP (no DTDs or entities; 64 KiB) and the `BinarySecurityToken` structurally: a PKCS#10; a CMC
   PKIData (in a SignedData, as Windows sends it) with exactly one TaggedCertificationRequest, whose bodyPartID the
   response echoes; or a renewal (the CMC signed by the old certificate). The PKCS#10's own signature proves
   possession of the key. RSA ≥ 2048 or EC P-256/P-384, not ROCA.
2. Template: from the CSR's template extension, else the caller kind; a user can't request the computer template or
   the other way round; the template must be on.
3. User certificates are per user **per PC**: the PC's name comes from the request's client information
   (1.3.6.1.4.1.311.21.20) and is recorded as a device of the user. Limits: at most 4 certificates per identity,
   template and PC per 24 hours, and 30 per identity and template (so hot desks and labs work, and a broken client
   can't mint certificates in a loop). Requests per caller: 60 a minute.
4. Issue (§2.5), record it (`key_origin = device`, `enrollment_source = gpo`), mark older active certificates for the
   same identity, template and PC as renewed (they stay valid to expiry, as with renewal); for a computer, also the
   computer certificate a setup file made for the same DNS name, so its renewal task stops. Evaluate the policy for
   the new certificate only (not the whole tenant) and bump the snapshot version; audit `certificate.autoenrolled`.
5. Answer: `RequestSecurityTokenResponseCollection` with `a:RelatesTo` = the request's MessageID and Action
   `…/RSTRC/wstep`, `DispositionMessage` Issued, the CMC full PKI response in `BinarySecurityToken`, the certificate
   in `RequestedSecurityToken`, and a small decimal `RequestID` (the event number). The CMC response is shaped like
   AD CS's (status info for the request's body part, Microsoft's issued-certificate hash attribute, the chain) and
   signed by the tenant's **enrollment-service certificate** (RSA 2048, issued by the tenant's issuing CA, key
   encrypted with the tenant's Transit key, renewed automatically). AD CS signs with the CA key, which OpenBao doesn't
   expose; whether Windows accepts another signer chaining to the same CA is the first thing the first-PC checklist
   verifies, and a setting switches to a certificates-only PKCS#7 if it doesn't.
6. Failures are SOAP faults with an HRESULT in `CertificateEnrollmentWSDetail/ErrorCode` (what Windows logs, as
   CertificateServicesClient-CertEnroll events): CERTSRV_E_TEMPLATE_DENIED, CERTSRV_E_ENROLL_DENIED,
   CERTSRV_E_KEY_LENGTH, CERTSRV_E_BAD_REQUESTSUBJECT, E_FAIL; `InvalidRequest` true for denials. The sentence a
   person needs is in the console's request log.

### 2.7 Console

- **RADIUS → Windows Group Policy** gains an **Autoenrollment** section (marked *Preview* until a real Windows PC
  has passed the checklist in §4): status, the policy URL, the computer and user switches, the computer group, the
  service-account script, the keytab upload with a parsed summary and **Test**, channel binding, and the Group Policy
  steps (Computer and User Configuration → Public Key Policies → *Certificate Services Client – Certificate Enrollment
  Policy* with the URL and Windows integrated; *Auto-Enrollment* enabled, renew and update; Wi-Fi/wired profiles with
  *User or computer authentication*).
- Last requests (time, caller, result, reason) so the first `certutil -pulse` shows up while the admin watches.
- People: a Computers view (DNS name, AD groups, certificates; no enrollment buttons).
- Readiness: keytab present and not failing, directory sync working, machine account quota.
- The Windows setup dialog warns against also making computer certificates with the setup file for domain PCs when
  computer autoenrollment is on.

## 3. Data

Migration 0008:
- `identities.kind` (`user` default) and `dns_name`.
- `autoenroll_configs` (tenant): enabled, computers/users switches, policy ID, OID root, keytab ciphertext and summary,
  require channel binding, computer group, response format, enrollment-service certificate and key ciphertext, last
  success/error.
- `certificate_templates.template_oid`, `revision_major`, `revision_minor`, `autoenroll_kind` (computer | user).
- `certificates.enrollment_source` (`gpo`).
- `autoenroll_events` (bounded per tenant; the console's last requests; the id is the WSTEP RequestID).

## 4. Tests

- Unit: XCEP and WSTEP builders parse and carry the right values; request parsing with the spec's own example request,
  a CMC request in a SignedData, a renewal, garbage, two requests; the CMC response against the spec's example's
  structure; template choice; limits; ROCA; computer and user mapping; realm, NTLM and channel-binding checks.
- Kerberos with a real MIT KDC (`tests/autoenroll/kerberos.sh`): tickets as a computer and a user, NTLM refused,
  replay refused, channel bindings matching, missing and wrong.
- Integration in the lab (Samba AD): SPN and keytab with the script EasyEAP generates for `samba-tool`, computer
  accounts and a user; an **independent client written from the specifications** (`tests/e2e/autoenroll_client.py`:
  hand-built DER and CMC, Kerberos with python-gssapi, channel binding from the proxy's certificate) against EasyEAP
  through the proxy as `PC-AE01$` and as a user: policy, enrollment, the template extension in the certificate, a
  re-enrollment after a new major revision, refusals (no binding, wrong binding, another template, a 1024-bit key,
  garbage, a user account named like a computer, a computer outside the group, the daily limit); the certificate
  authenticates through FreeRADIUS with the computer's VLAN. cepces was dropped: it needs its own Kerberos and
  certmonger setup and would test its own assumptions as much as ours.
- **Not verifiable here: real Windows.** This host has no virtualization for a Windows VM. Until a Windows 11 PC has
  passed this checklist, the console marks the feature *Preview* and the guide says so: (1) `certutil -pulse` in
  machine context issues a computer certificate (template extension, chain, private key in the TPM); (2) the same for
  a user; (3) a second pulse issues nothing; (4) the Certificate Enrollment Policy "Validate Server" passes; (5) the
  PC connects to 802.1X at the sign-in screen with the computer certificate.

## 5. Order

1. Migration, models, directory sync and computer lookup; Kerberos (channel binding, both OIDs); `/cep` answering
   GetPolicies.
2. Templates and OIDs, CEL issuing, enrollment-service certificate, request parsing, `/ces`, limits, events.
3. Console section, readiness, Computers view, `computer` purpose; proxy; docs; lab test with an independent client.

## 6. Not in this version

Key attestation (the TPM's EK chain) for computer keys; certificate "Publish to AD"; username/password or
certificate-authenticated CEP/CES (non-domain PCs use the setup file); several domains per tenant; mapping by the
ticket's PAC (the LDAP lookup by account name gives the same answer for a single domain).

## 7. Risks

The first two are why the feature ships as *Preview*:
1. Windows rejects a CMC response not signed by the issuing CA itself. Mitigation: the response-format switch.
2. Windows doesn't send channel bindings to a policy server. Mitigation: the setting, and the log says so.
3. MIT reports a different mechanism OID for Microsoft's Kerberos OID: both are accepted.

## 8. Review of the first draft (2026-11-07) and what changed

An independent review of the draft found 19 problems; all are addressed above.

| # | Finding | Change |
|---|---|---|
| 1 | `2.25.<UUID>` has a 128-bit arc; Windows' ASN.1 layer has 32-bit arcs | AD CS-style OIDs under 1.3.6.1.4.1.311.21.8, arcs < 2^24 (§2.4) |
| 2 | WSTEP requires a CMC full response, signed; RelatesTo and RSTRC action missing | Signed by an enrollment-service certificate; RelatesTo, Action; fallback switch (§2.6) |
| 3 | Walking the DER loses the bodyPartID and accepts several requests | Structural parsing, one request, bodyPartID echoed (§2.6) |
| 4 | Revision mismatch makes Windows re-enroll in a loop; so does a CA-truncated validity | Exact revision in the extension; minor vs major bumps; truncation refused (§2.4) |
| 5 | XCEP attributes underspecified | Pinned in a table and the code (§2.4) |
| 6 | Fault sentences aren't what Windows logs | HRESULTs in the fault; RequestID small decimal (§2.6) |
| 7 | No Windows client in the tests | Not possible on this host; *Preview* + first-PC checklist (§4) |
| 8 | nginx's 8 KiB header buffers reject big tickets | 64 KiB on the HTTPS server (§2.1) |
| 9 | MIT may report Microsoft's Kerberos OID | Both accepted (§2.2) |
| 10 | Account name length; keytabs that silently don't match | Short default name; **Test** with a real ticket (§2.2) |
| 11 | Realm uniqueness across tenants blocks CORP.LOCAL twice and adds nothing | Dropped (§2.2) |
| 12 | Tickets relayable without channel binding (ESC8 class) | Channel binding required by default (§2.2) |
| 13 | Computer by trailing `$`; MachineAccountQuota | AD objectClass + UAC check; computer group; readiness warning; users by GUID (§2.3) |
| 14 | Per-IP rate limit throttles NAT sites | Per-caller limits in the API (§2.1, §2.6) |
| 15 | User certificates per user per PC (hot desks, VDI) | Keyed on the PC from client info; user switch for VDI (§2.6) |
| 16 | ROCA keys from old Infineon TPMs | Refused (§2.4) |
| 17 | Sync marks every computer deleted | Separate computer search and counts (§2.3) |
| 18 | Whole-tenant recompute per enrollment | One certificate evaluated (§2.6) |
| 19 | `device` purpose collision; two machine certificates; no SID; uniqueness across realms | `computer` purpose; setup-file certificate superseded; GUID mapping; one realm per tenant (§2.3, §2.6, §6) |

## 9. Review of the build (2026-11-07) and what changed

An adversarial review of the finished code, and the first full lab run, found these; all are fixed and tested:

- **High: a computer was trusted by name while its cached record was fresh.** A renamed PC's old name, taken by a new
  account through MachineAccountQuota, would have enrolled as the old PC. Now every issuance re-reads the computer in
  AD by objectGUID (`confirm_computer`) and requires the same name, enabled, workstation, group; a name another
  account takes steps aside instead of being marked deleted.
- Turning **Require channel binding** off still passed bindings to the acceptor (MIT refuses a mismatch), so it
  couldn't help behind a TLS-inspecting proxy. Bindings now go to the acceptor only when required.
- With no acceptor name, MIT accepts a ticket for **any key in the keytab**: the keytab is cut to `HTTP/<host>` on
  upload and on load, and a whole-domain export (krbtgt) is refused.
- A user filter that matched computers would have broken the sync (duplicate objectGUID): users now always exclude
  `objectClass=computer`; computers synced as users by such a filter are converted.
- Log flooding and cost of unauthenticated requests: the credential-less first request is answered from a 30-second
  tenant cache; caller-less failures are capped per tenant as well as per address; a refusal of the same account is
  logged once an hour; the limiter forgets idle keys; nginx caps `/cep` and `/ces` per address.
- Replaced certificates are now `superseded` (as elsewhere), not only `renewed_at`.
- `dNSHostName` is checked (first label = computer name, AD domain, unique), and a computer added by a user with their
  quota doesn't supersede a setup-file certificate of a PC with the same name.
- LDAP failures no longer read as "not a computer" or "no groups"; a crash while identifying is a fault and a log line,
  not a bare 500; AD-down is remembered for a minute; the identity row is locked while issuing.
- XML: expat refuses any DOCTYPE or entity declaration (the byte check missed UTF-16 and late DOCTYPEs).
- The keytab test's krb5.conf inputs are validated and it runs on tmpfs; replaced keytabs are removed from tmpfs.
- Read-only domain controllers (0x04000000) aren't workstations; users need the directory connection on.
- Autoenrollment can be turned off while OpenBao is down; the migration's downgrade leaves 0007 consistent.
- Out-of-scope callers on `/cep` get an empty policy, as from AD CS, not a fault Windows logs at every refresh.
- Lab: Samba exports only the RC4 key for an SPN on a user account without `msDS-SupportedEncryptionTypes`; the
  Samba script sets 24 (AES). Credentials acquired by password for Kerberos alone can't be used through SPNEGO; the
  keytab test asks for SPNEGO credentials, and reports the underlying Kerberos error instead of SPNEGO's.
- Open: whether Windows accepts the unsigned CMC response (the default) is the first item of the checklist in §4; the
  "signed" fallback signs with a certificate from the computer role (client authentication EKU), not the CA.

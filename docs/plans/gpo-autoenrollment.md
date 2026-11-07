# Plan: Group Policy autoenrollment (MS-XCEP and MS-WSTEP with Kerberos)

Status: draft (2026-11-07). Request: "are you sure it can't be done via GPO automatically, like with SCEP?" and "you
need to build the machine certificates thing too, so users can log in without cred caching". The Windows setup file
([windows-setup.md](windows-setup.md)) covers PCs one at a time; this covers every domain PC and user through Group
Policy, with no file and no one at the PC.

## 1. How Windows does it

Windows' certificate autoenrollment (the Certificate Services Client) can use an enrollment policy server that isn't
Active Directory: Group Policy → *Certificate Services Client – Certificate Enrollment Policy* names its URL and the
authentication (Windows integrated = Kerberos). Every 8 hours, at startup and sign-in, and on `certutil -pulse`:

1. **Policy (MS-XCEP)**: SOAP 1.2 `GetPolicies` to the policy URL, authenticated with HTTP Negotiate as the computer
   (`PC01$`) or the user. The answer lists templates the caller may enroll for (`permission/autoEnroll`), the key to
   make (providers, algorithm, length), validity and renewal period, and the enrollment services (CES URLs).
2. **Enrollment (MS-WSTEP)**: for each autoenroll template without a valid certificate, Windows makes the key and
   sends a WS-Trust `RequestSecurityToken` with a PKCS#10 or a CMC/PKCS#7 request (a renewal is signed by the old
   certificate) to the CES URL. The answer carries the certificate and its chain.
3. Windows decides "already enrolled" from the **certificate template extension** (1.3.6.1.4.1.311.21.7: template
   OID and version) of the certificates in the store. Without it, it would enroll again on every run.

Nothing in Active Directory changes: no templates in the configuration partition, no NTAuth, no agent on site.
Reference implementations: Microsoft's specs (MS-XCEP, MS-WSTEP, MS-CRTD), tranquilit/adcs_python (MIT, Python),
openSUSE/cepces (the client Samba uses on Linux; our independent test client).

## 2. What EasyEAP adds

### 2.1 Endpoints (one pair per tenant)

- `POST https://<console host>/cep/<tenant slug>` — XCEP `GetPolicies`.
- `POST https://<console host>/ces/<tenant slug>` — WSTEP `RequestSecurityToken` (Issue).
- Both answer `401 WWW-Authenticate: Negotiate` without a ticket, and take a SPNEGO/Kerberos token in
  `Authorization: Negotiate`. **Kerberos only**: an NTLM token gets `401` and an event that says why (the PC couldn't
  get a ticket for `HTTP/<host>`: SPN missing or duplicated, or a CNAME).
- The proxy routes `/cep/` and `/ces/` to the API with a 64 KiB body limit and its own rate limit.

### 2.2 Kerberos per tenant

- Each tenant's AD gets a service account with the SPN `HTTP/<console host>` and AES keys; EasyEAP holds its
  **keytab**, encrypted with the tenant's Transit key like the directory password, never returned by the API (the
  console shows principal, KVNO, encryption types, upload time, last success, last error).
- The console generates a PowerShell script for a domain admin: create `svc-easyeap-<tenant>` with a random password,
  `msDS-SupportedEncryptionTypes = 0x18` (AES only), the SPN, and `ktpass` to write the keytab. Samba AD:
  `samba-tool spn add` + `samba-tool domain exportkeytab`.
- The API accepts with python-gssapi (MIT krb5) using a credential store pointing at that tenant's keytab, written
  0600 to a tmpfs only for the process' lifetime. Replay cache in tmpfs. No KDC traffic: acceptors don't need one.
- Checks after the context completes: mechanism is Kerberos; the client realm is one of the tenant's realms (the AD
  domain, upper case); no two tenants may claim the same realm. The tenant comes from the URL; another tenant's
  keytab can't decrypt the ticket anyway.
- Channel binding (EPA) is not checked in this version (TLS ends at the proxy); listed in §6.

### 2.3 Who the caller is

- `NAME$@REALM` → a **computer identity** (`identities.kind = 'computer'`, `username = NAME$`, display name `NAME`,
  `dns_name` = dNSHostName). Created on first contact by an LDAP lookup with the tenant's directory connection
  (sAMAccountName, objectGUID, dNSHostName, userAccountControl, tokenGroups), then refreshed by every directory sync.
  A disabled or deleted computer account is disabled or deleted here, so RADIUS refuses its certificate.
- `user@REALM` → the synced user with that sAMAccountName. Users outside the sync scope get no templates.
- Policy is unchanged: computer certificates have purpose `device`, their identity's groups are the computer's AD
  groups (Domain Computers, plus any group it's in), so rules like "Domain Computers → VLAN 20" just work. The policy
  simulator and the People screen gain a Computers view.

### 2.4 Templates

Two template rows per tenant, created on first use: **Domain computer** (purpose `device`) and **Domain user**
(purpose `user`). Each has a stable template OID `2.25.<UUID as integer>` (ITU-T X.667, no registration needed), a
revision, validity and renewal days, and on/off for autoenrollment. XCEP attributes:

| Attribute | Computer | User |
|---|---|---|
| policySchema | 3 (CNG providers) | 3 |
| permission | enroll, autoEnroll | enroll, autoEnroll |
| key | RSA 2048, keySpec 1, providers: Microsoft Platform Crypto Provider, then Microsoft Software Key Storage Provider; not exportable | same |
| subjectNameFlags | DNS as CN + DNS SAN (built by EasyEAP) | UPN SAN + CN (built by EasyEAP) |
| enrollmentFlags | 0x20 autoenrollment, 0x400 remove invalid certificates | 0x20, 0x400 |
| generalFlags | 0x40 machine | 0 |
| validity / renewal | 365 days / 42 days | 365 / 42 |

RSA 2048 rather than ECDSA: every TPM 2.0 has it, and it's the default when the template names no algorithm, so it's
the least likely to trip an untested Windows path.

### 2.5 Issuing: OpenBao CEL roles

The normal OpenBao `sign/<role>` can't add the template extension. OpenBao 2.4's **CEL roles**
(`<mount>/cel/roles/<name>`, `<mount>/cel/sign/<name>`) build the certificate from a `CertTemplate` that the role's
program fills; it sees the request fields and can set `ExtraExtensions` by OID (`base64.decode()` is available).
Checked on `openbao/openbao:2.4.1`: a CEL role produced a certificate with the template extension and a SAN taken from
the request, with the issuer's CRL and AIA URLs and stored for revocation.

The role's program fixes what EasyEAP mustn't vary: not a CA, key usage digital signature, EKU client
authentication, at most the template's validity. The request supplies the subject CN, the SAN extension (DER) and
the template extension (DER); the program accepts only those two OIDs from the request. Subjects in the CSR are
ignored: EasyEAP builds names from the directory (computer: CN = dNSHostName, SAN DNS; user: CN = UPN, SAN UPN).

### 2.6 Enrollment

1. Parse the SOAP (no DTDs; 64 KiB), take the `BinarySecurityToken` (PKCS#10, or PKCS#7/CMC: the PKCS#10 is found
   inside by walking the DER), check the CSR's signature and key (RSA ≥ 2048 or EC P-256/P-384).
2. Template: from the CSR's template extension or name, else from the caller kind; a user can't request the computer
   template or the other way round.
3. Rate: at most 4 issued per identity and template per 24 hours (a broken client can't mint certificates in a loop).
4. Issue (§2.5), record it (`key_origin = device`, `enrollment = gpo`), supersede that identity's older active
   certificates from the same template (they stay valid to expiry, as with renewal), recompute the tenant's decisions,
   audit `certificate.autoenrolled`.
5. Answer: `RequestSecurityTokenResponseCollection` with `DispositionMessage` Issued, the chain as a degenerate PKCS#7,
   the certificate in `RequestedSecurityToken`, and a `RequestID`. Failures are SOAP faults with a sentence Windows
   writes to its event log (CertificateServicesClient-AutoEnrollment).

Renewals arrive the same way (a PKCS#7 signed by the current certificate, plus Kerberos); Kerberos is the
authentication, so they're treated as new enrollments that supersede the old certificate.

### 2.7 Console

- **RADIUS → Windows Group Policy** gains an **Autoenrollment** section: status, the policy URL, the computer and user
  switches, the service-account script, the keytab upload with a parsed summary, and the Group Policy steps
  (Computer and User Configuration → Public Key Policies → *Certificate Enrollment Policy* with the URL and Windows
  integrated; *Auto-Enrollment* enabled, renew and update; Wi-Fi/wired profiles with *User or computer
  authentication*).
- Last requests (time, caller, result, reason) so the first `certutil -pulse` shows up while the admin watches.
- People: a Computers view (the identity page adapted: DNS name, AD groups, certificates; no enrollment buttons).
- Readiness on the tenant: keytab present and not failing, directory sync working.

## 3. Data

Migration 0008: `identities.kind` (`user` default) and `dns_name`; `kerberos_configs` (tenant, realms, principal,
kvno, enctypes, keytab_ct, enabled flags, last success/error); `certificate_templates.template_oid`, `revision`,
`autoenroll` and `ae_kind` (computer | user); `certificates.enrollment_source` (`gpo`) for display; an
`autoenroll_events` table (bounded, for the console's last requests).

## 4. Tests

- Unit: XCEP and WSTEP builders parse and carry the right flags; request parsing with the spec's own example request
  (PKCS#10 and CMC), a PKCS#7 renewal, garbage; template choice rules; rate limit; Kerberos name → identity mapping;
  realm checks; NTLM refused.
- Integration in the lab (Samba AD, which already runs there): SPN and keytab with `samba-tool`, a computer account and
  a user; a client container with MIT Kerberos that `kinit`s as `PC01$` and as a user and runs **cepces** against
  EasyEAP: policy, enrollment, the template extension in the result, a second run that doesn't enroll again; then the
  certificate authenticates through FreeRADIUS with the computer's VLAN.
- Not verifiable here: real Windows autoenrollment (no Windows VM); the guide lists what to check on the first PC.

## 5. Order

1. Kerberos acceptor + keytab storage and upload; `/cep` answering a GetPolicies; cepces fetches the policy.
2. Computer identities (JIT + sync), templates, CEL issuing, `/ces`; cepces enrolls a computer, then a user.
3. Console section, readiness, Computers view; docs; e2e step.

## 6. Not in this version

Channel binding tokens (EPA) behind the proxy; key attestation (the TPM's EK chain) for computer keys; certificate
"Publish to AD"; username/password or certificate-authenticated CEP/CES (non-domain PCs use the setup file); several
domains in one forest per tenant beyond the realm list.

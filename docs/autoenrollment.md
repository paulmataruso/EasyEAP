# Group Policy autoenrollment

Domain-joined Windows PCs, and the people who sign in to them, get their 802.1X certificates from EasyEAP through
Group Policy, the same way they would from Active Directory Certificate Services: nothing to download or click on the
PC, and Windows renews them. The computer's certificate connects at the sign-in screen, so people can sign in without
cached credentials, and on a port that enforces 802.1X a PC is on the network before anyone signs in.

EasyEAP answers Microsoft's two enrollment protocols: the certificate enrollment policy (MS-XCEP, which templates) and
the enrollment web service (MS-WSTEP, issuing). PCs authenticate with Kerberos. EasyEAP checks every computer and user
in Active Directory before it issues anything.

> **Preview.** Autoenrollment is tested against a Samba AD domain controller and a Kerberos client written from
> Microsoft's specifications, through EasyEAP's real proxy, CA and FreeRADIUS. It hasn't yet been run on a real
> Windows PC. Try it on one PC first, with the checklist in [Try one PC](#5-try-one-pc).

The console shows the same steps with your tenant's values filled in: **GPO autoenrollment** in the sidebar.

## When to use it

| | Group Policy autoenrollment | [Windows setup file](windows-setup.md) |
|---|---|---|
| PCs | Domain-joined | Any Windows 10/11 PC, joined or not |
| Who acts | Nobody: Group Policy does it | IT runs a file per PC and user |
| Computer certificate | The computer's own: access from the computer's AD groups | A device certificate of the user it was made for: that user's access |
| User certificates | One per user per PC, for everyone who signs in | The one user the file was made for |
| Renewal | Windows' autoenrollment | The setup file's scheduled task |

Both can run in one tenant. On a PC that gets a computer certificate from Group Policy, the setup file's computer
certificate is marked as replaced and its renewal stops: one PC, one source of machine certificates.

## What you need

- **A DNS name for EasyEAP** that PCs resolve, in `EASYEAP_HOSTNAME` (for example `easyeap.corp.example`). Kerberos
  doesn't work with an IP address, and the name must not be a CNAME to another name: Windows asks the domain
  controller for a ticket to `HTTP/<that name>`.
- **PCs reach `https://<that name>/` (443/tcp)**, and trust its TLS certificate. Windows checks the certificate before
  it sends anything: use a certificate from a CA your PCs trust (your own enterprise CA, or a public one), or push the
  self-signed one's issuer to Trusted Root Certification Authorities by Group Policy.
- **TLS ends at EasyEAP's proxy.** A load balancer or TLS-inspecting proxy that re-encrypts breaks channel binding
  (see [Security](#security)). Pass TLS through, or turn off **Require channel binding**.
- **Active Directory connected** (Directory) and the **certificate authority** set up.
- **A Domain Admin's user name and password, once**, typed into the console to create the service account (or, if
  you'd rather not type them into EasyEAP, a Domain Admin to run the service-account script on a domain controller).
- **Kerberos (88/tcp) from EasyEAP to a domain controller**, and LDAPS (636/tcp, or StartTLS on 389) as for the
  directory sync. The global catalog over TLS (3269/tcp) is used to check the whole forest for a duplicate SPN when
  it answers.
- After upgrading from a release without autoenrollment: the new `docker-compose.yml`, which mounts the proxy's
  certificate into the API (`./secrets/tls.crt:/etc/easyeap/proxy-tls.crt:ro`). Without it, readiness says the API
  can't check channel binding. It's a single-file mount, so when you replace the proxy's certificate, restart
  `easyeap-api` as well as `easyeap-proxy`; otherwise every PC is refused with "bound to a different TLS connection".

## Set it up

### 1. Create the service account

**GPO autoenrollment → Set up → Create the service account…** asks for a domain account that may create users (a
Domain Admin, or one delegated **Create User objects** on the container). Then EasyEAP, in one step:

- checks first that `ktutil` is there and a domain controller answers Kerberos (88/tcp): without it EasyEAP couldn't
  make the keys, so it stops before anything in Active Directory changes;
- signs in with it to a domain controller from Directory, over LDAPS or StartTLS only (Active Directory sets
  passwords only on an encrypted connection; a directory set to plain LDAP is refused), and checks that the domain is
  the tenant's realm. If Directory doesn't verify the domain controller's certificate, the dialog says so and sends
  the password only after you confirm (recorded in the audit log): someone on the network between EasyEAP and the
  domain controller could otherwise pose as it. Turning on **Verify the certificate** in Directory is better;
- checks that neither `HTTP/<console name>` nor `HOST/<console name>` is registered to another account: in the whole
  forest through the global catalog (3269/tcp, TLS) when it answers, otherwise in the domain. A duplicate SPN breaks
  Kerberos for that name, and Active Directory treats `HOST/` as covering `HTTP/`: if EasyEAP's name is a
  domain-joined computer's, give EasyEAP a DNS name of its own;
- creates the user `easyeap-cep` in the domain's Users container, or the OU you give (**Create it in**), with a
  random 40-character password, AES only (`msDS-SupportedEncryptionTypes` 24), not delegable, password never
  expires, and `HTTP/<console name>` as its SPN. A new account is added disabled, then given its password, then
  enabled (Windows doesn't accept a password in the add);
- derives the account's AES-256 and AES-128 keys from that password with the salt the domain controller reports for
  the account (MIT `ktutil addent -f`, over Kerberos 88/tcp), at the key version Active Directory reports
  (`msDS-KeyVersionNumber`), and keeps them as the keytab for `HTTP/<console name>`, encrypted with the tenant's key;
- runs the **Test** below.

The administrator's credentials and the account's password are used only during that request: they aren't stored,
logged or audited (the audit log records which administrator account was used, never a password). The Set up tab
shows the account, its key version and who created it. **Create it again…** sets a new password: Windows' tickets
made with the old key are refused until they expire (10 hours by default; `klist purge` on a PC clears them).

**If `easyeap-cep` already exists**, EasyEAP resets it only if it's the account EasyEAP made (the objectGUID it keeps),
or one the service-account script made (description "EasyEAP certificate enrollment…") that is owned by Domain Admins,
Administrators or you, has no other service names and nothing unusual set (no smart card requirement, delegation or
protected-group membership). Anyone who owns the account could set its key themselves and forge tickets to EasyEAP,
so an account a delegated user created is refused: remove it, and EasyEAP creates a new one. Create it in the Users
container or an OU only administrators control, for the same reason.

A reset derives the new keys before the password changes (the salt stays the same), so a failure before that point
changes nothing; once the password has changed, EasyEAP always keeps the keys that match it, and says which step
didn't finish. Only one run per tenant at a time.

If it fails, the console says which step: Kerberos (88/tcp blocked, or the domain controller doesn't know a new
account yet), signing in (403 with the directory's reason), the duplicate SPN or an account EasyEAP won't take over
(409). A new account can take a moment to reach every domain controller: EasyEAP asks the one it wrote to first and
retries for about ten seconds; if it still fails, try again and EasyEAP finishes the account it made.

**Test** asks your domain controller for a ticket to `HTTP/<console name>` with the directory's bind account, the
way a PC would, and opens it with the key. That needs Kerberos (88/tcp) from EasyEAP to the domain controller;
enrollment itself doesn't, because PCs bring their tickets with them.

#### Without typing administrator credentials into EasyEAP

**Other ways → Script for Windows AD** downloads `easyeap-service-account.ps1`. Run it on a domain controller, or a PC
with the RSAT Active Directory tools, as a Domain Admin:

```powershell
powershell -ExecutionPolicy Bypass -File .\easyeap-service-account.ps1
```

It makes the same checks and the same account, runs `ktpass` to write `easyeap-cep.keytab` (AES-256) next to the
script, and the password never leaves the domain controller. **Upload keytab**, then delete the file: EasyEAP keeps
only the keys for `HTTP/<console name>`, encrypted. Running the script again sets a new password, so upload the new
keytab. For Samba AD, use **Script for Samba AD** (`samba-tool user add`, `spn add`, `domain exportkeytab`) as root on
a domain controller.

### 2. Turn it on

**Settings**: turn on autoenrollment, and choose computers, users or both.

- **Only computers in** limits computer certificates to one AD group, for example "Corporate PCs". By default any
  domain user can join 10 computers to the domain (`ms-DS-MachineAccountQuota`), and each would get a computer
  certificate: set the quota to 0, or use a group. Readiness warns while neither is done.
- Each kind has its template, created the first time you turn autoenrollment on: **Domain computer** (Windows shows
  it as `EasyEAP-Computer`) and **Domain user** (`EasyEAP-User`). Validity and renewal are set per template (365 and
  42 days by default; the renewal period can be at most three quarters of the validity).

**Add an access rule for computers.** A computer's certificate is decided as the computer: its AD groups, with
certificate type **Domain computers**. In **Access policy**, add for example "Domain Computers → your PC VLAN",
applying to Domain computers. Rules for "any certificate" also apply to computers; rules for user or device
certificates don't. Readiness warns while no rule would let a computer on.

### 3. Point Group Policy at EasyEAP

In a GPO linked to the PCs' OU, under **Computer Configuration → Policies → Windows Settings → Security Settings →
Public Key Policies**:

1. **Certificate Services Client – Certificate Enrollment Policy**: Enabled. **Add**: the policy server URL from the
   console (`https://<console name>/cep/<tenant>`), authentication **Windows integrated**, **Validate Server**,
   **Add**. Tick **Default** on it. Keep "Active Directory Enrollment Policy" if you also use AD CS.
2. **Certificate Services Client – Auto-Enrollment**: Enabled, with **Renew expired certificates, update pending
   certificates, and remove revoked certificates** and **Update certificates that use certificate templates** ticked.
3. For user certificates, the same two policies under **User Configuration → Policies → Windows Settings → Security
   Settings → Public Key Policies**.
4. Trust and the network: the Wi-Fi and wired policies from [Windows Group Policy](windows-group-policy.md), with
   **User or computer authentication** so the computer's certificate connects at the sign-in screen and the user's
   after sign-in. The issuer filter (EasyEAP's CA) makes Windows pick the EasyEAP certificate.

### 4. Try one PC

1. `gpupdate /force`, then `certutil -pulse`. Within a minute **certlm.msc → Personal → Certificates** has a
   certificate from the `EasyEAP-Computer` template, issued by your EasyEAP issuing CA, with the PC's DNS name.
   The Request log shows it as issued. If it does, but no certificate appears and Event Viewer
   (CertificateServicesClient-CertEnroll) says the response can't be read, this is the one thing not yet confirmed
   on real Windows: set **Settings → Response format → Signed**, run `certutil -pulse` again, and tell us which
   worked.
2. Signed in as a user (if user certificates are on): `certutil -user -pulse`; **certmgr.msc → Personal**.
3. `certutil -pulse` again: nothing new is issued (the Request log shows the policy request, not a certificate).
4. In the Certificate Enrollment Policy dialog, **Validate Server** passes.
5. Sign out: the PC connects at the sign-in screen with its certificate. EasyEAP's Authentication log shows the
   computer (`host/<name>`) and its VLAN.

Please tell us how it went, especially the first two steps on Windows 11 with and without a TPM.

## How EasyEAP decides

- **Computers.** A Kerberos principal `NAME$@REALM` is looked up in Active Directory: it must be a computer account
  (`objectCategory=computer`) with the workstation trust flag (so not a domain controller or a trust), enabled, with
  a `dNSHostName`, and in the computer group if you set one. The first request creates the computer in **Users →
  Computers**; EasyEAP re-reads it from AD after 6 hours, and the directory sync keeps it current (disabled or deleted
  in AD → disabled or deleted here, and RADIUS refuses its certificate). If AD can't be reached, a computer EasyEAP
  already knows gets the policy from what EasyEAP knows, but **nothing is issued without asking AD**: before each
  certificate, EasyEAP reads the computer account again by its objectGUID and checks that it's still called what the
  ticket says, enabled, a workstation (read-only domain controllers aren't) and in the computer group. A new computer
  account that reuses an old one's name (a PC that rejoined, or a name freed by a rename) is a new computer: the old
  one steps aside as `NAME$~<guid>` until the directory sync renames it or marks it deleted.
- **The computer's DNS name** must be its own, because whoever creates a computer account can write its
  `dNSHostName`: the first label must be the computer's name (NetBIOS names are cut to 15 characters), the name must
  be in the AD domain (a disjoint namespace isn't supported in this version), and no other enabled computer may have
  it.
- **Users.** `user@REALM` must be a synced, enabled directory user (by sAMAccountName), with the directory connection
  on. Users outside the sync's search base or filter get nothing.
- **Who isn't covered** (a user who isn't synced, a computer outside the computer group, a disabled account) gets an
  empty policy, as from AD CS, so Windows doesn't log an error at every refresh; the Request log says why, once an
  hour per account.
- **What goes into the certificate** comes from the directory, never from the request: a computer gets its
  `dNSHostName` as subject and DNS name; a user gets their UPN as subject and UPN name. Client authentication only,
  digital signature only, not a CA, the template's validity (shortened if the issuing CA expires sooner; refused if
  that would leave it already due for renewal).
- **Keys** are RSA 2048, made by Windows. The template asks for the TPM (Microsoft Platform Crypto Provider) first and
  the Software Key Storage Provider second, so PCs without a TPM, including Windows 11 installed with the TPM check
  bypassed, make a software key. The private key never leaves the PC; EasyEAP records where Windows says it made it
  (TPM or software) on each certificate. Keys under 2048 bits, other curves and keys with the ROCA weakness (Infineon
  TPMs before 2017) are refused.
- **Limits**: a computer gets at most 4 certificates a day; a user at most 4 a day on one PC and 30 a day in all (hot
  desks, labs). A new certificate marks the one it replaces as superseded; the old one stays valid until it expires,
  as with renewal everywhere in EasyEAP. Revoke it if it must stop working now. On a PC that used the Windows setup
  file, the setup file's computer certificate is superseded too (its renewal task stops), unless the computer account
  was added by a user with their machine account quota.
- **Re-enroll everyone** (Settings) publishes a new major revision of a template, as AD CS's "Reenroll All Certificate
  Holders" does: every PC or user requests a new certificate at its next policy refresh.

## Security

- **Kerberos only.** NTLM is refused (the Request log says so: it usually means the SPN is missing, or the policy URL
  uses an IP address or a CNAME). Tickets must be for `HTTP/<console name>` in the tenant's realm.
- **Channel binding (Extended Protection)** is required by default: the PC's ticket must be bound to its own TLS
  connection to EasyEAP's proxy, so a ticket captured or relayed through another server (the ESC8 class of attacks
  on AD CS web enrollment) is refused. Turn the requirement off only if something you trust ends TLS in front of
  EasyEAP (a TLS-inspecting proxy): then bindings aren't checked at all, since the PC binds its ticket to the
  inspecting proxy's certificate.
- **The keytab** keeps only the keys for `HTTP/<console name>`: anything else in the uploaded file is dropped (with no
  service name to check, Kerberos would accept a ticket for any key in it), and a whole-domain export (with the
  `krbtgt` key) is refused. It's encrypted with the tenant's OpenBao Transit key and only ever written to
  memory-backed storage in the API container. Remove it in the console to stop all enrollment at once.
- **Requests** are limited to 64 KiB, XML with document type declarations is refused, and each account gets at most
  60 requests a minute (the proxy also caps each address at 30 a second, with room for a site's PCs behind one NAT
  address). The first, credential-less request of each exchange is answered without the database. Failed
  authentications are logged at most 20 a minute per address and 120 a minute per tenant.
- Turning autoenrollment off makes `/cep` and `/ces` answer 404. Certificates already issued keep working until they
  expire or you revoke them.

## Troubleshooting

On the PC: **Event Viewer → Applications and Services Logs → Microsoft → Windows → CertificateServicesClient-
AutoEnrollment** and **CertificateServicesClient-CertEnroll**. In EasyEAP: **GPO autoenrollment → Request log**, one
line per request with who, from which PC, and why it was refused.

| Request log | Meaning | What to do |
|---|---|---|
| NTLM, not Kerberos | The PC couldn't get a ticket | Check the SPN (`setspn -Q HTTP/<name>`), that the URL uses the console's DNS name, and that the name isn't a CNAME |
| Keytab problem | The keytab can't open the ticket | The account's password changed (the script was run again, or the password was reset in AD): **Create it again…**, or upload the new keytab |
| Channel binding | The ticket isn't bound to this TLS connection | Something between the PC and EasyEAP ends TLS; or turn off the requirement |
| Not a computer in AD / Not a workstation | `NAME$` isn't a member computer | Domain controllers and trust accounts don't get computer certificates |
| Not in the group | The computer isn't in the computer group | Add it in AD; EasyEAP re-reads it within 6 hours, or at the next sync |
| User not synced / Account disabled | The user isn't a synced, enabled user | Check the directory sync's search base and filter |
| Template not allowed | The request names a template this account doesn't get | Computer templates for computers, user templates for users |
| Key refused | RSA under 2048, another curve, or a ROCA key | Update the TPM firmware (ROCA) |
| Too many today | The daily limit | Usually a PC re-enrolling in a loop: check its event log |
| CA expiring | The issuing CA expires before a certificate would be useful | Renew the issuing CA |

If Windows logs that it can't read EasyEAP's response (for example `0x80093100` or "the enrollment server response
is invalid"), try **Settings → Response format → Signed** and run `certutil -pulse` again, and tell us which worked.

The keytab **Test** or readiness says **no AES key, only rc4-hmac**: EasyEAP accepts AES tickets only (Windows is
retiring RC4), and the service account doesn't allow AES. Run the current service-account script again: on Windows it
sets **This account supports Kerberos AES 128/256 bit encryption**; on Samba it sets `msDS-SupportedEncryptionTypes`
to 24 before exporting (without it, Samba exports only the RC4 key for an SPN on a user account). Then upload the new
keytab. On a domain whose functional level was raised from 2003, also reset the account's password once, so that it
has AES keys at all.

Clock skew over 5 minutes between the PC and the domain controller breaks Kerberos before EasyEAP sees anything.

## Not in this version

Key attestation (the TPM's endorsement key chain); publishing certificates to AD; username/password or certificate
authentication for the enrollment services (PCs that aren't domain-joined use the setup file); several domains or
forests per tenant; EC keys from Windows.

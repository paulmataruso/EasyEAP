# Deploying EasyEAP

EasyEAP runs as one Docker Compose project (`easyeap`) on a Linux host. One deployment serves many tenants.

## Requirements

- Linux host with Docker Engine 24+ and Docker Compose v2, 2 vCPU, 4 GB RAM, 20 GB disk (more for long event retention).
- `openssl` on the host (the installer generates secrets with it).
- A DNS name for the console, e.g. `easyeap.msp.example`, and a trusted TLS certificate for it.
- Network reachability from every wireless controller to the RADIUS ports, and from the host to each customer's
  domain controllers on LDAPS (TCP 636), normally over the site-to-site VPN you already run.

## Network

| Port | Protocol | From | To | Purpose |
|---|---|---|---|---|
| 443 | TCP | Administrators, enrolling users | easyeap-proxy | Console, enrollment portal, API |
| 80 | TCP | Wi-Fi clients, controllers, anyone validating certificates | easyeap-proxy | CRL and OCSP (plain HTTP by design); everything else redirects to HTTPS |
| 1812 / 1813 | UDP | Wireless controllers | easyeap-radius | RADIUS authentication / accounting |
| 1820–1839 | UDP | Wireless controllers | easyeap-radius | Dedicated per-tenant port pairs (only when two tenants' controllers share addresses) |
| 3799 (1700 on Catalyst 9800) | UDP | easyeap-radius | Controllers | CoA Disconnect-Request (outbound) |
| 636 | TCP | easyeap-api, easyeap-worker | Customer domain controllers | LDAPS directory sync (outbound) |

RADIUS over UDP must not cross the internet unprotected: route it through a VPN. Restrict the published ports to
internal interfaces with `EASYEAP_HTTPS_BIND`, `EASYEAP_HTTP_BIND` and `EASYEAP_RADIUS_BIND` where possible, and
firewall 1812/1813 to your controllers' addresses.

## Install

```sh
git clone https://github.com/paulmataruso/EasyEAP.git /opt/easyeap
cd /opt/easyeap/deploy
sudo ./install.sh --hostname easyeap.msp.example --radius-address 10.20.0.15
```

`install.sh` is safe to re-run. It:

1. generates every secret once into `deploy/secrets/` (0700 directory). These are the database passwords, the
   RADIUS agent token, the session HMAC key, and the initial OpenBao seal key (copied into the PKI's own volume on
   first start; from then on the volume's copy is the one in use, and it travels inside every backup);
2. writes `deploy/.env` from `.env.example`;
3. creates a temporary self-signed TLS certificate if none exists;
4. builds the images and starts the stack.

On first start the API initialises OpenBao (static seal, recovery keys written to the API's secrets volume), creates
a policy-limited token for itself, revokes the OpenBao root token, runs database migrations and generates a one-time
setup token.

### Replace the TLS certificate

Put your certificate chain and key at `deploy/secrets/tls.crt` and `deploy/secrets/tls.key` (PEM), then run
`docker compose restart easyeap-proxy`.

### Settings (`deploy/.env`)

| Variable | Meaning |
|---|---|
| `EASYEAP_HOSTNAME` | Console and enrollment hostname. Enrollment links use it. |
| `EASYEAP_PKI_HOSTNAME` | Host in the CRL and OCSP URLs embedded in every certificate (port 80). Defaults to `EASYEAP_HOSTNAME`. It must stay stable for the life of the certificates. |
| `EASYEAP_RADIUS_ADDRESS` | The IP controllers use to reach RADIUS, shown in the controller guides and snippets. Loopback and unspecified addresses (`127.0.0.1`, `0.0.0.0`) are not shown to controllers; the console warns instead. |
| `EASYEAP_*_BIND`, `EASYEAP_HTTP_PORT`, `EASYEAP_HTTPS_PORT` | Published interfaces and ports. Certificates assume CRLs are on port 80. |
| `EASYEAP_RADIUS_NODE` | Agent identifier shown in System health. |
| `EASYEAP_LAB_MODE` | `true` enables insecure test options (keeping a root CA online, plain LDAP). Never in production. |

## First run

1. `install.sh` prints the one-time setup token when it finishes. To print it again:
   `docker compose exec easyeap-api easyeap setup-token`
2. Open `https://<EASYEAP_HOSTNAME>/`. The first-run page offers **Set up new** or **Restore a backup**; both need
   the setup token, so nobody else who reaches a fresh server first can claim it. There is no default account; the
   token stops working once an administrator exists.
   - **Set up new:** create the first Super Administrator.
   - **Restore a backup:** upload an `.easyeap` file and enter its passphrase. You get the server exactly as it was
     when the backup was made, and sign in with an administrator from it. Skip the rest of this list.
3. Turn on two-factor authentication from the Account page.
4. Create a tenant. The setup wizard then guides you through it:
   1. **Certificate authority ceremony.** Choose a passphrase of at least 12 characters, download the encrypted
      root key file and store it offline. EasyEAP destroys its online copy.
   2. **Directory.** Point it at the customer's domain controllers over LDAPS with a read-only service account,
      upload the domain's CA certificate, test, and sync.
   3. **RADIUS.** Set the server name devices will validate and the SSID, then add each controller. The shared
      secret is shown once, with a filled configuration snippet for Cisco Catalyst 9800, AireOS or UniFi.
   4. **Access policy.** Add VLANs and rules (for example, Deny Contractors; Allow IT Dept → VLAN 120; Allow
      Staff → VLAN 100), preview the impact on real users, and publish.
   5. **Activate.** RADIUS starts enforcing the tenant within about 15 seconds.
5. Issue a certificate for a user. They open the one-time link on the device they're enrolling and follow the steps.

## Upgrades

Make a backup first (System health → Backup and restore → Create backup, then Download). Then check out the
release you want from [Releases](https://github.com/paulmataruso/EasyEAP/releases), here 1.0.1, and rebuild:

```sh
cd /opt/easyeap && git fetch --tags && git checkout v1.0.1
cd deploy && sed -i 's/^EASYEAP_VERSION=.*/EASYEAP_VERSION=1.0.1/' .env
docker compose build && docker compose up -d
```

`EASYEAP_VERSION` only names the images; System health shows the version that's actually running.

Migrations run automatically when the API starts (under an advisory lock). RADIUS keeps authenticating from its
local snapshot while the API restarts.

## Backup and restore

Everything happens in the console: **System health → Backup and restore** (Super Administrator).

- **Create backup.** Choose a passphrase (EasyEAP can generate one) and confirm your password and two-factor code.
  The backup holds everything on the server: the database, every tenant's issuing CA keys (OpenBao storage and its
  seal key) and the API's secrets. It's one `.easyeap` file, encrypted with [age](https://age-encryption.org)
  (scrypt for the passphrase, authenticated streaming encryption for the contents). Download it; the server copy is
  deleted after 24 hours, and a backup counts for System health only once it's been downloaded. Making one pauses
  the CA service for a few seconds; RADIUS keeps authenticating.
- **Restore.** Upload the file, enter its passphrase and review what's in it (date, tenants, counts, warnings), then
  type `RESTORE` and confirm your password. The console shows each step. Everyone is signed out, and you sign in
  with an administrator account from the backup. If any step fails, the server is rolled back to how it was.
- **New server.** A fresh installation's first-run page restores the same file (see First run). Point DNS at the new
  server: certificates carry the CRL and OCSP addresses of `EASYEAP_PKI_HOSTNAME`.

**Protect the file and the passphrase like the CAs themselves.** Anyone with both can run your PKI. Store them
apart. Without the passphrase, the file can't be opened by anyone, including us.

**Installations set up with a preview build before 1.0.0** have no OpenBao recovery keys, so a backup can regain CA access only while
the token it carries is valid: restore it within 32 days of making it. The console shows each backup's restore-by
date. New installations keep recovery keys and have no such limit.

**Disaster-recovery caveat:** certificates issued after the backup was made aren't in it. RADIUS rejects them as
unknown (fail closed), so re-issue them.

**What isn't in a backup:** the console's TLS certificate (`deploy/secrets/tls.*`) and `.env`, which are host
configuration. Keep them with your host build.

### Scheduled backups from the host

For automation only, `deploy/backup.sh` and `deploy/restore.sh` drive the same engine and produce or restore the
same `.easyeap` files:

```sh
sudo ./backup.sh --passphrase-file /root/easyeap-backup.pass --out /srv/backups
sudo ./restore.sh --file /srv/backups/easyeap-backup-20261106T081523Z.easyeap --passphrase-file /root/easyeap-backup.pass --yes
```

Backups made by preview builds before 1.0.0 (`.tar.gz.enc` or `.tar.gz.gpg`) can't be restored. Make a new backup after upgrading.

## Operations

- **Health:** System health in the console; `docker compose ps`; `GET /api/health` (liveness).
- **Logs:** the console's **System log** (System health → System log) holds messages from the API, worker, RADIUS
  agent and FreeRADIUS warnings and errors for 30 days. `docker compose logs -f` still shows everything, including
  FreeRADIUS's full output. Secrets are redacted from logs.
- **Remote syslog:** System health → Remote syslog sends the audit trail, every authentication and the system log
  to up to four syslog servers or SIEMs, over TLS (recommended; paste the CA if a private one signed the server),
  TCP or UDP, as RFC 5424 or RFC 3164 with a text or JSON body. **Send test message** checks the connection before
  you save. TCP and TLS deliver each message at least once and resume where they stopped after an outage; UDP can
  lose messages silently. A new destination starts with what happens from then on. The worker does the sending, so
  it must be running; the panel shows each destination's state, errors and backlog.
- **Audit chain:** `docker compose exec easyeap-api easyeap verify-audit`.
- **RADIUS independence:** if the API, worker or database stops, RADIUS keeps authenticating from its local
  snapshot until the snapshot exceeds the tenant's maximum age (24 hours by default). After that it denies everyone
  in that tenant (fail closed). The dashboard shows the exact deadline.
- **Lab:** `./install.sh --lab` adds a Samba AD domain controller and an `eapol_test` Wi-Fi client;
  `tests/e2e/run.sh` exercises the whole path. Never on production hosts.

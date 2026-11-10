# Deploying EasyEAP

EasyEAP runs as one Docker Compose project (`easyeap`) on a Linux host. One deployment serves many tenants.

## Requirements

- Linux host with Docker Engine 24+ and Docker Compose v2, 2 vCPU, 4 GB RAM, 20 GB disk (more for long event retention).
- `openssl` on the host (the installer generates secrets with it).
- chrony as the host's time daemon, so the NTP servers can be set from the console (System → Time). Every EasyEAP
  container, the database and every log take their time from the host's clock. The `easyeap-time` container uses
  chronyd's control socket (`/run/chrony`) and writes `/etc/chrony/sources.d/easyeap.sources`; chrony.conf must
  read that directory (`sourcedir /etc/chrony/sources.d`, there by default on Ubuntu and Debian). On a host with
  another time daemon, EasyEAP only measures the clock against the servers set there.
- A DNS name for the console, e.g. `easyeap.msp.example`, and a trusted TLS certificate for it.
- Network reachability from every controller and switch (Wi-Fi, wired 802.1X, MAC authentication) to the RADIUS
  ports, and from the host to each customer's domain controllers on LDAPS (TCP 636), normally over the site-to-site
  VPN you already run.

## Network

| Port | Protocol | From | To | Purpose |
|---|---|---|---|---|
| 443 | TCP | Administrators, enrolling users, domain PCs, computers that renew by themselves | easyeap-proxy | Console, enrollment portal, API. Also Group Policy autoenrollment (`/cep`, `/ces`) and the Windows and Linux renewal tasks' daily check-ins: needed for as long as devices renew, not only at enrollment |
| 80 | TCP | Wi-Fi clients, controllers, anyone validating certificates | easyeap-proxy | CRL and OCSP (plain HTTP by design); everything else redirects to HTTPS |
| 1812 / 1813 | UDP | Controllers and switches | easyeap-radius | RADIUS authentication / accounting |
| 1820–1839 | UDP | Controllers and switches | easyeap-radius | Dedicated per-tenant port pairs (only when two tenants' devices share addresses) |
| 3799 (1700 on Catalyst 9800 and Cisco switches) | UDP | easyeap-radius | Controllers and switches | CoA and Disconnect-Request (outbound) |
| 636 | TCP | easyeap-api, easyeap-worker | Customer domain controllers | LDAPS directory sync (outbound) |
| 88 | TCP | easyeap-api | Customer domain controllers | Kerberos for [Group Policy autoenrollment](docs/autoenrollment.md): creating the service account and its **Test** (outbound; only with autoenrollment) |
| 3269 | TCP | easyeap-api | Customer global catalog servers | Global catalog over TLS, to check the whole forest for a duplicate SPN when it answers (outbound; optional, only with autoenrollment) |
| 49 | TCP | Switches and controllers (management addresses) | easyeap-radius | TACACS+ admin logins ([device administration](docs/device-administration.md)); published only when `EASYEAP_TACACS_BIND` is set to a reachable address |
| 636 (389 StartTLS) | TCP | easyeap-radius | Customer domain controllers | AD admin logins: the administrator's own bind (outbound; only with device administration and directory access) |
| 161 | UDP | easyeap-collector | Cisco switches (management addresses) | [Switch audit](docs/switch-audit.md) SNMP polling (outbound; only for switches with monitoring set up) |
| 5514 | UDP | Switches and controllers (management addresses) | easyeap-syslog | [Device syslog](docs/switch-audit.md#syslog-what-the-switch-says); published only when `EASYEAP_SYSLOG_BIND` is set to a reachable address |
| 514 | UDP | AireOS controllers, switches that send only to 514 | easyeap-syslog | The same, on the standard port: with `docker-compose.syslog514.yml` (below) |

RADIUS over UDP must not cross the internet unprotected: route it through a VPN. Restrict the published ports to
internal interfaces with `EASYEAP_HTTPS_BIND`, `EASYEAP_HTTP_BIND` and `EASYEAP_RADIUS_BIND` where possible, and
firewall 1812/1813 to your controllers' and switches' addresses. TACACS+ only obfuscates its packets: keep TCP 49 on
the management network.

Device syslog is matched to a switch or controller by its source address, so that address must reach `easyeap-syslog` unchanged.
Docker's default port publishing (iptables DNAT) keeps it; rootless Docker, the userland proxy (for example IPv6
traffic to an IPv4-only network, or `"userland-proxy": true` without iptables) and NAT between the switches and the
server replace it, and every message is then dropped as coming from an unknown address. Device syslog lists, for MSP
operators, the addresses messages came from when that happens.

AireOS controllers (and classic IOS before 15.2(1)E, the Nexus 5000 and 3548, NX-OS before 9.3(3)) send syslog to UDP
514 only. `install.sh` publishes 514 as well when nothing on the host listens on it, by adding
`COMPOSE_FILE=docker-compose.yml:docker-compose.syslog514.yml` to `.env`; add that line yourself on an existing install
(then `docker compose up -d`), or remove it if the host needs 514 for something else: both ports belong to the
`easyeap-syslog` container, so if another program takes UDP 514 first, the container doesn't start and 5514 stops too.

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
3. adds `COMPOSE_FILE=docker-compose.yml:docker-compose.syslog514.yml` to `.env` when nothing on the host listens on
   UDP 514 (see [Network](#network));
4. creates a temporary self-signed TLS certificate if none exists;
5. builds the images and starts the stack.

On first start the API initialises OpenBao (static seal, recovery keys written to the API's secrets volume), creates
a policy-limited token for itself, revokes the OpenBao root token, runs database migrations and generates a one-time
setup token.

### Replace the TLS certificate

Put your certificate chain and key at `deploy/secrets/tls.crt` and `deploy/secrets/tls.key` (PEM), then run
`docker compose restart easyeap-proxy easyeap-api`. The API reads the certificate too (Group Policy autoenrollment
checks channel binding against it, and Linux setup scripts and Windows setup files pin its public key). It's a
single-file mount, so the API sees a replaced file only after a restart.

A computer that doesn't trust the certificate (the temporary self-signed one, for example) falls back on its setup
script's or setup file's pin, renewals included. If such computers won't trust the new certificate either, make it with
the same key (`deploy/secrets/tls.key`), or their renewals fail.

### Settings (`deploy/.env`)

| Variable | Meaning |
|---|---|
| `EASYEAP_HOSTNAME` | Console and enrollment hostname. Enrollment links use it. |
| `EASYEAP_PKI_HOSTNAME` | Host in the CRL and OCSP URLs embedded in every certificate (port 80). Defaults to `EASYEAP_HOSTNAME`. It must stay stable for the life of the certificates. |
| `EASYEAP_RADIUS_ADDRESS` | The IP controllers use to reach RADIUS, shown in the controller guides and snippets. Loopback and unspecified addresses (`127.0.0.1`, `0.0.0.0`) are not shown to controllers; the console warns instead. |
| `EASYEAP_*_BIND`, `EASYEAP_HTTP_PORT`, `EASYEAP_HTTPS_PORT` | Published interfaces and ports. Certificates assume CRLs are on port 80. |
| `EASYEAP_TACACS_BIND`, `EASYEAP_TACACS_PORT` | Where TACACS+ for device administration is published (default `127.0.0.1:49`, which keeps it off the network). Set the bind to the address switches reach EasyEAP on to accept admin logins. |
| `EASYEAP_SYSLOG_BIND`, `EASYEAP_SYSLOG_PORT` | Where `easyeap-syslog` receives syslog from switches and controllers (default `127.0.0.1:5514`, which keeps it off the network). Set the bind to the address devices reach EasyEAP on to receive it; the configuration EasyEAP generates then sends there. |
| `COMPOSE_FILE` | `docker-compose.yml:docker-compose.syslog514.yml` also publishes UDP 514 for syslog (set by `install.sh` when 514 is free). |
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
release you want from [Releases](https://github.com/paulmataruso/EasyEAP/releases), here 1.1.0, and rebuild:

```sh
cd /opt/easyeap && git fetch --tags && git checkout v1.1.0
cd deploy && sed -i 's/^EASYEAP_VERSION=.*/EASYEAP_VERSION=1.1.0/' .env
docker compose build && docker compose up -d
```

`EASYEAP_VERSION` only names the images; System health shows the version that's actually running.

Migrations run automatically when the API starts (under an advisory lock). RADIUS keeps authenticating from its
local snapshot while the API restarts.

**Upgrading from 1.0.x to 1.1.0:**

- Migrations 0004 to 0015 run by themselves when the API starts.
- Migration 0014 turns automatic renewal on for every tenant, starting at 80 % of each certificate's life, and sets
  each template's renewal period to a fifth of its validity. The default templates go from 30 to 73 days (User
  Wi-Fi, 365 days), 45 to 146 (Device Wi-Fi, 730) and 30 to 80 (RADIUS Server, 397). A RADIUS server certificate
  already past 80 % of its life is replaced soon after the upgrade; **Put the previous certificate back** on the
  RADIUS page undoes it.
- Wired 802.1X changes nothing that already works: every registered controller is allowed both Wi-Fi and wired
  requests (so a switch registered as "Other" keeps working and keeps receiving VLANs), every VLAN is the same VLAN
  on switch ports, and enrollment packages stay Wi-Fi only until you turn on "Wired settings in enrollment
  packages". Restrict a controller to Wi-Fi in its Edit dialog if it should never send wired requests.
- Two new containers, `easyeap-collector` (switch audit SNMP polling) and `easyeap-syslog` (device syslog), start
  with `docker compose up -d`.
- An existing `.env` has no `EASYEAP_TACACS_BIND` or `EASYEAP_SYSLOG_BIND`, so TACACS+ and syslog stay on
  `127.0.0.1` until you set them (see [Settings](#settings-deployenv)). UDP 514 also needs the `COMPOSE_FILE` line
  (see [Network](#network)).
- There's no downgrade: a 1.0.x API can't start on a database migrated to 0015. To roll back, restore the backup you
  made before upgrading into a fresh 1.0.x installation (its first-run page).

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
unknown (fail closed), so re-issue them. That includes certificates that renewed by themselves since the backup
(Windows, Linux, Group Policy): the device may already have deleted the older certificate the backup knows.

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
- **Logs:** the console's **System log** (System health → System log) holds messages from the API, worker, switch
  collector, switch syslog receiver, RADIUS agent and FreeRADIUS warnings and errors for 30 days. `docker compose logs -f` still shows everything, including
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
- **Lab:** `./install.sh --lab` adds a Samba AD domain controller, an `eapol_test` Wi-Fi client and a pretend Cisco
  switch for the switch audit (`easyeap-lab-switch`);
  `tests/e2e/run.sh` exercises the whole path. Never on production hosts.

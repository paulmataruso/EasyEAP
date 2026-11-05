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
git clone <your EasyEAP repository> /opt/easyeap
cd /opt/easyeap/deploy
sudo ./install.sh --hostname easyeap.msp.example --radius-address 10.20.0.15
```

`install.sh` is safe to re-run. It:

1. generates every secret once into `deploy/secrets/` (0700 directory). These are the database passwords, the
   RADIUS agent token, the session HMAC key, and the OpenBao unseal key;
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

1. Print the one-time setup token on the host:
   `docker compose exec easyeap-api easyeap setup-token`
2. Open `https://<EASYEAP_HOSTNAME>/` and create the first Super Administrator with that token. There is no
   default account; the token stops working once the account exists.
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

```sh
cd /opt/easyeap && git pull
cd deploy && sudo ./backup.sh --passphrase-file /root/easyeap-backup.pass
docker compose build && docker compose up -d
```

Migrations run automatically when the API starts (under an advisory lock). RADIUS keeps authenticating from its
local snapshot while the API restarts.

## Backup and restore

`backup.sh` writes an **encrypted** archive of the database, the OpenBao storage, the API secrets volume,
`deploy/secrets` and `.env`. It pauses the PKI container for a few seconds to take a consistent copy; RADIUS keeps
working throughout.

```sh
sudo ./backup.sh --passphrase-file /root/easyeap-backup.pass --out /srv/backups
sudo ./backup.sh --gpg-recipient backup@msp.example --out /srv/backups
```

The archive contains the OpenBao unseal key, so protect it like the CAs themselves. Schedule it (cron or a systemd
timer) and copy it off the host.

```sh
sudo ./restore.sh --file /srv/backups/easyeap-20261105T104200Z.tar.gz.enc --passphrase-file /root/easyeap-backup.pass --yes
```

`restore.sh` replaces all current data, restarts the stack and verifies the audit chain. **Disaster-recovery
caveat:** certificates issued after the backup are not in the restored database. RADIUS rejects them as unknown
(fail closed), so re-issue them to their users.

## Operations

- **Health:** System health in the console; `docker compose ps`; `GET /api/health` (liveness).
- **Logs:** `docker compose logs -f easyeap-api easyeap-worker easyeap-radius`. Secrets are redacted from logs.
- **Audit chain:** `docker compose exec easyeap-api easyeap verify-audit`.
- **RADIUS independence:** if the API, worker or database stops, RADIUS keeps authenticating from its local
  snapshot until the snapshot exceeds the tenant's maximum age (24 hours by default). After that it denies everyone
  in that tenant (fail closed). The dashboard shows the exact deadline.
- **Lab:** `./install.sh --lab` adds a Samba AD domain controller and an `eapol_test` Wi-Fi client;
  `tests/e2e/run.sh` exercises the whole path. Never on production hosts.

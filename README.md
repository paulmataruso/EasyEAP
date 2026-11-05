# EasyEAP

**Enterprise Wi-Fi Authentication, Simplified.**

EasyEAP gives MSPs and IT teams certificate-based (EAP-TLS) Wi-Fi without running a full network access control
suite. One deployment serves many customer organisations ("tenants"). Each tenant gets:

- **Its own PKI.** An offline Root CA from a one-time ceremony, and an Issuing CA held in OpenBao that never leaves it.
  CRL and OCSP are published automatically.
- **Active Directory authorization.** Read-only sync over LDAPS, including nested groups and account state
  (disabled, locked, deleted).
- **An access policy with dynamic VLANs.** "Deny Contractors; IT Dept → VLAN 120; Staff → VLAN 100". Deny always
  wins. Changes are previewed against real users before they are published.
- **FreeRADIUS** that keeps authenticating from a local snapshot when the console, API or database is down, and
  denies everyone once that snapshot is too old (fail closed).
- **Per-device enrollment** for Windows, macOS, iOS/iPadOS, Android and Linux. The device generates its own key by
  default; server-generated keys are an opt-in for a Tenant Administrator.
- **Monitoring in plain language.** Every decision shows why: "Member of IT Dept via Network Team → rule 2 Allow →
  VLAN 120", or "Certificate from an untrusted authority: re-enroll the device".
- **RBAC, a hash-chained audit trail, encrypted backups, and a setup wizard.**

## Quick start

On a Linux host with Docker Engine 24+ and Compose v2:

```sh
git clone <your EasyEAP repository> /opt/easyeap
cd /opt/easyeap/deploy
sudo ./install.sh --hostname easyeap.msp.example --radius-address 10.20.0.15
docker compose exec easyeap-api easyeap setup-token
```

Open `https://easyeap.msp.example/`, create the first administrator with the setup token, and create a tenant. The
setup wizard takes you through the CA ceremony, the directory, RADIUS and the access policy. There is no default
account. [DEPLOYMENT.md](DEPLOYMENT.md) covers ports, settings, upgrades, backup and restore.

To try it without a customer network, `./install.sh --lab` adds a Samba AD domain controller and a simulated Wi-Fi
client (`eapol_test`). `tests/e2e/run.sh` then builds a tenant and authenticates through real EAP-TLS.

## The console

| Area | What you do there |
|---|---|
| **Tenants** (MSP) | Every customer's posture at a glance: enforceable or not, what needs action, RADIUS and directory freshness |
| **Dashboard** | The tenant's needs-action queue, enforcement status and fail-closed deadline, accept/reject trends |
| **Users** | Directory users and whether each can connect now; issue a certificate; see the decision for any user |
| **Certificates** | Every device certificate, its remaining validity, revocation (with optional CoA disconnect) |
| **Authentication log** | Each RADIUS decision with its reason, rule, VLAN and controller |
| **Access policy** | VLANs and rules; draft, preview the impact on real users, publish; test a user |
| **RADIUS** | Server certificate and name, SSID, controllers and shared secrets, filled controller guides |
| **Directory** | LDAPS connection, sync status, groups |
| **Certificate authority** | CA ceremony, CA status, templates, CRL |
| **Audit** | Every administrative change, with chain verification |

Press `/` to search the tenant, or ⌘K / Ctrl+K for the command palette ("issue jordan", "revoke…", "rotate secret…").

## Documentation

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Services, multi-tenancy, PKI, enrollment, RADIUS flow, policy precedence, data model |
| [SECURITY.md](SECURITY.md) | Threat model, key custody, controls, RBAC matrix, what revocation means in practice |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Requirements, network, install, first run, upgrades, backup and restore, operations |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Repository layout, dev stack, tests, conventions |
| [docs/controllers/](docs/controllers/README.md) | Cisco Catalyst 9800, Cisco AireOS and UniFi configuration |
| [docs/enrollment.md](docs/enrollment.md) | Issuing certificates and what users do on each platform |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Every failure reason and how to fix it |
| [DESIGN.md](DESIGN.md) | The console's design system |
| [CHANGELOG.md](CHANGELOG.md) · [PROGRESS.md](PROGRESS.md) | What changed; what's done and what isn't |

## Security in one paragraph

EasyEAP has no default account and no custom cryptography: it uses OpenBao for PKI and envelope encryption,
pyca/cryptography, WebCrypto, PKI.js and argon2-cffi. The Root CA key is exported once, encrypted, and never stored
online. Issuing CA keys never leave OpenBao. Shared secrets, bind passwords and escrowed keys are stored only as
per-tenant Transit ciphertext, and shared secrets are shown once. PostgreSQL row-level security isolates tenants.
Every failure path denies access. Revocation stops new connections within about 15 seconds; connected devices are
removed by CoA, or at their session timeout. See [SECURITY.md](SECURITY.md).

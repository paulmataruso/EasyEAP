# Developing EasyEAP

## Layout

| Path | What |
|---|---|
| `backend/` | FastAPI API and worker (`app/`), Alembic migrations, pytest suite (`tests/`) |
| `services/radius/` | FreeRADIUS image and the radius-agent (`agent/easyeap_agent.py`, config renderer `agent/render.py`, the TACACS+ service `agent/tacacs.py`) |
| `services/lab-client/` | `eapol_test` image used by the lab and the end-to-end test |
| `frontend/` | React console (`src/app/`), enrollment portal (`src/enroll/`), shared domain code (`src/domain/`), design prototypes (`src/concepts/`, `src/prototype/`, `src/compare/`) |
| `deploy/` | Compose files, installer, backup and restore, proxy, OpenBao and lab configuration |
| `tests/e2e/` | End-to-end EAP-TLS test against the full stack |
| `tests/radius/` | FreeRADIUS integration test: the rendered configuration and agent store, real EAP-TLS, no API |
| `design/` | Design concepts, critiques, audits and the chosen direction (`design/CONCEPTS.md`); the logo (`design/brand/`) |
| `docs/` | Controller guides, enrollment, troubleshooting, plans and the README screenshots |
| `.github/` | CI workflow, Dependabot, issue and pull request templates |

## Run the stack for development

```sh
cd deploy
./install.sh --lab --no-start                     # secrets + .env once (lab adds Samba AD and a Wi-Fi client)
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile lab up -d --build
docker compose exec easyeap-api easyeap setup-token
cd ../frontend && pnpm install && EASYEAP_API=http://127.0.0.1:8000 pnpm dev
```

The dev override (`deploy/docker-compose.dev.yml`) publishes the API on `127.0.0.1:8000`, mounts `backend/` with
auto-reload, installs the test dependencies and allows the session cookie over plain `http://localhost`. Open
`http://localhost:5173/` for the console and `http://localhost:5173/enroll.html#/t/<token>` for the portal. Create the
first administrator with the setup token.

The lab domain is `LAB.EASYEAP.TEST`. Its domain controller listens on `dc1.lab.easyeap.test:636`; the bind account
and test users are described in `deploy/lab/README.md`. Read the domain's CA certificate with
`docker compose exec easyeap-lab-ad cat /var/lib/samba/private/tls/ca.pem` and paste it into Directory settings.

## Tests

| Suite | Command | Needs |
|---|---|---|
| Backend unit tests | `docker compose exec easyeap-api python -m pytest` | dev override |
| Backend integration (RLS, policy drafts) | `docker compose exec -e EASYEAP_TEST_INTEGRATION=1 easyeap-api python -m pytest` | dev override (real PostgreSQL) |
| RADIUS config renderer | `docker run --rm -v "$PWD":/src -w /src/backend python:3.13-slim sh -c "pip -q install pytest && python -m pytest tests/test_radius_render.py"` (from the repo root) | — |
| Frontend unit tests | `cd frontend && pnpm test` | — |
| Type check and lint | `cd frontend && pnpm typecheck && pnpm lint`; `docker compose exec easyeap-api ruff check --no-cache app tests` | — |
| RADIUS integration (wired and Wi-Fi detection, monitor mode, MAC authentication, TACACS+, version skew) | `tests/radius/run.sh` | Docker; the `v1.0.1` tag |
| End-to-end EAP-TLS | `tests/e2e/run.sh` | lab profile |
| Console smoke test (browser) | `node tests/e2e/console-smoke.mjs https://127.0.0.1` | running stack, Playwright Chromium |

GitHub Actions (`.github/workflows/ci.yml`) runs on every push to `main` and every pull request:

- the backend's `ruff` lint and unit tests, plus a compile check of the RADIUS agent;
- the frontend's type check, lint, unit tests and production build;
- the Compose file validation and the API, RADIUS and proxy image builds;
- `tests/radius/run.sh`: real FreeRADIUS with the rendered configuration and real EAP-TLS, in seconds.

The integration tests, the end-to-end EAP-TLS test and the browser smoke test need the full stack, so run them
locally before a release.

`tests/e2e/run.sh` rebuilds an `e2e-lab` tenant from the lab domain controller:

1. PKI ceremony with an offline root;
2. directory sync over LDAPS;
3. VLANs and rules;
4. a controller;
5. certificates issued from keys generated on the client.

Then it authenticates with real EAP-TLS through FreeRADIUS. It checks:

- the nested-group VLAN, the staff VLAN, the deny rule and a rogue self-signed client;
- revocation, and an AD account disabled after issuance;
- that RADIUS keeps authenticating with the API and worker stopped;
- wired 802.1X, through two more lab-client containers registered as switches inside the controller's subnet:
  monitor mode (accepted, no VLAN sent; the would-be VLAN logged), readiness and the pasted session list, the
  generated configuration (no shared secret in it), Enforce (confirmation required, then the mapped VLAN on ports,
  Wi-Fi unchanged), "keep the port's VLAN", wrong-network refusals, the wrong-secret diagnosis, wired
  enrollment packages and the Windows wired kit;
- MAC authentication: the allow list, "Seen, not allowed", the Enforce gate, group VLANs, block, Cisco MAB and UniFi
  MAC-Based;
- device administration: TACACS+ logins from a lab container acting as a switch, with an EasyEAP account and with AD
  users through nested group mappings (privilege 15 and 1), refusals with their reasons, the Admin log with a masked
  command, key rotation with grace, a break-glass name, and admin logins turned off;
- the audit chain.

`E2E_WIRED=0` skips the wired steps (for a build from before wired 802.1X), and `E2E_ADMIN=0` the device-administration
steps. `E2E_DEPLOY_DIR`, `COMPOSE_PROJECT_NAME`
and `COMPOSE_FILE` point it at another deployment, for example one installed from a previous release to test an
upgrade.

Two pieces of code exist twice and are tested to stay identical: the command masking in `backend/app/admin/mask.py`
and `services/radius/agent/tacmask.py` (the agent has no access to the backend's code), and the reason codes the TACACS+
service logs and their labels in `frontend/src/app/api/deviceAdmin.ts`.

The policy engine is implemented twice: `backend/app/policy/engine.py` is authoritative, and
`frontend/src/domain/policy.ts` serves previews in the prototypes. Both are tested against the same fixtures in
`backend/tests/fixtures/policy_cases.json`. Change both together.

## Conventions

- **Security rules are product rules.** Read SECURITY.md before touching keys, secrets, sessions or RADIUS.
- **Tenant scope.** Every tenant endpoint depends on `require("<permission>")`, which sets the row-level-security
  scope for the transaction. Never query another tenant's rows; platform-wide reads use `set_platform()`.
- **Audit.** Every change an administrator makes calls `audit.record(...)` with a target and a non-secret detail.
- **Policy changes** go through `recompute_tenant()` + `bump()`, so RADIUS receives a new snapshot.
- **Frontend.**
  - The console uses only real API data. Response types live next to their hooks in `src/app/api/`. Link with
    `paths.*` from `src/app/routes.ts`.
  - Format dates only with `src/app/lib/format.ts`.
  - Reuse the primitives in `src/app/ui/`. `EDialog` returns focus to its opener; one-time secrets use
    `OneTimeSecret` with `blockDismiss`.
  - Design decisions are recorded in `design/CONCEPTS.md` and `DESIGN.md`.
- **Prototypes.** `pnpm dev`, then open `/design.html#/compare` to see the six design concepts on synthetic data.
  `pnpm build` never includes them.
- **Commits.** Logical, imperative subject lines. Keep generated secrets, `deploy/.env` and `deploy/lab/certs/` out of git
  (they are ignored).

# Third-party software

EasyEAP's own code is licensed under the [Business Source License 1.1](LICENSE). It runs alongside, and builds on,
the open-source software below. Each component keeps its own license, and nothing in EasyEAP's license changes your
rights under those licenses.

## Services in the Compose stack

EasyEAP runs these as separate programs in their own containers. The images come from each project's official
distribution, or are built from it, and EasyEAP doesn't modify their source.

| Component | Used for | License |
|---|---|---|
| [FreeRADIUS](https://freeradius.org) 3.2 (`freeradius/freeradius-server`) | RADIUS and EAP-TLS | GPL-2.0 |
| [OpenBao](https://openbao.org) 2.4 (`openbao/openbao`) | Issuing CAs, Transit encryption | MPL-2.0 |
| [PostgreSQL](https://www.postgresql.org) 18 (`postgres`) | Database | PostgreSQL License |
| [nginx](https://nginx.org) (`nginxinc/nginx-unprivileged`) | TLS proxy, console, CRL and OCSP | BSD-2-Clause |
| [Python](https://www.python.org) 3.13 (`python:3.13-slim`) | API, worker, RADIUS agent | PSF-2.0 |
| [tini](https://github.com/krallin/tini) | Init process in the API and RADIUS images | MIT |
| [Samba](https://www.samba.org) (lab profile only) | Test Active Directory domain controller | GPL-3.0 |
| [wpa_supplicant `eapol_test`](https://w1.fi) (lab profile only) | Simulated Wi-Fi client | BSD-3-Clause |

The base images also contain Debian, Ubuntu or Alpine packages under their own licenses. Their source is available
from those distributions.

## Python packages (API and worker)

| Package | License |
|---|---|
| FastAPI | MIT |
| Uvicorn | BSD-3-Clause |
| SQLAlchemy | MIT |
| Alembic | MIT |
| psycopg 3 | LGPL-3.0 |
| Pydantic, pydantic-settings | MIT |
| email-validator | Unlicense |
| argon2-cffi | MIT |
| PyOTP | MIT |
| HTTPX | BSD-3-Clause |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| ldap3 | LGPL-3.0 |
| python-multipart | Apache-2.0 |
| pyrage | MIT |

psycopg and ldap3 are used unmodified, as installed packages. You can replace them with any compatible version.

## JavaScript packages (console and enrollment portal)

| Package | License |
|---|---|
| React, React DOM | MIT |
| React Router | MIT |
| TanStack Query | MIT |
| Radix UI | MIT |
| React Hook Form, @hookform/resolvers | MIT |
| Zod | MIT |
| PKI.js, ASN1.js | BSD-3-Clause |
| d3-array, d3-scale, d3-shape | ISC |
| Lucide | ISC |
| clsx | MIT |
| tailwind-merge | MIT |
| Tailwind CSS (build only) | MIT |
| Vite (build only) | MIT |

## Fonts

The console and enrollment portal bundle Hanken Grotesk and Red Hat Mono through Fontsource. The design-concept
prototypes (`frontend/src/concepts/`) also use Martian Mono, Archivo, Overpass, Overpass Mono, Plus Jakarta Sans,
Barlow, Barlow Condensed, Fira Sans, Fira Code and JetBrains Mono. All of these fonts are under the SIL Open Font
License 1.1.

This list covers direct dependencies. `backend/pyproject.toml` and `frontend/pnpm-lock.yaml` give the full
dependency trees.

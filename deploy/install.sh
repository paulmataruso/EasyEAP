#!/usr/bin/env bash
# EasyEAP installer: generates secrets, writes .env, builds and starts the stack.
#
#   ./install.sh --hostname easyeap.corp.example --radius-address 10.20.0.15
#   ./install.sh --lab                       # adds the Samba AD + simulated Wi-Fi client lab
#
# Safe to re-run: existing secrets and settings are never overwritten.
set -euo pipefail
cd "$(dirname "$0")"

HOSTNAME_ARG="" RADIUS_ADDR="" LAB=0 START=1
usage() { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --hostname) HOSTNAME_ARG="$2"; shift 2 ;;
    --radius-address) RADIUS_ADDR="$2"; shift 2 ;;
    --lab) LAB=1; shift ;;
    --no-start) START=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "Docker is required (https://docs.docker.com/engine/install/)."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose …)."
command -v openssl >/dev/null || die "openssl is required to generate secrets."

# ── Secrets ─────────────────────────────────────────────────────────────────
# Compose file secrets are bind-mounted, so the files must be readable by the container users
# (postgres, openbao, uid 10001, freerad). The directory is 0700, so only root/the installer can reach them on the host.
umask 077
mkdir -p secrets && chmod 0700 secrets
gen() { # gen <name> <command…>   — create once, never overwrite
  local f="secrets/$1"; shift
  if [ ! -s "$f" ]; then "$@" > "$f"; say "Generated secrets/$(basename "$f")"; fi
  chmod 0644 "$f"
}
hex() { openssl rand -hex "$1" | tr -d '\n'; }
gen db_owner_password hex 24          # hex only: safe inside connection URLs and SQL
gen db_app_password hex 24
gen agent_token hex 32
gen session_secret hex 32
gen openbao_unseal_key openssl rand 32
gen lab_ad_password sh -c 'printf "Lab-%s-Aa1!" "$(openssl rand -hex 8)"'

# ── Settings ────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  host="${HOSTNAME_ARG:-$(hostname -f 2>/dev/null || hostname)}"
  cp .env.example .env
  sed -i.bak "s|^EASYEAP_HOSTNAME=.*|EASYEAP_HOSTNAME=${host}|" .env
  [ -n "$RADIUS_ADDR" ] && sed -i.bak "s|^EASYEAP_RADIUS_ADDRESS=.*|EASYEAP_RADIUS_ADDRESS=${RADIUS_ADDR}|" .env
  [ "$LAB" = 1 ] && sed -i.bak "s|^EASYEAP_LAB_MODE=.*|EASYEAP_LAB_MODE=true|" .env
  rm -f .env.bak
  chmod 0600 .env
  say "Wrote .env (hostname ${host})"
else
  say "Keeping existing .env"
fi
host="$(grep '^EASYEAP_HOSTNAME=' .env | cut -d= -f2)"

# ── TLS certificate for the console (replace with your own; see DEPLOYMENT.md) ─
if [ ! -s secrets/tls.crt ] || [ ! -s secrets/tls.key ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 397 \
    -subj "/CN=${host}" -addext "subjectAltName=DNS:${host}" \
    -addext "extendedKeyUsage=serverAuth" -keyout secrets/tls.key -out secrets/tls.crt 2>/dev/null
  chmod 0644 secrets/tls.crt secrets/tls.key
  say "Created a temporary self-signed TLS certificate for ${host}. Replace secrets/tls.crt and secrets/tls.key with a trusted one."
fi

[ "$START" = 1 ] || { say "Secrets and settings are ready. Start with: docker compose up -d"; exit 0; }

PROFILE=()
[ "$LAB" = 1 ] && PROFILE=(--profile lab)
say "Building images (first run takes a few minutes)"
docker compose "${PROFILE[@]}" build
say "Starting EasyEAP"
docker compose "${PROFILE[@]}" up -d

say "Waiting for the API to become healthy"
for _ in $(seq 1 90); do
  state="$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q easyeap-api)" 2>/dev/null || true)"
  [ "$state" = healthy ] && break
  sleep 2
done
[ "${state:-}" = healthy ] || die "The API did not become healthy. Check: docker compose logs easyeap-api"

echo
say "EasyEAP is running."
echo "    Console:      https://${host}/"
if token="$(docker compose exec -T easyeap-api easyeap setup-token 2>/dev/null)"; then
  echo "    Setup token:  ${token}"
  echo "    Open the console and paste the setup token to create the first administrator."
  echo "    (It works once. Print it again with: docker compose exec easyeap-api easyeap setup-token)"
fi
echo
echo "    Back up now and after every change:  ./backup.sh --passphrase-file /secure/path"
echo "    secrets/openbao_unseal_key protects every CA key. Without it, a restore is impossible."

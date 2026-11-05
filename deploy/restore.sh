#!/usr/bin/env bash
# EasyEAP restore from an encrypted backup made by backup.sh. Replaces ALL current data.
#
#   ./restore.sh --file easyeap-20261105T104200Z.tar.gz.enc --passphrase-file /root/easyeap-backup.pass --yes
#   ./restore.sh --file easyeap-20261105T104200Z.tar.gz.gpg --yes          (decrypts with your GPG key)
#
# Restores the database, PKI storage, secrets and .env, restarts the stack and verifies the audit chain.
# Certificates issued after the backup are not in the restored CA: revoke or re-issue them (see DEPLOYMENT.md).
set -euo pipefail
cd "$(dirname "$0")"

FILE="" PASSFILE="" YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="$2"; shift 2 ;;
    --passphrase-file) PASSFILE="$2"; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
[ -s "$FILE" ] || die "Backup file not found: $FILE"
[ "$YES" = 1 ] || die "Restoring replaces every tenant, certificate, CA key and setting on this host. Re-run with --yes to confirm."

umask 077
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
say "Decrypting and checking the backup"
case "$FILE" in
  *.gpg) gpg --batch --decrypt "$FILE" | tar -C "$WORK" -xzf - ;;
  *.enc) [ -s "$PASSFILE" ] || die "--passphrase-file is required for .enc backups."
         openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass "file:$PASSFILE" -in "$FILE" | tar -C "$WORK" -xzf - ;;
  *) die "Unrecognised backup type (expected .tar.gz.enc or .tar.gz.gpg)." ;;
esac
B="$WORK/easyeap-backup"
[ -f "$B/SHA256SUMS" ] || die "Not an EasyEAP backup."
( cd "$B" && sha256sum -c --quiet SHA256SUMS ) || die "Checksum mismatch: the backup is damaged."
sed 's/^/    /' "$B/MANIFEST"

say "Stopping EasyEAP"
docker compose --profile lab down >/dev/null 2>&1 || true

say "Restoring deployment secrets and .env"
tar -C . -xf "$B/deploy-secrets.tar"
chmod 0700 secrets; find secrets -type f -exec chmod 0644 {} +; chmod 0600 .env

# Create the volumes (if this is a new host) without starting anything that writes to them.
docker compose create easyeap-db easyeap-pki easyeap-api >/dev/null
volume() { docker volume ls -q --filter "label=com.docker.compose.project=easyeap" --filter "label=com.docker.compose.volume=$1" | head -1; }
PKI_VOL="$(volume easyeap-pki)"; SEC_VOL="$(volume easyeap-secrets)"
[ -n "$PKI_VOL" ] && [ -n "$SEC_VOL" ] || die "Could not create the EasyEAP volumes."

say "Restoring PKI storage and the API secrets volume"
docker run --rm -i -v "$PKI_VOL":/data alpine:3.22 sh -c 'find /data -mindepth 1 -delete && tar -C /data -xpf -' < "$B/pki.tar"
docker run --rm -i -v "$SEC_VOL":/data alpine:3.22 sh -c 'find /data -mindepth 1 -delete && tar -C /data -xpf -' < "$B/api-secrets.tar"

say "Restoring the database"
docker compose up -d easyeap-db >/dev/null
for _ in $(seq 1 60); do docker compose exec -T easyeap-db pg_isready -U easyeap -d postgres >/dev/null 2>&1 && break; sleep 2; done
docker compose exec -T easyeap-db psql -v ON_ERROR_STOP=1 -U easyeap -d postgres \
  -v app_pw="$(cat secrets/db_app_password)" -v owner_pw="$(cat secrets/db_owner_password)" >/dev/null <<'SQL'
DROP DATABASE IF EXISTS easyeap WITH (FORCE);
CREATE DATABASE easyeap OWNER easyeap;
SELECT 'CREATE ROLE easyeap_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyeap_app') \gexec
SELECT format('ALTER ROLE easyeap_app PASSWORD %L', :'app_pw') \gexec
SELECT format('ALTER ROLE easyeap PASSWORD %L', :'owner_pw') \gexec
SQL
docker compose exec -T easyeap-db pg_restore -U easyeap -d easyeap --exit-on-error < "$B/database.dump"

say "Starting EasyEAP"
PROFILE=()
grep -q '^EASYEAP_LAB_MODE=true' .env && PROFILE=(--profile lab)
docker compose "${PROFILE[@]}" up -d >/dev/null
for _ in $(seq 1 90); do
  state="$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q easyeap-api)" 2>/dev/null || true)"
  [ "$state" = healthy ] && break; sleep 2
done
[ "${state:-}" = healthy ] || die "The API did not become healthy after restore. Check: docker compose logs easyeap-api"
docker compose exec -T easyeap-api easyeap verify-audit
docker compose exec -T easyeap-api easyeap recompute >/dev/null
say "Restore complete. RADIUS picks up the restored configuration within a minute."

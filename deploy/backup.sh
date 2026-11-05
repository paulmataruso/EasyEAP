#!/usr/bin/env bash
# EasyEAP backup: database, PKI storage (CA keys, sealed), the API secrets volume, deploy secrets and .env.
#
#   ./backup.sh --passphrase-file /root/easyeap-backup.pass [--out /srv/backups]
#   ./backup.sh --gpg-recipient backup@corp.example        [--out /srv/backups]
#
# The archive is always encrypted (AES-256 via openssl with PBKDF2, or GPG). It contains the OpenBao unseal
# key, so it must be protected like the CA itself. The PKI service is paused for a few seconds to take a
# consistent copy; RADIUS keeps authenticating from its local state the whole time.
set -euo pipefail
cd "$(dirname "$0")"

PASSFILE="" RECIPIENT="" OUT="./backups"
while [ $# -gt 0 ]; do
  case "$1" in
    --passphrase-file) PASSFILE="$2"; shift 2 ;;
    --gpg-recipient) RECIPIENT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
[ -n "$PASSFILE$RECIPIENT" ] || die "Choose --passphrase-file or --gpg-recipient. Unencrypted backups are not supported."
[ -z "$PASSFILE" ] || [ -s "$PASSFILE" ] || die "Passphrase file $PASSFILE is missing or empty."
[ -z "$RECIPIENT" ] || command -v gpg >/dev/null || die "gpg is not installed."
[ -f .env ] && [ -d secrets ] || die "Run from an installed deployment (missing .env or secrets/)."

volume() { docker volume ls -q --filter "label=com.docker.compose.project=easyeap" --filter "label=com.docker.compose.volume=$1" | head -1; }
PKI_VOL="$(volume easyeap-pki)"; SEC_VOL="$(volume easyeap-secrets)"
[ -n "$PKI_VOL" ] && [ -n "$SEC_VOL" ] || die "EasyEAP volumes not found. Is the stack installed?"

umask 077
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/easyeap-backup"
B="$WORK/easyeap-backup"

say "Dumping the database"
docker compose exec -T easyeap-db pg_dump -U easyeap -d easyeap -Fc > "$B/database.dump"

say "Copying PKI storage (pausing the PKI service briefly)"
docker compose stop easyeap-pki >/dev/null
trap 'docker compose start easyeap-pki >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
docker run --rm -v "$PKI_VOL":/data:ro alpine:3.22 tar -C /data -cf - . > "$B/pki.tar"
docker compose start easyeap-pki >/dev/null
trap 'rm -rf "$WORK"' EXIT

say "Copying the API secrets volume and deployment secrets"
docker run --rm -v "$SEC_VOL":/data:ro alpine:3.22 tar -C /data -cf - . > "$B/api-secrets.tar"
tar -cf "$B/deploy-secrets.tar" secrets .env

( cd "$B" && sha256sum database.dump pki.tar api-secrets.tar deploy-secrets.tar > SHA256SUMS )
cat > "$B/MANIFEST" <<MAN
EasyEAP backup
created: ${STAMP}
version: $(grep '^EASYEAP_VERSION=' .env | cut -d= -f2)
hostname: $(grep '^EASYEAP_HOSTNAME=' .env | cut -d= -f2)
MAN

mkdir -p "$OUT"
if [ -n "$RECIPIENT" ]; then
  FILE="$OUT/easyeap-${STAMP}.tar.gz.gpg"
  tar -C "$WORK" -czf - easyeap-backup | gpg --batch --yes --encrypt --recipient "$RECIPIENT" --output "$FILE"
else
  FILE="$OUT/easyeap-${STAMP}.tar.gz.enc"
  tar -C "$WORK" -czf - easyeap-backup | openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass "file:$PASSFILE" -out "$FILE"
fi
chmod 0600 "$FILE"
SIZE="$(wc -c < "$FILE" | tr -d ' ')"
docker compose exec -T easyeap-api easyeap record-backup --file "$(basename "$FILE")" --size "$SIZE" --encrypted >/dev/null || \
  echo "warning: the backup was written but could not be recorded in EasyEAP (is the API running?)" >&2
say "Backup written: $FILE ($SIZE bytes)"
echo "    Copy it off this host. Test restores regularly: ./restore.sh --help"

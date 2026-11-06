#!/usr/bin/env bash
# EasyEAP backup from the host, for scheduling with cron or a systemd timer. You don't need it otherwise: the
# console makes the same backup (System health → Backup and restore → Create backup).
#
#   ./backup.sh --passphrase-file /root/easyeap-backup.pass [--out /srv/backups]
#
# Writes one encrypted .easyeap file, the same format as the console's, restorable from the console, from a new
# installation's first-run page, or with ./restore.sh. It holds every CA key, encrypted with the passphrase: protect
# the file and the passphrase like the CAs themselves. RADIUS keeps authenticating while it runs.
set -euo pipefail
cd "$(dirname "$0")"

PASSFILE="" OUT="./backups"
while [ $# -gt 0 ]; do
  case "$1" in
    --passphrase-file) PASSFILE="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[ -n "$PASSFILE" ] || die "--passphrase-file is required. Backups are always encrypted."
[ -s "$PASSFILE" ] || die "Passphrase file $PASSFILE is missing or empty."
[ -f .env ] || die "Run from an installed deployment (missing .env)."

umask 077
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(sed -n 's/^EASYEAP_HOSTNAME=//p' .env | tr -d '"' | head -1)"
FILE="$OUT/easyeap-backup-${HOST:+$HOST-}$STAMP.easyeap"
PART="$FILE.partial"
trap 'rm -f "$PART"' EXIT
# The passphrase goes in on standard input and the backup comes back on standard output: neither touches the
# container's disk outside its own encrypted backup store, which the CLI clears afterwards.
docker compose exec -T easyeap-api easyeap backup create --passphrase-file - --stdout < "$PASSFILE" > "$PART"
[ -s "$PART" ] || die "The backup came back empty."
mv "$PART" "$FILE"
trap - EXIT
printf 'Wrote %s\n' "$FILE"

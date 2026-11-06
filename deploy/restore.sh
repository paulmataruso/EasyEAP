#!/usr/bin/env bash
# EasyEAP restore from the host. You don't need it otherwise: the console restores the same file (System health →
# Backup and restore → Restore), and so does a new installation's first-run page.
#
#   ./restore.sh --file easyeap-backup-20261106T081523Z.easyeap --passphrase-file /root/easyeap-backup.pass --yes
#
# Replaces every tenant, CA, administrator and setting on this server with the backup's, and signs everyone out.
# Certificates issued after the backup was made aren't in it: re-issue them. If anything fails, the server is
# rolled back to how it was.
set -euo pipefail
cd "$(dirname "$0")"

FILE="" PASSFILE="" YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="$2"; shift 2 ;;
    --passphrase-file) PASSFILE="$2"; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[ -s "$FILE" ] || die "Backup file not found: $FILE"
case "$FILE" in *.easyeap) ;; *) die "Expected an .easyeap file from the console or backup.sh." ;; esac
[ -s "$PASSFILE" ] || die "--passphrase-file is required."
[ "$YES" = 1 ] || die "Restoring replaces every tenant, CA key, administrator and setting on this server. Re-run with --yes to confirm."

# Stream the file into the API's backup store (as the API's own user), then restore it with the passphrase on
# standard input. The copy is removed afterwards either way.
NAME="incoming-$(date -u +%Y%m%dT%H%M%SZ)-$$.easyeap"
cleanup() { docker compose exec -T easyeap-api rm -f "/var/lib/easyeap/backups/$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker compose exec -T easyeap-api sh -c "umask 077; cat > /var/lib/easyeap/backups/$NAME" < "$FILE"
docker compose exec -T easyeap-api easyeap backup restore --file "/var/lib/easyeap/backups/$NAME" --passphrase-file - --yes < "$PASSFILE"

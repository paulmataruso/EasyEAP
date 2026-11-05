#!/bin/sh
# EasyEAP api/worker entrypoint.
set -eu
role="${1:-api}"

# Database URLs are built from the Docker secret files by app.config (EASYEAP_DB_*_PASSWORD_FILE).

wait_for() {
  i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 60 ] && { echo "Timed out waiting for: $*" >&2; exit 1; }
    sleep 2
  done
}

case "$role" in
  api)
    wait_for python -c "import psycopg; from app.config import get_settings as g; psycopg.connect(g().database_owner_url.replace('postgresql+psycopg','postgresql')).close()"
    # Migrations run as the schema owner under an advisory lock (see alembic/env.py).
    alembic upgrade head
    python -m app.cli bootstrap
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips "${EASYEAP_TRUSTED_PROXY:-*}" --no-server-header --log-level warning
    ;;
  worker)
    wait_for python -c "import psycopg; from app.config import get_settings as g; psycopg.connect(g().database_url.replace('postgresql+psycopg','postgresql')).close()"
    # Wait until the api has migrated and bootstrapped OpenBao.
    wait_for test -f /var/lib/easyeap/secrets/openbao-api-token
    exec python -m app.jobs.worker
    ;;
  *)
    exec "$@"
    ;;
esac

#!/bin/sh
# EasyEAP api/worker entrypoint.
set -eu
role="${1:-api}"

# Build database URLs from Docker secrets when provided (passwords never appear in the compose file or env).
if [ -n "${EASYEAP_DB_APP_PASSWORD_FILE:-}" ] && [ -f "$EASYEAP_DB_APP_PASSWORD_FILE" ]; then
  EASYEAP_DATABASE_URL="postgresql+psycopg://easyeap_app:$(cat "$EASYEAP_DB_APP_PASSWORD_FILE")@${EASYEAP_DB_HOST:-easyeap-db}:5432/easyeap"
  export EASYEAP_DATABASE_URL
fi
if [ -n "${EASYEAP_DB_OWNER_PASSWORD_FILE:-}" ] && [ -f "$EASYEAP_DB_OWNER_PASSWORD_FILE" ]; then
  EASYEAP_DATABASE_OWNER_URL="postgresql+psycopg://easyeap:$(cat "$EASYEAP_DB_OWNER_PASSWORD_FILE")@${EASYEAP_DB_HOST:-easyeap-db}:5432/easyeap"
  export EASYEAP_DATABASE_OWNER_URL
fi

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
    wait_for python -c "import psycopg,os; psycopg.connect(os.environ['EASYEAP_DATABASE_OWNER_URL'].replace('postgresql+psycopg','postgresql')).close()"
    # Migrations run as the schema owner under an advisory lock (see alembic/env.py).
    alembic upgrade head
    python -m app.cli bootstrap
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips "${EASYEAP_TRUSTED_PROXY:-*}" --no-server-header --log-level warning
    ;;
  worker)
    wait_for python -c "import psycopg,os; psycopg.connect(os.environ['EASYEAP_DATABASE_URL'].replace('postgresql+psycopg','postgresql')).close()"
    # Wait until the api has migrated and bootstrapped OpenBao.
    wait_for test -f /var/lib/easyeap/secrets/openbao-api-token
    exec python -m app.jobs.worker
    ;;
  *)
    exec "$@"
    ;;
esac

#!/bin/sh
# EasyEAP api/worker/collector entrypoint.
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
    # Wait for the database server (the maintenance database: an interrupted restore may have renamed ours aside).
    wait_for python -c "import psycopg; from sqlalchemy.engine import make_url; from app.config import get_settings as g; u=make_url(g().database_owner_url); psycopg.connect(host=u.host, port=u.port or 5432, user=u.username, password=g().db_owner_password, dbname='postgres').close()"
    # A restore interrupted by a restart is finished or rolled back before anything else touches the database.
    python -m app.cli restore-recover
    # Migrations run as the schema owner under an advisory lock (see alembic/env.py).
    alembic upgrade head
    python -m app.cli bootstrap
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips "${EASYEAP_TRUSTED_PROXY:-*}" --no-server-header --log-level warning ${EASYEAP_RELOAD:+--reload --reload-dir /app/app}
    ;;
  worker)
    wait_for python -c "import psycopg; from app.config import get_settings as g; psycopg.connect(g().database_url.replace('postgresql+psycopg','postgresql')).close()"
    # Wait until the api has migrated and bootstrapped OpenBao.
    wait_for test -f /var/lib/easyeap/secrets/openbao-api-token
    exec python -m app.jobs.worker
    ;;
  collector)
    # The switch audit's SNMP poller (app/switchaudit/collector.py): same database and OpenBao access as the worker.
    wait_for python -c "import psycopg; from app.config import get_settings as g; psycopg.connect(g().database_url.replace('postgresql+psycopg','postgresql')).close()"
    wait_for test -f /var/lib/easyeap/secrets/openbao-api-token
    exec python -m app.switchaudit.collector
    ;;
  syslog)
    # Syslog from monitored switches (app/switchaudit/syslog.py): the database only, no OpenBao.
    wait_for python -c "import psycopg; from app.config import get_settings as g; psycopg.connect(g().database_url.replace('postgresql+psycopg','postgresql')).close()"
    exec python -m app.switchaudit.syslog
    ;;
  *)
    exec "$@"
    ;;
esac

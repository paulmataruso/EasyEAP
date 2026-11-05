#!/bin/sh
# First-start initialisation: the application role (subject to row-level security) gets its own password.
# The password is passed as a psql variable and quoted by the server, never spliced into SQL text.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_pw="$(cat /run/secrets/db_app_password)" -v db="$POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE easyeap_app LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', :'app_pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'easyeap_app') \gexec
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO easyeap_app;
SQL

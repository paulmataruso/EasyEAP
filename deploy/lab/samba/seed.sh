#!/bin/sh
# Lab directory: groups from the EasyEAP documentation plus users in each state (enabled, disabled, nested).
set -u
P="$(cat "${LAB_ADMIN_PASSWORD_FILE:-/run/secrets/lab_ad_password}")"
t() { samba-tool "$@" >/dev/null 2>&1 || true; }
t user add svc-easyeap 'Svc-Read-0nly-Lab!' --description="EasyEAP read-only bind account"
for g in "IT Dept" "Network Team" "Staff" "Contractors" "Guests" "Executives"; do t group add "$g"; done
t group addmembers "IT Dept" "Network Team"   # nested: Network Team members inherit IT Dept
t user add alice 'Lab-Passw0rd-123!' --given-name=Alice --surname=Admin --mail-address=alice@lab.easyeap.test --department=IT
t user add bob 'Lab-Passw0rd-123!' --given-name=Bob --surname=Builder --mail-address=bob@lab.easyeap.test --department=Operations
t user add carol 'Lab-Passw0rd-123!' --given-name=Carol --surname=Contractor --mail-address=carol@lab.easyeap.test
t user add dave 'Lab-Passw0rd-123!' --given-name=Dave --surname=Disabled --mail-address=dave@lab.easyeap.test
t user add nina 'Lab-Passw0rd-123!' --given-name=Nina --surname=Network --mail-address=nina@lab.easyeap.test --department=IT
t group addmembers "IT Dept" alice
t group addmembers "Staff" alice,bob,dave
t group addmembers "Contractors" carol
t group addmembers "Network Team" nina
t user disable dave
echo "EasyEAP lab directory seeded"

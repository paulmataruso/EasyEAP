#!/usr/bin/env bash
# EasyEAP end-to-end test: real API, real OpenBao PKI, real Samba AD, real FreeRADIUS, real EAP-TLS (eapol_test).
#
#   deploy/install.sh --lab          # once
#   tests/e2e/run.sh                  # any time; rebuilds the "e2e-lab" tenant from scratch
#
# Scenarios: nested-group VLAN, staff VLAN, deny rule, revoked certificate (CRL), rogue self-signed client,
# AD account disabled after issuance, RADIUS keeps authenticating with the API and worker stopped.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/deploy"
DC="docker compose --profile lab"
CERTS="$ROOT/deploy/lab/certs"
PASS=0 FAILED=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED + 1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 2; }

[ -f .env ] || die "Run deploy/install.sh --lab first."
grep -q '^EASYEAP_LAB_MODE=true' .env || die "The lab profile is not enabled in deploy/.env (install with --lab)."
$DC ps --status running --services | grep -q easyeap-lab-client || die "Lab services are not running: docker compose --profile lab up -d"

# The e2e administrator's password is generated once and kept with the deployment secrets.
umask 077
[ -s secrets/e2e_admin_password ] || openssl rand -hex 16 > secrets/e2e_admin_password
export E2E_EMAIL="e2e-owner@easyeap-lab.example" E2E_PASSWORD="$(cat secrets/e2e_admin_password)"
SETUP_TOKEN="$($DC exec -T easyeap-api easyeap setup-token 2>/dev/null || true)"
AD_CA="$($DC exec -T easyeap-lab-ad cat /var/lib/samba/private/tls/ca.pem)" || die "Could not read the lab DC's CA certificate."

drive() { # drive <command> [args…] → JSON on stdout
  $DC exec -T -e E2E_EMAIL -e E2E_PASSWORD -e E2E_SETUP_TOKEN="${SETUP_TOKEN}" -e E2E_AD_CA="$AD_CA" \
    easyeap-api python - "$@" < "$ROOT/tests/e2e/provision.py"
}
SUBNET="$(docker network inspect easyeap_egress -f '{{(index .IPAM.Config 0).Subnet}}')"

step "1. Provision a tenant from the lab Active Directory (subnet $SUBNET)"
OUT="$(drive provision "$SUBNET")" || die "provisioning failed: $OUT"
SETUP_TOKEN=""   # the first administrator now exists
mkdir -p "$CERTS"
echo "$OUT" | python3 "$ROOT/tests/e2e/lab.py" unpack "$CERTS" || die "could not unpack the provisioning result"
ok "PKI ceremony with offline root; directory synced over LDAPS; certificates issued from on-device keys"
ok "RA ignored the requested subject; one-time links refused on reuse; disabled account (dave) refused enrollment"
SECRET="$(cat "$CERTS/secret")" SERVER="$(cat "$CERTS/server")"

# Rogue client: self-signed certificate claiming a real user's name.
$DC exec -T easyeap-lab-client sh -c 'cd /certs && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=nina@lab.easyeap.test" -keyout rogue.key -out rogue.pem 2>/dev/null && chmod 644 rogue.key'

auth() { # auth <name> → prints "accept <vlan>" or "reject"
  local out
  out="$($DC exec -T easyeap-lab-client easyeap-simulate easyeap-radius "$SECRET" "/certs/$1.pem" "/certs/$1.key" /certs/ca.pem "$SERVER" "02:00:00:00:00:$(printf '%02x' $((RANDOM % 250)))" "$1" 2>&1)"
  if echo "$out" | grep -q "SUCCESS"; then
    # eapol_test prints "Attribute 81 (Tunnel-Private-Group-Id) length=5" then "Value: 313230" (hex of "120").
    local hex; hex="$(echo "$out" | awk '/Tunnel-Private-Group-I[dD]/ { getline; sub(/.*Value: */, ""); gsub(/[^0-9A-Fa-f]/, ""); print; exit }')"
    echo "accept $(python3 -c 'import sys; print(bytes.fromhex(sys.argv[1]).decode())' "$hex")"
  else
    echo "reject"
  fi
}
must() { # must <description> <command…> — run a setup step; show its output if it fails
  local out
  if ! out="$("${@:2}" 2>&1)"; then bad "$1: $out"; return 1; fi
}
expect() { # expect <name> "accept <vlan>" <description>
  local got; got="$(auth "$1")"
  [ "$got" = "$2" ] && ok "$3 → $got" || bad "$3 → expected '$2', got '$got'"
}
expect_reject() { # expect_reject <name> <reason_code> <description> — the reject must be recorded with that reason
  local t got why=""
  t="$(python3 "$ROOT/tests/e2e/lab.py" now)"
  got="$(auth "$1")"
  if [ "$got" != "reject" ]; then bad "$3 → expected reject ($2), got '$got'"; return; fi
  for _ in $(seq 1 15); do
    why="$(drive events | python3 "$ROOT/tests/e2e/lab.py" has-reason "$t" "$2")" && { ok "$3 → reject, $why"; return; }
    sleep 3
  done
  bad "$3 → rejected, but $why"
}

step "2. Wait for RADIUS to apply the configuration and authorization snapshot"
drive wait >/dev/null && ok "RADIUS agent applied the tenant snapshot" || bad "RADIUS agent never applied the snapshot"

step "3. EAP-TLS authentication through FreeRADIUS"
expect nina  "accept 120" "nina (Network Team, nested in IT Dept) gets the IT VLAN"
expect alice "accept 120" "alice (IT Dept and Staff) gets the IT VLAN (lowest priority Allow)"
expect bob   "accept 100" "bob (Staff) gets the Staff VLAN"
expect_reject carol policy_deny "carol (Contractors) is denied by the deny rule"
expect_reject rogue unknown_ca "a self-signed certificate claiming nina's name is rejected"

step "4. Revocation"
BOB_SERIAL="$(openssl x509 -in "$CERTS/bob.pem" -noout -serial | cut -d= -f2)"
must "revoke bob's certificate" drive revoke "$BOB_SERIAL" && must "wait for snapshot" drive wait
expect_reject bob cert_revoked "bob's revoked certificate is rejected (CRL + snapshot)"

step "5. Directory change after issuance"
must "disable alice in AD" $DC exec -T easyeap-lab-ad samba-tool user disable alice
must "directory sync" drive sync && must "wait for snapshot" drive wait
expect_reject alice account_disabled "alice disabled in AD is rejected after sync"
must "enable alice in AD" $DC exec -T easyeap-lab-ad samba-tool user enable alice
must "directory sync" drive sync && must "wait for snapshot" drive wait
expect alice "accept 120" "alice re-enabled in AD is accepted again"

step "6. RADIUS independence"
$DC stop easyeap-api easyeap-worker >/dev/null 2>&1
expect nina "accept 120" "with the API and worker stopped, RADIUS still authenticates from its local snapshot"
$DC start easyeap-api easyeap-worker >/dev/null 2>&1
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$($DC ps -q easyeap-api)")" = healthy ] && break; sleep 2
done

step "7. Audit"
$DC exec -T easyeap-api easyeap verify-audit | grep -q '^OK' && ok "audit hash chain verifies" || bad "audit chain verification failed"

# Lab keys and the shared secret are removed unless E2E_KEEP=1 (debugging).
[ -n "${E2E_KEEP:-}" ] || rm -f "${CERTS:?}"/*.key "${CERTS:?}/secret"
printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[ "$FAILED" -eq 0 ]

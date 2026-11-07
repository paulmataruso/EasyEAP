#!/usr/bin/env bash
# EasyEAP end-to-end test: real API, real OpenBao PKI, real Samba AD, real FreeRADIUS, real EAP-TLS (eapol_test).
#
#   deploy/install.sh --lab          # once
#   tests/e2e/run.sh                  # any time; rebuilds the "e2e-lab" tenant from scratch
#
# Scenarios: nested-group VLAN, staff VLAN, deny rule, revoked certificate (CRL), rogue self-signed client,
# AD account disabled after issuance, RADIUS keeps authenticating with the API and worker stopped; wired 802.1X: a
# switch in monitor mode, readiness evidence, enforce, VLAN mapping on switch ports, MAB and wrong-network refusals,
# the wrong-secret diagnosis, wired enrollment packages and the Windows wired kit.
#
#   E2E_DEPLOY_DIR=<dir>   a deployment directory other than deploy/ (COMPOSE_PROJECT_NAME and COMPOSE_FILE are honoured)
#   E2E_WIRED=0            skip the wired 802.1X steps (a build from before wired 802.1X)
set -uo pipefail
shopt -s lastpipe   # `… | jok` runs jok in this shell, so its PASS/FAIL counts
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPLOY="${E2E_DEPLOY_DIR:-$ROOT/deploy}"
cd "$DEPLOY"
DC="docker compose --profile lab"
PROJECT="${COMPOSE_PROJECT_NAME:-easyeap}"
CERTS="$DEPLOY/lab/certs"
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
# A new lab DC provisions and seeds its users in the first minute or two after `up`: wait for its CA and a seeded user.
for _ in $(seq 1 90); do
  $DC exec -T easyeap-lab-ad sh -c 'test -s /var/lib/samba/private/tls/ca.pem && samba-tool user show nina' >/dev/null 2>&1 && break
  sleep 2
done
AD_CA="$($DC exec -T easyeap-lab-ad cat /var/lib/samba/private/tls/ca.pem)" || die "Could not read the lab DC's CA certificate."

drive() { # drive <command> [args…] → JSON on stdout
  $DC exec -T -e E2E_EMAIL -e E2E_PASSWORD -e E2E_SETUP_TOKEN="${SETUP_TOKEN}" -e E2E_AD_CA="$AD_CA" \
    easyeap-api python - "$@" < "$ROOT/tests/e2e/provision.py"
}
NET="${PROJECT}_egress"
SUBNET="$(docker network inspect "$NET" -f '{{(index .IPAM.Config 0).Subnet}}')"

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

if [ "${E2E_WIRED:-1}" != 0 ]; then
# Two more lab-client containers stand in for switches. Each is registered by its own address inside the controller's
# subnet: FreeRADIUS takes the longest prefix, so their requests are the switches' and the lab client's stay the
# controller's.
LAB_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$($DC ps -q easyeap-lab-client)")"
SW1="$PROJECT-e2e-switch1" SW2="$PROJECT-e2e-switch2"
drop_switches() { docker rm -f "$SW1" "$SW2" >/dev/null 2>&1; }
trap drop_switches EXIT
drop_switches
for c in "$SW1" "$SW2"; do docker run -d --name "$c" --network "$NET" -v "$CERTS":/certs:ro --entrypoint sleep "$LAB_IMAGE" infinity >/dev/null; done
ip_of() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
SW1_IP="$(ip_of "$SW1")" SW2_IP="$(ip_of "$SW2")"
RADIUS_IP="$(docker exec "$SW1" getent hosts easyeap-radius | awk '{print $1; exit}')"
lab() { python3 "$ROOT/tests/e2e/lab.py" "$@"; }
jok() { # … | jok <description> <python expression over d>
  local out; if out="$(lab check "$2")"; then ok "$1"; else bad "$1: $out"; fi
}
# wauth <container> <secret> <user> <mac> [-N attr…] → "accept <vlan>", "accept none" (no VLAN sent) or "reject"
wauth() {
  local from="$1" secret="$2" user="$3" mac="$4" out hex; shift 4
  out="$(docker exec -i "$from" sh -c 'cat > /tmp/sup.conf; eapol_test -c /tmp/sup.conf "$@"' sh \
    -a "$RADIUS_IP" -p 1812 -s "$secret" -M "$mac" -t 15 "$@" 2>&1 <<CONF
network={
	key_mgmt=IEEE8021X
	eapol_flags=0
	eap=TLS
	identity="$user"
	ca_cert="/certs/ca.pem"
	client_cert="/certs/$user.pem"
	private_key="/certs/$user.key"
	domain_suffix_match="$SERVER"
}
CONF
)"
  if echo "$out" | grep -q "^SUCCESS"; then
    hex="$(echo "$out" | awk '/Tunnel-Private-Group-I[dD]/ { getline; sub(/.*Value: */, ""); gsub(/[^0-9A-Fa-f]/, ""); print; exit }')"
    [ -n "$hex" ] && echo "accept $(python3 -c 'import sys; print(bytes.fromhex(sys.argv[1]).decode())' "$hex")" || echo "accept none"
  else
    echo "reject"
  fi
}
wexpect() { # wexpect <description> <want> <wauth args…>
  local got; got="$(wauth "${@:3}")"
  [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"
}
event() { # event <description> <since> <python expression over e> — waits for the agent to ship it
  local why=""
  for _ in $(seq 1 15); do
    why="$(drive events | lab has-event "$2" "$3")" && { ok "$1"; return; }
    sleep 3
  done
  bad "$1: $why"
}
# A Catalyst access port: NAS-Port-Type Ethernet, the port's MAC as Called-Station-Id (no SSID), NAS-Port-Id.
PORT5=(-N "61:d:15" -N "30:s:00-11-22-33-44-55" -N "87:s:GigabitEthernet1/0/5")
WIFI=(-N "61:d:19" -N "30:s:00-11-22-33-44-55:EasyEAP-Lab")

step "7. Wired 802.1X: a Catalyst switch starts in monitor mode"
VLANS="$(drive call GET /policy)"
IT_REF="$(echo "$VLANS" | python3 -c 'import json,sys; print(next(v["id"] for v in json.load(sys.stdin)["body"]["vlans"] if v["vlan_id"] == 120))')"
drive call PUT "/policy/vlans/$IT_REF" '{"vlan_id": 120, "name": "IT", "wired_mode": "vlan", "wired_vlan_id": 220}' \
  | jok "IT (VLAN 120 on Wi-Fi) set to VLAN 220 on switch ports" 'd["status"] == 200 and d["body"]["wired_mode"] == "vlan" and d["body"]["wired_vlan_id"] == 220'
drive call PUT "/policy/vlans/$IT_REF" '{"vlan_id": 120, "name": "IT", "wired_mode": "vlan"}' \
  | jok "\"another VLAN\" without its number is refused" 'd["status"] == 422'
SW1_OUT="$(drive call POST /radius/clients "{\"name\": \"lab-access-1\", \"vendor\": \"cisco-switch\", \"address\": \"$SW1_IP\",
  \"wired_profile\": {\"platform\": \"ibns2\", \"interfaces\": \"Gi1/0/1-24\", \"exclude\": \"Gi1/0/24\"}}")"
echo "$SW1_OUT" | jok "switch registered at $SW1_IP (inside the controller's $SUBNET): wired only, monitor mode, CoA port 1700; uplink 24 left alone" \
  'd["status"] == 201 and d["body"]["client"]["networks"] == ["wired"] and d["body"]["client"]["wired_mode"] == "monitor" and d["body"]["client"]["coa_port"] == 1700 and d["body"]["client"]["wired_profile"]["exclude"] == "GigabitEthernet1/0/24"'
SW1_ID="$(echo "$SW1_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["client"]["id"])')"
SW1_SECRET="$(echo "$SW1_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["shared_secret"])')"
drive call POST /radius/clients "{\"name\": \"lab-access-x\", \"vendor\": \"cisco-switch\", \"address\": \"$SW2_IP\", \"wired_profile\": {\"interfaces\": \"Gi1/0/1; end\"}}" \
  | jok "a port list with IOS commands in it is refused, naming the field" 'd["status"] == 422 and d["body"]["detail"]["field"] == "interfaces"'
must "wait for snapshot" drive wait && ok "RADIUS applied the switch and the wired VLAN mapping"

T0="$(lab now)"
wexpect "nina on a monitor-mode port: accepted, no VLAN sent" "accept none" "$SW1" "$SW1_SECRET" nina 02:00:00:00:10:01 "${PORT5[@]}"
wexpect "carol on a monitor-mode port: rejected by policy (the open port still lets her on)" "reject" "$SW1" "$SW1_SECRET" carol 02:00:00:00:10:02 "${PORT5[@]}"
wexpect "Wi-Fi request through the wired-only switch" "reject" "$SW1" "$SW1_SECRET" nina 02:00:00:00:10:03 "${WIFI[@]}"
MAB="$(docker exec "$SW1" sh -c "printf 'User-Name = \"020000001004\"\nUser-Password = \"020000001004\"\nService-Type = Call-Check\nNAS-Port-Type = Ethernet\nCalling-Station-Id = \"02-00-00-00-10-04\"\nMessage-Authenticator = 0x00\n' | radclient -t 5 -r 1 $RADIUS_IP auth '$SW1_SECRET'" 2>&1)"
echo "$MAB" | grep -q "Access-Reject" && ok "MAC Authentication Bypass request → Access-Reject" || bad "MAB request was not rejected: $(echo "$MAB" | tail -2)"
event "monitor-mode accept logged: wired, port Gi1/0/5, the VLAN it would assign (220), monitor" "$T0" \
  "e['result'] == 'accept' and e['network'] == 'wired' and e['port'] == 'GigabitEthernet1/0/5' and e['vlan'] == 220 and e['monitor'] and e['client'] == '$SW1_ID'"
event "carol's wired reject logged as policy_deny, in monitor mode" "$T0" "e['result'] == 'reject' and e['reason'] == 'policy_deny' and e['network'] == 'wired' and e['monitor']"
event "the Wi-Fi request through the switch logged as network_not_enabled" "$T0" "e['reason'] == 'network_not_enabled' and e['client'] == '$SW1_ID'"
event "the MAB attempt logged as mab_unsupported" "$T0" "e['reason'] == 'mab_unsupported'"

step "8. Before enforcing: readiness evidence, the switch's own sessions, the configuration"
drive call GET "/radius/clients/$SW1_ID/readiness" | jok "readiness: Gi1/0/5 accepted, would assign VLAN 220, carol's device would be refused" \
  'd["status"] == 200 and any(p["port"] == "GigabitEthernet1/0/5" and p["accepted"] >= 1 for p in d["body"]["ports"]) and 220 in d["body"]["would_assign_vlans"] and d["body"]["rejected_devices"] >= 1'
SESSIONS='Interface                MAC Address    Method  Domain  Status Fg  Session ID\n--------------------------------------------------------------------------------\nGi1/0/1                  0050.5690.1234 dot1x   DATA    Auth        0A0A0A0B000000123ABC0001\nGi1/0/2                  0050.5690.5678 dot1x   UNKNOWN Unauth      0A0A0A0B000000123ABC0002\n'
drive call POST "/radius/clients/$SW1_ID/readiness/sessions" "{\"text\": \"$SESSIONS\"}" \
  | jok "pasted 'show access-session': 2 sessions, Gi1/0/2 would lose access" 'd["body"]["sessions"] == 2 and [r["interface"] for r in d["body"]["would_lose_access"]] == ["Gi1/0/2"]'
drive call GET "/radius/clients/$SW1_ID/wired-guide" | jok "the configuration: IBNS 2.0 monitor policy, safe paste, the closed-mode change for later, no shared secret" \
  "d['status'] == 200 and d['body']['mode'] == 'monitor' and 'EASYEAP_MONITOR' in d['body']['cli'] and any('reload in' in x for x in d['body']['safe_paste']) and 'access-session closed' in d['body']['enforce_cli'] and 'interface range GigabitEthernet1/0/1 - 23' in d['body']['cli'].splitlines() and '$SW1_SECRET' not in str(d)"

step "9. Enforce: switch ports get the mapped VLAN"
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "enforce"}' | jok "enforce without confirming the session check is refused" 'd["status"] == 400'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "enforce", "confirmed": true}' \
  | jok "enforce: recorded, and the guide now gives the closed-mode change" 'd["status"] == 200 and d["body"]["client"]["wired_mode"] == "enforce" and d["body"]["guide"]["mode"] == "enforce"'
must "wait for snapshot" drive wait
T1="$(lab now)"
wexpect "nina (IT) on an enforcing port: IT's switch-port VLAN" "accept 220" "$SW1" "$SW1_SECRET" nina 02:00:00:00:11:01 "${PORT5[@]}"
wexpect "alice (IT) on an enforcing port: the same" "accept 220" "$SW1" "$SW1_SECRET" alice 02:00:00:00:11:02 "${PORT5[@]}"
wexpect "carol on an enforcing port: rejected" "reject" "$SW1" "$SW1_SECRET" carol 02:00:00:00:11:03 "${PORT5[@]}"
expect nina "accept 120" "nina on Wi-Fi through the controller: still the Wi-Fi VLAN"
event "enforced accept logged with VLAN 220 and not as monitor" "$T1" "e['result'] == 'accept' and e['network'] == 'wired' and e['vlan'] == 220 and not e['monitor']"
drive call PUT "/policy/vlans/$IT_REF" '{"vlan_id": 120, "name": "IT", "wired_mode": "port"}' | jok "IT set to keep the port's own VLAN" 'd["body"]["wired_mode"] == "port"'
must "wait for snapshot" drive wait
wexpect "nina on an enforcing port, IT keeps the port's VLAN: accepted, no VLAN sent" "accept none" "$SW1" "$SW1_SECRET" nina 02:00:00:00:11:04 "${PORT5[@]}"
expect nina "accept 120" "nina on Wi-Fi: still VLAN 120"
drive call GET "/events?network=wired&hours=1&page_size=200" | jok "the log's Wired filter returns only wired attempts" 'len(d["body"]["items"]) >= 6 and all(e["network"] == "wired" for e in d["body"]["items"])'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "monitor"}' | jok "back to monitor mode needs no confirmation" 'd["status"] == 200 and d["body"]["client"]["wired_mode"] == "monitor"'

step "10. The wrong-secret diagnosis"
drive call POST /radius/clients "{\"name\": \"lab-unifi-wired\", \"vendor\": \"unifi\", \"address\": \"$SW2_IP\", \"networks\": [\"wired\"], \"wired_profile\": {\"fallback_vlan\": 30}}" \
  | jok "UniFi switch registered for wired, in monitor mode (its fallback VLAN)" 'd["status"] == 201 and d["body"]["client"]["wired_mode"] == "monitor"'
SW2_ID="$(drive call GET /radius | python3 -c 'import json,sys; print(next(c["id"] for c in json.load(sys.stdin)["body"]["clients"] if c["name"] == "lab-unifi-wired"))')"
must "wait for snapshot" drive wait
for _ in 1 2; do
  docker exec "$SW2" sh -c "printf 'User-Name = \"probe\"\nUser-Password = \"probe\"\nNAS-Port-Type = Ethernet\nMessage-Authenticator = 0x00\n' | radclient -t 2 -r 1 $RADIUS_IP auth 'not-the-secret-easyeap-gave'" >/dev/null 2>&1
done
why=""
for _ in $(seq 1 20); do
  why="$(drive call GET "/radius/clients/$SW2_ID/activity" | lab check "any(h['kind'] == 'bad_secret' and h['address'] == '$SW2_IP' for h in d['body']['diagnostics'])")" && break
  sleep 3
done
[ -z "$why" ] && ok "no requests, but EasyEAP explains why: wrong shared secret from $SW2_IP" || bad "no wrong-secret diagnosis: $why"
drive call GET "/radius/clients/$SW2_ID/wired-guide" | jok "UniFi wired guide: steps, no CLI" 'd["status"] == 200 and d["body"]["cli"] is None and len(d["body"]["steps"]) > 3'

step "11. Enrollment packages with wired settings, and the Windows wired kit"
drive call PUT /radius '{"server_hostname": "radius.lab.easyeap.test", "ssid": "EasyEAP-Lab", "wired_enabled": true}' \
  | jok "wired settings in enrollment packages turned on" 'd["status"] == 200 and d["body"]["settings"]["wired_enabled"]'
drive enroll nina macos | jok "macOS: the portal says wired, and the profile has the Ethernet payload" \
  'd["info"]["network"]["wired"] and "com.apple.globalethernet.managed" in d["csr"]["profiles"]["mobileconfig_template"]'
drive enroll nina linux | jok "Linux: wired NetworkManager and wpa_supplicant files" \
  'd["csr"]["profiles"]["networkmanager_wired"] and "802-1x" in d["csr"]["profiles"]["networkmanager_wired"] and d["csr"]["profiles"]["wpa_supplicant_wired"]'
drive call GET /radius/wired-kit | jok "Windows wired kit: a LAN profile and an install script, no private key" \
  'd["status"] == 200 and "LANProfile" in d["body"]["files"][0]["content"] and "PRIVATE KEY" not in str(d)'
fi

step "12. Audit"
$DC exec -T easyeap-api easyeap verify-audit | grep -q '^OK' && ok "audit hash chain verifies" || bad "audit chain verification failed"

# Lab keys and the shared secret are removed unless E2E_KEEP=1 (debugging).
[ -n "${E2E_KEEP:-}" ] || rm -f "${CERTS:?}"/*.key "${CERTS:?}/secret"
printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[ "$FAILED" -eq 0 ]

#!/usr/bin/env bash
# EasyEAP end-to-end test: real API, real OpenBao PKI, real Samba AD, real FreeRADIUS, real EAP-TLS (eapol_test).
#
#   deploy/install.sh --lab          # once
#   tests/e2e/run.sh                  # any time; rebuilds the "e2e-lab" tenant from scratch
#
# Scenarios: nested-group VLAN, staff VLAN, deny rule, revoked certificate (CRL), rogue self-signed client,
# AD account disabled after issuance, RADIUS keeps authenticating with the API and worker stopped; wired 802.1X: a
# switch in monitor mode, readiness evidence, enforce, VLAN mapping on switch ports, wrong-network refusals; MAC
# authentication (Cisco MAB and UniFi MAC-Based): the allow list, "Seen, not allowed", the Enforce gate, VLANs, block;
# the wrong-secret diagnosis, wired enrollment packages and the Windows wired kit; device administration (TACACS+):
# switch logins with AD groups and EasyEAP accounts, the Admin log, key rotation, break-glass.
#
#   E2E_DEPLOY_DIR=<dir>   a deployment directory other than deploy/ (COMPOSE_PROJECT_NAME and COMPOSE_FILE are honoured)
#   E2E_WIRED=0            skip the wired 802.1X steps (a build from before wired 802.1X)
#   E2E_ADMIN=0            skip the device-administration (TACACS+) steps (a build from before device administration)
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
echo "$MAB" | grep -q "Access-Reject" && ok "MAC authentication request to a switch without it → Access-Reject" || bad "MAB request was not rejected: $(echo "$MAB" | tail -2)"
event "monitor-mode accept logged: wired, port Gi1/0/5, the VLAN it would assign (220), monitor" "$T0" \
  "e['result'] == 'accept' and e['network'] == 'wired' and e['port'] == 'GigabitEthernet1/0/5' and e['vlan'] == 220 and e['monitor'] and e['client'] == '$SW1_ID'"
event "carol's wired reject logged as policy_deny, in monitor mode" "$T0" "e['result'] == 'reject' and e['reason'] == 'policy_deny' and e['network'] == 'wired' and e['monitor']"
event "the Wi-Fi request through the switch logged as network_not_enabled" "$T0" "e['reason'] == 'network_not_enabled' and e['client'] == '$SW1_ID'"
event "the MAB attempt logged as mab_not_enabled, method mab" "$T0" "e['reason'] == 'mab_not_enabled' and e['method'] == 'mab' and e['client'] == '$SW1_ID'"

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

step "9b. MAC authentication: the allow list, Seen not allowed, the Enforce gate"
# mab <container> <secret> <user name> [Calling-Station-Id] → "accept <vlan>", "accept none" or "reject" (Cisco MAB: PAP, Call-Check)
mab() {
  local from="$1" secret="$2" user="$3" csid="${4:-}" out vlan
  [ -n "$csid" ] || csid="$(echo "$3" | sed 's/../&-/g; s/-$//' | tr a-f A-F)"
  out="$(docker exec "$from" sh -c "printf 'User-Name = \"$user\"\nUser-Password = \"$user\"\nService-Type = Call-Check\nNAS-Port-Type = Ethernet\nNAS-Port-Id = \"GigabitEthernet1/0/9\"\nCalling-Station-Id = \"$csid\"\nMessage-Authenticator = 0x00\n' | radclient -x -t 5 -r 1 $RADIUS_IP auth '$secret'" 2>&1)"
  if echo "$out" | grep -q "Received Access-Accept"; then
    vlan="$(echo "$out" | sed -n 's/.*Tunnel-Private-Group-Id[^=]*= *"\{0,1\}\([^" ]*\)"\{0,1\}.*/\1/p' | head -1)"
    [ -n "$vlan" ] && echo "accept $vlan" || echo "accept none"
  else
    echo "reject"
  fi
}
mexpect() { local got; got="$(mab "${@:3}")"; [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"; }
PRN_REF="$(drive call POST /policy/vlans '{"vlan_id": 140, "name": "Printers", "description": "", "color": "teal"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["id"])')"
[ -n "$PRN_REF" ] && ok "a Printers VLAN (140)" || bad "the Printers VLAN wasn't created"
drive call POST /mac/groups '{"name": "Loose"}' | jok "a device group without a VLAN choice is refused, naming the field" 'd["status"] == 422 and d["body"]["detail"]["field"] == "vlan_ref"'
GRP_OUT="$(drive call POST /mac/groups "{\"name\": \"Printers\", \"vlan_ref\": \"$PRN_REF\"}")"
echo "$GRP_OUT" | jok "device group Printers on VLAN 140" 'd["status"] == 201 and d["body"]["switch_vlan"] == 140 and not d["body"]["shared_with_certificates"]'
GRP_ID="$(echo "$GRP_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["id"])')"
drive call POST "/radius/clients/$SW1_ID/mab" '{"enabled": true}' \
  | jok "MAC authentication on for lab-access-1 (monitor mode): the change swaps the control policy, never edits it" \
  'd["status"] == 200 and d["body"]["client"]["wired_profile"]["mab"] and "authenticate using mab priority 20" in d["body"]["guide"]["mab_cli"] and " no service-policy type control subscriber EASYEAP_MONITOR_" in d["body"]["guide"]["mab_cli"] and "access-session closed" not in d["body"]["guide"]["mab_cli"]'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "enforce", "confirmed": true}' \
  | jok "Enforce is refused until EasyEAP has answered a MAC request from the switch" 'd["status"] == 409 and d["body"]["detail"]["field"] == "mab"'
must "wait for snapshot" drive wait
T2="$(lab now)"
mexpect "a printer not on the allow list" "reject" "$SW1" "$SW1_SECRET" 020000001005
event "logged as mac_unknown with its normalised MAC, method mab, in monitor mode" "$T2" "e['reason'] == 'mac_unknown' and e['method'] == 'mab' and e['device_mac'] == '020000001005' and e['monitor']"
drive call GET "/mac/sightings?days=1" | jok "it appears under Seen, not allowed: lab-access-1, its port, one attempt" \
  'any(s["mac"] == "02:00:00:00:10:05" and s["switch"] == "lab-access-1" and s["port"] == "GigabitEthernet1/0/9" for s in d["body"]["sightings"])'
mexpect "the same printer again within the hour" "reject" "$SW1" "$SW1_SECRET" 020000001005
NINA_MAC="$(drive events | python3 -c 'import json,sys; print(next((e["device_mac"] for e in json.load(sys.stdin) if e["user"] == "nina" and e["result"] == "accept" and e["device_mac"]), ""))')"
[ -n "$NINA_MAC" ] && drive call POST /mac/devices "{\"mac\": \"$NINA_MAC\", \"name\": \"nina's laptop\", \"group_id\": \"$GRP_ID\"}" \
  | jok "listing the MAC of a device that signs in with a certificate needs confirming" 'd["status"] == 422 and d["body"]["detail"]["code"] == "certificate_device"'
drive call POST /mac/devices "{\"mac\": \"0200.0000.1005\", \"name\": \"Printer, floor 2\", \"group_id\": \"$GRP_ID\"}" \
  | jok "printer allowed (Cisco dotted notation), and it leaves Seen, not allowed keeping where it was seen" \
  'd["status"] == 201 and d["body"]["mac"] == "02:00:00:00:10:05" and d["body"]["source"] == "learned" and d["body"]["last_seen_port"] == "GigabitEthernet1/0/9"'
DEV_ID="$(drive call GET /mac | python3 -c 'import json,sys; print(next(x["id"] for x in json.load(sys.stdin)["body"]["devices"] if x["mac"] == "02:00:00:00:10:05"))')"
drive call GET "/mac/sightings?days=1" | jok "Seen, not allowed no longer lists it" 'not any(s["mac"] == "02:00:00:00:10:05" for s in d["body"]["sightings"])'
must "wait for snapshot" drive wait && ok "RADIUS applied the MAC allow list"
T3="$(lab now)"
mexpect "the allowed printer on a monitor-mode port: accepted, VLAN withheld" "accept none" "$SW1" "$SW1_SECRET" 020000001005
mexpect "the same MAC, but Calling-Station-Id names another device" "reject" "$SW1" "$SW1_SECRET" 020000001005 02-00-00-00-10-06
event "accept logged with the allow-list entry, the VLAN it would assign (140), monitor" "$T3" \
  "e['result'] == 'accept' and e['method'] == 'mab' and e['mac_device'] == '$DEV_ID' and e['vlan'] == 140 and e['monitor']"
drive call GET "/radius/clients/$SW1_ID/readiness" | jok "readiness: MAC requests answered and accepted, the printer marked as a MAC device" \
  'd["body"]["mab"]["enabled"] and d["body"]["mab"]["answered"] >= 2 and d["body"]["mab"]["accepted"] >= 1 and any(x.get("method") == "mac" for p in d["body"]["ports"] for x in p["devices"])'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "enforce", "confirmed": true}' \
  | jok "Enforce allowed now: the closed policy has MAB after 802.1X gets no answer" 'd["status"] == 200 and "MAB_FAILED" in d["body"]["guide"]["enforce_cli"]'
drive call POST "/radius/clients/$SW1_ID/mab" '{"enabled": false}' | jok "MAC authentication can't be changed while enforcing" 'd["status"] == 409'
must "wait for snapshot" drive wait
mexpect "the printer on an enforcing port: its group's VLAN" "accept 140" "$SW1" "$SW1_SECRET" 020000001005
mexpect "Cisco's colon notation as user name, same device" "accept 140" "$SW1" "$SW1_SECRET" 02:00:00:00:10:05 02-00-00-00-10-05
wexpect "a certificate still works on the MAB switch" "accept none" "$SW1" "$SW1_SECRET" nina 02:00:00:00:11:05 "${PORT5[@]}"
drive call PUT "/mac/devices/$DEV_ID" '{"enabled": false}' | jok "printer blocked: its session on the switch it was last accepted on is found (this lab switch has no CoA, so none is queued)" 'd["status"] == 200 and d["body"]["status"] == "blocked" and d["body"]["coa"] == {"sessions": 1, "queued": 0, "without_coa": 1}'
must "wait for snapshot" drive wait
T4="$(lab now)"
mexpect "the blocked printer" "reject" "$SW1" "$SW1_SECRET" 020000001005
event "logged as mac_disabled" "$T4" "e['reason'] == 'mac_disabled' and e['method'] == 'mab'"
drive call POST /mac/devices/import "{\"text\": \"mac,name,group\\n02:00:00:00:10:07,Camera 1,Printers\\nnot-a-mac,Camera 2\", \"group_id\": \"$GRP_ID\"}" \
  | jok "an import with one bad line adds nothing and names the line" 'd["body"]["added"] == 0 and d["body"]["errors"][0]["line"] == 3'
drive call POST /mac/devices/import "{\"text\": \"02:00:00:00:10:07,Camera 1\\n02-00-00-00-10-08\", \"group_id\": \"$GRP_ID\"}" \
  | jok "a clean import adds every line" 'd["status"] == 200 and d["body"]["added"] == 2'
drive call GET /mac/devices.csv | jok "export: CSV with every entry" 'd["status"] == 200 and d["body"].count("\n") == 4 and "Printer, floor 2" in d["body"]'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "monitor"}' | jok "back to monitor mode" 'd["status"] == 200'

step "10. The wrong-secret diagnosis"
SW2_OUT="$(drive call POST /radius/clients "{\"name\": \"lab-unifi-wired\", \"vendor\": \"unifi\", \"address\": \"$SW2_IP\", \"networks\": [\"wired\"], \"wired_profile\": {\"fallback_vlan\": 30, \"mab\": true}}")"
echo "$SW2_OUT" | jok "UniFi switch registered for wired with MAC-Based authentication, in monitor mode (its fallback VLAN)" \
  'd["status"] == 201 and d["body"]["client"]["wired_mode"] == "monitor" and d["body"]["client"]["wired_profile"]["mab"]'
SW2_SECRET="$(echo "$SW2_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["shared_secret"])')"
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
drive call GET "/radius/clients/$SW2_ID/wired-guide" | jok "UniFi wired guide: steps including MAC-Based, no CLI" \
  'd["status"] == 200 and d["body"]["cli"] is None and len(d["body"]["steps"]) > 3 and any("MAC-Based" in s for s in d["body"]["steps"])'
md5() { # md5 <identity> <password> → accept <vlan> | accept none | reject (UniFi MAC-Based: EAP-MD5)
  local out hex
  out="$(docker exec -i "$SW2" sh -c 'cat > /tmp/md5.conf; eapol_test -n -c /tmp/md5.conf "$@"' sh \
    -a "$RADIUS_IP" -p 1812 -s "$SW2_SECRET" -M 02:00:00:00:10:07 -t 10 -N "61:d:15" 2>&1 <<CONF
network={
	key_mgmt=IEEE8021X
	eapol_flags=0
	eap=MD5
	identity="$1"
	password="$2"
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
got="$(md5 020000001007 020000001007)"; [ "$got" = "accept none" ] && ok "UniFi MAC-Based (EAP-MD5), camera on the allow list, monitor mode → $got" || bad "UniFi MAC-Based camera → expected 'accept none', got '$got'"
got="$(md5 020000001099 020000001099)"; [ "$got" = "reject" ] && ok "UniFi MAC-Based, not on the allow list → $got" || bad "UniFi MAC-Based unknown device → expected 'reject', got '$got'"

step "11. Enrollment packages with wired settings, and the Windows wired kit"
drive call PUT /radius '{"server_hostname": "radius.lab.easyeap.test", "ssid": "EasyEAP-Lab", "wired_enabled": true}' \
  | jok "wired settings in enrollment packages turned on" 'd["status"] == 200 and d["body"]["settings"]["wired_enabled"]'
drive enroll nina macos | jok "macOS: the portal says wired, and the profile has the Ethernet payload" \
  'd["info"]["network"]["wired"] and "com.apple.globalethernet.managed" in d["csr"]["profiles"]["mobileconfig_template"]'
drive enroll nina linux | jok "Linux: wired NetworkManager and wpa_supplicant files" \
  'd["csr"]["profiles"]["networkmanager_wired"] and "802-1x" in d["csr"]["profiles"]["networkmanager_wired"] and d["csr"]["profiles"]["wpa_supplicant_wired"]'
drive call GET /radius/wired-kit | jok "Windows wired kit: a LAN profile and an install script, no private key" \
  'd["status"] == 200 and "LANProfile" in d["body"]["files"][0]["content"] and "PRIVATE KEY" not in str(d)'

if [ "${E2E_ADMIN:-1}" != 0 ]; then
step "11b. Device administration: switch logins with AD and EasyEAP accounts over TACACS+"
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
OV="$(drive call GET /device-admin)"
echo "$OV" | jok "the RADIUS node runs the TACACS+ service; built-in roles exist" \
  'd["status"] == 200 and d["body"]["agent"]["supported"] and {r["name"] for r in d["body"]["roles"]} >= {"Network administrator", "Read-only"}'
R15="$(echo "$OV" | jget 'next(r["id"] for r in d["body"]["roles"] if r["priv_lvl"] == 15)')"
R1="$(echo "$OV" | jget 'next(r["id"] for r in d["body"]["roles"] if r["priv_lvl"] == 1)')"
EN="$(drive call POST "/device-admin/devices/$SW1_ID/enable" '{"enabled": true}')"
echo "$EN" | jok "admin logins on for $SW1_IP: a 40-character TACACS+ key, shown once" 'd["status"] == 200 and len(d["body"]["key"]) == 40 and d["body"]["device"]["admin_enabled"]'
TKEY="$(echo "$EN" | jget 'd["body"]["key"]')"
drive call POST "/device-admin/devices/$SW1_ID/enable" '{"enabled": true}' | jok "turning it on again doesn't show the key again" 'd["status"] == 200 and d["body"]["key"] is None'
drive call POST "/device-admin/devices/$SW2_ID/enable" '{"enabled": true}' | jok "UniFi (no TACACS+ for its administrators): refused with the reason" \
  'd["status"] == 422 and d["body"]["detail"]["code"] == "not_supported"'
drive call GET "/device-admin/devices/$SW1_ID/config" | jok "IOS-XE configuration: EasyEAP server, local fallback, console stays local; the key is a placeholder" \
  'd["status"] == 200 and "tacacs server EASYEAP-ADMIN-" in d["body"]["config"] and "group EASYEAP-ADMIN local" in d["body"]["config"] and "login authentication EASYEAP-CONSOLE" in d["body"]["config"] and "<tacacs-key>" in d["body"]["config"] and "'"$TKEY"'" not in str(d)'
drive call GET "/radius/clients/$SW1_ID/wired-guide" | jok "the switch's 802.1X configuration no longer sets local-only login lists" \
  'd["status"] == 200 and "aaa authentication login default local" not in d["body"]["cli"]'
drive call POST /device-admin/users "{\"username\": \"ops-local\", \"display_name\": \"Ops contractor\", \"role_id\": \"$R15\", \"password\": \"password12345678\"}" \
  | jok "a common password is refused" 'd["status"] == 422 and d["body"]["detail"]["field"] == "password"'
LPW="Plover-Granite-Lantern-47"
drive call POST /device-admin/users "{\"username\": \"ops-local\", \"display_name\": \"Ops contractor\", \"role_id\": \"$R15\", \"password\": \"$LPW\"}" \
  | jok "EasyEAP account ops-local created (Network administrator)" 'd["status"] == 201 and d["body"]["user"]["status"] == "active"'
DIR_GROUPS="$(drive call GET /directory/groups)"
G_IT="$(echo "$DIR_GROUPS" | jget 'next(g["id"] for g in d["body"]["groups"] if g["name"] == "IT Dept")')"
G_STAFF="$(echo "$DIR_GROUPS" | jget 'next(g["id"] for g in d["body"]["groups"] if g["name"] == "Staff")')"
drive call POST /device-admin/maps "{\"group_id\": \"$G_IT\", \"role_id\": \"$R15\"}" | jok "AD group IT Dept → Network administrator" 'd["status"] == 201'
drive call POST /device-admin/maps "{\"group_id\": \"$G_STAFF\", \"role_id\": \"$R1\"}" | jok "AD group Staff → Read-only (after IT Dept)" 'd["status"] == 201'
drive call GET /device-admin | jok "who can log in: nina (nested Network Team → IT Dept) at 15, bob at 1, not carol" \
  'any(a["username"] == "nina" and a["priv_lvl"] == 15 for a in d["body"]["admits"]) and any(a["username"] == "bob" and a["priv_lvl"] == 1 for a in d["body"]["admits"]) and not any(a["username"] == "carol" for a in d["body"]["admits"])'
must "wait for device-admin data" drive wait-admin && ok "RADIUS has the accounts and key, and TACACS+ runs"
# tac <key> <client args…>: the IOS-like client (tests/radius/tacacs_client.py) on the switch container
tac() { local key="$1"; shift; docker exec -i "$SW1" python3 - --host "$RADIUS_IP" --port 4949 --key "$key" "$@" < "$ROOT/tests/radius/tacacs_client.py" 2>&1; }
texpect() { local got; got="$(tac "${@:3}")"; [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"; }
texpect "EasyEAP account over SSH" "GETPASS PASS" "$TKEY" login ops-local "$LPW"
texpect "exec authorization: privilege 15" "PASS_ADD priv-lvl=15" "$TKEY" author ops-local
texpect "exec authorization for a session the switch authenticated itself (local): ERROR, the switch decides" "ERROR" "$TKEY" --method 5 author ops-local
texpect "nina's AD password (nested group, checked in AD at login)" "GETPASS PASS" "$TKEY" login nina 'Lab-Passw0rd-123!'
texpect "nina by UPN, over telnet" "GETUSER GETPASS PASS" "$TKEY" --telnet login nina@lab.easyeap.test 'Lab-Passw0rd-123!'
texpect "nina gets privilege 15 from IT Dept" "PASS_ADD priv-lvl=15" "$TKEY" author nina
texpect "bob's AD password: the Staff mapping admits him" "GETPASS PASS" "$TKEY" login bob 'Lab-Passw0rd-123!'
texpect "bob gets privilege 1 (Read-only)" "PASS_ADD priv-lvl=1" "$TKEY" author bob
texpect "bob can't enable to 15" "GETPASS FAIL" "$TKEY" --priv 15 enable bob 'Lab-Passw0rd-123!'
texpect "carol (no mapped group): refused" "GETPASS FAIL" "$TKEY" login carol 'Lab-Passw0rd-123!'
texpect "nina with a wrong password: refused" "GETPASS FAIL" "$TKEY" login nina 'not-her-password'
texpect "command accounting with a secret in it" "SUCCESS" "$TKEY" --cmd "snmp-server community S3cr3tCommunity RO <cr>" acct nina stop
tac "wrong-key-for-this-switch" login nina 'Lab-Passw0rd-123!' >/dev/null   # the reply is under the real key: unreadable here
why=""
for _ in $(seq 1 20); do
  why="$(drive call GET '/device-admin/events?hours=1&page_size=200' | lab check-script '
ev = d["body"]["items"]
k = {(e["kind"], e["result"], e["reason"], e["username"], e["source"]) for e in ev}
assert ("login", "pass", None, "ops-local", "local") in k, k
assert ("login", "pass", None, "nina", "directory") in k and ("login", "pass", None, "bob", "directory") in k, k
# carol is in no mapped group, so she is no candidate: refused without a bind, logged under a keyed hash
assert any(e["kind"] == "login" and e["result"] == "fail" and e["reason"] == "admin_unknown_user" and e["username"].startswith("unknown:") for e in ev), k
assert not any(e["username"] == "carol" for e in ev), k
assert any(e["reason"] == "admin_bad_password" and e["username"] == "nina" for e in ev), k
assert any(e["reason"] == "admin_priv_too_high" for e in ev), k
assert any(e["kind"] == "authz" and e["result"] == "error" and e["reason"] == "admin_not_easyeap_login" for e in ev), k
assert any(e["kind"] == "command" and e["command"] == "snmp-server community ***** RO <cr>" for e in ev), [e["command"] for e in ev]
assert "S3cr3tCommunity" not in str(d)
assert any(e["reason"] == "admin_bad_key" for e in ev), "no admin_bad_key event"
assert all(e["client_id"] == "'"$SW1_ID"'" for e in ev), [e["client_id"] for e in ev]')" && break
  sleep 3
done
[ -z "$why" ] && ok "Admin log: every login with its source and reason, the command's secret masked" || bad "admin log: $why"
drive call GET /device-admin | jok "last login shown for the switch and the EasyEAP account" \
  'next(x for x in d["body"]["devices"] if x["id"] == "'"$SW1_ID"'")["last_login_at"] and next(u for u in d["body"]["users"] if u["username"] == "ops-local")["last_login_at"]'
drive call PUT /device-admin/settings '{"local_only_usernames": ["breakglass"], "retention_days": 180}' | jok "break-glass name set" 'd["status"] == 200'
RK="$(drive call POST "/device-admin/devices/$SW1_ID/rotate-key")"
echo "$RK" | jok "key rotated: the old one works for 24 hours" 'd["status"] == 200 and len(d["body"]["key"]) == 40 and d["body"]["device"]["previous_key_until"]'
TKEY2="$(echo "$RK" | jget 'd["body"]["key"]')"
must "wait for device-admin data" drive wait-admin
texpect "the new key works" "GETPASS PASS" "$TKEY2" login ops-local "$LPW"
texpect "the old key still works during the grace period" "GETPASS PASS" "$TKEY" login ops-local "$LPW"
texpect "the break-glass name: ERROR, so the switch uses its own account" "GETPASS ERROR" "$TKEY2" login breakglass x
drive call POST "/device-admin/devices/$SW1_ID/enable" '{"enabled": false}' | jok "admin logins off" 'd["status"] == 200 and not d["body"]["device"]["admin_enabled"]'
must "wait for device-admin data" drive wait-admin
got="$(tac "$TKEY2" login ops-local "$LPW")"
case "$got" in CLOSED|CONNECT-FAILED*) ok "with admin logins off, EasyEAP doesn't answer the switch, so it uses its local accounts → $got" ;;
  *) bad "admin logins off: expected no answer, got '$got'" ;; esac
fi
fi

step "12. Audit"
$DC exec -T easyeap-api easyeap verify-audit | grep -q '^OK' && ok "audit hash chain verifies" || bad "audit chain verification failed"

# Lab keys and the shared secret are removed unless E2E_KEEP=1 (debugging).
[ -n "${E2E_KEEP:-}" ] || rm -f "${CERTS:?}"/*.key "${CERTS:?}/secret"
printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[ "$FAILED" -eq 0 ]

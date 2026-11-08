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
# switch logins with AD groups and EasyEAP accounts, the Admin log, key rotation, break-glass; the switch audit (SNMP
# from a pretend Catalyst: every finding, hysteresis, acknowledgement, a replaced switch, wrong keys, Poll now, v2c).
#
#   E2E_DEPLOY_DIR=<dir>   a deployment directory other than deploy/ (COMPOSE_PROJECT_NAME and COMPOSE_FILE are honoured)
#   E2E_WIRED=0            skip the wired 802.1X steps (a build from before wired 802.1X)
#   E2E_ADMIN=0            skip the device-administration (TACACS+) steps (a build from before device administration)
#   E2E_WINSETUP=0         skip the Windows setup steps (a build from before the Windows setup)
#   E2E_AUDIT=0            skip the switch audit steps (a build from before the switch audit)
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

if [ "${E2E_WINSETUP:-1}" != 0 ]; then
step "11a. Windows setup: user and computer certificates from one download, renewal, the computer certificate on the network"
WS="$(drive winsetup nina)"
for c in file:"the setup is one .cmd with two one-time codes and no key; sign-in mode machineOrUser" \
         user_code_once:"the user's code works once" computer_code_once:"the computer's code works once" \
         purposes:"a user certificate and a device certificate (the PC's) for nina" \
         pc_named:"both belong to one device named by the PC (PC-NINA01), which is in the certificate's name" \
         key_storage:"where Windows kept each key is recorded (TPM, software)" \
         not_yet:"renewal before the window issues nothing" computer_only_mode:"a computer-only setup uses the computer's certificate always" \
         wrong_key_refused:"a renewal signed by another key is refused" stale_refused:"a renewal signed an hour ago is refused" \
         same_key_refused:"a renewal that reuses the old key is refused" \
         renewed:"inside the window: a new certificate, the old one superseded, same device, key storage recorded" \
         renews_once:"a certificate renews once"; do
  echo "$WS" | jok "${c#*:}" "d['checks']['${c%%:*}']"
done
echo "$WS" | python3 -c 'import json,sys; d=json.load(sys.stdin); open(sys.argv[1]+"/nina-pc.pem","w").write(d["cert_pem"]); open(sys.argv[1]+"/nina-pc.key","w").write(d["key_pem"])' "$CERTS" \
  && chmod 644 "$CERTS/nina-pc.pem" "$CERTS/nina-pc.key"
must "wait for snapshot" drive wait
expect nina-pc "accept 120" "the renewed computer certificate connects with nina's VLAN"
fi

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

if [ "${E2E_AUTOENROLL:-1}" != 0 ]; then
step "11c. Group Policy autoenrollment: Kerberos from the lab DC, policy and certificates through the proxy, the computer on the network"
AE_HOST="$(grep '^EASYEAP_HOSTNAME=' .env | cut -d= -f2)"
AE_IMAGE="easyeap-api:$(grep '^EASYEAP_VERSION=' .env | cut -d= -f2)"
AD="$DC exec -T easyeap-lab-ad"
case "$AE_HOST" in *.*[a-z]*) ;; *) bad "EASYEAP_HOSTNAME is $AE_HOST: Kerberos needs a DNS name (the lab uses easyeap.lab.easyeap.test)";; esac
PROXY_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$($DC ps -q easyeap-proxy)")"
cat > "$CERTS/krb5.conf" <<CONF
[libdefaults]
    default_realm = LAB.EASYEAP.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 0
[realms]
    LAB.EASYEAP.TEST = {
        kdc = dc1.lab.easyeap.test
    }
CONF
pc() { # pc <scenario> <principal> <password> [json] → the client's JSON (a Windows PC, as far as EasyEAP can tell)
  docker run --rm -u 0 --network "$NET" --add-host "$AE_HOST:$PROXY_IP" -e AE_HOST="$AE_HOST" -e AE_PORT=8443 -e KRB5_CONFIG=/certs/krb5.conf \
    -e PYTHONDONTWRITEBYTECODE=1 -v "$ROOT/tests/e2e":/e2e:ro -v "$DEPLOY/secrets/tls.crt":/t/tls.crt:ro -v "$CERTS":/certs \
    --entrypoint python3 "$AE_IMAGE" /e2e/autoenroll_client.py "$@"
}
checks() { # … | checks <prefix> name:"description" … — one PASS/FAIL per check the client reported
  local out; out="$(cat)"; local prefix="$1"; shift
  for c in "$@"; do echo "$out" | jok "$prefix: ${c#*:}" "d['checks'].get('${c%%:*}') is True" || true; done
  echo "$out" | lab check 'all(v is True for v in d["checks"].values())' >/dev/null || echo "    notes: $(echo "$out" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["notes"])[:900])')"
}

# The service account, SPN and keytab, made by EasyEAP's own script for Samba AD.
SA="$(drive call GET '/autoenroll/script?flavor=samba')"
echo "$SA" | jok "the service-account script for Samba AD registers HTTP/$AE_HOST" "d['status'] == 200 and 'HTTP/$AE_HOST' in d['body']['content']"
$AD samba-tool user delete easyeap-cep >/dev/null 2>&1 || true  # each run makes the account from scratch
if SA_OUT="$(echo "$SA" | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["body"]["content"])' \
  | $AD sh -c 'mkdir -p /tmp/ae && cd /tmp/ae && cat > sa.sh && sh sa.sh' 2>&1)"; then ok "the script ran on the DC"
else bad "the service-account script failed on the DC: $(echo "$SA_OUT" | tail -n 3)"; fi
KT="$($AD sh -c 'base64 -w0 /tmp/ae/easyeap-cep.keytab')"
drive call PUT /autoenroll/keytab "{\"keytab_b64\": \"$KT\"}" | jok "keytab uploaded: a key for HTTP/$AE_HOST in LAB.EASYEAP.TEST, AES, no problems" \
  "d['status'] == 200 and d['body']['config']['keytab']['principal'] == 'HTTP/$AE_HOST@LAB.EASYEAP.TEST' and not d['body']['config']['keytab']['problems'] and any('aes256' in e for e in d['body']['config']['keytab']['enctypes'])"
drive call PUT /autoenroll/keytab '{"keytab_b64": "BQIAAAAQ"}' | jok "a damaged keytab is refused with the reason" 'd["status"] == 400'
drive call PUT /autoenroll/keytab "{\"keytab_b64\": \"$KT\"}" >/dev/null
drive call POST /autoenroll/keytab/test | jok "keytab test: the DC issues a ticket for the console's SPN to the bind account and the keytab opens it" \
  'd["status"] == 200 and d["body"]["config"]["keytab_test"]["ok"]'
FULL="$($AD sh -c 'rm -f /tmp/ae/full.kt && samba-tool domain exportkeytab /tmp/ae/full.kt >/dev/null && base64 -w0 /tmp/ae/full.kt; rm -f /tmp/ae/full.kt')"
drive call PUT /autoenroll/keytab "{\"keytab_b64\": \"$FULL\"}" | jok "a whole-domain keytab (with krbtgt) is refused, not stored" 'd["status"] == 400 and "krbtgt" in d["body"]["detail"]'

# Computers and a user in AD. --prepare-oldjoin sets a computer's password to its name in lower case.
# A domain join sets dNSHostName; samba-tool computer create doesn't.
for c in PC-AE01 PC-AE02; do
  $AD samba-tool computer delete "$c" >/dev/null 2>&1; must "create computer $c" $AD samba-tool computer create "$c" --prepare-oldjoin
  printf 'dn: CN=%s,CN=Computers,DC=lab,DC=easyeap,DC=test\nchangetype: modify\nreplace: dNSHostName\ndNSHostName: %s.lab.easyeap.test\n' "$c" "$(echo "$c" | tr 'A-Z' 'a-z')" \
    | $AD sh -c 'ldbmodify -H /var/lib/samba/private/sam.ldb' >/dev/null || bad "set $c's dNSHostName"
done
$AD samba-tool user delete 'evil$' >/dev/null 2>&1; must "create user evil\$" $AD samba-tool user add 'evil$' 'Lab-Passw0rd-123!'
$AD samba-tool group delete "Corporate PCs" >/dev/null 2>&1
must "create group Corporate PCs" $AD samba-tool group add "Corporate PCs"
must "PC-AE01 in Corporate PCs" $AD samba-tool group addmembers "Corporate PCs" 'PC-AE01$'
DNS1="$($AD samba-tool computer show PC-AE01 --attributes=dNSHostName | awk '/^dNSHostName:/ {print $2}')"
must "directory sync" drive sync
GROUPS_JSON="$(drive call GET /directory/groups)"
DCG="$(echo "$GROUPS_JSON" | python3 -c 'import json,sys; print(next(g["id"] for g in json.load(sys.stdin)["body"]["groups"] if g["name"] == "Domain Computers"))')"
CPG="$(echo "$GROUPS_JSON" | python3 -c 'import json,sys; print(next(g["id"] for g in json.load(sys.stdin)["body"]["groups"] if g["name"] == "Corporate PCs"))')"
V130="$(drive call POST /policy/vlans '{"vlan_id": 130, "name": "Domain PCs"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["id"])')"
drive call POST /policy/rules "{\"name\": \"Domain PCs\", \"action\": \"allow\", \"vlan_ref\": \"$V130\", \"group_ids\": [\"$DCG\"], \"purposes\": [\"computer\"]}" \
  | jok "a rule for Domain Computers, domain computer certificates only" 'd["status"] in (200, 201) and d["body"]["purposes"] == ["computer"]'

drive call GET /autoenroll | jok "before turning it on: the readiness list asks for nothing but the policy and quota" \
  '[i["key"] for i in d["body"]["readiness"] if i["level"] == "error"] == [] and not d["body"]["config"]["enabled"]'
drive call PUT /autoenroll '{"enabled": true, "computers": true, "users": true, "computer_group_id": null, "require_channel_binding": true, "response_format": "unsigned"}' \
  | jok "turned on: computer and user templates with AD CS-style OIDs, revision 100.0, ready" \
  'd["status"] == 200 and d["body"]["ready"] and sorted(t["kind"] for t in d["body"]["templates"]) == ["computer", "user"] and all(t["oid"].startswith("1.3.6.1.4.1.311.21.8.") and t["revision"] == "100.0" for t in d["body"]["templates"])'
ST="$(drive call GET /autoenroll)"
echo "$ST" | jok "readiness: the MachineAccountQuota warning (Samba's default is 10, read at the last sync)" \
  'any(i["key"] == "quota" and i["level"] == "warning" and "10" in i["message"] for i in d["body"]["readiness"])'
USER_OID="$(echo "$ST" | python3 -c 'import json,sys; print(next(t["oid"] for t in json.load(sys.stdin)["body"]["templates"] if t["kind"] == "user"))')"

pc computer 'PC-AE01$' pc-ae01 "{\"dns\": \"$DNS1\", \"save\": \"/certs/pc-ae01\"}" | checks "PC-AE01" \
  challenge:"no ticket: 401 Negotiate" mutual_auth:"mutual authentication completes" one_template:"the policy offers the computer template only" \
  template_flags:"machine template, autoenroll, RSA 2048, TPM provider first, subject from dNSHostName" template_ext:"the template extension matches the OID and revision" \
  ca:"one CA: Kerberos, the enrollment URL" issued:"Issued, RelatesTo our MessageID, a RequestID" same_key:"the certificate carries the PC's key" \
  issuer:"signed by the CA in the policy" key_usage:"key usage: digital signature only" eku:"client authentication only" not_ca:"not a CA" \
  cert_template_ext:"the certificate names the template and revision" names:"CN and DNS SAN are the AD dNSHostName ($DNS1)" \
  chain:"the PKCS#7 response carries the certificate and the CA" cmc_success:"CMC status success for body part 1 (a bare PKCS#10)"
pc refusals 'PC-AE01$' pc-ae01 "{\"user_oid\": \"$USER_OID\"}" | checks "PC-AE01" \
  unbound_refused:"a ticket without channel binding is refused (binding required)" wrong_binding_refused:"a ticket bound to another TLS connection is refused" \
  other_template_refused:"the user template's OID: CERTSRV_E_TEMPLATE_DENIED" weak_key_refused:"an RSA 1024 key: CERTSRV_E_KEY_LENGTH, invalid request" \
  garbage_refused:"a SOAP body that isn't a request: 400"
pc user alice 'Lab-Passw0rd-123!' "{\"upn\": \"alice@lab.easyeap.test\", \"machine\": \"$DNS1\"}" | checks "alice on PC-AE01" \
  one_template:"the policy offers the user template only" template_flags:"user template, subject from the directory (UPN)" \
  issued:"Issued" names:"CN and UPN SAN are alice@lab.easyeap.test" cmc_success:"CMC status success for the CMC body part (7)" chain:"chain in the response"
pc cep 'evil$' 'Lab-Passw0rd-123!' | jok "a user account named evil\$ isn't a computer: an empty policy, as from AD CS" \
  'd["notes"]["status"] == 200 and d["notes"]["templates"] == []'

drive call PUT /autoenroll "{\"enabled\": true, \"computers\": true, \"users\": true, \"computer_group_id\": \"$CPG\", \"require_channel_binding\": true, \"response_format\": \"unsigned\"}" \
  | jok "limited to the Corporate PCs group: the quota warning goes" 'd["status"] == 200 and not any(i["key"] == "quota" for i in d["body"]["readiness"])'
pc cep 'PC-AE02$' pc-ae02 | jok "PC-AE02 (not in Corporate PCs) is offered nothing" 'd["notes"]["status"] == 200 and d["notes"]["templates"] == []'
pc cep 'PC-AE01$' pc-ae01 | jok "PC-AE01 (in Corporate PCs) still gets the policy" 'd["notes"]["status"] == 200 and d["notes"]["templates"] == ["EasyEAP-Computer"]'

drive call POST /autoenroll/reenroll '{"kind": "computer"}' | jok "re-enroll every PC: computer template revision 101.0" \
  'd["status"] == 200 and next(t for t in d["body"]["templates"] if t["kind"] == "computer")["revision"] == "101.0"'
SECOND="$(pc computer 'PC-AE01$' pc-ae01 "{\"dns\": \"$DNS1\", \"save\": \"/certs/pc-ae01b\"}")"
echo "$SECOND" | jok "PC-AE01 enrolls again with revision 101" 'd["checks"]["issued"] and d["notes"]["template_rev"] == [101, 0] and d["checks"]["cert_template_ext"]'
PCID="$(drive call GET '/identities?kind=computer' | python3 -c 'import json,sys; print(next(i["id"] for i in json.load(sys.stdin)["body"]["items"] if i["username"] == "PC-AE01$"))')"
drive call GET "/identities?kind=computer" | jok "Computers: PC-AE01\$ with its DNS name and AD groups (Domain Computers, Corporate PCs)" \
  "any(i['username'] == 'PC-AE01\$' and i['kind'] == 'computer' and i['dns_name'] == '$DNS1' and {'Domain Computers', 'Corporate PCs'} <= {g['name'] for g in i['groups']} for i in d['body']['items'])"
drive call GET "/identities?page_size=200" | jok "People doesn't list computers" 'all(i["kind"] == "user" for i in d["body"]["items"])'
drive call GET "/certificates?identity_id=$PCID" | jok "two computer certificates; the first is marked renewed by the second" \
  'len(d["body"]["items"]) == 2 and all(c["purpose"] == "computer" for c in d["body"]["items"]) and sum(1 for c in d["body"]["items"] if c["renewed_at"] and c["status"] == "superseded") == 1 and sum(1 for c in d["body"]["items"] if c["renewal_of"]) == 1'
for i in 3 4 5; do pc computer 'PC-AE01$' pc-ae01 "{\"dns\": \"$DNS1\"}" > "$CERTS/ae-limit-$i.json"; done
lab check 'd["checks"].get("issued") is True' < "$CERTS/ae-limit-4.json" && python3 - "$CERTS/ae-limit-5.json" <<'PY' && ok "the fifth computer certificate in a day is refused (limit)" || bad "the daily limit didn't refuse the fifth certificate"
import json, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d["notes"].get("ces_status") == 500 and "24 hours" in d["notes"]["ces_fault"]["reason"] else 1)
PY

drive call GET "/autoenroll/events?limit=200" | jok "the request log: issued, refused (binding, template, key, not a computer, not in the group, limit)" \
  '{e["code"] for e in d["body"]["events"] if e["outcome"] == "denied"} >= {"binding", "template", "key", "not_computer", "not_in_group", "limit"} and sum(1 for e in d["body"]["events"] if e["service"] == "ces" and e["outcome"] == "ok") >= 4'
must "wait for snapshot" drive wait
expect pc-ae01b "accept 130" "the PC's autoenrolled certificate connects as the computer: Domain Computers → VLAN 130"
expect alice "accept 120" "alice's own certificate still gets IT (120)"
# Whoever creates a computer account can write its dNSHostName: a certificate only names the computer's own.
drive call PUT /autoenroll '{"enabled": true, "computers": true, "users": true, "computer_group_id": null, "require_channel_binding": true, "response_format": "unsigned"}' >/dev/null
printf 'dn: CN=PC-AE02,CN=Computers,DC=lab,DC=easyeap,DC=test\nchangetype: modify\nreplace: dNSHostName\ndNSHostName: dc1.lab.easyeap.test\n' \
  | $AD sh -c 'ldbmodify -H /var/lib/samba/private/sam.ldb' >/dev/null
pc computer 'PC-AE02$' pc-ae02 '{"dns": "dc1.lab.easyeap.test"}' | jok "PC-AE02 with the DC's DNS name is refused" \
  'd["notes"].get("ces_status") == 500 and "match its account name" in d["notes"]["ces_fault"]["reason"]'
drive call PUT /autoenroll '{"enabled": false, "computers": true, "users": true, "computer_group_id": null, "require_channel_binding": true, "response_format": "unsigned"}' >/dev/null
pc cep 'PC-AE01$' pc-ae01 | jok "turned off: EasyEAP doesn't answer Group Policy" 'd["notes"]["status"] == 404'
fi


if [ "${E2E_AUDIT:-1}" != 0 ] && [ -n "${SW1_ID:-}" ]; then
step "11d. Switch audit: SNMP and syslog from a pretend Catalyst, findings against EasyEAP's own answers"
LABSW="$DC exec -T easyeap-lab-switch"
LABSW_IP="$(ip_of "$($DC ps -q easyeap-lab-switch)")"
# dataset <json spec> — what the pretend switch reports (tests/e2e/lab_switch.py)
dataset() { python3 "$ROOT/tests/e2e/lab_switch.py" "$1" | $LABSW sh -c 'cat > /lab/data/new.json && mv /lab/data/new.json /lab/data/dataset.json'; }
spoll() { $DC exec -T easyeap-collector python -m app.switchaudit.collector --once "$SW1_ID" 2>/dev/null | tail -1; }
SCENE='{"ports": {"2": {"open": true}, "3": {"control": 3}}, "errdis": {"10": 2}, "sessions": [
  {"port": 1, "mac": "02:00:00:00:11:01", "vlan": 220, "user": "nina"},
  {"port": 4, "mac": "02:00:00:00:99:01"},
  {"port": 5, "mac": "02:00:00:00:11:03"},
  {"port": 6, "mac": "02:00:00:00:11:02", "vlan": 999},
  {"port": 8, "mac": "02:00:00:00:10:08", "method": "mab"},
  {"port": 9, "mac": "02:00:00:00:99:02", "critical": 60},
  {"port": 11, "mac": "02:00:00:00:99:03", "status": 5}]}'
must "write the switch's dataset" dataset "$SCENE"
# A MAB device EasyEAP accepted, then blocked without the switch hearing of it (no CoA on this lab switch).
T5="$(lab now)"
mexpect "camera 02:00:00:00:10:08 on the allow list: accepted (monitor mode)" "accept none" "$SW1" "$SW1_SECRET" 020000001008
CAM_ID="$(drive call GET /mac | python3 -c 'import json,sys; print(next(x["id"] for x in json.load(sys.stdin)["body"]["devices"] if x["mac"] == "02:00:00:00:10:08"))')"
event "the camera's accept is logged" "$T5" "e['method'] == 'mab' and e['device_mac'] == '020000001008' and e['result'] == 'accept'"
drive call PUT "/mac/devices/$CAM_ID" '{"enabled": false}' | jok "camera blocked on the allow list" 'd["status"] == 200'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "enforce", "confirmed": true}' | jok "lab-access-1 enforcing" 'd["status"] == 200'

drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "not set up yet; the switch's RADIUS address offered as the SNMP address" \
  'd["status"] == 200 and not d["body"]["monitoring"]["set_up"] and d["body"]["default_host"] == "'"$SW1_IP"'" and d["body"]["config"] is None'
drive call POST "/radius/clients/$SW2_ID/monitoring/setup" '{"host": "10.0.0.9"}' | jok "a UniFi switch can't be audited over SNMP" 'd["status"] == 400'
drive call POST "/radius/clients/$SW1_ID/monitoring/setup" '{"host": "127.0.0.1"}' | jok "a loopback address is refused, naming the field" 'd["status"] == 422 and d["body"]["detail"]["field"] == "host"'
drive call POST "/radius/clients/$SW1_ID/monitoring/setup" "{\"host\": \"$LABSW_IP\", \"version\": \"v3\", \"auth\": \"sha\", \"priv\": \"aes256\"}" \
  | jok "AES-256 with SHA-1 is refused" 'd["status"] == 422 and d["body"]["detail"]["field"] == "priv"'
SETUP="$(drive call POST "/radius/clients/$SW1_ID/monitoring/setup" "{\"host\": \"$LABSW_IP\", \"version\": \"v3\", \"interval_minutes\": 15}")"
echo "$SETUP" | jok "SNMPv3 set up: keys shown once, the block has placeholders, monitoring off until tested" \
  'd["status"] == 200 and len(d["body"]["credentials"]["auth_key"]) == 24 and d["body"]["credentials"]["auth_key"] not in d["body"]["config"] and "snmp-server user easyeap EASYEAP v3 auth sha-2 256 <authentication key> priv aes 128 <privacy key>" in d["body"]["config"] and not d["body"]["monitoring"]["enabled"]'
AUTHK="$(echo "$SETUP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["credentials"]["auth_key"])')"
PRIVK="$(echo "$SETUP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["credentials"]["priv_key"])')"
drive call POST "/radius/clients/$SW1_ID/monitoring/test" | jok "Test connection before the switch is configured: no answer" 'd["status"] == 200 and not d["body"]["ok"] and d["body"]["error_kind"] in ("timeout", "auth")'
must "configure the lab switch (SNMPv3 SHA-256/AES-128)" $LABSW /lab/configure.sh - easyeap "$AUTHK" "$PRIVK" SHA-256 AES
sleep 2
drive call POST "/radius/clients/$SW1_ID/monitoring/test" | jok "Test connection: the model, IOS-XE version and serial, the 802.1X tables answer; monitoring on" \
  'd["body"]["ok"] and d["body"]["facts"]["model"] == "C9300-48P" and d["body"]["facts"]["version"] == "17.9.4a" and d["body"]["facts"]["serial"] == "FOC1234X0AB" and d["body"]["capabilities"] == {"caf": True, "errdisable": True} and d["body"]["monitoring"]["enabled"]'
spoll | jok "the collector polls the switch: 24 ports, 7 sessions" 'd["ok"] and d["ports"] == 24 and d["sessions"] == 7'
spoll >/dev/null
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "after two polls: every staged finding is open, and nothing for nina's correct session or the excluded uplink" \
  '{(f["kind"], f["port"], f["mac"]) for f in d["body"]["findings"]} == {("open_access_in_enforce", "GigabitEthernet1/0/2", None), ("port_not_covered", "GigabitEthernet1/0/3", None), ("authorized_without_easyeap", "GigabitEthernet1/0/4", "020000009901"), ("authorized_despite_reject", "GigabitEthernet1/0/5", "020000001103"), ("vlan_mismatch", "GigabitEthernet1/0/6", "020000001102"), ("authorized_after_deny", "GigabitEthernet1/0/8", "020000001008"), ("critical_auth", "GigabitEthernet1/0/9", "020000009902"), ("err_disabled", "GigabitEthernet1/0/10", None)}'
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "severities and details: the VLAN EasyEAP sent, why the camera is denied, the err-disable cause; the polled sessions are stored" \
  '(lambda f: f["vlan_mismatch"]["detail"]["sent"] == 220 and f["vlan_mismatch"]["detail"]["vlan"] == 999 and f["authorized_after_deny"]["detail"]["reason"] == "blocked on the MAC allow list" and f["err_disabled"]["detail"]["cause"] == "BPDU guard" and f["authorized_despite_reject"]["severity"] == "critical" and f["port_not_covered"]["severity"] == "critical")({x["kind"]: x for x in d["body"]["findings"]}) and len(d["body"]["state"]["sessions"]) == 7 and d["body"]["state"]["facts"]["name"] == "lab-sw1"'
drive call GET "/radius/clients/$SW1_ID/readiness" | jok "readiness uses the switch's own sessions: 7, one not authorized" \
  'd["body"]["switch_sessions"]["sessions"] == 7 and d["body"]["switch_sessions"]["authorized"] == 6 and [r["interface"] for r in d["body"]["switch_sessions"]["would_lose_access"]] == ["GigabitEthernet1/0/11"]'
drive call GET /dashboard | jok "the dashboard lists the switch's findings as critical" \
  'any(q["code"] == "switch_audit:'"$SW1_ID"'" and q["severity"] == "critical" for q in d["body"]["queue"])'
VM_ID="$(drive call GET "/radius/clients/$SW1_ID/monitoring" | python3 -c 'import json,sys; print(next(f["id"] for f in json.load(sys.stdin)["body"]["findings"] if f["kind"] == "vlan_mismatch"))')"
drive call POST "/radius/clients/$SW1_ID/monitoring/findings/$VM_ID/ack" '{"note": "VLAN 999 is the lab quarantine"}' \
  | jok "acknowledged with a note" 'd["status"] == 200 and d["body"]["finding"]["ack_note"] == "VLAN 999 is the lab quarantine" and d["body"]["finding"]["acknowledged_by"]'
drive call GET /radius/switch-audit | jok "the summary counts open findings nobody acknowledged (3 critical, 4 warnings)" \
  'd["body"]["switches"][0]["critical"] == 3 and d["body"]["switches"][0]["warning"] == 4'

must "fix the ports on the switch" dataset "$(echo "$SCENE" | python3 -c 'import json,sys; s=json.load(sys.stdin); s["ports"]={}; print(json.dumps(s))')"
spoll >/dev/null; spoll >/dev/null
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "two clean polls later the port findings are resolved; the acknowledged one stays acknowledged" \
  '(lambda k: "open_access_in_enforce" not in k and "port_not_covered" not in k and k["vlan_mismatch"]["acknowledged_at"])({f["kind"]: f for f in d["body"]["findings"]}) and {f["kind"] for f in d["body"]["resolved"]} >= {"open_access_in_enforce", "port_not_covered"}'

must "replace the switch" dataset "$(echo "$SCENE" | python3 -c 'import json,sys; s=json.load(sys.stdin); s["ports"]={}; s["serial"]="FOC9999Z1ZZ"; print(json.dumps(s))')"
spoll >/dev/null
SC_ID="$(drive call GET "/radius/clients/$SW1_ID/monitoring" | python3 -c 'import json,sys; print(next((f["id"] for f in json.load(sys.stdin)["body"]["findings"] if f["kind"] == "switch_changed"), ""))')"
[ -n "$SC_ID" ] && ok "a different serial number at the switch's address: switch_changed after one poll" || bad "switch_changed not raised"
drive call POST "/radius/clients/$SW1_ID/monitoring/findings/$SC_ID/ack" '{"note": "replaced under RMA"}' | jok "acknowledging accepts the new switch" 'd["status"] == 200 and d["body"]["finding"]["resolved_at"]'
spoll >/dev/null
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "the new serial is pinned: no new switch_changed" \
  'd["body"]["monitoring"]["pinned"]["serial"] == "FOC9999Z1ZZ" and not any(f["kind"] == "switch_changed" for f in d["body"]["findings"])'

must "change the key on the switch" $LABSW /lab/configure.sh - easyeap "wrong-$AUTHK" "$PRIVK" SHA-256 AES
sleep 2
spoll | jok "polling with a key the switch doesn't accept fails as an authentication error" 'not d["ok"] and d["error_kind"] == "auth"'
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "snmp_auth is open at once; the session findings stay as they were (no evidence either way)" \
  '{"snmp_auth", "authorized_despite_reject"} <= {f["kind"] for f in d["body"]["findings"]}'
must "restore the key" $LABSW /lab/configure.sh - easyeap "$AUTHK" "$PRIVK" SHA-256 AES
sleep 2
spoll | jok "polling works again" 'd["ok"]'
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "snmp_auth resolved by one good poll" '"snmp_auth" not in {f["kind"] for f in d["body"]["findings"]}'

BEFORE="$(drive call GET "/radius/clients/$SW1_ID/monitoring" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["state"]["polled_at"])')"
drive call POST "/radius/clients/$SW1_ID/monitoring/poll" | jok "Poll now: accepted" 'd["status"] == 202'
drive call POST "/radius/clients/$SW1_ID/monitoring/poll" | jok "Poll now again at once: refused" 'd["status"] == 429'
polled=""
for _ in $(seq 1 20); do
  polled="$(drive call GET "/radius/clients/$SW1_ID/monitoring" | python3 -c 'import json,sys; b=json.load(sys.stdin)["body"]; print(b["state"]["polled_at"] if not b["poll_requested_at"] else "")')"
  [ -n "$polled" ] && [ "$polled" != "$BEFORE" ] && break
  sleep 3
done
[ -n "$polled" ] && [ "$polled" != "$BEFORE" ] && ok "the collector service picked up Poll now" || bad "Poll now wasn't picked up by the collector (last poll $polled)"

V2="$(drive call POST "/radius/clients/$SW1_ID/monitoring/setup" "{\"host\": \"$LABSW_IP\", \"version\": \"v2c\"}")"
echo "$V2" | jok "switching to SNMPv2c: a new community, and the lines that retire the v3 user" \
  'len(d["body"]["credentials"]["community"]) == 24 and "no snmp-server user easyeap EASYEAP v3" in d["body"]["retire"] and "snmp-server community <community> view EASYEAP-RO RO EASYEAP-SNMP" in d["body"]["config"]'
COMM="$(echo "$V2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["body"]["credentials"]["community"])')"
must "configure the lab switch (SNMPv2c)" $LABSW /lab/configure.sh "$COMM"
sleep 2
drive call POST "/radius/clients/$SW1_ID/monitoring/test" | jok "SNMPv2c test connection" 'd["body"]["ok"] and d["body"]["monitoring"]["enabled"] and d["body"]["monitoring"]["version"] == "v2c"'
spoll | jok "SNMPv2c poll" 'd["ok"] and d["sessions"] == 7'

# Syslog (docs/plans/switch-audit.md §0a): the pretend switch sends Cisco messages from its own address straight to
# easyeap-syslog's UDP 5514 on the lab network (EASYEAP_SYSLOG_BIND publishes the same port on the host).
SYSLOG_IP="$(ip_of "$($DC ps -q easyeap-syslog)")"
SEND='import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for m in sys.argv[2:]:
    s.sendto(m.encode(), (sys.argv[1], 5514))'
say() { $LABSW python3 -c "$SEND" "$SYSLOG_IP" "$@"; }
syslog_json() { drive call GET "/radius/clients/$SW1_ID/monitoring" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["body"]["syslog"]))'; }
heard=""
for _ in $(seq 1 25); do   # easyeap-syslog reloads the switches' verified addresses every 30 s
  say "<189>21: lab-sw1: *Nov  7 22:39:22: %SYS-5-CONFIG_I: Configured from console by e2e on vty0 (10.9.9.9)"
  sleep 2
  heard="$(syslog_json | python3 -c 'import json,sys; print(json.load(sys.stdin)["stats"].get("last_at") or "")')"
  [ -n "$heard" ] && break
done
[ -n "$heard" ] && ok "syslog from the switch's address is received" || bad "no syslog received from the switch"
say "<189>101: %DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 0A0A0A0B0000000200ABCDEF" \
    "<189>102: %DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 0A0A0A0B0000000200ABCDEF" \
    "<189>103: %DOT1X-5-FAIL: Switch 1 R0/0: sessmgrd: Authentication failed for client (0200.0000.1103) on Interface Gi1/0/5 AuditSessionID 0A0A0A0B0000000200ABCDEF" \
    "<188>104: %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/10, putting Gi1/0/10 in err-disable state" \
    "<188>105: %RADIUS-4-RADIUS_DEAD: RADIUS server $RADIUS_IP:1812,1813 is not responding." \
    "<189>106: %AUTHMGR-5-FAIL: Authorization failed for client (0200.0000.1104) username=bob password hunter2 on Interface Gi1/0/7" \
    "<189>107: %SESSION_MGR-5-START: Switch 1 R0/0: sessmgrd: Starting 'dot1x' for client (0200.0000.1105) on Interface Gi1/0/7"
$DC exec -T easyeap-api python -c "$SEND" "$SYSLOG_IP" "<189>%DOT1X-5-FAIL: Authentication failed for client (0200.0000.6666) on Interface Gi1/0/1 from-elsewhere"
sleep 4
syslog_json | jok "kept: the 802.1X failures coalesced (3), the err-disable, the RADIUS server down; a session start isn't kept" \
  '(lambda r: sum(x["count"] for x in r if x["tag"] == "DOT1X-5-FAIL" and x["mac"] == "020000001103" and x["port"] == "GigabitEthernet1/0/5" and x["session_id"] == "0A0A0A0B0000000200ABCDEF") == 3 and any(x["tag"] == "PM-4-ERR_DISABLE" and x["port"] == "GigabitEthernet1/0/10" for x in r) and not any("START" in x["tag"] for x in r))(d["recent"]) and d["stats"]["filtered"] >= 1'
syslog_json | jok "user names and passwords redacted before they're stored" \
  '(lambda t: "hunter2" not in t and "bob" not in t and "password <redacted>" in t)(" ".join(x["text"] for x in d["recent"]))'
syslog_json | jok "a message from an address that isn't the switch is dropped" 'not any(x["mac"] == "020000006666" for x in d["recent"])'
syslog_json | jok "the switch says a RADIUS server isn't responding (per server)" \
  "[(x['tag'], x['server']) for x in d['radius_down']] == [('RADIUS-4-RADIUS_DEAD', '$RADIUS_IP')]"
syslog_json | jok "the syslog receiver's heartbeat is current" "d['listening']"
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "with syslog published, the configuration has the discriminator, then the logging host" \
  "(lambda b: not b['syslog']['receiving'] or (b['config'].index('logging discriminator EASYEAP facility includes') < b['config'].index('logging host %s discriminator EASYEAP transport udp port %s' % (b['syslog']['address'], b['syslog']['port'])) and 'no logging discriminator EASYEAP' in b['removal']))(d['body'])"
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "findings show what the switch says about their device or port" \
  '(lambda f: any(x["tag"] == "DOT1X-5-FAIL" for x in f["authorized_despite_reject"]["switch_says"]) and any(x["tag"] == "PM-4-ERR_DISABLE" for x in f["err_disabled"]["switch_says"]))({x["kind"]: x for x in d["body"]["findings"]})'
drive call GET "/radius/clients/$SW1_ID/monitoring/syslog?mac=02:00:00:00:11:03&hours=48" | jok "the switch's messages filtered by MAC" \
  'd["status"] == 200 and d["body"]["messages"] and all(x["mac"] == "020000001103" for x in d["body"]["messages"])'
# An err-disable is a hint, not a command: the next poll moves to five minutes after the last one (the interval is 15).
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "an err-disable message brought the next poll forward to 5 minutes after the last" \
  '(lambda st: 290 <= (datetime.fromisoformat(st["next_poll_at"]) - datetime.fromisoformat(st["polled_at"])).total_seconds() <= 310)(d["body"]["state"])'
say "<188>109: %RADIUS-4-RADIUS_ALIVE: RADIUS server $RADIUS_IP:1812,1813 is being marked alive."
sleep 4
syslog_json | jok "RADIUS server marked alive: no longer shown as down" 'd["radius_down"] == []'
drive call DELETE "/radius/clients/$SW1_ID/monitoring" | jok "monitoring removed: the lines to take EasyEAP's access off the switch" \
  'd["status"] == 200 and "no snmp-server view EASYEAP-RO" in d["body"]["removal"]'
drive call GET "/radius/clients/$SW1_ID/monitoring" | jok "nothing open after removal, credentials gone" 'not d["body"]["findings"] and not d["body"]["monitoring"]["set_up"]'
drive call POST "/radius/clients/$SW1_ID/wired-mode" '{"mode": "monitor"}' >/dev/null
fi

step "12. Audit"
$DC exec -T easyeap-api easyeap verify-audit | grep -q '^OK' && ok "audit hash chain verifies" || bad "audit chain verification failed"

# Lab keys and the shared secret are removed unless E2E_KEEP=1 (debugging).
[ -n "${E2E_KEEP:-}" ] || rm -f "${CERTS:?}"/*.key "${CERTS:?}/secret"
printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[ "$FAILED" -eq 0 ]

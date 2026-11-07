#!/usr/bin/env bash
# RADIUS integration test: the real FreeRADIUS 3.2 image, a configuration rendered by the agent's renderer, the
# agent's own snapshot store, and real EAP-TLS from eapol_test. No API, database or OpenBao: seconds, not minutes.
#
#   tests/radius/run.sh               # builds the two images if they're missing
#
# Covers wired 802.1X (docs/plans/wired-8021x.md): which network a request is counted as (hostapd's empty SSID,
# NAS-Port-Type, the client's registration, the SSID in Called-Station-Id), the VLAN on switch ports (mapped, or the
# port's own), refusal of a network the client isn't registered for, nested registrations, monitor mode withholding
# VLANs, the named rejection of a MAB attempt, the network and switch port in event records, and version skew with
# the 1.0.1 agent and configuration in every combination.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RADIUS_IMAGE="${RADIUS_IMAGE:-easyeap-radius:test}"
CLIENT_IMAGE="${CLIENT_IMAGE:-easyeap-lab-client:test}"
NET_NAME="easyeap-radius-test-$$"
SUBNET="${RADIUS_TEST_NET:-172.31.250}"
PASS=0 FAILED=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=$((FAILED + 1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 2; }

docker image inspect "$RADIUS_IMAGE" >/dev/null 2>&1 || docker build -q -t "$RADIUS_IMAGE" "$ROOT/services/radius" >/dev/null || die "could not build $RADIUS_IMAGE"
docker image inspect "$CLIENT_IMAGE" >/dev/null 2>&1 || docker build -q -t "$CLIENT_IMAGE" "$ROOT/services/lab-client" >/dev/null || die "could not build $CLIENT_IMAGE"

WORK="$(mktemp -d)"
chmod 755 "$WORK"
cleanup() {
  docker rm -f "$NET_NAME-fr" "$NET_NAME-fr101" "$NET_NAME-wlc" "$NET_NAME-switch" "$NET_NAME-unifi" "$NET_NAME-lab" "$NET_NAME-stranger" >/dev/null 2>&1
  docker network rm "$NET_NAME" >/dev/null 2>&1
  docker run --rm -v "$WORK":/work --entrypoint sh "$CLIENT_IMAGE" -c 'rm -rf /work/*' >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

step "1. Throwaway PKI: root, issuing CA (with its CRL), RADIUS server, three users"
docker run --rm -v "$WORK":/work --entrypoint sh "$CLIENT_IMAGE" -c '
set -e
mkdir -p /work/pki && cd /work/pki
ec() { openssl ecparam -name prime256v1 -genkey -noout -out "$1.key"; }
ec root;    openssl req -x509 -new -key root.key -subj "/CN=RADIUS Test Root" -days 30 -out root.pem \
              -addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign
ec issuing; openssl req -new -key issuing.key -subj "/CN=RADIUS Test Issuing" -out issuing.csr
printf "basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > ca.ext
openssl x509 -req -in issuing.csr -CA root.pem -CAkey root.key -CAcreateserial -days 30 -extfile ca.ext -out issuing.pem
ec server;  openssl req -new -key server.key -subj "/CN=radius.test" -out server.csr
printf "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.test\n" > server.ext
openssl x509 -req -in server.csr -CA issuing.pem -CAkey issuing.key -CAcreateserial -days 30 -extfile server.ext -out server.pem
for u in alice bob carol; do
  ec $u; openssl req -new -key $u.key -subj "/CN=$u@radius.test" -out $u.csr
  printf "extendedKeyUsage=clientAuth\n" > client.ext
  openssl x509 -req -in $u.csr -CA issuing.pem -CAkey issuing.key -CAcreateserial -days 30 -extfile client.ext -out $u.pem
done
mkdir -p ca/newcerts && touch ca/index.txt && echo 01 > ca/crlnumber
printf "[ca]\ndefault_ca=d\n[d]\ndatabase=ca/index.txt\nnew_certs_dir=ca/newcerts\ncrlnumber=ca/crlnumber\ndefault_md=sha256\ndefault_crl_days=30\n" > ca.cnf
openssl ca -config ca.cnf -gencrl -keyfile issuing.key -cert issuing.pem -out issuing.crl 2>/dev/null
cat issuing.pem root.pem > chain.pem
chmod 644 *
' || die "PKI generation failed"
ok "PKI generated"

step "2. Render FreeRADIUS with the agent's renderer; write the snapshot with the agent's store"
# The 1.0.1 agent and renderer, for the version-skew checks in step 9.
mkdir -p "$WORK/v101"
for f in easyeap_agent.py render.py; do git -C "$ROOT" show "v1.0.1:services/radius/agent/$f" > "$WORK/v101/$f" || die "could not read $f at v1.0.1"; done
chmod -R a+rX "$WORK/v101"
fixture() { docker run --rm --user root -e RADIUS_TEST_NET="$SUBNET" -v "$WORK":/work -v "$ROOT/services/radius/agent":/opt/easyeap-agent:ro \
  -v "$ROOT/tests/radius/fixture.py":/fixture.py:ro --entrypoint python3 "$RADIUS_IMAGE" /fixture.py "$@"; }
BUILD="$(fixture build)" || die "fixture build failed: $BUILD"
SECRET="$(echo "$BUILD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["secret"])')"
echo "$BUILD" | grep -q '"authz": 3, "authz_wired": 3' && ok "snapshot: one decision per certificate, a wired VLAN row for each" || bad "unexpected snapshot: $BUILD"
CHECK="$(docker run --rm --user root -v "$WORK":/work --entrypoint freeradius "$RADIUS_IMAGE" -C -d /work/state/raddb/live 2>&1)"
[ $? -eq 0 ] && ok "freeradius -C accepts the rendered configuration" || { bad "freeradius -C rejected it"; echo "$CHECK" | tail -20; exit 1; }

docker network create --subnet "$SUBNET.0/24" "$NET_NAME" >/dev/null || die "could not create the test network"
docker run -d --name "$NET_NAME-fr" --network "$NET_NAME" --ip "$SUBNET.2" --user root -v "$WORK":/work \
  --entrypoint freeradius "$RADIUS_IMAGE" -f -l stdout -d /work/state/raddb/live >/dev/null || die "FreeRADIUS did not start"
for n in wlc:10 switch:11 unifi:17 lab:20 stranger:99; do
  docker run -d --name "$NET_NAME-${n%%:*}" --network "$NET_NAME" --ip "$SUBNET.${n##*:}" -v "$WORK":/work:ro --entrypoint sleep "$CLIENT_IMAGE" 600 >/dev/null
done
for _ in $(seq 1 20); do docker logs "$NET_NAME-fr" 2>&1 | grep -q "Ready to process requests" && break; sleep 0.5; done
docker logs "$NET_NAME-fr" 2>&1 | grep -q "Ready to process requests" || { docker logs "$NET_NAME-fr" 2>&1 | tail -30; die "FreeRADIUS never became ready"; }

# auth <from> <user> <mac> [-N attr spec…] → "accept <vlan>", "accept none" (no VLAN sent) or "reject".
# RADIUS_AT picks the server (.2 this build's configuration, .3 the 1.0.1 configuration).
RADIUS_AT=2
auth() {
  local from="$1" user="$2" mac="$3"; shift 3
  local out
  out="$(docker exec -i "$NET_NAME-$from" sh -c 'cat > /tmp/sup.conf; eapol_test -c /tmp/sup.conf "$@"' sh \
    -a "$SUBNET.$RADIUS_AT" -p 1812 -s "$SECRET" -M "$mac" -t 10 "$@" 2>&1 <<CONF
network={
	key_mgmt=IEEE8021X
	eapol_flags=0
	eap=TLS
	identity="$user@radius.test"
	ca_cert="/work/pki/chain.pem"
	client_cert="/work/pki/$user.pem"
	private_key="/work/pki/$user.key"
	domain_suffix_match="radius.test"
}
CONF
)"
  if echo "$out" | grep -q "^SUCCESS"; then
    local hex; hex="$(echo "$out" | awk '/Tunnel-Private-Group-I[dD]/ { getline; sub(/.*Value: */, ""); gsub(/[^0-9A-Fa-f]/, ""); print; exit }')"
    [ -n "$hex" ] && echo "accept $(python3 -c 'import sys; print(bytes.fromhex(sys.argv[1]).decode())' "$hex")" || echo "accept none"
  else
    echo "reject"
  fi
}
expect() { # expect <description> <want> <auth args…>
  local got; got="$(auth "${@:3}")"
  [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"
}
# eapol_test always adds NAS-Port-Type = Wireless-802.11 unless told otherwise, so "no usable port type" is sent as
# Virtual (5): FreeRADIUS takes the same path as when the attribute is absent.
WIRED="61:d:15" WIFI="61:d:19" OTHER="61:d:5"

step "3. Which network a request is counted as"
expect "Catalyst 9800 (Wi-Fi only), NAS-Port-Type Wireless-802.11" "accept 100" wlc alice 02:00:00:00:01:01 -N "$WIFI" -N "30:s:00-11-22-33-44-55:Corp"
expect "Catalyst switch (wired only), NAS-Port-Type Ethernet: the wired VLAN" "accept 110" switch alice 02:00:00:00:01:02 -N "$WIRED" -N "87:s:GigabitEthernet1/0/5"
expect "Switch with no Ethernet/802.11 port type: its one registered network (wired)" "accept 110" switch alice 02:00:00:00:01:03 -N "$OTHER"
expect "UniFi (both), no port type, SSID in Called-Station-Id: Wi-Fi" "accept 100" unifi alice 02:00:00:00:01:04 -N "$OTHER" -N "30:s:00-11-22-33-44-55:Corp"
expect "UniFi (both), no port type, no SSID: wired" "accept 110" unifi alice 02:00:00:00:01:05 -N "$OTHER" -N "30:s:00-11-22-33-44-66"
expect "UniFi (both), NAS-Port-Type Ethernet wins over an SSID-like Called-Station-Id" "accept 110" unifi alice 02:00:00:00:01:06 -N "$WIRED" -N "30:s:00-11-22-33-44-55:Corp"
expect "hostapd wired form (Wireless-802.11 port type, \"MAC:\" with no SSID): wired" "accept 110" unifi alice 02:00:00:00:01:07 -N "$WIFI" -N "30:s:00-11-22-33-44-66:"

step "4. The VLAN on switch ports"
expect "bob on Wi-Fi gets his VLAN" "accept 100" wlc bob 02:00:00:00:02:01 -N "$WIFI"
expect "bob on a switch port keeps the port's own VLAN" "accept none" switch bob 02:00:00:00:02:02 -N "$WIRED"
expect "carol is denied on Wi-Fi" "reject" wlc carol 02:00:00:00:02:03 -N "$WIFI"
expect "carol is denied on a switch port" "reject" switch carol 02:00:00:00:02:04 -N "$WIRED"

step "5. Networks a client isn't registered for are refused"
expect "wired request through the Wi-Fi-only 9800" "reject" wlc alice 02:00:00:00:03:01 -N "$WIRED"
expect "Wi-Fi request through the wired-only switch" "reject" switch alice 02:00:00:00:03:02 -N "$WIFI"
expect "Wi-Fi request from the switch inside the UniFi range (longest prefix: the switch)" "reject" lab alice 02:00:00:00:03:03 -N "$WIFI" -N "30:s:00-11-22-33-44-55:Corp"

step "6. Monitor mode: decide and log, change nothing on the port"
expect "alice through the monitor-mode switch: accepted, no VLAN sent" "accept none" lab alice 02:00:00:00:05:01 -N "$WIRED" -N "87:s:GigabitEthernet1/0/9"
expect "carol through the monitor-mode switch: still rejected (the open port lets her on; the log says she'd be refused)" "reject" lab carol 02:00:00:00:05:02 -N "$WIRED"

step "7. MAC Authentication Bypass attempt from a switch"
MAB="$(docker exec "$NET_NAME-switch" sh -c "printf 'User-Name = \"020000000401\"\nUser-Password = \"020000000401\"\nService-Type = Call-Check\nNAS-Port-Type = Ethernet\nCalling-Station-Id = \"02-00-00-00-04-01\"\nMessage-Authenticator = 0x00\n' | radclient -x -t 5 -r 1 $SUBNET.2 auth '$SECRET'" 2>&1)"
echo "$MAB" | grep -q "Received Access-Reject" && ok "MAB request → Access-Reject" || bad "MAB request was not rejected: $(echo "$MAB" | tail -3)"

step "8. Event records (what the agent ships to EasyEAP)"
sleep 1
EVENTS="$(fixture events)"
has() { echo "$EVENTS" | python3 -c '
import json, sys
want = json.loads(sys.argv[1])
rows = [json.loads(l) for l in sys.stdin if l.strip()]
sys.exit(0 if any(all(str(r.get(k)) == str(v) for k, v in want.items()) for r in rows) else 1)' "$1"; }
has '{"mac": "02-00-00-00-01-02", "result": "accept", "network": "wired", "port_id": "GigabitEthernet1/0/5", "port_type": "Ethernet", "vlan": "110", "monitor": "None"}' \
  && ok "wired accept records network, switch port, port type and VLAN" || bad "wired accept event lacks network/port"
has '{"mac": "02-00-00-00-01-01", "result": "accept", "network": "wireless", "vlan": "100"}' && ok "Wi-Fi accept records network wireless" || bad "Wi-Fi event lacks network"
has '{"mac": "02-00-00-00-05-01", "result": "accept", "network": "wired", "vlan": "110", "monitor": "yes", "port_id": "GigabitEthernet1/0/9"}' \
  && ok "monitor-mode accept records the VLAN it withheld" || bad "monitor-mode event lacks monitor/vlan"
has '{"mac": "02-00-00-00-03-01", "result": "reject", "reason": "network_not_enabled", "network": "wired"}' \
  && ok "refused network recorded as network_not_enabled" || bad "network_not_enabled not recorded"
has '{"mac": "02-00-00-00-02-04", "result": "reject", "reason": "policy_deny", "network": "wired"}' && ok "wired deny recorded with its reason" || bad "wired policy_deny not recorded"
has '{"mac": "02-00-00-00-04-01", "result": "reject", "reason": "mab_unsupported"}' && ok "MAB attempt recorded as mab_unsupported" || bad "MAB attempt not named"

step "9. Version skew: every combination degrades to 1.0.1 behaviour (switch ports get the Wi-Fi VLAN), never another decision"
OUT="$(fixture apply old-api)"; echo "$OUT" | grep -q '"authz_wired": 0' || bad "old-API snapshot wrote wired rows: $OUT"
expect "this agent, API from before wired 802.1X: alice on a switch port gets her Wi-Fi VLAN" "accept 100" switch alice 02:00:00:00:06:01 -N "$WIRED"
OUT="$(fixture apply new)"
expect "this agent, this API again: the wired VLAN" "accept 110" switch alice 02:00:00:00:06:02 -N "$WIRED"
fixture render-v101 >/dev/null || die "could not render the 1.0.1 configuration"
CHECK="$(docker run --rm --user root -v "$WORK":/work --entrypoint freeradius "$RADIUS_IMAGE" -C -d /work/state/raddb/v101 2>&1)"
[ $? -eq 0 ] || { echo "$CHECK" | tail -20; die "freeradius -C rejected the 1.0.1 configuration"; }
docker run -d --name "$NET_NAME-fr101" --network "$NET_NAME" --ip "$SUBNET.3" --user root -v "$WORK":/work \
  --entrypoint freeradius "$RADIUS_IMAGE" -f -l stdout -d /work/state/raddb/v101 >/dev/null || die "the 1.0.1 FreeRADIUS did not start"
for _ in $(seq 1 20); do docker logs "$NET_NAME-fr101" 2>&1 | grep -q "Ready to process requests" && break; sleep 0.5; done
RADIUS_AT=3
expect "1.0.1 configuration (new one rejected) on this agent's store: alice on a switch port gets her Wi-Fi VLAN" "accept 100" switch alice 02:00:00:00:06:03 -N "$WIRED"
expect "1.0.1 configuration: carol still denied" "reject" switch carol 02:00:00:00:06:04 -N "$WIRED"
RADIUS_AT=2
OUT="$(fixture apply v101-agent)"; echo "$OUT" | grep -q '"version": 4' || bad "1.0.1 agent did not apply the snapshot: $OUT"
expect "1.0.1 agent (rollback) wrote the newest snapshot; leftover wired rows are ignored: Wi-Fi VLAN" "accept 100" switch alice 02:00:00:00:06:05 -N "$WIRED"
expect "1.0.1 agent's snapshot: bob's Wi-Fi VLAN too" "accept 100" switch bob 02:00:00:00:06:06 -N "$WIRED"
UP="$(fixture upgrade)"
echo "$UP" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["same_rows"] and d["same_columns"] and d["authz_wired"] == 0 and d["version"] == 7, d' \
  && ok "a store written by the 1.0.1 agent opens unchanged in this one (authz_wired added, empty)" || bad "upgrade: $UP"

step "10. The two silent failures the wizard explains (FreeRADIUS answers neither)"
STATUS_REQ='User-Name = "probe"\nUser-Password = "probe"\nNAS-Port-Type = Ethernet\nMessage-Authenticator = 0x00\n'
docker exec "$NET_NAME-stranger" sh -c "printf '$STATUS_REQ' | radclient -t 2 -r 1 $SUBNET.2 auth '$SECRET'" >/dev/null 2>&1
docker exec "$NET_NAME-switch" sh -c "printf '$STATUS_REQ' | radclient -t 2 -r 1 $SUBNET.2 auth 'not-the-right-secret'" >/dev/null 2>&1
sleep 1
FRLOG="$(docker logs "$NET_NAME-fr" 2>&1)"
CLASSIFIED="$(echo "$FRLOG" | docker run --rm -i --user root -v "$ROOT/services/radius/agent":/opt/easyeap-agent:ro -v "$ROOT/tests/radius/fixture.py":/fixture.py:ro \
  -v "$WORK":/work --entrypoint python3 "$RADIUS_IMAGE" /fixture.py classify)"
echo "$CLASSIFIED" | grep -q "error.*unknown client $SUBNET.99" && ok "unregistered address: logged as an error naming it ('unknown client')" \
  || bad "no classified 'unknown client' line: $(echo "$FRLOG" | grep -i unknown | tail -2)"
echo "$CLASSIFIED" | grep -q "warning.*$SUBNET.11.*Message-Authenticator" && ok "wrong shared secret: kept as a warning naming the address ('Message-Authenticator')" \
  || bad "no classified bad-secret line: $(echo "$FRLOG" | grep -i authenticator | tail -2)"

if [ "$FAILED" -gt 0 ]; then
  echo; echo "FreeRADIUS log (last 80 lines):"; docker logs "$NET_NAME-fr" 2>&1 | tail -80
fi
printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[ "$FAILED" -eq 0 ]

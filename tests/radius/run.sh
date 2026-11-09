#!/usr/bin/env bash
# RADIUS integration test: the real FreeRADIUS 3.2 image, a configuration rendered by the agent's renderer, the
# agent's own snapshot store, and real EAP-TLS from eapol_test. No API, database or OpenBao: seconds, not minutes.
#
#   tests/radius/run.sh               # builds the two images if they're missing
#
# Covers wired 802.1X (docs/plans/wired-8021x.md): which network a request is counted as (hostapd's empty SSID,
# NAS-Port-Type, the client's registration, the SSID in Called-Station-Id), the VLAN on switch ports (mapped, or the
# port's own), refusal of a network the client isn't registered for, nested registrations, monitor mode withholding
# VLANs, the network and switch port in event records, and version skew with the 1.0.1 agent and configuration in
# every combination. And MAC authentication (docs/plans/mac-auth.md): Cisco PAP and UniFi EAP-MD5 against the MAC
# allow list, every refusal reason, monitor mode, switches without it, and requests without Message-Authenticator.
# And device administration (docs/plans/device-admin.md): the TACACS+ service driven by an IOS-like client.
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
  docker rm -f "$NET_NAME-fr" "$NET_NAME-fr101" "$NET_NAME-tac" "$NET_NAME-wlc" "$NET_NAME-switch" "$NET_NAME-plain" "$NET_NAME-unifi" "$NET_NAME-lab" "$NET_NAME-stranger" "$NET_NAME-nexus" "$NET_NAME-nexusenf" "$NET_NAME-nexus3k" >/dev/null 2>&1
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
echo "$BUILD" | grep -q '"authz_mac": 6' && ok "MAC allow list: six entries written, the malformed one refused" || bad "unexpected MAC part: $BUILD"
CHECK="$(docker run --rm --user root -v "$WORK":/work --entrypoint freeradius "$RADIUS_IMAGE" -C -d /work/state/raddb/live 2>&1)"
[ $? -eq 0 ] && ok "freeradius -C accepts the rendered configuration" || { bad "freeradius -C rejected it"; echo "$CHECK" | tail -20; exit 1; }

docker network create --subnet "$SUBNET.0/24" "$NET_NAME" >/dev/null || die "could not create the test network"
docker run -d --name "$NET_NAME-fr" --network "$NET_NAME" --ip "$SUBNET.2" --user root -v "$WORK":/work \
  --entrypoint freeradius "$RADIUS_IMAGE" -f -l stdout -d /work/state/raddb/live >/dev/null || die "FreeRADIUS did not start"
for n in wlc:10 switch:11 plain:12 unifi:17 lab:20 nexus:21 nexusenf:22 nexus3k:23 stranger:99; do
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

step "7. MAC authentication (Cisco: PAP with Service-Type Call-Check)"
# mab <from> <user-name> <calling-station-id> [password] [port type] → "accept <vlan>", "accept none" or "reject".
mab() {
  local from="$1" user="$2" csid="$3" pass="${4:-$2}" ptype="${5:-Ethernet}" out
  out="$(docker exec "$NET_NAME-$from" sh -c "printf 'User-Name = \"$user\"\nUser-Password = \"$pass\"\nService-Type = Call-Check\nNAS-Port-Type = $ptype\nNAS-Port-Id = \"GigabitEthernet1/0/7\"\nCalling-Station-Id = \"$csid\"\nMessage-Authenticator = 0x00\n' | radclient -x -t 5 -r 1 $SUBNET.$RADIUS_AT auth '$SECRET'" 2>&1)"
  if echo "$out" | grep -q "Received Access-Accept"; then
    local vlan; vlan="$(echo "$out" | sed -n 's/.*Tunnel-Private-Group-Id[^=]*= *"\{0,1\}\([^" ]*\)"\{0,1\}.*/\1/p' | head -1)"
    [ -n "$vlan" ] && echo "accept $vlan" || echo "accept none"
  else
    echo "reject"
  fi
}
mexpect() { local got; got="$(mab "${@:3}")"; [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"; }
mexpect "printer on the allow list (Cisco's lowercase user name): its group's VLAN" "accept 120" switch 020000000a01 02-00-00-00-0A-01
mexpect "camera in a group on the port's own VLAN: accepted, no VLAN" "accept none" switch 020000000a05 02-00-00-00-0A-05
mexpect "dotted notation, same device" "accept 120" switch 0200.0000.0a01 0200.0000.0a01
mexpect "not on the allow list" "reject" switch 020000000a99 02-00-00-00-0A-99
mexpect "blocked device" "reject" switch 020000000a02 02-00-00-00-0A-02
mexpect "entry expired a minute ago (same snapshot version)" "reject" switch 020000000a03 02-00-00-00-0A-03
mexpect "entry with a future expiry" "accept 130" switch 020000000a06 02-00-00-00-0A-06
mexpect "group turned off" "reject" switch 020000000a04 02-00-00-00-0A-04
mexpect "Calling-Station-Id names another device" "reject" switch 020000000a01 02-00-00-00-0A-06
mexpect "password isn't the MAC" "reject" switch 020000000a01 02-00-00-00-0A-01 not-the-mac
mexpect "user name isn't a MAC" "reject" switch printer01 02-00-00-00-0A-01
mexpect "switch without MAC authentication" "reject" plain 020000000a01 02-00-00-00-0A-01
mexpect "MAB switch, but the request says Wi-Fi (no evidence of a switch port)" "reject" switch 020000000a01 02-00-00-00-0A-01 020000000a01 Wireless-802.11
mexpect "Wi-Fi controller doing MAC filtering" "reject" wlc 020000000a01 02-00-00-00-0A-01 020000000a01 Wireless-802.11
mexpect "monitor-mode switch: accepted, VLAN withheld" "accept none" lab 020000000a01 02-00-00-00-0A-01
expect "a certificate still works on the MAB switch (EAP-TLS path unchanged)" "accept 110" switch alice 02:00:00:00:0A:01 -N "$WIRED"
# radclient always adds Message-Authenticator, so this request is built by hand: what a switch that doesn't send it does.
NOMA="$(docker exec -i "$NET_NAME-switch" python3 - "$SUBNET.2" "$SECRET" <<'PY'
import hashlib, os, socket, struct, sys
server, secret = sys.argv[1], sys.argv[2].encode()
auth = os.urandom(16)
pw = b"020000000a01".ljust(16, b"\0")
enc = bytes(a ^ b for a, b in zip(pw, hashlib.md5(secret + auth).digest()))  # noqa: S324 — RADIUS PAP
def attr(t, v): return struct.pack("BB", t, len(v) + 2) + v
attrs = attr(1, b"020000000a01") + attr(2, enc) + attr(6, struct.pack("!I", 10)) + attr(61, struct.pack("!I", 15)) + attr(31, b"02-00-00-00-0A-01")
pkt = struct.pack("!BBH", 1, 77, 20 + len(attrs)) + auth + attrs
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(pkt, (server, 1812))
try:
    print("answered", s.recv(4096)[0])
except socket.timeout:
    print("none")
PY
)"
# FreeRADIUS logs nothing for this at its normal level, so EasyEAP can't count such drops: the switch panel works from
# what did arrive instead (no answered MAC request → no Enforce; docs/plans/mac-auth.md §6.5).
[ "$NOMA" = "none" ] && ok "MAB request without Message-Authenticator: dropped (no answer)" || bad "a MAB request without Message-Authenticator was answered: $NOMA"

step "7a. Nexus and Meraki (docs/plans/cisco-platforms.md §4, §5): PAP without Call-Check or Message-Authenticator"
# pap <from> <user> <password> [pap_client options] → "accept <vlan|none> <session-timeout|->", "reject" or "none".
pap() { local from="$1"; shift; docker exec -i "$NET_NAME-$from" python3 - "$SUBNET.2" "$SECRET" "$@" < "$ROOT/tests/radius/pap_client.py" 2>&1; }
pexpect() { local got; got="$(pap "${@:3}")"; [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"; }
pexpect "monitor: device not on the allow list is let through (no VLAN, 30-minute session)" "accept none 1800" nexus 020000000a99 020000000a99
pexpect "monitor: blocked device is let through too, logged as refused" "accept none 1800" nexus 020000000a02 020000000a02
pexpect "monitor: allowed printer, VLAN withheld" "accept none 3600" nexus 020000000a01 020000000a01
pexpect "monitor: Calling-Station-Id names another device: refused even in monitor" "reject" nexus 020000000a01 020000000a01 --csid 02-00-00-00-0A-06
pexpect "monitor: password isn't the MAC: refused even in monitor" "reject" nexus 020000000a99 not-the-mac
pexpect "monitor: a switch admin's RADIUS login (Service-Type Login) named like a MAC: refused" "reject" nexus 020000000a99 020000000a99 --service 1
pexpect "monitor: Administrative login named like a MAC: refused" "reject" nexus 020000000a99 020000000a99 --service 6
pexpect "monitor: NAS-Prompt login named like a MAC: refused" "reject" nexus 020000000a99 020000000a99 --service 7
pexpect "monitor: a PAP login that isn't a MAC: refused" "reject" nexus admin 020000000a99
pexpect "Proxy-State without Message-Authenticator: dropped (Blast-RADIUS)" "none" nexus 020000000a01 020000000a01 --proxy-state
pexpect "Proxy-State with Message-Authenticator: answered" "accept none 3600" nexus 020000000a01 020000000a01 --proxy-state --ma
pexpect "enforced: allowed printer gets its VLAN" "accept 120 3600" nexusenf 020000000a01 020000000a01 --csid 02:00:00:00:0a:01
pexpect "enforced: not on the allow list: refused" "reject" nexusenf 020000000a99 020000000a99
pexpect "enforced: Service-Type Call-Check (Meraki may send it): same decision" "accept 120 3600" nexusenf 020000000a01 020000000a01 --service 10
pexpect "enforced, a switch that can't apply VLANs: allowed printer, no VLAN" "accept none 3600" nexus3k 020000000a01 020000000a01
pexpect "port evidence: NAS-Port-Type Virtual (VPN, remote login) with a NAS-Port isn't a MAC request: refused" "reject" nexusenf 020000000a01 020000000a01 --port-type 5
pexpect "port evidence: no NAS-Port-Type, a NAS-Port: a MAC request" "accept 120 3600" nexusenf 020000000a01 020000000a01 --port-type -1
pexpect "a Catalyst switch's MAB request still needs Message-Authenticator" "none" switch 020000000a01 020000000a01 --service 10

step "7b. MAC authentication (UniFi MAC-Based: EAP-MD5 with the MAC as identity and password)"
md5() { # md5 <from> <identity> <password> [-N …] → accept <vlan> | accept none | reject
  local from="$1" ident="$2" pass="$3"; shift 3
  local out
  # -n: EAP-MD5 derives no keys, so eapol_test mustn't expect any.
  out="$(docker exec -i "$NET_NAME-$from" sh -c 'cat > /tmp/md5.conf; eapol_test -n -c /tmp/md5.conf "$@"' sh \
    -a "$SUBNET.2" -p 1812 -s "$SECRET" -M 02:00:00:00:0a:01 -t 10 "$@" 2>&1 <<CONF
network={
	key_mgmt=IEEE8021X
	eapol_flags=0
	eap=MD5
	identity="$ident"
	password="$pass"
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
dexpect() { local got; got="$(md5 "${@:3}")"; [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"; }
dexpect "UniFi MAC-Based port, device on the allow list: its group's VLAN" "accept 120" unifi 020000000A01 020000000A01 -N "$WIRED"
dexpect "UniFi, device not on the allow list" "reject" unifi 020000000A99 020000000A99 -N "$WIRED"
dexpect "UniFi, wrong MD5 password" "reject" unifi 020000000A01 wrong -N "$WIRED"
dexpect "UniFi, EAP-MD5 with a user name instead of a MAC (never offered)" "reject" unifi alice alice -N "$WIRED"
dexpect "UniFi on Wi-Fi (SSID): EAP-MD5 never offered" "reject" unifi 020000000A01 020000000A01 -N "$OTHER" -N "30:s:00-11-22-33-44-55:Corp"
dexpect "Cisco switch (PAP mode): EAP-MD5 with a MAC identity is never offered" "reject" switch 020000000A01 020000000A01 -N "$WIRED"
expect "a certificate still works on the UniFi MAB switch" "accept 110" unifi alice 02:00:00:00:0b:01 -N "$WIRED"

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
has '{"device_mac": "020000000A01", "result": "accept", "method": "mab", "vlan": "120", "mac_device": "9d000000-0000-4000-8000-000000000001", "mac_group": "9a000000-0000-4000-8000-000000000001", "port_id": "GigabitEthernet1/0/7", "service_type": "Call-Check"}' \
  && ok "MAB accept records the method, device MAC, allow-list device and group, and VLAN" || bad "MAB accept event incomplete"
for r in mac_unknown:020000000A99 mac_disabled:020000000A02 mac_expired:020000000A03 mac_group_disabled:020000000A04 mab_mismatch:020000000A01 mab_password:020000000A01; do
  has "{\"device_mac\": \"${r#*:}\", \"result\": \"reject\", \"method\": \"mab\", \"reason\": \"${r%%:*}\"}" && ok "MAB refusal recorded as ${r%%:*}" || bad "no ${r%%:*} event"
done
has '{"result": "reject", "method": "mab", "reason": "mab_not_enabled", "src_ip": "'"$SUBNET"'.12"}' && ok "MAB from a switch without it recorded as mab_not_enabled" || bad "no mab_not_enabled event"
has '{"device_mac": "020000000A01", "result": "accept", "method": "mab", "monitor": "yes", "vlan": "120"}' && ok "monitor-mode MAB accept records the VLAN it withheld" || bad "monitor MAB event lacks monitor/vlan"
has '{"device_mac": "020000000A99", "result": "accept", "method": "mab", "monitor": "accepted", "reason": "mac_unknown", "src_ip": "'"$SUBNET"'.21"}' \
  && ok "server-side monitor accept records the refusal it stood in for (monitor = accepted, mac_unknown)" || bad "no monitor-accepted event"
has '{"device_mac": "020000000A02", "result": "accept", "method": "mab", "monitor": "accepted", "reason": "mac_disabled"}' \
  && ok "server-side monitor accept of a blocked device keeps its reason" || bad "monitor-accepted deny lacks its reason"
has '{"device_mac": "020000000A01", "result": "accept", "method": "mab-eap", "vlan": "120"}' && ok "UniFi EAP-MD5 accept recorded as mab-eap" || bad "no mab-eap accept event"
has '{"mac": "02-00-00-00-0A-01", "result": "accept", "method": "None", "device_mac": "None", "vlan": "110"}' && ok "certificate accept on a MAB switch: no MAC method, no device MAC" || bad "certificate event on a MAB switch looks like MAB"

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
echo "$CLASSIFIED" | grep -q "warning.*$SUBNET.11.*invalid Message-Authenticator" && ok "wrong shared secret: kept as a warning naming the address ('Message-Authenticator')" \
  || bad "no classified bad-secret line: $(echo "$FRLOG" | grep -i authenticator | tail -2)"

step "11. Device administration: the TACACS+ service (docs/plans/device-admin.md)"
ADM="$(fixture admin)" || die "fixture admin failed: $ADM"
TKEY="$(echo "$ADM" | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])')"
TPW="$(echo "$ADM" | python3 -c 'import json,sys; print(json.load(sys.stdin)["password"])')"
docker run -d --name "$NET_NAME-tac" --network "$NET_NAME" --ip "$SUBNET.4" --user root -e EASYEAP_RADIUS_STATE=/work/state \
  -e EASYEAP_AGENT_TOKEN=radius-test-token -v "$WORK":/work -v "$ROOT/services/radius/agent":/opt/easyeap-agent:ro \
  --entrypoint python3 "$RADIUS_IMAGE" /opt/easyeap-agent/tacacs.py >/dev/null || die "the TACACS+ service did not start"
for _ in $(seq 1 20); do docker logs "$NET_NAME-tac" 2>&1 | grep -q "TACACS+ listening" && break; sleep 0.5; done
docker logs "$NET_NAME-tac" 2>&1 | grep -q "TACACS+ listening on TCP 4949" && ok "TACACS+ service listening on 4949" \
  || { docker logs "$NET_NAME-tac" 2>&1 | tail -20; die "the TACACS+ service never listened"; }
# tac <from> <key> <client args…>: the IOS-like client from tests/radius/tacacs_client.py, run on a lab container
tac() { local from="$1" key="$2"; shift 2
  docker exec -i "$NET_NAME-$from" python3 - --host "$SUBNET.4" --port 4949 --key "$key" "$@" < "$ROOT/tests/radius/tacacs_client.py" 2>&1; }
texpect() { local got; got="$(tac "${@:3}")"; [ "$got" = "$2" ] && ok "$1 → $got" || bad "$1 → expected '$2', got '$got'"; }
echo "$ADM" | grep -q '"mode": "0o600"' && ok "admin.json (keys, hashes) is readable by its owner only" || bad "admin.json mode: $ADM"
ms() { echo $(( $(date +%s%N) / 1000000 )); }
T0=$(ms); texpect "SSH login (name in START): GETPASS, then PASS" "GETPASS PASS" switch "$TKEY" login ops "$TPW"; T_PASS=$(( $(ms) - T0 ))
texpect "telnet login (no name): GETUSER, GETPASS, PASS" "GETUSER GETPASS PASS" switch "$TKEY" --telnet login ops "$TPW"
T0=$(ms); texpect "wrong password: FAIL (final on IOS)" "GETPASS FAIL" switch "$TKEY" login ops "not it"; T_FAIL=$(( $(ms) - T0 ))
[ "$T_FAIL" -ge $(( T_PASS + 500 )) ] && ok "a failure is answered after the uniform delay (pass ${T_PASS} ms, fail ${T_FAIL} ms)" \
  || bad "failure not delayed: pass ${T_PASS} ms, fail ${T_FAIL} ms"
texpect "unknown name: FAIL, after the same delay" "GETPASS FAIL" switch "$TKEY" login mallory "x"
texpect "PAP login" "PASS" switch "$TKEY" pap ops "$TPW"
texpect "CHAP: refused (EasyEAP needs the password)" "FAIL" switch "$TKEY" chap ops
texpect "local-only (break-glass) name: ERROR, so the switch uses its own account" "GETPASS ERROR" switch "$TKEY" login breakglass "x"
texpect "enable 15 for a privilege-15 role" "GETPASS PASS" switch "$TKEY" --priv 15 enable ops "$TPW"
texpect "enable 15 for a read-only role: FAIL" "GETPASS FAIL" switch "$TKEY" --priv 15 enable viewer "$TPW"
texpect "exec authorization: the role's privilege level" "PASS_ADD priv-lvl=15" switch "$TKEY" author ops
texpect "exec authorization for a session nobody logged in through EasyEAP: ERROR (the switch's own list decides)" "ERROR" switch "$TKEY" author viewer
texpect "read-only account login" "GETPASS PASS" switch "$TKEY" login viewer "$TPW"
texpect "exec authorization, read-only role" "PASS_ADD priv-lvl=1" switch "$TKEY" author viewer
texpect "Nexus login" "GETPASS PASS" nexus "$TKEY" login ops "$TPW"
texpect "Nexus role request, level-15 role: network-admin, no priv-lvl" 'PASS_ADD shell:roles="network-admin"' nexus "$TKEY" author ops
texpect "Nexus login, read-only account" "GETPASS PASS" nexus "$TKEY" login viewer "$TPW"
texpect "Nexus role request, read-only role: network-operator" 'PASS_ADD shell:roles="network-operator"' nexus "$TKEY" author viewer
texpect "exec authorization when the switch authenticated the session itself (local): ERROR" "ERROR" switch "$TKEY" --method 5 author ops
texpect "accounting start" "SUCCESS" switch "$TKEY" acct ops start
texpect "command accounting with a secret in it" "SUCCESS" switch "$TKEY" --cmd "username bob secret 0 Hunter2Hunter2 <cr>" acct ops stop
texpect "ABORT from the user: no reply, no failure counted" "GETPASS CLOSED" switch "$TKEY" abort ops
texpect "a packet without obfuscation: dropped" "CLOSED" switch "$TKEY" plain ops
texpect "a device whose tenant's admin data expired: ERROR (fall back to local)" "GETPASS ERROR" plain "$TKEY" login ops "$TPW"
texpect "an address without admin logins: the connection is closed unanswered" "CLOSED" stranger "$TKEY" login ops "$TPW"
tac switch "wrong-key-for-this-device" login ops "$TPW" >/dev/null
sleep 0.5
AEV="$(docker run --rm --user root -v "$ROOT/services/radius/agent":/opt/easyeap-agent:ro -v "$ROOT/tests/radius/fixture.py":/fixture.py:ro \
  -v "$WORK":/work --entrypoint python3 "$RADIUS_IMAGE" /fixture.py admin-events)"
echo "$AEV" | python3 -c '
import json, sys
ev = [json.loads(x) for x in sys.stdin if x.strip()]
k = [(e["kind"], e["result"], e.get("reason")) for e in ev]
assert ("login", "pass", None) in k and ("login", "fail", "admin_bad_password") in k and ("login", "fail", "admin_unknown_user") in k, k
assert ("login", "error", "admin_local_only") in k and ("login", "error", "admin_data_expired") in k and ("login", "error", "admin_bad_key") in k, k
assert ("enable", "fail", "admin_priv_too_high") in k and ("authz", "pass", None) in k and ("session", "start", None) in k, k
assert ("authz", "error", "admin_not_easyeap_login") in k, k
cmd = [e for e in ev if e["kind"] == "command"]
assert cmd and cmd[0]["command"] == "username bob secret 0 ***** <cr>", cmd
assert not any("Hunter2" in json.dumps(e) for e in ev)
assert all(e["username"] != "mallory" for e in ev), "unknown names are logged as a keyed hash"
assert {e["client_id"] for e in ev} == {"switch", "plain", "nexus"}' && ok "admin log: every outcome spooled with its reason, secrets masked, unknown names hashed" \
  || bad "admin events: $(echo "$AEV" | head -c 600)"
docker logs "$NET_NAME-tac" 2>&1 | grep -q "isn't a device with admin logins on" && ok "the unregistered address is logged once" || bad "no log line for the unregistered address"

if [ "$FAILED" -gt 0 ]; then
  echo; echo "FreeRADIUS log (last 80 lines):"; docker logs "$NET_NAME-fr" 2>&1 | tail -80
  echo; echo "TACACS+ log (last 40 lines):"; docker logs "$NET_NAME-tac" 2>&1 | tail -40
fi
printf '\n%d passed, %d failed\n' "$PASS" "$FAILED"
[ "$FAILED" -eq 0 ]

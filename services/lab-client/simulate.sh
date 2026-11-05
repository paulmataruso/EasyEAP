#!/bin/sh
# Simulate a Wi-Fi client authenticating with EAP-TLS through a controller.
# Usage: easyeap-simulate <radius-host> <shared-secret> <cert.pem> <key.pem> <ca.pem> <server-name> [mac] [identity]
set -eu
host="$1"; secret="$2"; cert="$3"; key="$4"; ca="$5"; server="$6"; mac="${7:-02:00:00:00:00:01}"; ident="${8:-anonymous}"
conf=$(mktemp)
cat > "$conf" <<CONF
network={
	key_mgmt=WPA-EAP
	eap=TLS
	identity="$ident"
	ca_cert="$ca"
	client_cert="$cert"
	private_key="$key"
	domain_suffix_match="$server"
}
CONF
addr=$(getent hosts "$host" | awk '{print $1}' | head -1)
eapol_test -c "$conf" -a "${addr:-$host}" -p 1812 -s "$secret" -M "$mac" -N "30:s:00-11-22-33-44-55:EasyEAP-Lab" -N "4:x:0a000005" -t 15 2>&1 \
  | grep -E "SUCCESS|FAILURE|Access-Accept|Access-Reject|Tunnel|Attribute|Value:|EAP: Status|TLS: |CTRL-EVENT-EAP-(FAILURE|SUCCESS)|Reply-Message" | grep -v "^EAPOL" || true
rm -f "$conf"

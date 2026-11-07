#!/usr/bin/env bash
# Kerberos acceptance for Group Policy autoenrollment (docs/plans/gpo-autoenrollment.md §2.2) against a real MIT KDC:
# a throwaway realm, the service principal's keytab, and SPNEGO tokens from a computer and a user (as Windows sends
# them), accepted by app/autoenroll/kerberos.py. Also: a wrong keytab, a foreign realm and an NTLM token are refused.
#   API_IMAGE=easyeap-api-test:local tests/autoenroll/kerberos.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
API_IMAGE="${API_IMAGE:-easyeap-api-test:local}"
docker run --rm -u 0 -v "$PWD/backend":/src:ro -v "$PWD/tests/autoenroll":/t:ro -w /src -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 \
  -e EASYEAP_KRB_DIR=/tmp/krb --entrypoint bash "$API_IMAGE" -c '
set -e
apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq krb5-kdc krb5-admin-server krb5-user >/dev/null 2>&1
cat > /etc/krb5.conf <<CONF
[libdefaults]
    default_realm = TEST.EXAMPLE
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
    TEST.EXAMPLE = {
        kdc = 127.0.0.1
    }
CONF
mkdir -p /etc/krb5kdc && printf "[kdcdefaults]\n kdc_ports = 88\n[realms]\n TEST.EXAMPLE = {\n  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n }\n" > /etc/krb5kdc/kdc.conf
kdb5_util create -r TEST.EXAMPLE -s -P masterpw >/dev/null 2>&1
kadmin.local -q "addprinc -randkey HTTP/easyeap.test" >/dev/null
kadmin.local -q "ktadd -k /tmp/http.keytab HTTP/easyeap.test" >/dev/null
kadmin.local -q "addprinc -randkey HTTP/other.test" >/dev/null
kadmin.local -q "ktadd -k /tmp/wrong.keytab HTTP/other.test" >/dev/null
kadmin.local -q "addprinc -pw pc01pass PC01\$" >/dev/null
kadmin.local -q "addprinc -pw ninapass nina" >/dev/null
krb5kdc && sleep 1
python3 /t/kerberos_check.py
'

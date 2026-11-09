"""The Linux setup script: one bash file, made for one enrollment link, that sets a Linux computer up end to end.

Why a script and not the desktop's Wi-Fi dialog (see docs/enrollment.md, "Linux"): GNOME's dialog turns any EAP-TLS
failure into a "private key password" prompt, never shows its form again once a profile exists for the SSID, and
can save the key password where NetworkManager then has to ask for it. The script avoids all of it: it makes the key
on the computer (no PKCS#12, no password), stores it root-only under /etc/easyeap/<tenant>/ and creates a
system-wide connection whose key needs no password (802-1x.private-key-password-flags 4), so nothing ever prompts.

It finds what the computer uses and configures that:
  - NetworkManager (Ubuntu, Fedora, Debian desktop, Mint, Pop!_OS, Raspberry Pi OS Bookworm+): nmcli, Wi-Fi and,
    when the tenant has wired 802.1X, network ports (802-1x.optional, so ports without 802.1X still work). Wired
    profiles the computer already has (a fixed address, DNS, one port) are kept: the script adds 802.1X to a copy of
    each, preferred over the original, so the port's own settings still apply.
  - iwd on its own: /var/lib/iwd/<ssid>.8021x.
  - systemd-networkd + wpa_supplicant (Ubuntu Server without NetworkManager): wpa_supplicant@<if> and a DHCP .network.
  - dhcpcd + wpa_supplicant (older Raspberry Pi OS): a block in /etc/wpa_supplicant/wpa_supplicant.conf.
netplan is never written: its auth block has no server-name check, so the connection couldn't pin the RADIUS name.
iwd can't sign with ECDSA keys (its TLS library signs with RSA only), so computers whose Wi-Fi goes through iwd get
an RSA-3072 key; everything else gets ECDSA P-256.

It also installs a daily renewal (systemd timer, or cron.daily) that renews the certificate with its own key through
POST /api/enroll/renew (docs/plans/cert-renewal.md §4.2, protocol v2): each day it checks in, signed with the
certificate's key, saying what it is and which roots it trusts; EasyEAP answers when renewal starts. From then it
sends a request for a new key, kept until the new certificate is in, so a lost answer is asked for again with the
same request. Without an answer it falls back on the template's renewal period it was made with.

Talking to EasyEAP: curl, else python3 (Ubuntu desktops ship without curl). The link is never on a command line
(other users can read those): curl gets the URL on stdin, python3 in its environment. The server's TLS certificate is
checked as usual; if this computer doesn't trust it (a temporary self-signed certificate), the script accepts the
public key EasyEAP served when it made the script (a SubjectPublicKeyInfo pin, which survives re-issuing the
certificate with the same key).
"""
from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

FILENAME = "EasyEAP-WiFi-Setup.sh"
_RENEW_EOF = "EASYEAP_RENEW_SCRIPT_END"


def shq(value: str) -> str:
    """A bash single-quoted word. Control characters can't appear in a setting, but are dropped to be sure."""
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    return "'" + value.replace("'", "'\\''") + "'"


def iwd_name(ssid: str) -> str:
    """iwd's file name for an SSID: as is when it's only letters, digits, space, '-' and '_'; otherwise '=' + hex."""
    if re.fullmatch(r"[A-Za-z0-9 _-]+", ssid):
        return ssid
    return "=" + ssid.encode().hex()


def tls_pin(cert_path: Path) -> str:
    """sha256 of the SubjectPublicKeyInfo (base64, curl's --pinnedpubkey form) of the first certificate in the file
    the proxy serves, or "" when it can't be read."""
    try:
        cert = x509.load_pem_x509_certificates(cert_path.read_bytes())[0]
    except (OSError, ValueError, IndexError):
        return ""
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(hashlib.sha256(spki).digest()).decode()


def root_first(chain_pem: str) -> str:
    """The CA certificates root first (the API keeps them issuing CA first)."""
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", chain_pem, re.DOTALL)
    return "\n".join(reversed(blocks)) + "\n" if len(blocks) > 1 else chain_pem


def _ca_block(ca_chain_pem: str) -> str:
    pem = "\n".join(line for line in ca_chain_pem.strip().splitlines() if line.strip())
    return f"IFS= read -r -d '' CA_CHAIN <<'EASYEAP_CA_END'\n{pem}\nEASYEAP_CA_END\nCA_CHAIN=${{CA_CHAIN%$'\\n'}}\n"


def _common_config(*, api_base: str, org: str, slug: str, renew_days: int, pin: str) -> str:
    return (f"API={shq(api_base.rstrip('/'))}\nORG={shq(org)}\nSLUG={shq(slug)}\n# shellcheck disable=SC2034  # the renewal uses it\nRENEW_DAYS={int(renew_days)}\n"
            f"PIN_SPKI={shq(pin)}\nDIR=\"${{EASYEAP_DIR:-/etc/easyeap/$SLUG}}\"  # EASYEAP_DIR: tests only\n"
            'case "$DIR" in /*/"$SLUG") ;; *) DIR="/etc/easyeap/$SLUG" ;; esac\n')


def renew_script(*, api_base: str, org: str, slug: str, renew_days: int, pin: str) -> str:
    return ("#!/usr/bin/env bash\n# shellcheck disable=SC2034  # shared settings and colours the renewal doesn't use\n"
            f"# EasyEAP certificate renewal for {re.sub(r'[^ -~]', '', org)}, installed by the EasyEAP setup. Runs daily: checks in\n"
            "# with EasyEAP and renews the certificate with a new key once its renewal starts. Log: renew.log next to this file.\n"
            "set -u\numask 077\nexport LC_ALL=C\nPATH=\"$PATH:/usr/sbin:/sbin\"\n"
            + _common_config(api_base=api_base, org=org, slug=slug, renew_days=renew_days, pin=pin) + _COMMON + _RENEW)


def setup_script(*, api_base: str, token: str, org: str, slug: str, ssid: str, server_name: str, identity: str, wpa3: bool,
                 wired: bool, ca_chain_pem: str, renew_days: int, pin: str) -> str:
    renew = renew_script(api_base=api_base, org=org, slug=slug, renew_days=renew_days, pin=pin)
    if _RENEW_EOF in renew:  # can't happen: the renewal script is fixed text plus quoted settings
        raise ValueError("renewal script contains its own end marker")
    config = (_common_config(api_base=api_base, org=org, slug=slug, renew_days=renew_days, pin=pin)
              + f"TOKEN={shq(token)}\nSSID={shq(ssid)}\nSSID_HEX={shq(ssid.encode().hex())}\nIWD_NAME={shq(iwd_name(ssid))}\n"
              f"SERVER={shq(server_name)}\nIDENTITY={shq(identity)}\nIDENTITY_HEX={shq(identity.encode().hex())}\n"
              f"WPA3={1 if wpa3 else 0}\nWIRED={1 if wired else 0}\n"
              + _ca_block(root_first(ca_chain_pem)))
    body = _SETUP.replace("__EASYEAP_RENEW_HEREDOC__\n", f"cat > \"$DIR/renew.sh\" <<'{_RENEW_EOF}'\n{renew}{_RENEW_EOF}\n")
    return _HEAD + config + _COMMON + body


_HEAD = r"""#!/usr/bin/env bash
# EasyEAP network setup for Linux, made for one enrollment link. Don't share it: whoever runs it first gets the
# certificate. Run it as yourself (it asks for your password when it needs administrator rights):
#
#     bash EasyEAP-WiFi-Setup.sh            set this computer up
#     bash EasyEAP-WiFi-Setup.sh --check    only show what it would do; changes nothing
#     bash EasyEAP-WiFi-Setup.sh --remove   remove what it set up
#
# It creates a private key on this computer (it never leaves it), gets the certificate from EasyEAP, and adds the
# Wi-Fi network for NetworkManager, iwd or wpa_supplicant, whichever this computer uses. Files: /etc/easyeap/.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -u
umask 077
PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"  # Debian: a user's PATH has no sbin, where wpa_supplicant and dhcpcd live
# English messages to parse, but UTF-8, or nmcli prints a non-ASCII network name ("Café") as "Caf?".
if locale -a 2>/dev/null | grep -qiE '^c\.utf-?8$'; then export LC_ALL=C.UTF-8; else export LC_ALL=C; fi
"""

# Shared by the setup and the renewal script: output helpers and one HTTPS client (curl, else python3).
_COMMON = r"""
if [ -t 1 ]; then B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'; else B=; R=; G=; Y=; N=; fi
say() { printf '%s\n' "$*"; }
ok() { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# http METHOD URL [BODY_FILE]: the answer goes to $WORK/resp, its status to HTTP_CODE. Returns non-zero (with
# TRANSPORT_ERR) only when no answer came back.
http() {
  local method=$1 url=$2 data=${3:-} rc
  : > "$WORK/resp"; HTTP_CODE=000; TRANSPORT_ERR=
  if have curl; then
    # The URL (it carries the link) goes in on stdin: a command line is visible to every user of the computer.
    local args=(-sS --proto "=${API%%://*}" --tlsv1.2 --connect-timeout 15 --max-time 90 -o "$WORK/resp" -w '%{http_code}'
                -H 'Accept: text/plain, application/json' -K -)
    [ "$method" = POST ] && args+=(-X POST -H 'Content-Type: application/json' --data-binary "@$data")
    HTTP_CODE=$(printf 'url = "%s"\n' "$url" | curl "${args[@]}" 2>"$WORK/err"); rc=$?
    if [ "$rc" = 60 ] && [ -n "$PIN_SPKI" ]; then
      # This computer doesn't trust the server's certificate: accept the public key EasyEAP made this script with.
      HTTP_CODE=$(printf 'url = "%s"\n' "$url" | curl "${args[@]}" -k --pinnedpubkey "sha256//$PIN_SPKI" 2>"$WORK/err"); rc=$?
    fi
    [ "$rc" = 0 ] && return 0
    TRANSPORT_ERR=$(tr '\n' ' ' < "$WORK/err" | cut -c1-300); return 1
  elif have python3; then
    : > "$WORK/code"
    EASYEAP_URL=$url python3 -I - "$method" "$data" "$WORK/resp" "$PIN_SPKI" "$WORK/code" 2>"$WORK/err" <<'PY'
import base64, hashlib, http.client, os, ssl, sys, urllib.parse
method, data, out, pin, code = sys.argv[1:6]
u = urllib.parse.urlsplit(os.environ["EASYEAP_URL"])  # not on the command line: other users can read those
def spki(der):
    # The certificate's SubjectPublicKeyInfo, by walking its DER: Certificate > TBSCertificate > ([0] version),
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
    def tlv(i):
        n = der[i + 1]; i += 2
        if n & 0x80:
            k = n & 0x7F; n = int.from_bytes(der[i:i + k], "big"); i += k
        return i, i + n
    i, _ = tlv(0); i, _ = tlv(i)
    if der[i] == 0xA0:
        i = tlv(i)[1]
    for _ in range(5):
        i = tlv(i)[1]
    return der[i:tlv(i)[1]]
def connect(ctx):
    if u.scheme == "http":
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=90)
    else:
        c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=90, context=ctx)
    c.connect()
    return c
try:
    c = connect(ssl.create_default_context())
except ssl.SSLCertVerificationError:
    if not pin:
        raise
    # The computer does not trust the server certificate: accept the public key EasyEAP made this script with.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = connect(ctx)
    if base64.b64encode(hashlib.sha256(spki(c.sock.getpeercert(True))).digest()).decode() != pin:
        sys.exit("The server certificate is not the one this script was made with.")
headers = {"Accept": "text/plain, application/json"}
body = open(data, "rb").read() if data else None
if body is not None:
    headers["Content-Type"] = "application/json"
c.request(method, u.path + ("?" + u.query if u.query else ""), body=body, headers=headers)
r = c.getresponse()
open(out, "wb").write(r.read())
open(code, "w").write(str(r.status))
PY
    rc=$?; HTTP_CODE=$(cat "$WORK/code"); HTTP_CODE=${HTTP_CODE:-000}
    [ "$rc" = 0 ] && return 0
    TRANSPORT_ERR=$(tail -n 1 "$WORK/err" | cut -c1-300); return 1
  else
    TRANSPORT_ERR="neither curl nor python3 is installed"; return 1
  fi
}

# The "detail" of an EasyEAP error answer, else the start of the answer.
api_detail() {
  local d
  d=$(sed -n 's/.*"detail" *: *"\(\([^"\\]\|\\.\)*\)".*/\1/p' "$WORK/resp" | head -n 1 | sed 's/\\"/"/g')
  [ -n "$d" ] && { printf '%s' "$d"; return; }
  printf 'EasyEAP answered %s: %s' "$HTTP_CODE" "$(tr '\n' ' ' < "$WORK/resp" | cut -c1-200)"
}

# A refusal's code (EasyEAP 2026-11 and later): whether a waiting request is finished with.
api_code() { sed -n 's/.*"code" *: *"\([a-z_]*\)".*/\1/p' "$WORK/resp" | head -n 1; }

sha256_hex() { openssl dgst -sha256 | sed 's/.*= *//'; }
same_key() { [ "$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null)" = "$(openssl pkey -in "$2" -pubout 2>/dev/null)" ]; }

# new_key TYPE FILE: ec (P-256, PKCS#8: NetworkManager 1.36 refuses SEC1 "EC PRIVATE KEY") or rsa (3072).
new_key() {
  if [ "$1" = rsa ]; then openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$2" 2>>"$WORK/err"
  else openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" 2>>"$WORK/err"; fi
}

# new_csr KEY OUT: a request with a neutral subject (EasyEAP takes the names from the directory).
new_csr() {
  printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=EasyEAP enrollment\n' > "$WORK/req.cnf"
  openssl req -new -config "$WORK/req.cnf" -key "$1" -sha256 -out "$2" 2>>"$WORK/err"
}

json_pem() { awk '{ printf "%s\\n", $0 }' "$1"; }
key_type_of() { if openssl pkey -in "$1" -noout -text 2>/dev/null | grep -q 'ASN1 OID'; then echo ec; else echo rsa; fi; }
"""

_RENEW = r"""
RENEWER_VERSION=2.0
LOG="$DIR/renew.log"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"; printf '%s\n' "$*"; }
cert="$DIR/client.pem"; key="$DIR/client.key"
[ -r "$cert" ] && [ -r "$key" ] || { log "No certificate in $DIR."; exit 1; }
if ! openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1; then log "The certificate has expired; it can't renew itself. Enroll again."; exit 1; fi
WORK=$(mktemp -d "${TMPDIR:-/tmp}/easyeap-renew.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/err"
# The new key and its request stay in $DIR until the new certificate is in: if EasyEAP's answer gets lost (sleep, a
# Wi-Fi drop), the next run sends the same request, and EasyEAP sends the certificate it already issued for it.
pkey="$DIR/renew-pending.key"; pcsr="$DIR/renew-pending.csr"; final="$DIR/renew-refused"
pending() { [ -s "$pkey" ] && [ -s "$pcsr" ] && [ "$(openssl req -in "$pcsr" -noout -pubkey 2>/dev/null)" = "$(openssl pkey -in "$pkey" -pubout 2>/dev/null)" ]; }
sign() { printf '%s' "$1" > "$WORK/msg"; openssl dgst -sha256 -sign "$key" "$WORK/msg" | openssl base64 -A; }
now=$(date +%s)
cert_hex=$(openssl x509 -in "$cert" -outform DER | sha256_hex)
der=$(openssl x509 -in "$cert" -outform DER | openssl base64 -A)

# What this renewer is and the roots the connection trusts (the self-signed certificates in ca.pem), for the console.
roots=
if [ -s "$DIR/ca.pem" ]; then
  awk -v d="$WORK" '/BEGIN CERTIFICATE/ { n++ } n { print > (d "/ca-" n ".pem") }' "$DIR/ca.pem"
  for f in "$WORK"/ca-*.pem; do
    [ -f "$f" ] || continue
    [ "$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed 's/^subject *= *//')" = "$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed 's/^issuer *= *//')" ] || continue
    roots="$roots${roots:+,}\"$(openssl x509 -in "$f" -outform DER | sha256_hex)\""
  done
fi
CLIENT=$(printf '{"kind":"linux","version":"%s","scope":"computer","roots":[%s]}' "$RENEWER_VERSION" "$roots")
client_hex=$(printf '%s' "$CLIENT" | sha256_hex)
client_json=$(printf '%s' "$CLIENT" | sed 's/"/\\"/g')
PROTO=2

# Due? A request still waiting from an earlier run is sent again at once. Otherwise a signed check-in: EasyEAP answers
# when renewal starts (a share of the certificate's life set in the console). Without an answer, the template's
# renewal period this script was made with decides.
if ! pending; then
  sig=$(sign "easyeap-check-v2|$cert_hex|$now|$client_hex")
  printf '{"certificate":"%s","signed_at":%s,"signature":"%s","client":"%s"}' "$der" "$now" "$sig" "$client_json" > "$WORK/body.json"
  http POST "$API/api/enroll/renew" "$WORK/body.json"; rc=$?
  if [ "$rc" = 0 ] && [ "$HTTP_CODE" = 200 ]; then
    # Refused for good earlier (this certificate was renewed elsewhere, or revoked): asking again changes nothing.
    if [ "$(cat "$final" 2>/dev/null)" = "$cert_hex" ]; then log "EasyEAP won't renew this certificate (see renew.log). Enroll again."; exit 1; fi
    # Renewed, but the new certificate never got here and no request is waiting (its key was lost): EasyEAP replaces it
    # if nothing used it, within limits.
    # (Its renew_from is the moment EasyEAP answered, which can be a second past this run's start: not compared.)
    superseded=
    if grep -q '"superseded" *: *true' "$WORK/resp"; then
      superseded=1; log "EasyEAP renewed this certificate, but the new one never arrived here. Asking again with a new key."
    fi
    rf=$(sed -n 's/.*"renew_from" *: *"\([^"]*\)".*/\1/p' "$WORK/resp" | head -n 1)
    rf_s=$(date -u -d "$rf" +%s 2>/dev/null) || rf_s=
    if [ -n "$superseded" ]; then
      if grep -q '"renewal_enabled" *: *false' "$WORK/resp"; then log "Automatic renewal is turned off in EasyEAP. Ask your IT team for a new link."; exit 1; fi
    elif [ -n "$rf_s" ]; then
      [ "$now" -ge "$rf_s" ] || exit 0
      if grep -q '"renewal_enabled" *: *false' "$WORK/resp"; then log "Renewal is due, but automatic renewal is turned off in EasyEAP. Ask your IT team for a new link."; exit 1; fi
    else
      openssl x509 -in "$cert" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null 2>&1 && exit 0
    fi
  elif [ "$rc" = 0 ] && [ "$HTTP_CODE" = 400 ]; then
    log "Check-in refused: $(api_detail)"; exit 1
  else
    # No answer, or an EasyEAP from before check-ins (it wants a request: protocol 1).
    case "$HTTP_CODE" in 404|422) PROTO=1 ;; esac
    openssl x509 -in "$cert" -noout -checkend $((RENEW_DAYS * 86400)) >/dev/null 2>&1 && exit 0
    [ "$rc" = 0 ] || log "Couldn't reach EasyEAP to check in: $TRANSPORT_ERR"
  fi
fi

if ! pending; then
  new_key "$(key_type_of "$key")" "$WORK/key.pem" && new_csr "$WORK/key.pem" "$WORK/req.csr" || { log "openssl failed: $(head -c 300 "$WORK/err")"; exit 1; }
  cp "$WORK/key.pem" "$pkey" && cp "$WORK/req.csr" "$pcsr" && chmod 600 "$pkey" || { log "Couldn't write $pkey."; exit 1; }
fi
csr_hex=$(openssl req -in "$pcsr" -outform DER | sha256_hex)
if [ "$PROTO" = 2 ]; then
  sig=$(sign "easyeap-renew-v2|$cert_hex|$now|$csr_hex|$client_hex"); extra=",\"client\":\"$client_json\""
else
  sig=$(sign "easyeap-renew-v1|$cert_hex|$now|$csr_hex"); extra=
fi
printf '{"certificate":"%s","csr":"%s","signed_at":%s,"signature":"%s","key_storage":"software"%s}' "$der" "$(json_pem "$pcsr")" "$now" "$sig" "$extra" > "$WORK/body.json"
http POST "$API/api/enroll/renew?format=pem" "$WORK/body.json" || { log "Couldn't reach EasyEAP: $TRANSPORT_ERR"; exit 1; }
case "$HTTP_CODE" in
  204) log "EasyEAP doesn't renew it yet."; exit 0 ;;
  200) ;;
  # Refused (the reason is in EasyEAP's audit log too). Only a final refusal finishes the request: after a wrong clock,
  # say, a certificate may already exist for that key, so it stays and is sent again.
  400) log "Renewal refused: $(api_detail)"
       case "$(api_code)" in renewed|conflict|revoked|expired|same_key|request|gpo|kind|missing)
         rm -f "$pkey" "$pcsr"; printf '%s' "$cert_hex" > "$final" ;; esac
       exit 1 ;;
  *) log "Renewal failed, asking again next time: $(api_detail)"; exit 1 ;;
esac
grep -q 'BEGIN CERTIFICATE' "$WORK/resp" && same_key "$WORK/resp" "$pkey" || { log "EasyEAP's answer isn't a certificate for the new key."; exit 1; }
# The key first, then the certificate: a reader in between sees the old certificate with a key it doesn't match,
# for a moment, once a year; NetworkManager and wpa_supplicant read both files at each connection anyway.
cp "$pkey" "$key.new" && cp "$WORK/resp" "$cert.new" && chmod 600 "$key.new" && chmod 644 "$cert.new" \
  && mv -f "$key.new" "$key" && mv -f "$cert.new" "$cert" || { log "Couldn't write the new files in $DIR."; exit 1; }
rm -f "$pkey" "$pcsr" "$final"
have restorecon && restorecon -R "$DIR" >/dev/null 2>&1
log "Renewed: $(openssl x509 -in "$cert" -noout -enddate)"
"""

_SETUP = r"""
WIRED_NAME="Wired 802.1X ($ORG)"
TIMER="easyeap-renew-$SLUG"
CHANGED=0

die() {
  printf '\n%sSetup did not finish:%s %s\n' "$R" "$N" "$*" >&2
  if [ "$CHANGED" = 0 ]; then printf 'Nothing was changed on this computer. ' >&2; fi
  printf 'Ask your IT team for help, and include this message.\n' >&2
  exit 1
}
step() { printf '\n%s%s%s\n' "$B" "$*" "$N"; }

usage() {
  cat <<EOF
EasyEAP network setup for $ORG: Wi-Fi "$SSID".

  bash $(basename -- "$0")              set this computer up (asks for your password)
  bash $(basename -- "$0") --check      only show what it would do; changes nothing
  bash $(basename -- "$0") --remove     remove what an earlier run set up
  bash $(basename -- "$0") --no-wired   set up Wi-Fi only, not network ports
EOF
}

MODE=setup
for a in "$@"; do
  case "$a" in
    --check) MODE=check ;;
    --remove) MODE=remove ;;
    --no-wired) WIRED=0 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n\n' "$a"; usage; exit 2 ;;
  esac
done

[ "$(uname -s)" = Linux ] || { printf 'This script is for Linux.\n' >&2; exit 1; }

if [ "$(id -u)" != 0 ] && [ "$MODE" != check ]; then
  self=$(readlink -f -- "$0" 2>/dev/null || printf '%s' "$0")
  say "Adding a network needs administrator rights. If asked, type the password you use for $(id -un) and press Enter."
  say "(Nothing shows while you type.)"
  if have sudo; then exec sudo -- bash "$self" "$@"; fi
  if have pkexec; then exec pkexec bash "$self" "$@"; fi
  printf 'Run it as root: this computer has neither sudo nor pkexec.\n' >&2
  exit 1
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/easyeap.XXXXXX") || { printf 'Could not create a temporary folder.\n' >&2; exit 1; }
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/err"

# ── What this computer is ───────────────────────────────────────────────
os_name() { ( . /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-${NAME:-Linux}}" ); }
svc_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }
nm_running() { have nmcli && [ "$(nmcli -t -f RUNNING general 2>/dev/null)" = running ]; }
wifi_ifaces() { local d; for d in /sys/class/net/*; do if [ -d "$d/wireless" ] || [ -e "$d/phy80211" ]; then basename -- "$d"; fi; done; }
eth_ifaces() {
  local d
  for d in /sys/class/net/*; do
    [ -e "$d/device" ] && [ ! -d "$d/wireless" ] && [ ! -e "$d/phy80211" ] && [ "$(cat "$d/type" 2>/dev/null)" = 1 ] && basename -- "$d"
  done
}
nm_backend() { local b; b=$(NetworkManager --print-config 2>/dev/null | sed -n 's/^wifi\.backend=//p' | head -n 1); printf '%s' "${b:-wpa_supplicant}"; }

detect_stack() {
  if nm_running; then echo nm
  elif svc_active iwd || pgrep -x iwd >/dev/null 2>&1; then echo iwd
  elif have wpa_supplicant && svc_active systemd-networkd; then echo networkd
  elif have dhcpcd && [ -f /etc/wpa_supplicant/wpa_supplicant.conf ] && pgrep -x wpa_supplicant >/dev/null 2>&1 \
       && { svc_active dhcpcd || pgrep -x dhcpcd >/dev/null 2>&1; }; then echo dhcpcd  # Raspberry Pi OS before Bookworm
  else echo none; fi
}

OS=$(os_name)
mapfile -t WIFI < <(wifi_ifaces)
mapfile -t ETH < <(eth_ifaces)
STACK=$(detect_stack)
KEYTYPE=ec
case "$STACK" in
  nm) STACK_TEXT="NetworkManager $(nmcli --version 2>/dev/null | awk '{ print $NF }'), Wi-Fi through $(nm_backend)"
      [ "$(nm_backend)" = iwd ] && KEYTYPE=rsa ;;
  iwd) STACK_TEXT="iwd"; KEYTYPE=rsa ;;
  networkd) STACK_TEXT="systemd-networkd with wpa_supplicant" ;;
  dhcpcd) STACK_TEXT="dhcpcd with wpa_supplicant" ;;
  *) STACK_TEXT="none that this script knows (NetworkManager, iwd or wpa_supplicant)" ;;
esac
IF=${WIFI[0]:-}
[ "$STACK" = nm ] || WIRED=0

say "${B}EasyEAP setup for $ORG${N}"
say "  Computer:  $OS ($(uname -n))"
say "  Network:   $STACK_TEXT"
say "  Wi-Fi:     ${WIFI[*]:-no Wi-Fi adapter found}"
[ "$WIRED" = 1 ] && say "  Wired:     ${ETH[*]:-no network port found}: 802.1X when the port asks for it"
say "  Joins:     \"$SSID\", checking that the server is $SERVER"

# ── --remove ────────────────────────────────────────────────────────────
nm_name() { nmcli -g connection.id connection show uuid "$1" 2>/dev/null | sed 's/\\\(.\)/\1/g'; }  # -g escapes : and \
nm_get() { nmcli -g "$1" connection show uuid "$2" 2>/dev/null; }
nm_val() { nm_get "$1" "$2" | sed 's/\\\(.\)/\1/g'; }  # without -g's escaping of : and \
nm_eth() { nmcli -t -f UUID,TYPE connection show 2>/dev/null | sed -n 's/^\([0-9a-f-]*\):802-3-ethernet$/\1/p'; }
port_mac() {  # the permanent address of network port $1, when it is here
  local m
  m=$(ip -d -o link show dev "$1" 2>/dev/null | sed -n 's/.* permaddr \([0-9a-fA-F:]\{17\}\).*/\1/p')
  [ -n "$m" ] || m=$(cat "/sys/class/net/$1/address" 2>/dev/null)
  printf '%s' "$m" | tr 'A-F' 'a-f'
}
# NetworkManager's own "Wired connection 1" lives in memory, and isn't made again (after a restart) while another
# connection fits its port: the copy this script made of it. Without the copy, the port would have no connection at
# all, so it gets a plain one back, like NetworkManager's.
nm_restore_ports() {
  local u dev ifn mac n names claimed=' '
  for u in $(nm_eth); do
    ifn=$(nm_val connection.interface-name "$u"); mac=$(nm_val 802-3-ethernet.mac-address "$u" | tr 'A-F' 'a-f')
    if [ -n "$ifn" ]; then claimed+="$ifn "
    elif [ -n "$mac" ]; then for dev in ${ETH[@]+"${ETH[@]}"}; do [ "$(port_mac "$dev")" = "$mac" ] && claimed+="$dev "; done
    else return 0; fi  # a connection that can fit any port
  done
  for dev in ${ETH[@]+"${ETH[@]}"}; do
    case "$claimed" in *" $dev "*) continue ;; esac
    names=$(for u in $(nmcli -t -f UUID connection show 2>/dev/null); do nm_name "$u"; done)
    n=1; while printf '%s\n' "$names" | grep -qxF "Wired connection $n"; do n=$((n+1)); done
    nmcli connection add type ethernet con-name "Wired connection $n" connection.interface-name "$dev" \
      connection.autoconnect-priority -999 >/dev/null 2>&1 && ok "Gave $dev a plain wired connection back (\"Wired connection $n\")"
  done
}
nm_ours() {  # UUIDs of NetworkManager connections that use this tenant's files
  local uuid ca
  nmcli -t -f UUID connection show 2>/dev/null | while read -r uuid; do
    ca=$(nmcli -g 802-1x.ca-cert connection show uuid "$uuid" 2>/dev/null | sed 's#^file://##')
    [ "$ca" = "$DIR/ca.pem" ] && printf '%s\n' "$uuid"
  done
}
drop_block() {  # remove this tenant's network from a wpa_supplicant file; non-zero when it had none
  # By its id_str, which survives tools that rewrite the file (wpa_cli save_config, raspi-config), and its comments.
  [ -f "$1" ] || return 1
  awk -v id="id_str=\"easyeap-$SLUG\"" -v b="# BEGIN EasyEAP $SLUG" -v e="# END EasyEAP $SLUG" '
    $0 == b || $0 == e { hit = 1; next }
    !inb && /^[[:space:]]*network[[:space:]]*=[[:space:]]*[{]/ { inb = 1; buf = ""; mine = 0 }
    inb { buf = buf $0 "\n"; if (index($0, id)) mine = 1
          if ($0 ~ /^[[:space:]]*[}]/) { inb = 0; if (mine) hit = 1; else printf "%s", buf }
          next }
    { print }
    END { if (inb) printf "%s", buf; exit !hit }' "$1" > "$1.easyeap" || { rm -f "$1.easyeap"; return 1; }
  cat "$1.easyeap" > "$1" && rm -f "$1.easyeap"
}
remove_all() {
  local u f i n=0 wired=0
  if have nmcli && nm_running; then
    for u in $(nm_ours); do
      i=$(nm_name "$u"); [ "$(nm_get connection.type "$u")" = 802-3-ethernet ] && wired=1
      nmcli connection delete uuid "$u" >/dev/null 2>&1 && { ok "Removed the NetworkManager connection \"$i\""; n=$((n+1)); }
    done
    [ "$wired" = 1 ] && nm_restore_ports
  fi
  f="/var/lib/iwd/$IWD_NAME.8021x"
  if [ -f "$f" ] && grep -q "$DIR/" "$f"; then rm -f "$f" && ok "Removed $f"; n=$((n+1)); fi
  for f in /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant-*.conf; do
    [ -f "$f" ] && drop_block "$f" || continue
    ok "Removed the network from $f"; n=$((n+1))
    case "$f" in
      */wpa_supplicant-*.conf)
        i=${f##*/wpa_supplicant-}; i=${i%.conf}
        if grep -q '^# Created by EasyEAP' "$f" && ! grep -q 'network={' "$f"; then
          have systemctl && systemctl disable --now "wpa_supplicant@$i.service" >/dev/null 2>&1
          rm -f "$f"
          if [ -f "/etc/systemd/network/60-easyeap-$i.network" ]; then
            rm -f "/etc/systemd/network/60-easyeap-$i.network"; have networkctl && networkctl reload >/dev/null 2>&1
          fi
        else
          have wpa_cli && wpa_cli -i "$i" reconfigure >/dev/null 2>&1
        fi ;;
      *) for i in "${WIFI[@]}"; do have wpa_cli && wpa_cli -i "$i" reconfigure >/dev/null 2>&1; done ;;
    esac
  done
  if [ -f "/etc/systemd/system/$TIMER.timer" ]; then
    systemctl disable --now "$TIMER.timer" >/dev/null 2>&1
    rm -f "/etc/systemd/system/$TIMER.timer" "/etc/systemd/system/$TIMER.service"; systemctl daemon-reload >/dev/null 2>&1
    ok "Removed the renewal timer"; n=$((n+1))
  fi
  [ -f "/etc/cron.daily/$TIMER" ] && rm -f "/etc/cron.daily/$TIMER" && { ok "Removed the daily renewal"; n=$((n+1)); }
  if [ -d "$DIR" ]; then rm -rf "$DIR" && ok "Removed $DIR (certificate and key)"; n=$((n+1)); fi
  rmdir /etc/easyeap 2>/dev/null
  [ "$n" = 0 ] && say "Nothing from EasyEAP for $ORG was set up on this computer."
  return 0
}
if [ "$MODE" = remove ]; then step "Removing the EasyEAP setup for $ORG"; remove_all; exit 0; fi

# ── Before changing anything ────────────────────────────────────────────
case "$STACK" in
  none) die "This computer doesn't run NetworkManager, iwd or wpa_supplicant (with systemd-networkd or dhcpcd), so this script can't add the network. Install NetworkManager, or set it up by hand with the settings on the enrollment page." ;;
  networkd|dhcpcd) [ -n "$IF" ] || die "This computer has no Wi-Fi adapter." ;;
esac
if [ "$STACK" = networkd ] && grep -qs -- "^[[:space:]]*$IF:" /etc/netplan/*.yaml; then
  die "netplan already configures $IF. Add the network there by hand, or let NetworkManager manage Wi-Fi."
fi
if ! have openssl; then
  if [ "$MODE" = check ]; then warn "openssl isn't installed: the setup installs it."
  elif have apt-get; then apt-get install -y openssl >/dev/null 2>&1
  elif have dnf; then dnf -y install openssl >/dev/null 2>&1
  elif have zypper; then zypper -n install openssl >/dev/null 2>&1
  elif have pacman; then pacman -S --noconfirm openssl >/dev/null 2>&1; fi
  [ "$MODE" = check ] || have openssl || die "openssl isn't installed, and installing it didn't work. Install the openssl package, then run this again."
fi
have curl || have python3 || die "This script needs curl or python3 to reach EasyEAP. Install curl, then run this again."

step "Checking your enrollment link"
http GET "$API/api/enroll/$TOKEN" || die "Can't reach $API: $TRANSPORT_ERR. Check that this computer is online, then try again."
LINK=other
if [ "$HTTP_CODE" = 200 ]; then
  if grep -Eq '"status" *: *"pending"' "$WORK/resp"; then LINK=pending
  elif grep -Eq '"status" *: *"completed"' "$WORK/resp"; then LINK=used
  elif grep -Eq '"status" *: *"expired"' "$WORK/resp"; then LINK=expired
  elif grep -Eq '"status" *: *"cancelled"' "$WORK/resp"; then LINK=cancelled; fi
fi
reusable() {  # a certificate from an earlier run of this script for this person, still good, for this key and this CA
  [ -s "$DIR/client.pem" ] && [ -s "$DIR/client.key" ] && [ -s "$DIR/ca.pem" ] || return 1
  [ "$(cat "$DIR/identity" 2>/dev/null)" = "$IDENTITY" ] || return 1
  openssl x509 -in "$DIR/client.pem" -noout -checkend 86400 >/dev/null 2>&1 || return 1
  same_key "$DIR/client.pem" "$DIR/client.key" || return 1
  [ "$KEYTYPE" = rsa ] && [ "$(key_type_of "$DIR/client.key")" != rsa ] && return 1
  printf '%s\n' "$CA_CHAIN" > "$WORK/ca.pem"
  openssl verify -CAfile "$WORK/ca.pem" "$DIR/client.pem" >/dev/null 2>&1
}
case "$LINK" in
  pending) ok "The link is ready" ;;
  used) if reusable; then ok "The link was used by an earlier run on this computer: its certificate is still good"
        else die "This link has already been used. Each link works once. If you downloaded the setup script again for a newer link, run the newest file (it may be called \"EasyEAP-WiFi-Setup (1).sh\"). Otherwise ask your IT team for a new link."; fi ;;
  expired) die "This link has expired. If you downloaded the setup script again for a newer link, run the newest file (it may be called \"EasyEAP-WiFi-Setup (1).sh\"). Otherwise ask your IT team for a new link." ;;
  cancelled) die "Your IT team cancelled this link. Ask them for a new one." ;;
  *) die "$(api_detail)" ;;
esac

if [ "$MODE" = check ]; then
  step "What the setup would do"
  say "  - Create a private key on this computer ($([ "$KEYTYPE" = rsa ] && echo RSA-3072 || echo ECDSA P-256)) and get its certificate from EasyEAP"
  say "  - Save them in $DIR (the key readable by root only)"
  case "$STACK" in
    nm) say "  - Add the NetworkManager connection \"$SSID\" for all users, and connect if the network is in range"
        [ "$WIRED" = 1 ] && say "  - Network ports: add 802.1X to a copy of each wired connection, and a connection for the ports without one (a dock, a USB adapter)" ;;
    iwd) say "  - Write /var/lib/iwd/$IWD_NAME.8021x" ;;
    networkd) say "  - Add the network to /etc/wpa_supplicant/wpa_supplicant-$IF.conf, run wpa_supplicant@$IF and DHCP on $IF" ;;
    dhcpcd) say "  - Add the network to /etc/wpa_supplicant/wpa_supplicant.conf" ;;
  esac
  say "  - Renew the certificate by itself before it expires (checked daily)"
  say ""
  say "Nothing was changed."
  exit 0
fi

# ── The certificate ─────────────────────────────────────────────────────
install_files() {  # install_files KEY CERT
  mkdir -p /etc/easyeap "$DIR" && chown root:root /etc/easyeap "$DIR" && chmod 755 /etc/easyeap && chmod 700 "$DIR" || die "Couldn't create $DIR."
  printf '%s\n' "$CA_CHAIN" > "$DIR/ca.pem.new" && cp "$1" "$DIR/client.key.new" && cp "$2" "$DIR/client.pem.new" \
    && printf '%s\n' "$IDENTITY" > "$DIR/identity.new" \
    && chmod 644 "$DIR/ca.pem.new" "$DIR/client.pem.new" "$DIR/identity.new" && chmod 600 "$DIR/client.key.new" \
    && mv -f "$DIR/ca.pem.new" "$DIR/ca.pem" && mv -f "$DIR/client.key.new" "$DIR/client.key" && mv -f "$DIR/client.pem.new" "$DIR/client.pem" \
    && mv -f "$DIR/identity.new" "$DIR/identity" && rm -f "$DIR/renew-pending.key" "$DIR/renew-pending.csr" "$DIR/renew-refused" \
    || die "Couldn't write the certificate files in $DIR."
  have restorecon && restorecon -R /etc/easyeap >/dev/null 2>&1
  return 0
}
if [ "$LINK" = pending ]; then
  step "Getting your certificate"
  new_key "$KEYTYPE" "$WORK/key.pem" && new_csr "$WORK/key.pem" "$WORK/req.csr" || die "openssl couldn't create a key: $(head -c 300 "$WORK/err")"
  hint=$(uname -n | tr -cd 'A-Za-z0-9._-' | cut -c1-60)
  printf '{"csr":"%s","key_origin":"device","key_storage":"software","device_hint":"%s"}' "$(json_pem "$WORK/req.csr")" "$hint" > "$WORK/body.json"
  http POST "$API/api/enroll/$TOKEN/csr?format=pem" "$WORK/body.json" || die "Can't reach $API: $TRANSPORT_ERR. Check that this computer is online, then try again."
  [ "$HTTP_CODE" = 200 ] || die "$(api_detail)"
  grep -q 'BEGIN CERTIFICATE' "$WORK/resp" && same_key "$WORK/resp" "$WORK/key.pem" || die "EasyEAP's answer isn't a certificate for this key."
  CHANGED=1
  install_files "$WORK/key.pem" "$WORK/resp"
  ok "Certificate saved in $DIR: $(openssl x509 -in "$DIR/client.pem" -noout -enddate | sed 's/notAfter=/valid until /')"
else
  CHANGED=1
  printf '%s\n' "$CA_CHAIN" > "$DIR/ca.pem" && chmod 644 "$DIR/ca.pem"
fi

# ── The network ─────────────────────────────────────────────────────────
FAILED=
nm_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/:/\\:/g'; }
NM_8021X=(802-1x.eap tls 802-1x.identity "$IDENTITY" 802-1x.domain-suffix-match "$SERVER" 802-1x.ca-cert "$DIR/ca.pem"
          802-1x.client-cert "$DIR/client.pem" 802-1x.private-key "$DIR/client.key" 802-1x.private-key-password-flags 4)
setup_nm() {
  local uuid name out ssid wifi_uuid=
  step "Adding the network to NetworkManager"
  # This script's connections from an earlier run, then other settings for this network (a manual attempt in the
  # desktop's Wi-Fi dialog), would compete with the new ones.
  for uuid in $(nm_ours); do nmcli connection delete uuid "$uuid" >/dev/null 2>&1; done
  for uuid in $(nmcli -t -f UUID,TYPE connection show 2>/dev/null | sed -n 's/^\([0-9a-f-]*\):802-11-wireless$/\1/p'); do
    ssid=$(nm_get 802-11-wireless.ssid "$uuid")
    [ "$ssid" = "$(nm_escape "$SSID")" ] || [ "$ssid" = "$SSID" ] || continue
    name=$(nm_name "$uuid")
    nmcli connection delete uuid "$uuid" >/dev/null 2>&1 && ok "Replaced the earlier settings for this network (\"$name\")"
  done
  local args=(connection add type wifi con-name "$SSID" ssid "$SSID" connection.autoconnect yes wifi-sec.key-mgmt wpa-eap "${NM_8021X[@]}")
  [ "$WPA3" = 1 ] && args+=(wifi-sec.pmf required)
  out=$(nmcli "${args[@]}" 2>&1) || die "NetworkManager didn't accept the Wi-Fi settings: $out"
  wifi_uuid=$(printf '%s' "$out" | sed -n 's/.*(\([0-9a-f-]\{36\}\)).*/\1/p')
  ok "Added the Wi-Fi network \"$SSID\" for all users of this computer"
  [ "$WIRED" = 1 ] && setup_nm_wired
  [ -n "$IF" ] || { warn "No Wi-Fi adapter right now: it connects once there is one."; return; }
  nmcli device wifi rescan >/dev/null 2>&1; sleep 4
  if ! nmcli -t -f SSID-HEX device wifi list 2>/dev/null | grep -qixF -- "$SSID_HEX" \
     && ! nmcli -t -f SSID device wifi list 2>/dev/null | grep -qxF -- "$(nm_escape "$SSID")"; then
    ok "\"$SSID\" isn't in range here. This computer connects by itself when it is."; return
  fi
  step "Connecting to \"$SSID\""
  if out=$(nmcli --wait 90 connection up uuid "$wifi_uuid" 2>&1); then
    ok "Connected$(ip -4 -o addr show dev "$IF" 2>/dev/null | awk '{ split($4, a, "/"); printf ", address %s", a[1]; exit }')"
  else
    FAILED="$(printf '%s' "$out" | head -n 1)"
  fi
}
# Network ports. 802.1X is optional on them: a port that doesn't ask for it connects anyway, after up to 15 seconds.
# Wired connections this computer already has keep their settings (a fixed address, DNS, one port): each gets a copy
# with 802.1X added that NetworkManager prefers over the original. One more connection is for the ports none of
# them is for (a dock, a USB adapter), and leaves the others out, so that NetworkManager offers one 802.1X connection
# per port. A connection is for one port by connection.interface-name (NetworkManager's own "Wired connection 1") or
# ethernet.mac-address; one with neither, and no match, can go on any port. Nothing is reconnected now.
nm_version() {  # 1.48.10 -> 1048; 0 when unknown
  local v a b
  v=$(nmcli --version 2>/dev/null | awk '{ print $NF }'); a=${v%%.*}; b=${v#*.}; b=${b%%.*}
  case "$a:$b" in *[!0-9:]*|:*|*:) echo 0 ;; *) echo $((10#$a * 1000 + 10#$b)) ;; esac
}
nm_claim() {  # setup_nm_wired: the port of the connection in hand ($ifn, $mac) has a connection of its own
  if [ -n "$ifn" ]; then ports+=("$ifn"); elif [ -n "$mac" ]; then macs+=("$mac"); fi
}
setup_nm_wired() {
  local uuid name prio out new ifn mac p list key gname everywhere='' ports=() macs=() excl=()
  local wired=(802-1x.optional yes 802-1x.auth-timeout 15)
  for uuid in $(nm_eth); do
    name=$(nm_name "$uuid")
    ifn=$(nm_val connection.interface-name "$uuid"); mac=$(nm_val 802-3-ethernet.mac-address "$uuid")
    if [ -n "$(nm_get connection.master "$uuid")" ]; then nm_claim; continue; fi  # part of a bond or a bridge: left alone
    if [ -n "$(nm_get 802-1x.eap "$uuid")" ]; then warn "\"$name\" already uses 802.1X: left as it is"; nm_claim; continue; fi
    prio=$(nm_get connection.autoconnect-priority "$uuid")
    case "$prio" in ''|*[!0-9-]*|-) prio=0 ;; esac
    [ "$prio" -lt 10 ] && prio=10
    prio=$((prio + 10)); [ "$prio" -gt 999 ] && prio=999
    out=$(nmcli connection clone uuid "$uuid" "$WIRED_NAME: $name" 2>&1) || { warn "Couldn't add 802.1X to \"$name\": $out"; continue; }
    new=$(printf '%s' "$out" | grep -o '[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}' | tail -n 1)
    if [ -n "$new" ] && out=$(nmcli connection modify uuid "$new" connection.autoconnect-priority "$prio" "${NM_8021X[@]}" "${wired[@]}" 2>&1); then
      ok "Added 802.1X to a copy of \"$name\": the same settings, used in its place"
      nm_claim
      # A copy that can go on any port, by itself, does the other connection's job.
      p=$(nm_get match.interface-name "$new")$(nm_get match.driver "$new")$(nm_get match.path "$new")
      p+=$(nm_get 802-3-ethernet.mac-address-blacklist "$new")
      if [ -z "$ifn$mac$p" ] && [ "$(nm_get connection.autoconnect "$new")" = yes ]; then everywhere=${everywhere:-$name}; fi
    else
      [ -n "$new" ] && nmcli connection delete uuid "$new" >/dev/null 2>&1
      warn "Couldn't add 802.1X to \"$name\": $out"
    fi
  done
  if [ -n "$everywhere" ]; then
    ok "The copy of \"$everywhere\" goes on any network port: no other wired connection needed"; return
  fi
  # Leave out the ports above: by name ("!name", NetworkManager 1.22 and later, which wired 802.1X needs anyway), and
  # by address for connections bound by address (a name with characters the match syntax reads is skipped).
  list=''
  for p in ${ports[@]+"${ports[@]}"}; do
    case "$p" in *[!A-Za-z0-9._+@-]*) continue ;; esac
    list+="${list:+,}!$p"
  done
  [ -n "$list" ] && excl+=(match.interface-name "$list")
  if [ ${#macs[@]} -gt 0 ]; then
    key=802-3-ethernet.mac-address-blacklist; [ "$(nm_version)" -ge 1048 ] && key=802-3-ethernet.mac-address-denylist
    excl+=("$key" "$(IFS=,; printf '%s' "${macs[*]}")")
  fi
  gname=$WIRED_NAME; [ ${#excl[@]} -gt 0 ] && gname="$WIRED_NAME: other ports"
  if out=$(nmcli connection add type ethernet con-name "$gname" connection.autoconnect yes connection.autoconnect-priority 10 \
           "${NM_8021X[@]}" "${wired[@]}" ${excl[@]+"${excl[@]}"} 2>&1); then
    if [ ${#excl[@]} -gt 0 ]; then ok "Added \"$gname\" for the network ports without a connection of their own (a dock, a USB adapter)"
    else ok "Added \"$gname\" for the network ports: 802.1X where the port asks for it"; fi
  elif [ ${#excl[@]} -gt 0 ]; then
    warn "Couldn't add \"$gname\" for other network ports (a dock, a USB adapter): $out"
  else
    die "NetworkManager didn't accept the wired settings: $out"
  fi
}

setup_iwd() {
  local f="/var/lib/iwd/$IWD_NAME.8021x" out ident=${IDENTITY//\\/\\\\}  # iwd reads \\ as \
  step "Adding the network to iwd"
  mkdir -p /var/lib/iwd
  cat > "$f.easyeap" <<EOF || die "Couldn't write $f."
[Security]
EAP-Method=TLS
EAP-Identity=$ident
EAP-TLS-CACert=$DIR/ca.pem
EAP-TLS-ClientCert=$DIR/client.pem
EAP-TLS-ClientKey=$DIR/client.key
EAP-TLS-ServerDomainMask=$SERVER

[Settings]
AutoConnect=true
EOF
  chmod 600 "$f.easyeap" && mv -f "$f.easyeap" "$f" || die "Couldn't write $f."
  ok "Wrote $f"
  [ -n "$IF" ] && have iwctl || return 0
  iwctl station "$IF" scan >/dev/null 2>&1; sleep 4
  if ! iwctl station "$IF" get-networks 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -qF -- " $SSID "; then
    ok "\"$SSID\" isn't in range here. iwd connects by itself when it is."; return 0
  fi
  step "Connecting to \"$SSID\""
  if out=$(iwctl station "$IF" connect "$SSID" 2>&1); then
    ok "Connected (the address comes from iwd's own DHCP, systemd-networkd or dhcpcd)"
  else
    FAILED="$(printf '%s' "$out" | sed 's/\x1b\[[0-9;]*m//g' | head -n 1)"
  fi
}

wpa_block() {
  cat <<EOF
# BEGIN EasyEAP $SLUG
network={
	ssid=$SSID_HEX
	key_mgmt=WPA-EAP WPA-EAP-SHA256
	ieee80211w=$([ "$WPA3" = 1 ] && echo 2 || echo 1)
	eap=TLS
	identity=$IDENTITY_HEX
	ca_cert="$DIR/ca.pem"
	client_cert="$DIR/client.pem"
	private_key="$DIR/client.key"
	domain_suffix_match="$SERVER"
	id_str="easyeap-$SLUG"
}
# END EasyEAP $SLUG
EOF
}
put_block() {  # put_block FILE: this tenant's network block replaces any earlier one; the rest of the file stays
  local f=$1
  mkdir -p /etc/wpa_supplicant
  if [ ! -f "$f" ]; then printf '# Created by EasyEAP for %s.\nctrl_interface=DIR=/run/wpa_supplicant GROUP=root\nupdate_config=0\n\n' "$ORG" > "$f"; fi
  drop_block "$f"
  wpa_block >> "$f" && chmod 600 "$f" || die "Couldn't write $f."
}
wait_wpa() {
  local i
  for i in $(seq 1 30); do
    wpa_cli -i "$IF" status 2>/dev/null | grep -q '^wpa_state=COMPLETED' && { ok "Connected"; return 0; }
    sleep 1
  done
  ok "\"$SSID\" isn't connected yet: wpa_supplicant connects by itself when it's in range."
}
setup_networkd() {
  local f="/etc/wpa_supplicant/wpa_supplicant-$IF.conf" n="/etc/systemd/network/60-easyeap-$IF.network"
  step "Adding the network to wpa_supplicant on $IF"
  put_block "$f"
  ok "Wrote $f"
  if [ ! -f "$n" ] && ! grep -qs -- "^Name=$IF\$" /etc/systemd/network/*.network /run/systemd/network/*.network; then
    printf '# Created by EasyEAP for %s.\n[Match]\nName=%s\n\n[Network]\nDHCP=yes\n' "$ORG" "$IF" > "$n" && chmod 644 "$n"
    networkctl reload >/dev/null 2>&1 || systemctl restart systemd-networkd
    ok "DHCP on $IF ($n)"
  fi
  systemctl enable "wpa_supplicant@$IF.service" >/dev/null 2>&1
  systemctl restart "wpa_supplicant@$IF.service" || die "wpa_supplicant@$IF didn't start: see journalctl -u wpa_supplicant@$IF"
  wait_wpa
}
setup_dhcpcd() {
  local f=/etc/wpa_supplicant/wpa_supplicant.conf
  step "Adding the network to wpa_supplicant"
  put_block "$f"
  ok "Wrote $f"
  wpa_cli -i "$IF" reconfigure >/dev/null 2>&1
  wait_wpa
}

case "$STACK" in
  nm) setup_nm ;;
  iwd) setup_iwd ;;
  networkd) setup_networkd ;;
  dhcpcd) setup_dhcpcd ;;
esac

# ── Renewal ─────────────────────────────────────────────────────────────
step "Renewal"
__EASYEAP_RENEW_HEREDOC__
chmod 700 "$DIR/renew.sh"
if have systemctl && [ -d /run/systemd/system ]; then
  unit_org=$(printf '%s' "$ORG" | sed 's/%/%%/g')
  cat > "/etc/systemd/system/$TIMER.service" <<EOF
[Unit]
Description=EasyEAP certificate renewal ($unit_org)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $DIR/renew.sh
EOF
  cat > "/etc/systemd/system/$TIMER.timer" <<EOF
[Unit]
Description=Daily EasyEAP certificate renewal ($unit_org)

[Timer]
OnBootSec=15min
OnUnitActiveSec=1d
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  chmod 644 "/etc/systemd/system/$TIMER.service" "/etc/systemd/system/$TIMER.timer"
  systemctl daemon-reload && systemctl enable --now "$TIMER.timer" >/dev/null 2>&1 \
    && ok "The certificate renews itself before it expires (checked daily: $TIMER.timer)" \
    || warn "The daily renewal didn't start: run $DIR/renew.sh before the certificate expires."
elif [ -d /etc/cron.daily ]; then
  printf '#!/bin/sh\nexec /bin/bash %s/renew.sh >/dev/null 2>&1\n' "$DIR" > "/etc/cron.daily/$TIMER" && chmod 755 "/etc/cron.daily/$TIMER"
  ok "The certificate renews itself before it expires (checked daily: /etc/cron.daily/$TIMER)"
else
  warn "No systemd or cron here: run $DIR/renew.sh before the certificate expires."
fi

if [ -n "$FAILED" ]; then
  printf '\n%sThe network is set up, but connecting failed:%s %s\n' "$R" "$N" "$FAILED"
  printf 'Check that you are near "%s", then choose it in the Wi-Fi menu. If it still fails, tell your IT team what this says.\n' "$SSID"
  exit 3
fi
printf '\n%sDone.%s "%s" is set up for everyone who uses this computer. It connects by itself; no password is needed.\n' "$G" "$N" "$SSID"
printf 'To undo: bash %s --remove\n' "$(basename -- "$0")"
"""

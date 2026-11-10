#!/usr/bin/env bash
# Windows setup checks without Windows (docs/plans/windows-setup.md §6): the generated .cmd, renew.ps1 and portal helper
# files parse in PowerShell, their profiles carry the right sign-in mode and issuer filter, a v2 renewal and check-in
# signed by the script's own PowerShell code verify in EasyEAP (ECDSA P1363 and RSA), and renew.ps1's decisions hold
# against a stand-in store and EasyEAP (renew-decisions.ps1), the server-certificate pin against a self-signed HTTPS
# server (tls-pin.ps1), the certificate requests as Windows PowerShell 5.1 would send them (request-bodies.ps1),
# and the setup program (backend/winlauncher) built, filled and run under Mono (launcher.py).
# Not covered: certreq, TPM, netsh, UAC, SmartScreen, tasks, toasts.
#   API_IMAGE=easyeap-api-test:local PWSH_IMAGE=mcr.microsoft.com/powershell:7.5-ubuntu-24.04 tests/windows/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
API_IMAGE="${API_IMAGE:-easyeap-api-test:local}"
PWSH_IMAGE="${PWSH_IMAGE:-mcr.microsoft.com/powershell:7.5-ubuntu-24.04}"
MONO_IMAGE="${MONO_IMAGE:-mono:6.12.0.182}"   # as backend/Dockerfile builds the launcher
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
chmod 0777 "$OUT"
py() { local script="$1"; shift
       docker run --rm --network none -v "$PWD/backend":/src:ro -v "$PWD/tests/windows":/t:ro -v "$OUT":/out -w /src -e PYTHONPATH=/src \
         -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python "$API_IMAGE" "/t/$script" "$@" /out; }
mono() { docker run --rm --network none -v "$PWD/backend/winlauncher":/src:ro -v "$OUT":/out "$@"; }
py fixture.py make
set +e
docker run --rm --network none -v "$OUT":/out -v "$PWD/tests/windows":/t:ro "$PWSH_IMAGE" pwsh -NoProfile -File /t/check.ps1
ps=$?
# The certificate requests as each script builds them, checked for what Windows PowerShell 5.1 would send.
docker run --rm --network none -v "$OUT":/out:ro -v "$PWD/tests/windows":/t:ro "$PWSH_IMAGE" pwsh -NoProfile -File /t/request-bodies.ps1
pb=$?
py fixture.py verify
pv=$?
# The setup program: built as the API image builds it, then each one run with the extract hook instead of PowerShell.
# The launcher alone (nothing appended) must refuse with exit code 2.
pl=0
if mono "$MONO_IMAGE" csc -nologo -deterministic -optimize+ -target:exe -platform:anycpu -win32manifest:/src/app.manifest \
     -out:/out/launcher.exe /src/Launcher.cs && py launcher.py wrap; then
  for c in full helper; do
    mono -e EASYEAP_LAUNCHER_EXTRACT=/out/$c.extracted "$MONO_IMAGE" mono /out/$c.exe || pl=1
  done
  py launcher.py check || pl=1
  bare="$(mono -i "$MONO_IMAGE" mono /out/launcher.exe </dev/null)"; rc=$?
  if [ "$rc" = 2 ] && grep -q "incomplete or damaged" <<<"$bare"; then echo "  PASS the launcher alone says it's damaged (exit 2)"
  else echo "  FAIL the launcher alone: exit $rc, said: $bare"; pl=1; fi
else
  pl=1
fi
# The server-certificate pin against a real HTTPS server with a self-signed certificate (tls-pin.ps1), on a network of
# its own.
NET="easyeap-wintls-$$"
docker network create --internal "$NET" >/dev/null
SRV="$(docker run -d --rm --network "$NET" --network-alias tls-server -v "$OUT":/out:ro -v "$PWD/tests/windows":/t:ro \
        --entrypoint python "$API_IMAGE" /t/tls_server.py /out/tls.crt /out/tls.key 8443)"
docker run --rm --network "$NET" -v "$OUT":/out:ro -v "$PWD/tests/windows":/t:ro "$PWSH_IMAGE" \
  pwsh -NoProfile -File /t/tls-pin.ps1 -Url https://tls-server:8443/
pt=$?
docker rm -f "$SRV" >/dev/null 2>&1
docker network rm "$NET" >/dev/null 2>&1
set -e
fails=$((ps + pb + pv + pt + pl))
echo "windows checks: $fails failure(s)"
exit $((fails > 0))

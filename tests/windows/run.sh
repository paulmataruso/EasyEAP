#!/usr/bin/env bash
# Windows setup checks without Windows (docs/plans/windows-setup.md §6): the generated .cmd, renew.ps1 and portal helper
# files parse in PowerShell, their profiles carry the right sign-in mode and issuer filter, a v2 renewal and check-in
# signed by the script's own PowerShell code verify in EasyEAP (ECDSA P1363 and RSA), and renew.ps1's decisions hold
# against a stand-in store and EasyEAP (renew-decisions.ps1). Not covered: certreq, TPM, netsh, UAC, tasks, toasts.
#   API_IMAGE=easyeap-api-test:local PWSH_IMAGE=mcr.microsoft.com/powershell:7.5-ubuntu-24.04 tests/windows/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
API_IMAGE="${API_IMAGE:-easyeap-api-test:local}"
PWSH_IMAGE="${PWSH_IMAGE:-mcr.microsoft.com/powershell:7.5-ubuntu-24.04}"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
chmod 0777 "$OUT"
py() { docker run --rm --network none -v "$PWD/backend":/src:ro -v "$PWD/tests/windows":/t:ro -v "$OUT":/out -w /src -e PYTHONPATH=/src \
         -e PYTHONDONTWRITEBYTECODE=1 --entrypoint python "$API_IMAGE" /t/fixture.py "$@" /out; }
py make
set +e
docker run --rm --network none -v "$OUT":/out -v "$PWD/tests/windows":/t:ro "$PWSH_IMAGE" pwsh -NoProfile -File /t/check.ps1
ps=$?
py verify
pv=$?
set -e
fails=$((ps + pv))
echo "windows checks: $fails failure(s)"
exit $((fails > 0))

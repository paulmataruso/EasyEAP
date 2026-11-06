#!/bin/sh
# EasyEAP PKI supervisor: runs OpenBao and carries out backup requests from the EasyEAP API.
#
# The API cannot (and must never) control Docker. Instead it drops request files on the private control volume that
# only it and this container mount; nothing here listens on the network. Requests:
#
#   req/<id>.snapshot   stop OpenBao, copy its storage and the active seal key to out/<id>.tar, start it again
#   req/<id>.restore    install in/<id>.tar (storage + seal key from a backup), keeping the current ones for rollback;
#                       if OpenBao does not come up unsealed with them, roll back on the spot
#   req/<id>.rollback   put back what the last restore replaced
#   req/<id>.commit     forget the rollback copy
#
# Each request gets res/<id>.json: {"ok": true} or {"ok": false, "error": "..."}.
# The seal key lives on its own volume (state/unseal.key). On first start it is seeded from the Docker secret, so
# existing installs keep the same key; after a restore it is the backup's key.
set -u

DATA=/openbao/file
STATE=/openbao/state
SEAL=$STATE/unseal.key
ROLLBACK=$STATE/rollback
CTRL=/control
CONFIG=/openbao/config/config.hcl
API_UID=10001
BAO=""

say() { echo "easyeap-pki-supervisor: $*"; }

result() { # result <id> <ok:true|false> [error]
  tmp="$CTRL/res/.$1.tmp"
  if [ "$2" = true ]; then printf '{"ok": true}\n' > "$tmp"
  else printf '{"ok": false, "error": "%s"}\n' "$(printf '%s' "${3:-failed}" | tr -d '"\\\n')" > "$tmp"; fi
  chown "$API_UID:$API_UID" "$tmp"; chmod 0600 "$tmp"; mv "$tmp" "$CTRL/res/$1.json"
}

start_bao() {
  su-exec openbao bao server -config="$CONFIG" &
  BAO=$!
}

stop_bao() {
  [ -n "$BAO" ] || return 0
  kill -TERM "$BAO" 2>/dev/null
  i=0
  while kill -0 "$BAO" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 60 ] && { kill -KILL "$BAO" 2>/dev/null; break; }
    sleep 1
  done
  wait "$BAO" 2>/dev/null
  BAO=""
}

# sys/health answers 200 only when OpenBao is initialised, unsealed and active.
wait_unsealed() {
  i=0
  while [ "$i" -lt "$1" ]; do
    wget -q -O /dev/null http://127.0.0.1:8200/v1/sys/health 2>/dev/null && return 0
    kill -0 "$BAO" 2>/dev/null || return 1
    i=$((i + 1)); sleep 1
  done
  return 1
}

empty_dir() { find "$1" -mindepth 1 -maxdepth 1 -exec rm -rf {} + ; }
move_contents() { find "$1" -mindepth 1 -maxdepth 1 -exec mv {} "$2"/ \; ; }

fix_owner() {
  chown -R openbao:openbao "$DATA" /openbao/logs
  chown openbao:openbao "$STATE" "$SEAL"; chmod 0700 "$STATE"; chmod 0600 "$SEAL"
}

do_snapshot() {
  id=$1; tmp="$CTRL/out/.$id.tmp"
  stop_bao
  if tar -C /openbao -cf "$tmp" file state/unseal.key; then
    chown "$API_UID:$API_UID" "$tmp"; chmod 0600 "$tmp"; mv "$tmp" "$CTRL/out/$id.tar"; ok=true
  else
    rm -f "$tmp"; ok=false
  fi
  start_bao
  if ! wait_unsealed 90; then result "$id" false "OpenBao did not come back after the snapshot"; return; fi
  if [ "$ok" = true ]; then result "$id" true; else result "$id" false "Could not copy the PKI storage"; fi
  say "snapshot $id done (ok=$ok)"
}

restore_rollback_files() {
  empty_dir "$DATA"
  move_contents "$ROLLBACK/file" "$DATA"
  cp "$ROLLBACK/unseal.key" "$SEAL"
  rm -rf "$ROLLBACK"
  fix_owner
}

do_restore() {
  id=$1; in="$CTRL/in/$id.tar"
  [ -f "$in" ] || { result "$id" false "No staged PKI data"; return; }
  # Only OpenBao storage and the seal key, with relative paths that stay inside the target.
  if tar -tf "$in" | grep -q -v -E '^(file|file/.*|state/|state/unseal\.key)$' \
     || tar -tf "$in" | grep -q -E '(^/|(^|/)\.\.(/|$))' \
     || ! tar -tf "$in" | grep -q -x 'state/unseal.key'; then
    rm -f "$in"; result "$id" false "The PKI data in this backup is not in the expected layout"; return
  fi
  stop_bao
  rm -rf "$ROLLBACK" "$STATE/incoming"
  mkdir -p "$ROLLBACK/file" "$STATE/incoming"
  move_contents "$DATA" "$ROLLBACK/file"
  cp "$SEAL" "$ROLLBACK/unseal.key"
  if ! tar -C "$STATE/incoming" -xf "$in" || [ ! -s "$STATE/incoming/state/unseal.key" ]; then
    rm -rf "$STATE/incoming" "$in"; restore_rollback_files; start_bao; wait_unsealed 90
    result "$id" false "Could not unpack the PKI data"; return
  fi
  rm -f "$in"
  [ -d "$STATE/incoming/file" ] && move_contents "$STATE/incoming/file" "$DATA"
  cp "$STATE/incoming/state/unseal.key" "$SEAL"
  rm -rf "$STATE/incoming"
  fix_owner
  start_bao
  if wait_unsealed 90; then
    result "$id" true; say "restore $id installed (rollback kept until commit)"
  else
    say "restore $id: OpenBao did not unseal with the backup's data; rolling back"
    stop_bao; restore_rollback_files; start_bao; wait_unsealed 90
    result "$id" false "OpenBao did not unseal with the backup's seal key"
  fi
}

do_rollback() {
  id=$1
  if [ -d "$ROLLBACK/file" ] && [ -s "$ROLLBACK/unseal.key" ]; then
    stop_bao; restore_rollback_files; start_bao
    if wait_unsealed 90; then result "$id" true; else result "$id" false "OpenBao did not come back after the rollback"; fi
    say "rollback $id done"
  else
    result "$id" true
  fi
}

do_commit() { rm -rf "$ROLLBACK"; result "$1" true; say "commit $1"; }

# ── Start ────────────────────────────────────────────────────────────────────
ulimit -c 0
mkdir -p "$STATE" "$CTRL/req" "$CTRL/in" "$CTRL/out" "$CTRL/res"
chown "$API_UID:$API_UID" "$CTRL" "$CTRL/req" "$CTRL/in" "$CTRL/out" "$CTRL/res"
chmod 0700 "$CTRL" "$CTRL/req" "$CTRL/in" "$CTRL/out" "$CTRL/res"
if [ ! -s "$SEAL" ]; then
  [ -s /run/secrets/openbao_unseal_key ] || { say "no seal key: /run/secrets/openbao_unseal_key is missing"; exit 1; }
  cp /run/secrets/openbao_unseal_key "$SEAL"
  say "seal key seeded from the Docker secret"
fi
if [ -d "$ROLLBACK/file" ]; then
  say "a restore was left uncommitted; keeping its rollback copy until the API decides"
fi
fix_owner
printf '{"version": 1}\n' > "$CTRL/.supervisor.tmp"; chown "$API_UID:$API_UID" "$CTRL/.supervisor.tmp"; mv "$CTRL/.supervisor.tmp" "$CTRL/supervisor.json"

trap 'stop_bao; exit 0' TERM INT
start_bao
while :; do
  if [ -n "$BAO" ] && ! kill -0 "$BAO" 2>/dev/null; then
    wait "$BAO"; code=$?
    say "OpenBao exited ($code)"; exit 1
  fi
  for req in "$CTRL"/req/*; do
    [ -e "$req" ] || continue
    name=$(basename "$req"); rm -f "$req"
    id=${name%.*}; op=${name##*.}
    case "$id" in ''|*[!a-z0-9]*) say "ignoring request $name"; continue ;; esac
    case "$op" in
      snapshot) do_snapshot "$id" ;;
      restore) do_restore "$id" ;;
      rollback) do_rollback "$id" ;;
      commit) do_commit "$id" ;;
      *) say "ignoring request $name" ;;
    esac
  done
  sleep 1
done

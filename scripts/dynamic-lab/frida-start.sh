#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

msap_log_section "Managed Frida server start"
msap_require_file "$ADB_WIN"
msap_require_command frida
msap_require_command frida-ps
msap_require_command timeout
msap_require_env_vars MSAP_EXPECTED_FRIDA_SERVER_SHA256

client_version="$(msap_frida_client_version)"
[[ "$client_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Frida client mismatch: expected $MSAP_EXPECTED_FRIDA_VERSION, got ${client_version:-missing}"

local_binary="$(msap_frida_expected_binary)"
msap_require_file "$local_binary"
msap_verify_local_frida_sha256
msap_wait_for_device
msap_android_root
msap_assert_selinux_enforcing

server_version="$(msap_frida_server_binary_version)"
server_sha256=""
if msap_android_path_exists "$MSAP_ANDROID_FRIDA_BINARY"; then
  server_sha256="$(msap_android_sha256_file "$MSAP_ANDROID_FRIDA_BINARY")"
fi
managed_pid="$(msap_frida_managed_pid)"
if [[ -n "$managed_pid" ]] && msap_frida_pid_is_managed "$managed_pid" &&
   { [[ "$server_version" != "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
     [[ "$server_sha256" != "$MSAP_EXPECTED_FRIDA_SERVER_SHA256" ]]; }; then
  msap_log "Stopping mismatched managed server PID $managed_pid"
  msap_adb shell "kill '$managed_pid' 2>/dev/null || true"
  sleep 1
fi

if [[ "$server_version" != "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
   [[ "$server_sha256" != "$MSAP_EXPECTED_FRIDA_SERVER_SHA256" ]]; then
  msap_log "Deploying Frida server $MSAP_EXPECTED_FRIDA_VERSION"
  local_binary_for_adb="$(msap_adb_host_path "$local_binary")"
  msap_adb push "$local_binary_for_adb" "${MSAP_ANDROID_FRIDA_BINARY}.new" >/dev/null
  msap_adb shell "
    mv '${MSAP_ANDROID_FRIDA_BINARY}.new' '$MSAP_ANDROID_FRIDA_BINARY'
    chown root:root '$MSAP_ANDROID_FRIDA_BINARY'
    chmod 0755 '$MSAP_ANDROID_FRIDA_BINARY'
  "
  server_version="$(msap_frida_server_binary_version)"
  server_sha256="$(msap_android_sha256_file "$MSAP_ANDROID_FRIDA_BINARY")"
fi

[[ "$server_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Android Frida server mismatch: expected $MSAP_EXPECTED_FRIDA_VERSION, got ${server_version:-missing}"
[[ "$server_sha256" == "$MSAP_EXPECTED_FRIDA_SERVER_SHA256" ]] ||
  msap_fail "Android Frida server SHA-256 mismatch"

managed_pid="$(msap_frida_managed_pid)"
if [[ -z "$managed_pid" ]] || ! msap_frida_pid_is_managed "$managed_pid"; then
  msap_adb shell "
    rm -f '$MSAP_FRIDA_REMOTE_PID'
    nohup '$MSAP_ANDROID_FRIDA_BINARY' </dev/null >'$MSAP_FRIDA_REMOTE_LOG' 2>&1 &
    echo \"\$!\" > '$MSAP_FRIDA_REMOTE_PID'
  "
  sleep 2
  managed_pid="$(msap_frida_managed_pid)"
fi
msap_frida_pid_is_managed "$managed_pid" ||
  msap_fail "Managed Frida server did not remain running"

msap_adb forward --remove "tcp:$MSAP_FRIDA_ADB_PORT" >/dev/null 2>&1 || true
msap_adb forward "tcp:$MSAP_FRIDA_ADB_PORT" tcp:27042 >/dev/null

endpoint="$(msap_frida_endpoint)"
bridge_host="${endpoint%:*}"
bridge_port="${endpoint##*:}"
msap_tcp_test "$bridge_host" "$bridge_port" 5 ||
  msap_fail "Frida bridge is unavailable at $endpoint; run refresh-frida-bridge.sh"

process_file="$(mktemp)"
trap 'rm -f -- "$process_file"' EXIT
timeout 20s frida-ps -H "$endpoint" >"$process_file"
process_count="$(awk 'NR > 2 && $1 ~ /^[0-9]+$/ { count++ } END { print count + 0 }' "$process_file")"
[[ "$process_count" -gt 0 ]] || msap_fail "Frida connected but returned no processes"

msap_log "Server PID: $managed_pid"
msap_log "Server version: $server_version"
msap_log "Endpoint: $endpoint"
echo "FRIDA_START_RESULT=PASS"

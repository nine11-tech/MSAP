#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

msap_log_section "Frida connectivity test"
msap_require_command frida-ps
msap_require_command timeout
msap_wait_for_device

client_version="$(msap_frida_client_version)"
server_version="$(msap_frida_server_binary_version)"
managed_pid="$(msap_frida_managed_pid)"
endpoint="$(msap_frida_endpoint)"

[[ "$client_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Frida client version mismatch"
[[ "$server_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Frida server version mismatch"
[[ -n "$managed_pid" ]] && msap_frida_pid_is_managed "$managed_pid" ||
  msap_fail "Managed Frida server is not running"
msap_assert_selinux_enforcing

msap_adb forward --list | msap_trim_cr |
  grep -Fq "$MSAP_ANDROID_SERIAL tcp:$MSAP_FRIDA_ADB_PORT tcp:27042" ||
  msap_fail "Expected ADB Frida forward is missing"

bridge_host="${endpoint%:*}"
bridge_port="${endpoint##*:}"
msap_tcp_test "$bridge_host" "$bridge_port" 5 ||
  msap_fail "Frida bridge is unavailable at $endpoint"

process_file="$(mktemp)"
trap 'rm -f -- "$process_file"' EXIT
timeout 20s frida-ps -H "$endpoint" >"$process_file"
process_count="$(awk 'NR > 2 && $1 ~ /^[0-9]+$/ { count++ } END { print count + 0 }' "$process_file")"
[[ "$process_count" -gt 0 ]] || msap_fail "Frida enumerated no processes"

echo "Expected version: $MSAP_EXPECTED_FRIDA_VERSION"
echo "Client version:   $client_version"
echo "Server version:   $server_version"
echo "Managed PID:      $managed_pid"
echo "Remote endpoint:  $endpoint"
echo "Process count:     $process_count"
echo "TEST_RESULT=PASS"

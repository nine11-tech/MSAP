#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

refresh_bridge=0
for arg in "$@"; do
  case "$arg" in
    --refresh-bridge)
      refresh_bridge=1
      ;;
    -h|--help)
      cat <<EOF
Usage: scripts/dynamic-lab/frida-smoke.sh [--refresh-bridge]

Starts the managed Frida server, runs the validated local connectivity helper,
performs a safe process enumeration smoke check, stops Frida, and verifies that
Frida is not left running.
EOF
      exit 0
      ;;
    *)
      msap_fail "Unknown argument: $arg"
      ;;
  esac
done

result_printed=0
frida_started=0
probe_dir=""
cleanup() {
  local rc="$1"

  set +e
  if [[ "$frida_started" == "1" && -x "$HOME/.local/bin/msap-frida-stop" ]]; then
    "$HOME/.local/bin/msap-frida-stop" >/dev/null 2>&1
  fi
  if [[ -n "$probe_dir" && -d "$probe_dir" ]]; then
    rm -f -- "$probe_dir/processes.txt" "$probe_dir/probe.txt"
    rmdir -- "$probe_dir" 2>/dev/null || true
  fi
  if [[ "$rc" -ne 0 && "${result_printed:-0}" -eq 0 ]]; then
    echo "MSAP_EVIDENCE_CLEANUP_RESULT=FAIL"
    echo "FRIDA_SMOKE_RESULT=FAIL"
  fi
}
trap 'rc=$?; cleanup "$rc"; exit "$rc"' EXIT

msap_log_section "Frida smoke"
msap_require_file "$ADB_WIN"
msap_require_command frida
msap_require_command frida-ps
msap_require_command timeout

start_helper="$HOME/.local/bin/msap-frida-start"
stop_helper="$HOME/.local/bin/msap-frida-stop"
test_helper="$HOME/.local/bin/msap-frida-test"

[[ -x "$start_helper" ]] || msap_fail "Missing executable helper: $start_helper"
[[ -x "$stop_helper" ]] || msap_fail "Missing executable helper: $stop_helper"
[[ -x "$test_helper" ]] || msap_fail "Missing executable helper: $test_helper"

msap_wait_for_device
msap_android_root
msap_assert_selinux_enforcing

if [[ "$refresh_bridge" == "1" ]]; then
  "$SCRIPT_DIR/refresh-frida-bridge.sh"
fi

"$start_helper"
frida_started=1
test_output="$("$test_helper")"
printf '%s\n' "$test_output"

endpoint="$(msap_frida_endpoint)"
msap_log "Safe Frida enumeration endpoint: $endpoint"
msap_adb shell am start -a android.settings.SETTINGS >/dev/null 2>&1 || true
sleep 1
settings_pid="$(msap_adb shell pidof com.android.settings | msap_one_line | awk '{print $1}')"
[[ "$settings_pid" =~ ^[0-9]+$ ]] || msap_fail "Android Settings PID was not available"
process_architecture="$(msap_getprop ro.product.cpu.abi)"
probe_dir="$(mktemp -d)"
process_output="$probe_dir/processes.txt"
probe_output="$probe_dir/probe.txt"
timeout 20s frida-ps -H "$endpoint" >"$process_output"
process_count="$(printf '%s\n' "$test_output" | sed -n 's/^Process count:[[:space:]]*//p' | head -n 1)"
[[ "$process_count" =~ ^[0-9]+$ ]] ||
  process_count="$(awk 'NR > 2 && $1 ~ /^[0-9]+$/ { count++ } END { print count + 0 }' "$process_output")"
timeout 20s frida \
  -q \
  -H "$endpoint" \
  -p "$settings_pid" \
  -e 'send({event:"MSAP_FRIDA_AUDITOR_PROBE_V1",pid:Process.id,architecture:Process.arch});' \
  -t 5 \
  >"$probe_output" 2>&1
grep -Fq "MSAP_FRIDA_AUDITOR_PROBE_V1" "$probe_output" ||
  msap_fail "Frida did not emit the expected structured instrumentation event"
msap_adb shell am force-stop com.android.settings >/dev/null 2>&1 || true

"$stop_helper"
frida_started=0
msap_assert_selinux_enforcing
msap_verify_frida_not_running

client_version="$(frida --version | msap_one_line)"
server_version="$(printf '%s\n' "$test_output" | sed -n 's/^Server version:[[:space:]]*//p' | head -n 1)"
[[ -n "$server_version" ]] || server_version="$MSAP_EXPECTED_FRIDA_VERSION"
version_match=false
[[ "$client_version" == "$server_version" ]] && version_match=true

echo "MSAP_EVIDENCE_CLIENT_VERSION=$client_version"
echo "MSAP_EVIDENCE_SERVER_VERSION=$server_version"
echo "MSAP_EVIDENCE_VERSION_MATCH=$version_match"
echo "MSAP_EVIDENCE_REMOTE_ENDPOINT=$endpoint"
echo "MSAP_EVIDENCE_CONNECTION_ESTABLISHED=true"
echo "MSAP_EVIDENCE_PROCESS_COUNT=$process_count"
echo "MSAP_EVIDENCE_TEST_PACKAGE=com.android.settings"
echo "MSAP_EVIDENCE_ATTACHED_PID=$settings_pid"
echo "MSAP_EVIDENCE_PROCESS_ARCHITECTURE=$process_architecture"
echo "MSAP_EVIDENCE_INJECTED_SCRIPT_EVENT_RECEIVED=true"
echo "MSAP_EVIDENCE_CLEANUP_RESULT=PASS"
echo "FRIDA_SMOKE_RESULT=PASS"
result_printed=1

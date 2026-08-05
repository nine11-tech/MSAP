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
cleanup() {
  local rc="$1"

  set +e
  if [[ "$frida_started" == "1" && -x "$HOME/.local/bin/msap-frida-stop" ]]; then
    "$HOME/.local/bin/msap-frida-stop" >/dev/null 2>&1
  fi
  if [[ "$rc" -ne 0 && "${result_printed:-0}" -eq 0 ]]; then
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
"$test_helper"

endpoint="$(msap_frida_endpoint)"
msap_log "Safe Frida enumeration endpoint: $endpoint"
msap_adb shell am start -a android.settings.SETTINGS >/dev/null 2>&1 || true
sleep 1
timeout 20s frida-ps -H "$endpoint" >/dev/null
msap_adb shell am force-stop com.android.settings >/dev/null 2>&1 || true

"$stop_helper"
frida_started=0
msap_assert_selinux_enforcing
msap_verify_frida_not_running

echo "FRIDA_SMOKE_RESULT=PASS"
result_printed=1

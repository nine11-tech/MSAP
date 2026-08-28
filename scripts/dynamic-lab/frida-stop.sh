#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

msap_log_section "Managed Frida server stop"
msap_require_file "$ADB_WIN"
msap_wait_for_device

managed_pid="$(msap_frida_managed_pid)"
if [[ -n "$managed_pid" ]] && msap_frida_pid_is_managed "$managed_pid"; then
  msap_adb shell "kill '$managed_pid'"
  for _attempt in 1 2 3 4 5; do
    msap_frida_pid_is_managed "$managed_pid" || break
    sleep 1
  done
  msap_frida_pid_is_managed "$managed_pid" &&
    msap_fail "Managed Frida process did not stop"
elif [[ -n "$managed_pid" ]]; then
  msap_warn "Stale PID file did not identify the managed binary; no process was killed"
fi

msap_adb shell "rm -f '$MSAP_FRIDA_REMOTE_PID'"
msap_adb forward --remove "tcp:$MSAP_FRIDA_ADB_PORT" >/dev/null 2>&1 || true
echo "FRIDA_STOP_RESULT=PASS"

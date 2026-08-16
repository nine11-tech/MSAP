#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

clear_logcat=0
for arg in "$@"; do
  case "$arg" in
    --clear-logcat)
      clear_logcat=1
      ;;
    -h|--help)
      cat <<EOF
Usage: scripts/dynamic-lab/cleanup-runtime-state.sh [--clear-logcat]

Restores transient dynamic-lab state without deleting snapshots, staged public
CA material, or the Android Frida server binary.
EOF
      exit 0
      ;;
    *)
      msap_fail "Unknown argument: $arg"
      ;;
  esac
done

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "CLEANUP_RUNTIME_STATE_RESULT=FAIL"; fi' EXIT

msap_log_section "Cleanup runtime state"
msap_require_file "$ADB_WIN"
msap_wait_for_device
msap_android_root

msap_cleanup_proxy
msap_log "Android proxy restored to :0"

msap_stop_known_temp_apps
if msap_adb shell pm path "$MSAP_TRUST_PROBE_PACKAGE" >/dev/null 2>&1; then
  msap_adb uninstall "$MSAP_TRUST_PROBE_PACKAGE" >/dev/null || true
  msap_log "Temporary trust-probe package uninstalled"
fi

msap_remove_known_android_runtime_dir "$MSAP_RUNTIME_CA_OVERLAY_DIR" >/dev/null
msap_remove_known_android_runtime_dir "$MSAP_MOUNT_PROBE_DIR" >/dev/null
msap_log "Runtime overlay directories removed"

pid="$(msap_frida_managed_pid)"
if [[ -n "$pid" ]] && msap_frida_pid_is_managed "$pid"; then
  msap_adb shell kill "$pid" >/dev/null 2>&1 || true
  msap_log "Managed Frida server stopped: PID $pid"
fi

for pid in $(msap_adb shell pidof msap-frida-server 2>/dev/null | msap_one_line || true); do
  if msap_frida_pid_is_managed "$pid"; then
    msap_adb shell kill "$pid" >/dev/null 2>&1 || true
    msap_log "Managed Frida server stopped without pid file: PID $pid"
  else
    msap_fail "Refusing to stop an unrecognized Frida process: PID $pid"
  fi
done

msap_adb shell rm -f "$MSAP_FRIDA_REMOTE_PID" "$MSAP_FRIDA_REMOTE_LOG" >/dev/null 2>&1 || true
msap_log "Managed Frida pid/log files removed"

msap_verify_frida_not_running

msap_adb forward --remove "tcp:$MSAP_FRIDA_ADB_PORT" >/dev/null 2>&1 || true

if [[ "$clear_logcat" == "1" ]]; then
  msap_adb logcat -c >/dev/null 2>&1 || true
  msap_log "Logcat cleared"
fi

msap_assert_selinux_enforcing
msap_verify_no_permanent_ca
msap_verify_apex_ca_count
msap_log "SELinux and permanent CA state verified"

echo "CLEANUP_RUNTIME_STATE_RESULT=PASS"
result_printed=1

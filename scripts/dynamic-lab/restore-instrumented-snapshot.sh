#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "RESTORE_INSTRUMENTED_SNAPSHOT_RESULT=FAIL"; fi' EXIT

msap_log_section "Restore instrumented snapshot"
msap_require_file "$ADB_WIN"
msap_wait_for_device

if ! msap_snapshot_exists "$MSAP_INSTRUMENTED_SNAPSHOT"; then
  msap_snapshot_list | sed -n '1,30p' >&2
  msap_fail "Snapshot is missing: $MSAP_INSTRUMENTED_SNAPSHOT"
fi

msap_log "Loading snapshot: $MSAP_INSTRUMENTED_SNAPSHOT"
msap_adb emu avd snapshot load "$MSAP_INSTRUMENTED_SNAPSHOT" >/dev/null
sleep 3
msap_wait_for_device
msap_android_root

msap_log_section "Acceptance checks"
proxy_value="$(msap_android_proxy)"
[[ "$proxy_value" == ":0" ]] ||
  msap_fail "Android proxy must be :0 after restore, got ${proxy_value:-empty}"
msap_log "Android proxy: $proxy_value"

msap_assert_selinux_enforcing
msap_assert_api_abi_build
msap_log "SELinux: Enforcing"

server_version="$(msap_frida_server_binary_version)"
[[ "$server_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Android Frida binary version mismatch: expected $MSAP_EXPECTED_FRIDA_VERSION, got ${server_version:-missing}"
msap_log "Android Frida binary: $server_version"

msap_verify_staged_ca
msap_verify_no_third_party_packages
msap_verify_no_permanent_ca
msap_verify_apex_ca_count
msap_verify_frida_not_running

echo "RESTORE_INSTRUMENTED_SNAPSHOT_RESULT=PASS"
result_printed=1

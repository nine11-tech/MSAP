#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "PROVISION_INSTRUMENTED_SNAPSHOT_RESULT=FAIL"; fi' EXIT

msap_log_section "Provision instrumented snapshot"
msap_require_env_vars \
  MSAP_EXPECTED_CA_SHA256 \
  MSAP_EXPECTED_CA_NAME \
  MSAP_EXPECTED_FRIDA_SERVER_SHA256 \
  MSAP_EXPECTED_APEX_CA_COUNT
msap_require_file "$ADB_WIN"
local_frida_binary="$(msap_frida_expected_binary)"
local_ca="$(msap_expected_ca_file)"
msap_require_file "$local_frida_binary"
msap_require_file "$local_ca"
msap_verify_local_frida_sha256

msap_wait_for_device
msap_android_root
msap_assert_api_abi_build
msap_assert_selinux_enforcing
msap_cleanup_proxy
msap_verify_no_third_party_packages
msap_verify_no_permanent_ca
msap_verify_public_ca_sha256
msap_verify_apex_ca_count
msap_verify_frida_not_running

if msap_snapshot_exists "$MSAP_INSTRUMENTED_SNAPSHOT"; then
  msap_fail "Snapshot already exists: $MSAP_INSTRUMENTED_SNAPSHOT; choose a new name or delete it explicitly in Android Studio"
fi

frida_for_adb="$(msap_adb_host_path "$local_frida_binary")"
ca_for_adb="$(msap_adb_host_path "$local_ca")"
staged_ca_dir="$(dirname "$MSAP_ANDROID_STAGED_CA")"

msap_adb push "$frida_for_adb" "${MSAP_ANDROID_FRIDA_BINARY}.new" >/dev/null
msap_adb shell "
  mv '${MSAP_ANDROID_FRIDA_BINARY}.new' '$MSAP_ANDROID_FRIDA_BINARY'
  chown root:root '$MSAP_ANDROID_FRIDA_BINARY'
  chmod 0755 '$MSAP_ANDROID_FRIDA_BINARY'
  mkdir -p '$staged_ca_dir'
  chmod 0700 '$staged_ca_dir'
"
msap_adb push "$ca_for_adb" "${MSAP_ANDROID_STAGED_CA}.new" >/dev/null
msap_adb shell "
  mv '${MSAP_ANDROID_STAGED_CA}.new' '$MSAP_ANDROID_STAGED_CA'
  chown root:root '$MSAP_ANDROID_STAGED_CA'
  chmod 0644 '$MSAP_ANDROID_STAGED_CA'
"

server_version="$(msap_frida_server_binary_version)"
[[ "$server_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Staged Frida version mismatch"
msap_verify_android_frida_sha256
msap_verify_staged_ca
msap_verify_no_permanent_ca
msap_verify_frida_not_running

msap_log "Saving snapshot: $MSAP_INSTRUMENTED_SNAPSHOT"
msap_adb emu avd snapshot save "$MSAP_INSTRUMENTED_SNAPSHOT" >/dev/null
sleep 2
msap_snapshot_exists "$MSAP_INSTRUMENTED_SNAPSHOT" ||
  msap_fail "Instrumented snapshot was not saved"

echo "PROVISION_INSTRUMENTED_SNAPSHOT_RESULT=PASS"
result_printed=1

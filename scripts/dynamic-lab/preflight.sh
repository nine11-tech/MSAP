#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "PREFLIGHT_RESULT=FAIL"; fi' EXIT

msap_log_section "Dynamic environment"
if [[ -n "$MSAP_ENV_SOURCES_LOADED" ]]; then
  msap_log "Loaded env: $MSAP_ENV_SOURCES_LOADED"
else
  msap_warn "No local env file was loaded; using repository-safe defaults"
fi

msap_require_env_vars \
  MSAP_ANDROID_SERIAL \
  MSAP_AVD_NAME \
  MSAP_INSTRUMENTED_SNAPSHOT \
  MSAP_ANDROID_API_LEVEL \
  MSAP_ANDROID_ABI \
  MSAP_EXPECTED_FRIDA_VERSION \
  MSAP_EXPECTED_FRIDA_SERVER_SHA256 \
  MSAP_EXPECTED_MITMPROXY_VERSION \
  MSAP_EXPECTED_CA_SHA256 \
  MSAP_EXPECTED_CA_NAME \
  MSAP_EXPECTED_APEX_CA_COUNT \
  ANDROID_SDK_WSL \
  ADB_WIN \
  EMULATOR_WIN \
  MSAP_DYNAMIC_HOME \
  MSAP_MITMPROXY_VENV \
  MSAP_MITMPROXY_CONF

msap_log_section "Host tooling"
msap_require_command frida
msap_require_command python3
msap_require_command sha256sum
msap_require_dir "$ANDROID_SDK_WSL"
msap_require_file "$ADB_WIN"
msap_require_file "$EMULATOR_WIN"
msap_require_file "$MSAP_ANDROID_PLATFORM_JAR"
msap_require_file "$MSAP_BUILD_TOOLS_DIR/aapt2.exe"
msap_require_file "$MSAP_BUILD_TOOLS_DIR/d8.bat"
msap_require_file "$MSAP_BUILD_TOOLS_DIR/apksigner.bat"
msap_require_file "$MSAP_BUILD_TOOLS_DIR/zipalign.exe"
msap_log "Android SDK: $ANDROID_SDK_WSL"
msap_log "Build tools: $MSAP_BUILD_TOOLS_DIR"

client_version="$(frida --version 2>/dev/null | tr -d '\r\n ')"
[[ "$client_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Frida client version mismatch: expected $MSAP_EXPECTED_FRIDA_VERSION, got ${client_version:-missing}"
msap_log "Frida client: $client_version"

local_frida_binary="$(msap_frida_expected_binary)"
msap_require_file "$local_frida_binary"
msap_verify_local_frida_sha256
msap_log "Frida local binary: $local_frida_binary"

msap_require_dir "$MSAP_MITMPROXY_VENV"
mitmdump_bin="$(msap_mitmdump_bin)"
msap_require_file "$mitmdump_bin"
mitmdump_version="$(msap_mitmdump_version)"
[[ "$mitmdump_version" == "$MSAP_EXPECTED_MITMPROXY_VERSION" ]] ||
  msap_fail "mitmdump version mismatch: expected $MSAP_EXPECTED_MITMPROXY_VERSION, got ${mitmdump_version:-missing}"
msap_log "mitmproxy: $mitmdump_version"
msap_verify_public_ca_sha256
msap_log "Public CA SHA-256: $MSAP_EXPECTED_CA_SHA256"

msap_log_section "Android state"
msap_wait_for_device
msap_android_root
msap_assert_api_abi_build
msap_assert_selinux_enforcing
msap_log "Device: $MSAP_ANDROID_SERIAL"
msap_log "Android API: $(msap_getprop ro.build.version.sdk)"
msap_log "ABI: $(msap_getprop ro.product.cpu.abi)"
msap_log "Build type: $(msap_getprop ro.build.type)"
msap_log "SELinux: Enforcing"

proxy_value="$(msap_android_proxy)"
[[ "$proxy_value" == ":0" ]] ||
  msap_fail "Android proxy must be :0 before preflight, got ${proxy_value:-empty}"
msap_log "Android proxy: $proxy_value"

msap_android_path_exists "$MSAP_ANDROID_FRIDA_BINARY" ||
  msap_fail "Android Frida binary is missing: $MSAP_ANDROID_FRIDA_BINARY"
server_version="$(msap_frida_server_binary_version)"
[[ "$server_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Android Frida binary version mismatch: expected $MSAP_EXPECTED_FRIDA_VERSION, got ${server_version:-missing}"
msap_verify_android_frida_sha256
msap_log "Android Frida binary: $server_version"

msap_verify_staged_ca
msap_log "Android staged CA: $MSAP_ANDROID_STAGED_CA"

msap_verify_no_permanent_ca
msap_verify_apex_ca_count
msap_log "Permanent CA state: clean"
msap_log "APEX CA count: $MSAP_EXPECTED_APEX_CA_COUNT"

msap_verify_preflight_third_party_packages

msap_log_section "Snapshot and bridge"
if ! msap_snapshot_exists "$MSAP_INSTRUMENTED_SNAPSHOT"; then
  msap_snapshot_list | sed -n '1,30p' >&2
  msap_fail "Snapshot is missing: $MSAP_INSTRUMENTED_SNAPSHOT"
fi
msap_log "Snapshot exists: $MSAP_INSTRUMENTED_SNAPSHOT"

if endpoint="$(msap_frida_endpoint 2>/dev/null)"; then
  bridge_host="${endpoint%:*}"
  bridge_port="${endpoint##*:}"
  if msap_tcp_test "$bridge_host" "$bridge_port" 2; then
    msap_log "Frida bridge reachable: $endpoint"
  else
    msap_warn "Frida bridge is stale or unreachable at $endpoint"
    msap_warn "Run scripts/dynamic-lab/refresh-frida-bridge.sh"
  fi
else
  msap_warn "Could not determine Windows gateway IP for Frida bridge check"
fi

msap_verify_frida_not_running
msap_log "Frida final state: not running"

echo "PREFLIGHT_RESULT=PASS"
result_printed=1

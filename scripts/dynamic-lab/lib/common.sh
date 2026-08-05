#!/usr/bin/env bash

# Shared helpers for MSAP dynamic Android lab reproducibility scripts.
# Source this file from scripts that already enable set -euo pipefail.

MSAP_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MSAP_DYNAMIC_LAB_DIR="$(cd "$MSAP_COMMON_DIR/.." && pwd)"
MSAP_REPO_ROOT="$(cd "$MSAP_DYNAMIC_LAB_DIR/../.." && pwd)"
MSAP_ENV_SOURCES_LOADED=""

msap_source_env_file() {
  local env_file="$1"

  if [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    source "$env_file" >/dev/null
    if [[ -z "$MSAP_ENV_SOURCES_LOADED" ]]; then
      MSAP_ENV_SOURCES_LOADED="$env_file"
    else
      MSAP_ENV_SOURCES_LOADED="$MSAP_ENV_SOURCES_LOADED $env_file"
    fi
  fi
}

msap_load_env() {
  msap_source_env_file "$HOME/.local/bin/msap-dynamic-env"
  msap_source_env_file "$MSAP_REPO_ROOT/.msap-dynamic-lab.local.env"

  export MSAP_ANDROID_SERIAL="${MSAP_ANDROID_SERIAL:-emulator-5554}"
  export MSAP_AVD_NAME="${MSAP_AVD_NAME:-Lab-Root}"
  export MSAP_CLEAN_SNAPSHOT="${MSAP_CLEAN_SNAPSHOT:-msap-clean-base}"
  export MSAP_INSTRUMENTED_SNAPSHOT="${MSAP_INSTRUMENTED_SNAPSHOT:-msap-instrumented-base}"
  export MSAP_ANDROID_API_LEVEL="${MSAP_ANDROID_API_LEVEL:-35}"
  export MSAP_ANDROID_ABI="${MSAP_ANDROID_ABI:-x86_64}"
  export MSAP_EXPECTED_BUILD_TYPE="${MSAP_EXPECTED_BUILD_TYPE:-userdebug}"
  export MSAP_EXPECTED_FRIDA_VERSION="${MSAP_EXPECTED_FRIDA_VERSION:-17.16.4}"
  export MSAP_EXPECTED_MITMPROXY_VERSION="${MSAP_EXPECTED_MITMPROXY_VERSION:-12.2.3}"
  export MSAP_EXPECTED_CA_SHA256="${MSAP_EXPECTED_CA_SHA256:-dec0e1d91937af25da3b84e6350cb12dc0382f1371960351baffcfa91736dc05}"
  export MSAP_EXPECTED_APEX_CA_COUNT="${MSAP_EXPECTED_APEX_CA_COUNT:-145}"
  export MSAP_PROXY_PORT="${MSAP_PROXY_PORT:-18080}"
  export MSAP_FRIDA_ADB_PORT="${MSAP_FRIDA_ADB_PORT:-27042}"
  export MSAP_FRIDA_BRIDGE_PORT="${MSAP_FRIDA_BRIDGE_PORT:-27043}"

  export ANDROID_SDK_WIN="${ANDROID_SDK_WIN:-C:\\Users\\lenovo\\AppData\\Local\\Android\\Sdk}"

  if [[ -z "${ANDROID_SDK_WSL:-}" ]]; then
    if [[ "$ANDROID_SDK_WIN" == /* ]]; then
      ANDROID_SDK_WSL="$ANDROID_SDK_WIN"
    elif command -v wslpath >/dev/null 2>&1; then
      ANDROID_SDK_WSL="$(wslpath -u "$ANDROID_SDK_WIN" 2>/dev/null || true)"
    fi
  fi
  export ANDROID_SDK_WSL="${ANDROID_SDK_WSL:-/mnt/c/Users/lenovo/AppData/Local/Android/Sdk}"

  export ADB_WIN="${ADB_WIN:-$ANDROID_SDK_WSL/platform-tools/adb.exe}"
  export EMULATOR_WIN="${EMULATOR_WIN:-$ANDROID_SDK_WSL/emulator/emulator.exe}"
  export MSAP_ANDROID_PLATFORM_JAR="${MSAP_ANDROID_PLATFORM_JAR:-$ANDROID_SDK_WSL/platforms/android-$MSAP_ANDROID_API_LEVEL/android.jar}"
  export MSAP_BUILD_TOOLS_DIR="${MSAP_BUILD_TOOLS_DIR:-$ANDROID_SDK_WSL/build-tools/36.0.0}"

  export MSAP_DYNAMIC_HOME="${MSAP_DYNAMIC_HOME:-$HOME/.local/share/msap-dynamic}"
  export MSAP_MITMPROXY_VENV="${MSAP_MITMPROXY_VENV:-$MSAP_DYNAMIC_HOME/venvs/mitmproxy}"
  export MSAP_MITMPROXY_CONF="${MSAP_MITMPROXY_CONF:-$MSAP_DYNAMIC_HOME/tools/mitmproxy/conf}"
  export MSAP_EVIDENCE_ROOT="${MSAP_EVIDENCE_ROOT:-$MSAP_DYNAMIC_HOME/evidence/reproducibility}"

  export MSAP_ANDROID_FRIDA_BINARY="${MSAP_ANDROID_FRIDA_BINARY:-/data/local/tmp/msap-frida-server}"
  export MSAP_FRIDA_REMOTE_PID="${MSAP_FRIDA_REMOTE_PID:-/data/local/tmp/msap-frida-server.pid}"
  export MSAP_FRIDA_REMOTE_LOG="${MSAP_FRIDA_REMOTE_LOG:-/data/local/tmp/msap-frida-server.log}"
  export MSAP_EXPECTED_CA_NAME="${MSAP_EXPECTED_CA_NAME:-c8750f0d.0}"
  export MSAP_ANDROID_STAGED_CA="${MSAP_ANDROID_STAGED_CA:-/data/local/tmp/msap-instrumentation/ca/$MSAP_EXPECTED_CA_NAME}"
  export MSAP_RUNTIME_CA_OVERLAY_DIR="${MSAP_RUNTIME_CA_OVERLAY_DIR:-/data/local/tmp/msap-instrumentation/runtime-ca-overlay}"
  export MSAP_MOUNT_PROBE_DIR="${MSAP_MOUNT_PROBE_DIR:-/data/local/tmp/msap-mount-probe}"
  export MSAP_TRUST_PROBE_PACKAGE="${MSAP_TRUST_PROBE_PACKAGE:-tech.nine11.msap.trustprobe}"
  export MSAP_TRUST_PROBE_ACTIVITY="${MSAP_TRUST_PROBE_ACTIVITY:-$MSAP_TRUST_PROBE_PACKAGE/.MainActivity}"
}

msap_log_section() {
  printf '\n== %s ==\n' "$1"
}

msap_log() {
  printf '%s\n' "$*"
}

msap_warn() {
  printf 'WARN: %s\n' "$*" >&2
}

msap_fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

msap_require_command() {
  local command_name="$1"

  command -v "$command_name" >/dev/null 2>&1 ||
    msap_fail "Required command is missing: $command_name"
}

msap_require_file() {
  local file_path="$1"

  [[ -f "$file_path" ]] || msap_fail "Required file is missing: $file_path"
}

msap_require_dir() {
  local dir_path="$1"

  [[ -d "$dir_path" ]] || msap_fail "Required directory is missing: $dir_path"
}

msap_require_env_vars() {
  local name

  for name in "$@"; do
    [[ -n "${!name:-}" ]] || msap_fail "Required environment variable is empty: $name"
  done
}

msap_trim_cr() {
  tr -d '\r'
}

msap_one_line() {
  tr -d '\r' | sed -e 's/[[:space:]]*$//' | sed -n '1p'
}

msap_windows_path() {
  local path="$1"

  if [[ "$path" == [A-Za-z]:\\* ]]; then
    printf '%s\n' "$path"
  elif command -v wslpath >/dev/null 2>&1; then
    wslpath -w "$path"
  else
    printf '%s\n' "$path"
  fi
}

msap_adb_host_path() {
  local path="$1"

  if [[ "$ADB_WIN" == *.exe && "$path" != [A-Za-z]:\\* ]] &&
     command -v wslpath >/dev/null 2>&1; then
    wslpath -w "$path"
  else
    printf '%s\n' "$path"
  fi
}

msap_adb() {
  "$ADB_WIN" -s "$MSAP_ANDROID_SERIAL" "$@"
}

msap_wait_for_device() {
  local timeout_seconds="${1:-180}"
  local deadline
  local boot_completed

  msap_adb wait-for-device
  deadline=$((SECONDS + timeout_seconds))

  while (( SECONDS < deadline )); do
    boot_completed="$(msap_getprop sys.boot_completed 2>/dev/null || true)"
    if [[ "$boot_completed" == "1" ]]; then
      return 0
    fi
    sleep 2
  done

  msap_fail "Timed out waiting for Android boot completion on $MSAP_ANDROID_SERIAL"
}

msap_android_root() {
  local uid

  msap_adb root >/dev/null
  msap_adb wait-for-device
  uid="$(msap_adb shell id -u | msap_one_line)"
  [[ "$uid" == "0" ]] || msap_fail "Android adbd is not running as root"
}

msap_getprop() {
  local property_name="$1"

  msap_adb shell getprop "$property_name" | msap_one_line
}

msap_android_proxy() {
  msap_adb shell settings get global http_proxy | msap_one_line
}

msap_cleanup_proxy() {
  msap_adb shell settings put global http_proxy :0 >/dev/null
}

msap_assert_selinux_enforcing() {
  local mode

  mode="$(msap_adb shell getenforce | msap_one_line)"
  [[ "$mode" == "Enforcing" ]] || msap_fail "SELinux is not Enforcing: $mode"
}

msap_assert_api_abi_build() {
  local api_level
  local abi
  local build_type

  api_level="$(msap_getprop ro.build.version.sdk)"
  abi="$(msap_getprop ro.product.cpu.abi)"
  build_type="$(msap_getprop ro.build.type)"

  [[ "$api_level" == "$MSAP_ANDROID_API_LEVEL" ]] ||
    msap_fail "Unexpected Android API level: expected $MSAP_ANDROID_API_LEVEL, got $api_level"
  [[ "$abi" == "$MSAP_ANDROID_ABI" ]] ||
    msap_fail "Unexpected Android ABI: expected $MSAP_ANDROID_ABI, got $abi"
  [[ "$build_type" == "$MSAP_EXPECTED_BUILD_TYPE" ]] ||
    msap_fail "Unexpected Android build type: expected $MSAP_EXPECTED_BUILD_TYPE, got $build_type"
}

msap_wsl_ip() {
  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show eth0 2>/dev/null |
      awk '{
        split($4, address, "/")
        print address[1]
        exit
      }'
  else
    hostname -I 2>/dev/null | awk '{print $1}'
  fi
}

msap_windows_gateway_ip() {
  ip route show default 2>/dev/null | awk '{print $3; exit}'
}

msap_count_third_party_packages() {
  msap_adb shell pm list packages -3 2>/dev/null |
    msap_trim_cr |
    awk '
      /^package:/ { count++ }
      END { print count + 0 }
    '
}

msap_snapshot_list() {
  msap_adb emu avd snapshot list 2>/dev/null | msap_trim_cr
}

msap_snapshot_exists() {
  local snapshot_name="${1:-$MSAP_INSTRUMENTED_SNAPSHOT}"

  msap_snapshot_list | awk -v snapshot="$snapshot_name" '
    index($0, snapshot) { found = 1 }
    END { exit found ? 0 : 1 }
  '
}

msap_frida_expected_binary() {
  printf '%s/downloads/frida-server-%s-android-%s\n' \
    "$MSAP_DYNAMIC_HOME" \
    "$MSAP_EXPECTED_FRIDA_VERSION" \
    "$MSAP_ANDROID_ABI"
}

msap_expected_ca_file() {
  printf '%s/mitmproxy-ca-cert.pem\n' "$MSAP_MITMPROXY_CONF"
}

msap_sha256_file() {
  local file_path="$1"

  sha256sum "$file_path" | awk '{print $1}'
}

msap_android_path_exists() {
  local android_path="$1"

  msap_adb shell test -e "$android_path" >/dev/null 2>&1
}

msap_android_sha256_file() {
  local android_path="$1"

  msap_adb shell sha256sum "$android_path" 2>/dev/null |
    msap_trim_cr |
    awk 'NR == 1 { print $1 }'
}

msap_verify_public_ca_sha256() {
  local ca_file
  local actual_hash

  ca_file="$(msap_expected_ca_file)"
  msap_require_file "$ca_file"
  actual_hash="$(msap_sha256_file "$ca_file")"

  [[ "$actual_hash" == "$MSAP_EXPECTED_CA_SHA256" ]] ||
    msap_fail "Public CA SHA-256 mismatch for $ca_file: expected $MSAP_EXPECTED_CA_SHA256, got $actual_hash"
}

msap_verify_staged_ca() {
  local actual_hash

  msap_android_path_exists "$MSAP_ANDROID_STAGED_CA" ||
    msap_fail "Android staged CA is missing: $MSAP_ANDROID_STAGED_CA"

  actual_hash="$(msap_android_sha256_file "$MSAP_ANDROID_STAGED_CA")"
  [[ "$actual_hash" == "$MSAP_EXPECTED_CA_SHA256" ]] ||
    msap_fail "Android staged CA SHA-256 mismatch: expected $MSAP_EXPECTED_CA_SHA256, got ${actual_hash:-missing}"
}

msap_android_cert_hash_present() {
  local cert_dir="$1"

  msap_adb shell "
    for cert in '$cert_dir'/*.0; do
      [ -f \"\$cert\" ] || continue
      sha256sum \"\$cert\"
    done
  " 2>/dev/null |
    msap_trim_cr |
    awk -v expected="$MSAP_EXPECTED_CA_SHA256" '
      $1 == expected { found = 1 }
      END { exit found ? 0 : 1 }
    '
}

msap_verify_no_permanent_ca() {
  local ca_name
  local cert_dir

  ca_name="$(basename "$MSAP_ANDROID_STAGED_CA")"

  for cert_dir in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; do
    if msap_android_path_exists "$cert_dir/$ca_name"; then
      msap_fail "Generated MSAP CA exists in permanent trust store: $cert_dir/$ca_name"
    fi

    if msap_android_cert_hash_present "$cert_dir"; then
      msap_fail "Generated MSAP CA hash exists in permanent trust store: $cert_dir"
    fi
  done
}

msap_verify_apex_ca_count() {
  local actual_count

  actual_count="$(
    msap_adb shell \
      "find /apex/com.android.conscrypt/cacerts -maxdepth 1 -type f -name '*.0' 2>/dev/null | wc -l" |
      msap_one_line
  )"

  [[ "$actual_count" == "$MSAP_EXPECTED_APEX_CA_COUNT" ]] ||
    msap_fail "Unexpected APEX CA count: expected $MSAP_EXPECTED_APEX_CA_COUNT, got ${actual_count:-missing}"
}

msap_verify_no_third_party_packages() {
  local package_count
  local preview

  package_count="$(msap_count_third_party_packages)"
  if [[ "$package_count" != "0" ]]; then
    preview="$(
      msap_adb shell pm list packages -3 2>/dev/null |
        msap_trim_cr |
        sed -n '1,20p'
    )"
    printf '%s\n' "$preview" >&2
    msap_fail "Expected zero third-party packages, found $package_count"
  fi
}

msap_frida_managed_pid() {
  msap_adb shell "
    if [ -f '$MSAP_FRIDA_REMOTE_PID' ]; then
      cat '$MSAP_FRIDA_REMOTE_PID'
    fi
  " 2>/dev/null |
    tr -cd '0-9'
}

msap_frida_pid_command() {
  local pid="$1"

  msap_adb shell "
    if [ -r '/proc/$pid/cmdline' ]; then
      tr '\000' ' ' < '/proc/$pid/cmdline'
    fi
  " 2>/dev/null |
    msap_trim_cr
}

msap_frida_pid_is_managed() {
  local pid="$1"
  local command_line

  [[ -n "$pid" ]] || return 1

  if ! msap_adb shell "kill -0 '$pid'" >/dev/null 2>&1; then
    return 1
  fi

  command_line="$(msap_frida_pid_command "$pid")"
  [[ "$command_line" == "$MSAP_ANDROID_FRIDA_BINARY"* ]]
}

msap_verify_frida_not_running() {
  local pid
  local process_output

  pid="$(msap_frida_managed_pid)"
  if [[ -n "$pid" ]] && msap_frida_pid_is_managed "$pid"; then
    msap_fail "Managed Frida server is still running as PID $pid"
  fi

  process_output="$(
    msap_adb shell pidof msap-frida-server 2>/dev/null |
      msap_one_line || true
  )"

  [[ -z "$process_output" ]] ||
    msap_fail "Frida server process is still running: PID $process_output"
}

msap_stop_known_temp_apps() {
  msap_adb shell am force-stop "$MSAP_TRUST_PROBE_PACKAGE" >/dev/null 2>&1 || true
}

msap_remove_known_android_runtime_dir() {
  local android_path="$1"

  case "$android_path" in
    /data/local/tmp/msap-instrumentation/runtime-ca-overlay|/data/local/tmp/msap-mount-probe)
      msap_adb shell rm -rf "$android_path"
      ;;
    *)
      msap_warn "Refusing to remove unexpected Android runtime path: $android_path"
      return 1
      ;;
  esac
}

msap_frida_server_binary_version() {
  msap_adb shell "
    if [ -x '$MSAP_ANDROID_FRIDA_BINARY' ]; then
      '$MSAP_ANDROID_FRIDA_BINARY' --version
    fi
  " 2>/dev/null |
    tr -d '\r\n '
}

msap_mitmdump_bin() {
  printf '%s/bin/mitmdump\n' "$MSAP_MITMPROXY_VENV"
}

msap_mitmdump_version() {
  "$(msap_mitmdump_bin)" --version 2>/dev/null |
    awk -F': ' '/^Mitmproxy:/ { print $2; exit }'
}

msap_tcp_test() {
  local host="$1"
  local port="$2"
  local timeout_seconds="${3:-5}"

  python3 - "$host" "$port" "$timeout_seconds" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
timeout = float(sys.argv[3])

try:
    with socket.create_connection((host, port), timeout=timeout):
        pass
except OSError:
    raise SystemExit(1)
PY
}

msap_frida_endpoint() {
  local gateway_ip

  gateway_ip="$(msap_windows_gateway_ip)"
  [[ -n "$gateway_ip" ]] || return 1
  printf '%s:%s\n' "$gateway_ip" "$MSAP_FRIDA_BRIDGE_PORT"
}

msap_timestamp() {
  date -u '+%Y%m%dT%H%M%SZ'
}

msap_load_env

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "FRIDA_BRIDGE_REFRESH_RESULT=FAIL"; fi' EXIT

ps_script="$SCRIPT_DIR/configure-frida-bridge.ps1"
windows_host_ip="$(msap_windows_gateway_ip)"
wsl_ip="$(msap_wsl_ip)"

msap_log_section "Frida bridge refresh"
msap_log "WSL IP: $wsl_ip"
msap_log "Windows gateway IP: $windows_host_ip"
msap_warn "A Windows UAC prompt may appear; this only scopes a portproxy/firewall rule for the Frida bridge."

msap_require_command powershell.exe
msap_require_command wslpath
msap_require_file "$ps_script"
[[ -n "$windows_host_ip" && -n "$wsl_ip" ]] ||
  msap_fail "Could not determine the WSL/Windows bridge addresses"

ps_script_win="$(wslpath -w "$ps_script")"
powershell.exe -NoProfile -Command \
  "Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', '$ps_script_win',
    '-ListenAddress', '$windows_host_ip',
    '-WslAddress', '$wsl_ip',
    '-BridgePort', '$MSAP_FRIDA_BRIDGE_PORT',
    '-AdbForwardPort', '$MSAP_FRIDA_ADB_PORT'
  )"

msap_log "Bridge rule configured; frida-smoke.sh performs the end-to-end connection check"

echo "FRIDA_BRIDGE_REFRESH_RESULT=PASS"
result_printed=1

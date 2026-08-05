#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "FRIDA_BRIDGE_REFRESH_RESULT=FAIL"; fi' EXIT

helper="$HOME/.local/bin/msap-frida-configure-bridge"

msap_log_section "Frida bridge refresh"
msap_log "WSL IP: $(msap_wsl_ip)"
msap_log "Windows gateway IP: $(msap_windows_gateway_ip)"
msap_warn "A Windows UAC prompt may appear; this only scopes a portproxy/firewall rule for the Frida bridge."

if [[ ! -x "$helper" ]]; then
  cat >&2 <<EOF
ERROR: Missing Frida bridge helper:
  $helper

Recreate the local helper from the Frida setup checkpoint, then rerun:
  scripts/dynamic-lab/refresh-frida-bridge.sh

This script does not disable the Windows firewall globally.
EOF
  exit 1
fi

"$helper"

echo "FRIDA_BRIDGE_REFRESH_RESULT=PASS"
result_printed=1

#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "LAUNCH_EMULATOR_FROM_WSL_RESULT=FAIL"; fi' EXIT

snapshot="${1:-$MSAP_INSTRUMENTED_SNAPSHOT}"
ps_script="$SCRIPT_DIR/launch-emulator.ps1"

msap_log_section "Launch emulator from WSL"
msap_require_file "$EMULATOR_WIN"
msap_require_command powershell.exe

ps_script_win="$(msap_windows_path "$ps_script")"
emulator_win="$(msap_windows_path "$EMULATOR_WIN")"

powershell.exe \
  -NoProfile \
  -ExecutionPolicy Bypass \
  -File "$ps_script_win" \
  -AvdName "$MSAP_AVD_NAME" \
  -Snapshot "$snapshot" \
  -NoSnapshotSave:\$true \
  -EmulatorPath "$emulator_win"

cat <<EOF

Next validation command:
  scripts/dynamic-lab/preflight.sh

LAUNCH_EMULATOR_FROM_WSL_RESULT=PASS
EOF
result_printed=1

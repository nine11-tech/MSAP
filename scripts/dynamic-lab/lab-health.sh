#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

result_printed=0
trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "DYNAMIC_LAB_HEALTH_RESULT=FAIL"; fi' EXIT

"$SCRIPT_DIR/preflight.sh"
"$SCRIPT_DIR/frida-smoke.sh"
"$SCRIPT_DIR/mitmproxy-smoke.sh"

cat <<EOF

For full TLS platform verification:
  scripts/dynamic-lab/platform-tls-probe.sh

DYNAMIC_LAB_HEALTH_RESULT=PASS
EOF
result_printed=1

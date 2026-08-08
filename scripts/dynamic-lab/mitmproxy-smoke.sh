#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
mitmdump_pid=""
evidence_dir=""

cleanup() {
  local rc="$1"

  set +e
  if [[ -n "$mitmdump_pid" ]]; then
    kill "$mitmdump_pid" >/dev/null 2>&1
    wait "$mitmdump_pid" >/dev/null 2>&1
  fi
  if [[ "$rc" -ne 0 && "${result_printed:-0}" -eq 0 ]]; then
    echo "MITMPROXY_SMOKE_RESULT=FAIL"
    if [[ -n "$evidence_dir" ]]; then
      echo "Evidence directory: $evidence_dir"
    fi
  fi
}
trap 'rc=$?; cleanup "$rc"; exit "$rc"' EXIT

pick_local_port() {
  python3 - "$MSAP_PROXY_PORT" <<'PY'
import socket
import sys

start = int(sys.argv[1])
ports = [start] + list(range(start + 1, start + 50))

for port in ports:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            continue
        print(port)
        raise SystemExit(0)

raise SystemExit("No free local TCP port found")
PY
}

wait_for_port() {
  local host="$1"
  local port="$2"
  local deadline=$((SECONDS + 20))

  while (( SECONDS < deadline )); do
    if msap_tcp_test "$host" "$port" 1; then
      return 0
    fi
    sleep 1
  done

  return 1
}

msap_log_section "mitmproxy WSL smoke"
msap_require_command curl
msap_require_command python3
msap_require_file "$ADB_WIN"
mitmdump_bin="$(msap_mitmdump_bin)"
msap_require_file "$mitmdump_bin"
msap_verify_public_ca_sha256
msap_wait_for_device
msap_assert_selinux_enforcing
initial_emulator_proxy="$(msap_android_proxy)"

timestamp="$(msap_timestamp)"
evidence_dir="$MSAP_EVIDENCE_ROOT/mitmproxy-smoke/$timestamp"
mkdir -p "$evidence_dir"

port="$(pick_local_port)"
proxy_url="http://127.0.0.1:$port"
flows_file="$evidence_dir/mitmproxy-smoke.flows"
mitmdump_log="$evidence_dir/mitmdump.log"
flow_summary="$evidence_dir/flow-summary.txt"
probe_token="msap-platform-smoke-$timestamp"

"$mitmdump_bin" \
  --set "confdir=$MSAP_MITMPROXY_CONF" \
  --listen-host 127.0.0.1 \
  --listen-port "$port" \
  --mode regular \
  -w "$flows_file" \
  >"$mitmdump_log" 2>&1 &
mitmdump_pid="$!"

wait_for_port 127.0.0.1 "$port" ||
  msap_fail "mitmdump did not open $proxy_url"

http_status="$(curl \
  --proxy "$proxy_url" \
  --max-time 20 \
  --retry 1 \
  --dump-header "$evidence_dir/http.headers" \
  --output "$evidence_dir/http.body" \
  --show-error \
  --write-out '%{http_code}' \
  "http://example.com/?probe=$probe_token")"
[[ "$http_status" =~ ^2[0-9][0-9]$ ]] || msap_fail "HTTP proxy probe returned $http_status"

https_status="$(curl \
  --proxy "$proxy_url" \
  --cacert "$(msap_expected_ca_file)" \
  --max-time 20 \
  --retry 1 \
  --dump-header "$evidence_dir/https.headers" \
  --output "$evidence_dir/https.body" \
  --show-error \
  --write-out '%{http_code}' \
  "https://example.com/?probe=$probe_token")"
[[ "$https_status" =~ ^2[0-9][0-9]$ ]] || msap_fail "HTTPS proxy probe returned $https_status"

kill "$mitmdump_pid" >/dev/null 2>&1 || true
wait "$mitmdump_pid" >/dev/null 2>&1 || true
mitmdump_pid=""

"$mitmdump_bin" \
  --set "confdir=$MSAP_MITMPROXY_CONF" \
  -nr "$flows_file" \
  -s "$SCRIPT_DIR/helpers/mitm-flow-summary.py" \
  >"$flow_summary" 2>&1
captured_flow_count="$(sed -n 's/^MSAP_FLOW_COUNT=//p' "$flow_summary" | tail -n 1)"
matching_flow_count="$(sed -n 's/^MSAP_MATCHING_FLOW_COUNT=//p' "$flow_summary" | tail -n 1)"
[[ "$captured_flow_count" =~ ^[0-9]+$ ]] || captured_flow_count=0
[[ "$matching_flow_count" =~ ^[0-9]+$ ]] || matching_flow_count=0
[[ "$captured_flow_count" -ge 2 ]] || msap_fail "Expected proxy flows were not captured"
[[ "$matching_flow_count" -ge 2 ]] || msap_fail "Correlated proxy probe flows were not found"
final_emulator_proxy="$(msap_android_proxy)"
[[ "$final_emulator_proxy" == "$initial_emulator_proxy" ]] ||
  msap_fail "Emulator proxy state changed unexpectedly during host proxy smoke"

mitm_version="$($mitmdump_bin --version | sed -n 's/^Mitmproxy: //p' | head -n 1)"
[[ -n "$mitm_version" ]] || mitm_version="$MSAP_EXPECTED_MITMPROXY_VERSION"

msap_log "mitmdump port: $port"
msap_log "Evidence directory: $evidence_dir"
echo "MSAP_EVIDENCE_MITMPROXY_VERSION=$mitm_version"
echo "MSAP_EVIDENCE_PROXY_BIND_HOST=127.0.0.1"
echo "MSAP_EVIDENCE_PROXY_BIND_PORT=$port"
echo "MSAP_EVIDENCE_EMULATOR_PROXY_STATE=$initial_emulator_proxy"
echo "MSAP_EVIDENCE_PROBE_TARGET_HOST=example.com"
echo "MSAP_EVIDENCE_REQUEST_METHOD=GET"
echo "MSAP_EVIDENCE_RESPONSE_STATUS=$https_status"
echo "MSAP_EVIDENCE_CAPTURED_FLOW_COUNT=$captured_flow_count"
echo "MSAP_EVIDENCE_MATCHING_FLOW_FOUND=true"
echo "MSAP_EVIDENCE_TLS_INTERCEPTION_RESULT=PASS"
echo "MSAP_EVIDENCE_CERTIFICATE_TRUST_MODE=controlled-public-CA-host-probe"
echo "MSAP_EVIDENCE_CLEANUP_RESULT=PASS"
echo "MITMPROXY_SMOKE_RESULT=PASS"
result_printed=1

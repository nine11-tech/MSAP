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
mitmdump_bin="$(msap_mitmdump_bin)"
msap_require_file "$mitmdump_bin"
msap_verify_public_ca_sha256

timestamp="$(msap_timestamp)"
evidence_dir="$MSAP_EVIDENCE_ROOT/mitmproxy-smoke/$timestamp"
mkdir -p "$evidence_dir"

port="$(pick_local_port)"
proxy_url="http://127.0.0.1:$port"
flows_file="$evidence_dir/mitmproxy-smoke.flows"
mitmdump_log="$evidence_dir/mitmdump.log"

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

curl \
  --proxy "$proxy_url" \
  --max-time 20 \
  --retry 1 \
  --dump-header "$evidence_dir/http.headers" \
  --output "$evidence_dir/http.body" \
  --fail \
  --show-error \
  "http://example.com/"

curl \
  --proxy "$proxy_url" \
  --cacert "$(msap_expected_ca_file)" \
  --max-time 20 \
  --retry 1 \
  --dump-header "$evidence_dir/https.headers" \
  --output "$evidence_dir/https.body" \
  --fail \
  --show-error \
  "https://example.com/"

kill "$mitmdump_pid" >/dev/null 2>&1 || true
wait "$mitmdump_pid" >/dev/null 2>&1 || true
mitmdump_pid=""

msap_log "mitmdump port: $port"
msap_log "Evidence directory: $evidence_dir"
echo "MITMPROXY_SMOKE_RESULT=PASS"
result_printed=1

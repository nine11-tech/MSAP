#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
RUNTIME_DIR="$REPO_ROOT/.runtime/msap-demo"
PID_DIR="$RUNTIME_DIR/pids"
LOG_DIR="$RUNTIME_DIR/logs"
PID_FILE="$PID_DIR/host-agent-compose.pid"
LOG_FILE="$LOG_DIR/host-agent-compose.log"
BIND_HOST="${MSAP_DYNAMIC_HOST_AGENT_BIND:-0.0.0.0}"
PORT="${MSAP_DYNAMIC_HOST_AGENT_PORT:-8765}"

usage() {
  printf 'Usage: scripts/demo/start-compose-host-agent.sh {start|stop|status|logs}\n'
}

require_runtime() {
  [[ -x "$BACKEND_DIR/.venv/bin/python" ]] || {
    printf 'ERROR: missing backend interpreter: %s\n' "$BACKEND_DIR/.venv/bin/python" >&2
    exit 1
  }
  [[ -r "$HOME/.local/bin/msap-dynamic-env" ]] || {
    printf 'ERROR: missing dynamic environment: %s\n' "$HOME/.local/bin/msap-dynamic-env" >&2
    exit 1
  }
  command -v docker >/dev/null 2>&1 || {
    printf 'ERROR: docker is required.\n' >&2
    exit 1
  }
  command -v curl >/dev/null 2>&1 || {
    printf 'ERROR: curl is required.\n' >&2
    exit 1
  }
}

backend_token() {
  docker compose -f "$REPO_ROOT/compose.yaml" --project-directory "$REPO_ROOT" \
    exec -T backend sh -c 'printf %s "$MSAP_DYNAMIC_HOST_AGENT_TOKEN"'
}

managed_pid() {
  [[ -r "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE")"
  [[ -n "$pid" && -r "/proc/$pid/stat" ]] || return 1
  printf '%s\n' "$pid"
}

listener_pid() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -ltnp "sport = :$PORT" 2>/dev/null |
    sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' |
    head -1
}

stop_agent() {
  local pid
  if pid="$(managed_pid)"; then
    kill "$pid" 2>/dev/null || true
  fi
  if pid="$(listener_pid)" && [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
  fi
  rm -f -- "$PID_FILE"
}

start_agent() {
  require_runtime
  mkdir -p "$PID_DIR" "$LOG_DIR"
  chmod 700 "$RUNTIME_DIR" "$PID_DIR" "$LOG_DIR"
  stop_agent

  local token
  token="$(backend_token)"
  [[ -n "$token" ]] || {
    printf 'ERROR: backend MSAP_DYNAMIC_HOST_AGENT_TOKEN is empty.\n' >&2
    exit 1
  }

  (
    cd "$BACKEND_DIR"
    # shellcheck disable=SC1091
    source "$HOME/.local/bin/msap-dynamic-env" >/dev/null
    export MSAP_DYNAMIC_HOST_AGENT_TOKEN="$token"
    export MSAP_DYNAMIC_HOST_AGENT_ENABLED=true
    export MSAP_DYNAMIC_HOST_AGENT_URL="http://$BIND_HOST:$PORT"
    exec setsid .venv/bin/python manage.py run_dynamic_host_agent --host "$BIND_HOST" --port "$PORT"
  ) >"$LOG_FILE" 2>&1 < /dev/null &
  printf '%s\n' "$!" > "$PID_FILE"
  chmod 600 "$PID_FILE"

  for _attempt in $(seq 1 30); do
    if curl --fail --silent --show-error --max-time 2 \
      -H "X-MSAP-Agent-Token: $token" \
      "http://127.0.0.1:$PORT/health" >/dev/null; then
      printf 'HOST_AGENT_COMPOSE_RESULT=PASS\n'
      printf 'Host Agent: http://%s:%s\n' "$BIND_HOST" "$PORT"
      return 0
    fi
    sleep 1
  done
  printf 'ERROR: Host Agent did not become healthy. See %s\n' "$LOG_FILE" >&2
  exit 1
}

status_agent() {
  local pid
  if pid="$(listener_pid)" && [[ -n "$pid" ]]; then
    printf 'Host Agent process: RUNNING pid=%s\n' "$pid"
  elif pid="$(managed_pid)"; then
    printf 'Host Agent process: STARTING pid=%s\n' "$pid"
  else
    printf 'Host Agent process: STOPPED\n'
  fi
  if [[ -r "$LOG_FILE" ]]; then
    printf 'Log: %s\n' "$LOG_FILE"
  fi
}

case "${1:-}" in
  start) start_agent ;;
  stop) stop_agent ;;
  status) status_agent ;;
  logs) tail -n 120 "$LOG_FILE" ;;
  *) usage; exit 2 ;;
esac

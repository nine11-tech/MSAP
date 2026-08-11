#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
FRONTEND_DIR="$REPO_ROOT/frontend"
PYTHON="$BACKEND_DIR/.venv/bin/python"
CELERY="$BACKEND_DIR/.venv/bin/celery"
VITE="$FRONTEND_DIR/node_modules/.bin/vite"
RUNTIME_DIR="$REPO_ROOT/.runtime/msap-demo"
PID_DIR="$RUNTIME_DIR/pids"
LOG_DIR="$RUNTIME_DIR/logs"
TOKEN_FILE="$RUNTIME_DIR/host-agent.token"
MAX_LOG_BYTES=$((2 * 1024 * 1024))
SERVICE_NAMES=(host-agent backend worker frontend)
UP_IN_PROGRESS=0

on_error() {
  local exit_code="$?"
  if [[ "$UP_IN_PROGRESS" == "1" ]]; then
    printf 'ERROR: local MVP startup failed. See %s\n' "$LOG_DIR" >&2
    stop_managed_services || true
    rm -f -- "$TOKEN_FILE"
  fi
  exit "$exit_code"
}

trap on_error ERR

usage() {
  printf 'Usage: scripts/demo/start-local-mvp-demo.sh {up|status|logs|down}\n'
}

require_local_tools() {
  command -v docker >/dev/null 2>&1 || {
    printf 'ERROR: docker is required.\n' >&2
    exit 1
  }
  command -v curl >/dev/null 2>&1 || {
    printf 'ERROR: curl is required.\n' >&2
    exit 1
  }
  command -v setsid >/dev/null 2>&1 || {
    printf 'ERROR: setsid is required for managed background services.\n' >&2
    exit 1
  }
  [[ -x "$PYTHON" ]] || {
    printf 'ERROR: missing backend interpreter: %s\n' "$PYTHON" >&2
    exit 1
  }
  [[ -x "$CELERY" ]] || {
    printf 'ERROR: missing Celery executable: %s\n' "$CELERY" >&2
    exit 1
  }
  [[ -x "$VITE" ]] || {
    printf 'ERROR: missing Vite executable: %s\n' "$VITE" >&2
    exit 1
  }
  [[ -r "$HOME/.local/bin/msap-dynamic-env" ]] || {
    printf 'ERROR: missing dynamic environment: %s\n' "$HOME/.local/bin/msap-dynamic-env" >&2
    exit 1
  }
}

prepare_runtime() {
  umask 077
  mkdir -p "$PID_DIR" "$LOG_DIR"
  chmod 700 "$RUNTIME_DIR" "$PID_DIR" "$LOG_DIR"
}

write_pid_record() {
  local service_name="$1"
  local pid="$2"
  local start_ticks
  start_ticks="$(awk '{print $22}' "/proc/$pid/stat")"
  printf '%s %s\n' "$pid" "$start_ticks" >"$PID_DIR/$service_name.pid"
  chmod 600 "$PID_DIR/$service_name.pid"
}

managed_pid() {
  local service_name="$1"
  local record="$PID_DIR/$service_name.pid"
  local pid=""
  local expected_ticks=""
  local current_ticks=""
  [[ -r "$record" ]] || return 1
  read -r pid expected_ticks <"$record" || return 1
  [[ "$pid" =~ ^[0-9]+$ && "$expected_ticks" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  [[ -r "/proc/$pid/stat" ]] || return 1
  current_ticks="$(awk '{print $22}' "/proc/$pid/stat")"
  [[ "$current_ticks" == "$expected_ticks" ]] || return 1
  printf '%s\n' "$pid"
}

start_bounded_logger() {
  local service_name="$1"
  local fifo="$RUNTIME_DIR/$service_name.fifo"
  local log_file="$LOG_DIR/$service_name.log"
  rm -f -- "$fifo"
  : >"$log_file"
  chmod 600 "$log_file"
  mkfifo -m 600 "$fifo"
  setsid "$PYTHON" "$SCRIPT_DIR/bounded-log-writer.py" \
    "$log_file" "$MAX_LOG_BYTES" <"$fifo" >/dev/null 2>&1 &
  write_pid_record "$service_name-logger" "$!"
}

start_service() {
  local service_name="$1"
  local workdir="$2"
  shift 2
  local fifo="$RUNTIME_DIR/$service_name.fifo"
  start_bounded_logger "$service_name"
  (
    cd "$workdir"
    exec setsid "$@"
  ) < /dev/null >"$fifo" 2>&1 &
  write_pid_record "$service_name" "$!"
}

start_host_agent() {
  local fifo="$RUNTIME_DIR/host-agent.fifo"
  start_bounded_logger host-agent
  (
    cd "$BACKEND_DIR"
    # The Android/Frida bridge environment is intentionally scoped to this process.
    # shellcheck disable=SC1091
    source "$HOME/.local/bin/msap-dynamic-env"
    exec setsid "$PYTHON" manage.py run_dynamic_host_agent --host 127.0.0.1 --port 8765
  ) < /dev/null >"$fifo" 2>&1 &
  write_pid_record host-agent "$!"
}

stop_one() {
  local service_name="$1"
  local pid=""
  if pid="$(managed_pid "$service_name")"; then
    kill -TERM "$pid" 2>/dev/null || true
    for _attempt in $(seq 1 40); do
      [[ -r "/proc/$pid/stat" ]] || break
      sleep 0.25
    done
    if [[ -r "/proc/$pid/stat" ]]; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f -- "$PID_DIR/$service_name.pid"
}

stop_managed_services() {
  local index
  for ((index=${#SERVICE_NAMES[@]}-1; index>=0; index--)); do
    stop_one "${SERVICE_NAMES[$index]}"
  done
  for service_name in "${SERVICE_NAMES[@]}"; do
    stop_one "$service_name-logger"
    rm -f -- "$RUNTIME_DIR/$service_name.fifo"
  done
}

export_backend_environment() {
  export DJANGO_SETTINGS_MODULE=msap.settings.development
  export DJANGO_DEBUG=true
  export DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,host.docker.internal
  export DJANGO_CSRF_TRUSTED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:8000,http://127.0.0.1:8000
  export DJANGO_CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
  export POSTGRES_HOST=127.0.0.1
  export POSTGRES_PORT="${POSTGRES_HOST_PORT:-5432}"
  export POSTGRES_DB="${POSTGRES_DB:-msap}"
  export POSTGRES_USER="${POSTGRES_USER:-msap_app}"
  export POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-msap-dev-password}"
  export POSTGRES_SSLMODE=disable
  export REDIS_URL="redis://127.0.0.1:${REDIS_HOST_PORT:-6379}/0"
  export CELERY_BROKER_URL="$REDIS_URL"
  export CELERY_RESULT_BACKEND="redis://127.0.0.1:${REDIS_HOST_PORT:-6379}/1"
  export CELERY_TASK_ALWAYS_EAGER=false
  export MINIO_ENDPOINT="http://127.0.0.1:${MINIO_API_PORT:-9000}"
  export MINIO_PUBLIC_ENDPOINT="$MINIO_ENDPOINT"
  export MINIO_ACCESS_KEY="${MINIO_ROOT_USER:-msap-dev}"
  export MINIO_SECRET_KEY="${MINIO_ROOT_PASSWORD:-msap-dev-password}"
  export MINIO_SECURE=false
  export MSAP_UPLOAD_REQUIRE_SHA256=true
  export MSAP_VERIFY_UPLOAD_WITH_HEAD=true
  export MSAP_DYNAMIC_HOST_AGENT_ENABLED=true
  export MSAP_DYNAMIC_HOST_AGENT_URL=http://127.0.0.1:8765
  export MSAP_DYNAMIC_HOST_AGENT_TOKEN
  MSAP_DYNAMIC_HOST_AGENT_TOKEN="$(<"$TOKEN_FILE")"
  export MSAP_DYNAMIC_HOST_AGENT_TIMEOUT_SECONDS=120
  export MSAP_DYNAMIC_ADB_SERIAL=emulator-5554
  export MSAP_DYNAMIC_RUNNER_ENABLED=true
  export MSAP_DYNAMIC_RUNNER_SYNC_DEMO_ENABLED=false
  export MSAP_AGENT_CONTAINER_ENABLED="${MSAP_AGENT_CONTAINER_ENABLED:-false}"
  export MSAP_AGENT_CONTAINER_IMAGE="${MSAP_AGENT_CONTAINER_IMAGE:-msap-agent-runtime:local}"
  export MSAP_AGENT_CONTAINER_NETWORK="${MSAP_AGENT_CONTAINER_NETWORK:-}"
  export MSAP_AGENT_GATEWAY_URL="${MSAP_AGENT_GATEWAY_URL:-http://host.docker.internal:8000}"
  export MSAP_AGENT_RUN_TOKEN_TTL_SECONDS="${MSAP_AGENT_RUN_TOKEN_TTL_SECONDS:-300}"
  export MSAP_AGENT_CONTAINER_TIMEOUT_SECONDS="${MSAP_AGENT_CONTAINER_TIMEOUT_SECONDS:-120}"
  export VITE_API_BASE_URL=http://127.0.0.1:8000/api
}

wait_for_url() {
  local label="$1"
  local url="$2"
  local attempts="${3:-60}"
  local managed_service="${4:-}"
  for _attempt in $(seq 1 "$attempts"); do
    if curl --fail --silent --show-error --max-time 2 "$url" >/dev/null 2>&1; then
      printf 'PASS  %s\n' "$label"
      return 0
    fi
    if [[ -n "$managed_service" ]] && ! managed_pid "$managed_service" >/dev/null; then
      printf 'ERROR: %s process exited before readiness.\n' "$managed_service" >&2
      return 1
    fi
    sleep 1
  done
  printf 'ERROR: %s did not become ready: %s\n' "$label" "$url" >&2
  return 1
}

wait_for_host_agent() {
  local attempts=60
  for _attempt in $(seq 1 "$attempts"); do
    if curl --fail --silent --show-error --max-time 2 \
      -H "X-MSAP-Agent-Token: $MSAP_DYNAMIC_HOST_AGENT_TOKEN" \
      http://127.0.0.1:8765/health >/dev/null 2>&1; then
      printf 'PASS  dynamic host agent\n'
      return 0
    fi
    if ! managed_pid host-agent >/dev/null; then
      printf 'ERROR: dynamic host agent exited before readiness.\n' >&2
      return 1
    fi
    sleep 1
  done
  printf 'ERROR: dynamic host agent did not become ready.\n' >&2
  return 1
}

up() {
  UP_IN_PROGRESS=1
  require_local_tools
  prepare_runtime
  stop_managed_services
  cd "$REPO_ROOT"
  printf 'Stopping competing Compose web processes...\n'
  docker compose stop backend worker frontend >/dev/null 2>&1 || true
  printf 'Starting PostgreSQL, Redis, MinIO, and bucket initialization...\n'
  docker compose up -d postgres redis minio minio-init
  wait_for_url "MinIO" "http://127.0.0.1:${MINIO_API_PORT:-9000}/minio/health/ready"

  "$PYTHON" -c 'import secrets; print(secrets.token_hex(32))' >"$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  export_backend_environment

  if [[ "$MSAP_AGENT_CONTAINER_ENABLED" == "true" ]]; then
    printf 'Building the ephemeral agent runtime image...\n'
    docker build -t "$MSAP_AGENT_CONTAINER_IMAGE" "$REPO_ROOT/agent_runtime"
  fi

  printf 'Applying database migrations...\n'
  (cd "$BACKEND_DIR" && "$PYTHON" manage.py migrate --noinput)
  start_host_agent
  wait_for_host_agent
  local backend_bind=127.0.0.1:8000
  if [[ "$MSAP_AGENT_CONTAINER_ENABLED" == "true" ]]; then
    backend_bind=0.0.0.0:8000
  fi
  start_service backend "$BACKEND_DIR" \
    "$PYTHON" manage.py runserver "$backend_bind" --noreload
  wait_for_url "Django backend" http://127.0.0.1:8000/api/health/ 60 backend
  start_service worker "$BACKEND_DIR" \
    "$CELERY" -A msap worker --loglevel=info --pool=solo --hostname=msap-demo@localhost
  for _attempt in $(seq 1 60); do
    if (cd "$BACKEND_DIR" && "$PYTHON" manage.py check_dynamic_runner) >/dev/null 2>&1; then
      printf 'PASS  Celery worker\n'
      break
    fi
    if [[ "$_attempt" == "60" ]]; then
      printf 'ERROR: Celery worker did not become ready.\n' >&2
      return 1
    fi
    sleep 1
  done
  start_service frontend "$FRONTEND_DIR" \
    "$VITE" --host 127.0.0.1 --port 5173
  wait_for_url "Vite frontend" http://127.0.0.1:5173/ 60 frontend

  printf '\nMSAP local MVP is ready.\n'
  printf 'URL: http://127.0.0.1:5173\n'
  printf 'Logs: %s\n' "$LOG_DIR"
  printf 'Shutdown: scripts/demo/start-local-mvp-demo.sh down\n'
  printf 'The helper did not install an APK or run a disruptive emulator action.\n'
  UP_IN_PROGRESS=0
}

status() {
  local service_name
  printf 'Managed local services:\n'
  for service_name in "${SERVICE_NAMES[@]}"; do
    if managed_pid "$service_name" >/dev/null; then
      printf '  ONLINE   %s\n' "$service_name"
    else
      printf '  OFFLINE  %s\n' "$service_name"
    fi
  done
  printf 'Compose infrastructure:\n'
  (cd "$REPO_ROOT" && docker compose ps postgres redis minio minio-init)
}

logs() {
  local service_name
  for service_name in "${SERVICE_NAMES[@]}"; do
    printf '\n== %s ==\n' "$service_name"
    if [[ -r "$LOG_DIR/$service_name.log" ]]; then
      tail -n 80 "$LOG_DIR/$service_name.log"
    else
      printf 'No log captured.\n'
    fi
  done
}

down() {
  prepare_runtime
  stop_managed_services
  rm -f -- "$TOKEN_FILE"
  cd "$REPO_ROOT"
  docker compose stop postgres redis minio >/dev/null
  printf 'MSAP local MVP processes stopped. Runtime token and PID files removed.\n'
}

case "${1:-}" in
  up) up ;;
  status) status ;;
  logs) logs ;;
  down) down ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac

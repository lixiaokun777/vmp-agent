#!/usr/bin/env sh
set -eu

agent_home=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
agent_bin="$agent_home/vmlease-agent"
agent_config="${VMLEASE_AGENT_CONFIG:-$agent_home/conf/agent.env}"
agent_pid_file="$agent_home/run/agent.pid"
agent_log_file="$agent_home/logs/agent.log"

load_config() {
  if [ ! -f "$agent_config" ]; then
    echo "configuration not found: $agent_config" >&2
    exit 1
  fi
  if [ ! -x "$agent_bin" ]; then
    echo "agent binary is missing or not executable: $agent_bin" >&2
    exit 1
  fi
  set -a
  . "$agent_config"
  # 持久化凭据和任务结果随发布目录保存，升级时禁止删除该目录。
  AGENT_STATE_DIR="${AGENT_STATE_DIR:-$agent_home/run/state}"
  set +a
}

read_pid() {
  [ -f "$agent_pid_file" ] || return 1
  agent_pid=$(sed -n '1p' "$agent_pid_file")
  case "$agent_pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
}

is_agent_process() {
  read_pid || return 1
  kill -0 "$agent_pid" 2>/dev/null || return 1
  if [ -e "/proc/$agent_pid/exe" ]; then
    agent_exe=$(readlink "/proc/$agent_pid/exe" 2>/dev/null || true)
    [ "$agent_exe" = "$agent_bin" ] || return 1
  fi
}

start_agent() {
  load_config
  mkdir -p "$agent_home/run" "$agent_home/logs"
  chmod 700 "$agent_home/run" "$agent_home/logs"
  if is_agent_process; then
    echo "vmlease-agent is already running (pid $agent_pid)"
    return 0
  fi
  rm -f "$agent_pid_file"
  umask 077
  nohup "$agent_bin" >>"$agent_log_file" 2>&1 &
  agent_pid=$!
  echo "$agent_pid" >"$agent_pid_file"
  sleep 1
  if ! is_agent_process; then
    echo "vmlease-agent failed to start; inspect $agent_log_file" >&2
    rm -f "$agent_pid_file"
    return 1
  fi
  echo "vmlease-agent started (pid $agent_pid)"
}

stop_agent() {
  if ! is_agent_process; then
    echo "vmlease-agent is not running"
    rm -f "$agent_pid_file"
    return 0
  fi
  kill -TERM "$agent_pid"
  wait_count=0
  while kill -0 "$agent_pid" 2>/dev/null; do
    wait_count=$((wait_count + 1))
    if [ "$wait_count" -ge 20 ]; then
      echo "vmlease-agent did not stop within 20 seconds; refusing to force kill" >&2
      return 1
    fi
    sleep 1
  done
  rm -f "$agent_pid_file"
  echo "vmlease-agent stopped"
}

status_agent() {
  if is_agent_process; then
    echo "vmlease-agent is running (pid $agent_pid)"
    return 0
  fi
  echo "vmlease-agent is not running"
  return 1
}

case "${1:-}" in
  start) start_agent ;;
  stop) stop_agent ;;
  restart) stop_agent && start_agent ;;
  status) status_agent ;;
  preflight) load_config; exec "$agent_bin" preflight ;;
  logs) touch "$agent_log_file"; exec tail -n "${2:-100}" -f "$agent_log_file" ;;
  *)
    echo "usage: $0 {start|stop|restart|status|preflight|logs [lines]}" >&2
    exit 2
    ;;
esac

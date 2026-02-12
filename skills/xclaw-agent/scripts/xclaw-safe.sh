#!/usr/bin/env bash
set -euo pipefail

# Safety wrapper around xclaw-agent to keep commands consistent and avoid accidental unsafe usage.
# Usage examples:
#   xclaw-safe.sh status
#   xclaw-safe.sh intents-poll
#   xclaw-safe.sh approval-check <intent_id>
#   xclaw-safe.sh trade-exec <intent_id>
#   xclaw-safe.sh report-send <trade_id>

require_bin() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required binary: $1" >&2
    exit 127
  }
}

require_env() {
  local var="$1"
  if [ -z "${!var:-}" ]; then
    echo "missing required env: $var" >&2
    exit 2
  fi
}

require_bin xclaw-agent
require_env XCLAW_API_BASE_URL
require_env XCLAW_AGENT_API_KEY
require_env XCLAW_DEFAULT_CHAIN

cmd="${1:-}"
case "$cmd" in
  status)
    exec xclaw-agent status --json
    ;;
  intents-poll)
    exec xclaw-agent intents poll --chain "$XCLAW_DEFAULT_CHAIN" --json
    ;;
  approval-check)
    intent_id="${2:-}"
    [ -n "$intent_id" ] || { echo "usage: $0 approval-check <intent_id>" >&2; exit 2; }
    exec xclaw-agent approvals check --intent "$intent_id" --chain "$XCLAW_DEFAULT_CHAIN" --json
    ;;
  trade-exec)
    intent_id="${2:-}"
    [ -n "$intent_id" ] || { echo "usage: $0 trade-exec <intent_id>" >&2; exit 2; }
    exec xclaw-agent trade execute --intent "$intent_id" --chain "$XCLAW_DEFAULT_CHAIN" --json
    ;;
  report-send)
    trade_id="${2:-}"
    [ -n "$trade_id" ] || { echo "usage: $0 report-send <trade_id>" >&2; exit 2; }
    exec xclaw-agent report send --trade "$trade_id" --json
    ;;
  *)
    cat >&2 <<USAGE
usage: $0 <command>
commands:
  status
  intents-poll
  approval-check <intent_id>
  trade-exec <intent_id>
  report-send <trade_id>
USAGE
    exit 2
    ;;
esac

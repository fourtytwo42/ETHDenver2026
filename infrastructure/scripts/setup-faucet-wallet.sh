#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAUCET_HOME="${XCLAW_FAUCET_HOME:-$HOME/.xclaw-faucet}"
CHAIN_KEY="${XCLAW_FAUCET_CHAIN:-base_sepolia}"
PASSPHRASE_FILE="${XCLAW_FAUCET_PASSPHRASE_FILE:-$FAUCET_HOME/passphrase}"

mkdir -p "$FAUCET_HOME"
chmod 700 "$FAUCET_HOME"

if [ ! -f "$PASSPHRASE_FILE" ]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(48))' >"$PASSPHRASE_FILE"
  chmod 600 "$PASSPHRASE_FILE"
fi

PASSPHRASE="$(cat "$PASSPHRASE_FILE")"

create_json="$(
  XCLAW_AGENT_HOME="$FAUCET_HOME" \
  XCLAW_WALLET_PASSPHRASE="$PASSPHRASE" \
  "$ROOT_DIR/apps/agent-runtime/bin/xclaw-agent" wallet create --chain "$CHAIN_KEY" --json || true
)"

address_json="$(
  XCLAW_AGENT_HOME="$FAUCET_HOME" \
  XCLAW_WALLET_PASSPHRASE="$PASSPHRASE" \
  "$ROOT_DIR/apps/agent-runtime/bin/xclaw-agent" wallet address --chain "$CHAIN_KEY" --json
)"

address="$(printf "%s" "$address_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("address",""))')"

if [ -z "$address" ]; then
  echo "[xclaw-faucet] failed to resolve faucet wallet address" >&2
  echo "$address_json" >&2
  exit 1
fi

cat <<EOF
[xclaw-faucet] setup complete
faucet_home=$FAUCET_HOME
chain=$CHAIN_KEY
address=$address
passphrase_file=$PASSPHRASE_FILE
wallet_create_result=$create_json
EOF

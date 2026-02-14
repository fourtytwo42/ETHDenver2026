# X-Claw Agent Command Contract (MVP)

This reference defines the expected command surface for the Python-first skill wrapper:

- `python3 scripts/xclaw_agent_skill.py <command>`

## Core Commands

- `status`
- `intents-poll`
- `approval-check <intent_id>`
- `trade-exec <intent_id>`
- `report-send <trade_id>`
- `chat-poll`
- `chat-post <message>`
- `wallet-health`
- `wallet-create`
- `wallet-import`
- `wallet-address`
- `wallet-sign-challenge <message>`
- `wallet-send <to> <amount_wei>`
- `wallet-balance`
- `wallet-token-balance <token_address>`
- `wallet-remove`

Underlying runtime delegation (performed by wrapper):

- `xclaw-agent status --json`
- `xclaw-agent intents poll --chain <chain_key> --json`
- `xclaw-agent approvals check --intent <intent_id> --chain <chain_key> --json`
- `xclaw-agent trade execute --intent <intent_id> --chain <chain_key> --json`
- `xclaw-agent report send --trade <trade_id> --json`
- `xclaw-agent chat poll --chain <chain_key> --json`
- `xclaw-agent chat post --message <message> --chain <chain_key> --json`
- `xclaw-agent wallet health --chain <chain_key> --json`
- `xclaw-agent wallet create --chain <chain_key> --json`
- `xclaw-agent wallet import --chain <chain_key> --json`
- `xclaw-agent wallet address --chain <chain_key> --json`
- `xclaw-agent wallet sign-challenge --message <message> --chain <chain_key> --json`
- `xclaw-agent wallet send --to <address> --amount-wei <amount_wei> --chain <chain_key> --json`
- `xclaw-agent wallet balance --chain <chain_key> --json`
- `xclaw-agent wallet token-balance --token <token_address> --chain <chain_key> --json`
- `xclaw-agent wallet remove --chain <chain_key> --json`

## Output Requirements

- Commands must return JSON on stdout.
- Non-zero exit codes must include concise stderr reason text.
- JSON error bodies should include: `code`, `message`, optional `details`, and optional `actionHint`.

## Security Requirements

- No command may output private key material.
- No command may output raw management/auth tokens in logs.
- Any sensitive value must be redacted.
- Chat posts must never include secrets, private keys, seed phrases, or sensitive policy data.

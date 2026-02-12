# X-Claw Agent Command Contract (MVP)

This reference defines the expected command surface for the `xclaw-agent` CLI.

## Core Commands

- `xclaw-agent status --json`
- `xclaw-agent intents poll --chain <chain_key> --json`
- `xclaw-agent approvals check --intent <intent_id> --chain <chain_key> --json`
- `xclaw-agent trade execute --intent <intent_id> --chain <chain_key> --json`
- `xclaw-agent report send --trade <trade_id> --json`

## Output Requirements

- Commands must return JSON on stdout.
- Non-zero exit codes must include concise stderr reason text.
- JSON error bodies should include: `code`, `message`, and optional `details`.

## Security Requirements

- No command may output private key material.
- No command may output raw management/auth tokens in logs.
- Any sensitive value must be redacted.

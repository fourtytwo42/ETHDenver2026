# X-Claw Wallet Command Contract (MVP)

This document defines the canonical wallet command surface for the Python-first skill wrapper:

- `python3 skills/xclaw-agent/scripts/xclaw_agent_skill.py <command> [args...]`

The wrapper delegates wallet operations to `xclaw-agent` and enforces JSON I/O and input validation.

## 1) Command Set

Required wallet commands:

1. `wallet-health`
2. `wallet-create`
3. `wallet-import`
4. `wallet-address`
5. `wallet-sign-challenge <message>`
6. `wallet-send <to> <amount_wei>`
7. `wallet-balance`
8. `wallet-token-balance <token_address>`
9. `wallet-remove`

Notes:
- `chain` is sourced from `XCLAW_DEFAULT_CHAIN`.
- `wallet-send` uses base-unit amount for deterministic automation.

## 2) Delegated Runtime Commands

Wrapper delegation target commands:

- `xclaw-agent wallet health --chain <chain_key> --json`
- `xclaw-agent wallet create --chain <chain_key> --json`
- `xclaw-agent wallet import --chain <chain_key> --json`
- `xclaw-agent wallet address --chain <chain_key> --json`
- `xclaw-agent wallet sign-challenge --message <message> --chain <chain_key> --json`
- `xclaw-agent wallet send --to <address> --amount-wei <amount_wei> --chain <chain_key> --json`
- `xclaw-agent wallet balance --chain <chain_key> --json`
- `xclaw-agent wallet token-balance --token <token_address> --chain <chain_key> --json`
- `xclaw-agent wallet remove --chain <chain_key> --json`

Wrapper binary resolution order:
1. PATH lookup (`shutil.which("xclaw-agent")`)
2. Repo-local fallback (`apps/agent-runtime/bin/xclaw-agent`)
3. Structured `missing_binary` error with exit code `127`

## 3) JSON Success Shape

Commands MUST return JSON on stdout.

Minimum shape:

```json
{
  "ok": true,
  "code": "ok",
  "message": "..."
}
```

Runtime-specific fields may be appended (for example `address`, `txHash`, `balanceWei`, `signature`).

## 4) JSON Error Shape

Errors MUST be machine-parseable and human-readable:

```json
{
  "ok": false,
  "code": "...",
  "message": "...",
  "actionHint": "...",
  "details": {}
}
```

`actionHint` and `details` are optional but recommended.

## 5) Validation Rules

1. `wallet-send` validates recipient address format before delegation.
2. `wallet-send` validates amount is non-negative integer string.
3. `wallet-token-balance` validates token address format before delegation.
4. `wallet-sign-challenge` rejects empty message.

## 6) Runtime-Behavior Alignment (Slice 03)

Current behavior in `apps/agent-runtime/xclaw_agent/cli.py`:

1. `wallet-health` and `wallet-remove` return live scaffold JSON responses.
2. `wallet-address` returns `wallet_missing` when no wallet exists for the chain.
3. `wallet-create`, `wallet-import`, `wallet-sign-challenge`, `wallet-send`, `wallet-balance`, and `wallet-token-balance` currently return structured `not_implemented` runtime errors.
4. Wrapper-level input validation executes before runtime delegation.
5. On delegated non-zero exits, wrapper passes runtime JSON through unchanged when stdout is parseable JSON payload with `ok` and `code`; otherwise wrapper emits structured `agent_command_failed`.

This is contract-compliant for Slice 03 because command surface, delegation reliability, and JSON error semantics are fixed while real wallet implementation is completed in later slices.

## 7) Security Rules

1. Never print private keys, mnemonics, or raw secret material.
2. No persistent plaintext password stash in production runtime.
3. No persistent plaintext private-key files in production runtime.
4. Wallet signing is local-only; server receives signatures/tx metadata, never key material.
5. All sensitive values in logs/output must be redacted.

## 8) Exit Codes

- `0`: success
- `1`: runtime command failure
- `2`: usage or required environment missing
- `127`: missing runtime binary (`xclaw-agent`)

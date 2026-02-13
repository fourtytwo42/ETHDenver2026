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
5. `wallet-create` and `wallet-import` require interactive TTY and fail with `non_interactive` in non-interactive contexts.

## 6) Runtime-Behavior Alignment (Slice 04)

Current behavior in `apps/agent-runtime/xclaw_agent/cli.py`:

1. `wallet-create` is implemented with interactive TTY passphrase prompts and encrypted-at-rest storage.
2. `wallet-import` is implemented with interactive TTY secret intake and encrypted-at-rest storage.
3. `wallet-address` returns active chain-bound address or `wallet_missing`.
4. `wallet-health` reports live runtime state (`hasCast`, `hasWallet`, `address`, `metadataValid`, `filePermissionsSafe`, `integrityChecked`, `timestamp`) and fails closed on unsafe permissions/invalid wallet metadata.
5. `wallet-sign-challenge`, `wallet-send`, `wallet-balance`, and `wallet-token-balance` remain structured `not_implemented` runtime handlers pending later slices.
6. Wrapper-level input validation executes before runtime delegation.
7. On delegated non-zero exits, wrapper passes runtime JSON through unchanged when stdout is parseable JSON payload with `ok` and `code`; otherwise wrapper emits structured `agent_command_failed`.

This is contract-compliant for Slice 04 because wallet core lifecycle baseline is implemented while signing and spend-path commands are deferred to later slices.

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

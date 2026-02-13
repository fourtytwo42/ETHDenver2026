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
6. `wallet-send` fails closed when spend policy file is missing, invalid, or unsafe (`~/.xclaw-agent/policy.json`).
7. `wallet-send` enforces policy preconditions (`paused`, `chain_enabled`, approval gate, `max_daily_native_wei`).

## 6) Canonical Challenge Format (`wallet-sign-challenge`)

`wallet-sign-challenge` requires line-based `key=value` message with exactly:

1. `domain`
2. `chain`
3. `nonce`
4. `timestamp`
5. `action`

Validation rules:
- `domain` allowlist: `xclaw.trade`, `staging.xclaw.trade`, `localhost`, `127.0.0.1`, `::1`
- `chain` must match command `--chain`
- `nonce` regex: `[A-Za-z0-9_-]{16,128}`
- `timestamp` must be ISO-8601 UTC (`Z` or `+00:00`) and within 5 minutes
- `action` must be non-empty

Success payload fields for signing include:
- `signature` (65-byte hex, `0x`-prefixed)
- `scheme: "eip191_personal_sign"`
- `challengeFormat: "xclaw-auth-v1"`
- `address`
- `chain`

## 7) Runtime-Behavior Alignment (Slice 06)

Current behavior in `apps/agent-runtime/xclaw_agent/cli.py`:

1. `wallet-create` is implemented with interactive TTY passphrase prompts and encrypted-at-rest storage.
2. `wallet-import` is implemented with interactive TTY secret intake and encrypted-at-rest storage.
3. `wallet-address` returns active chain-bound address or `wallet_missing`.
4. `wallet-health` reports live runtime state (`hasCast`, `hasWallet`, `address`, `metadataValid`, `filePermissionsSafe`, `integrityChecked`, `timestamp`) and fails closed on unsafe permissions/invalid wallet metadata.
5. `wallet-sign-challenge` is implemented with canonical challenge validation and cast-backed EIP-191 signing.
6. Non-interactive signing requires `XCLAW_WALLET_PASSPHRASE`; otherwise interactive TTY prompt is used.
7. `wallet-send` is implemented with fail-closed policy precondition checks from `~/.xclaw-agent/policy.json` before any chain spend:
   - `paused == false`
   - `chains.<chain>.chain_enabled == true`
   - if `spend.approval_required == true`, then `spend.approval_granted == true`
   - `spend.max_daily_native_wei` not exceeded (UTC day ledger in `state.json`)
8. `wallet-balance` is implemented via cast-backed native balance query for wallet address and chain RPC.
9. `wallet-token-balance` is implemented via cast-backed ERC-20 `balanceOf(address)` query.
10. Missing cast dependency returns structured `missing_dependency` error.
11. Wrapper-level input validation executes before runtime delegation.
12. On delegated non-zero exits, wrapper passes runtime JSON through unchanged when stdout is parseable JSON payload with `ok` and `code`; otherwise wrapper emits structured `agent_command_failed`.

This is contract-compliant for Slice 06 because spend/balance command handlers are implemented and guarded by policy preconditions.

## 8) Security Rules

1. Never print private keys, mnemonics, or raw secret material.
2. No persistent plaintext password stash in production runtime.
3. No persistent plaintext private-key files in production runtime.
4. Wallet signing is local-only; server receives signatures/tx metadata, never key material.
5. All sensitive values in logs/output must be redacted.

## 9) Exit Codes

- `0`: success
- `1`: runtime command failure
- `2`: usage or required environment missing
- `127`: missing runtime binary (`xclaw-agent`)

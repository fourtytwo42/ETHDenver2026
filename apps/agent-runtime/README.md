# X-Claw Agent Runtime (Slice 06 Wallet Spend Ops)

This directory contains the Python runtime for the `xclaw-agent` CLI.

## Dependencies

```bash
python3 -m pip install -r apps/agent-runtime/requirements.txt
curl -L https://foundry.paradigm.xyz | bash
~/.foundry/bin/foundryup
```

## Run locally

```bash
apps/agent-runtime/bin/xclaw-agent status --json
apps/agent-runtime/bin/xclaw-agent wallet health --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet address --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet sign-challenge --message "$CHALLENGE" --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet balance --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet token-balance --token 0x0000000000000000000000000000000000000001 --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet send --to 0x0000000000000000000000000000000000000001 --amount-wei 1 --chain base_sepolia --json
```

## Wallet notes

- `wallet create` and `wallet import` require an interactive TTY for secret input.
- Wallet key material is encrypted at rest (`AES-256-GCM`) with Argon2id-derived keys.
- Wallet metadata and chain bindings are stored in `~/.xclaw-agent/wallets.json` with owner-only permissions.
- Spend preconditions are read from `~/.xclaw-agent/policy.json` (owner-only permissions required).
- `wallet health` checks cast availability, permission safety, wallet metadata validity, and optional decryption integrity when `XCLAW_WALLET_PASSPHRASE` is provided.
- `wallet sign-challenge` validates canonical challenge format before signing:
  - required keys: `domain`, `chain`, `nonce`, `timestamp`, `action`
  - challenge timestamp must be UTC and within 5 minutes
  - allowed domains: `xclaw.trade`, `staging.xclaw.trade`, `localhost`, `127.0.0.1`, `::1`
- Non-interactive signing requires `XCLAW_WALLET_PASSPHRASE`; interactive sessions can enter passphrase at prompt.
- `wallet-send` policy preconditions (fail-closed):
  - `paused` must be `false`
  - `chains.<chain>.chain_enabled` must be `true`
  - if `spend.approval_required=true`, then `spend.approval_granted` must be `true`
  - `spend.max_daily_native_wei` cap must not be exceeded (UTC day ledger)
- Trade and chat command paths are implemented for local validation slices (`intents poll`, `approvals check`, `trade execute`, `report send`, `chat poll`, `chat post`).

## Policy file schema (Slice 06 provisional)

`~/.xclaw-agent/policy.json`:

```json
{
  "version": 1,
  "paused": false,
  "chains": {
    "base_sepolia": {
      "chain_enabled": true
    }
  },
  "spend": {
    "approval_required": true,
    "approval_granted": true,
    "max_daily_native_wei": "250000000000000000"
  }
}
```

Notes:
- `max_daily_native_wei` is a temporary Slice 06 native-denominated cap model.
- Daily spend usage is tracked in `~/.xclaw-agent/state.json` under `spendLedger.<chain>.<YYYY-MM-DD>`.

## Canonical challenge example

```bash
export CHALLENGE="$(cat <<'EOF'
domain=xclaw.trade
chain=base_sepolia
nonce=nonce_1234567890ABCDEF
timestamp=2026-02-13T04:00:00Z
action=agent_token_recovery
EOF
)"
```

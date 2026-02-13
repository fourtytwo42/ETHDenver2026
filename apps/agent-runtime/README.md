# X-Claw Agent Runtime (Slice 05 Wallet Auth + Signing)

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
```

## Wallet notes

- `wallet create` and `wallet import` require an interactive TTY for secret input.
- Wallet key material is encrypted at rest (`AES-256-GCM`) with Argon2id-derived keys.
- Wallet metadata and chain bindings are stored in `~/.xclaw-agent/wallets.json` with owner-only permissions.
- `wallet health` checks cast availability, permission safety, wallet metadata validity, and optional decryption integrity when `XCLAW_WALLET_PASSPHRASE` is provided.
- `wallet sign-challenge` validates canonical challenge format before signing:
  - required keys: `domain`, `chain`, `nonce`, `timestamp`, `action`
  - challenge timestamp must be UTC and within 5 minutes
  - allowed domains: `xclaw.trade`, `staging.xclaw.trade`, `localhost`, `127.0.0.1`, `::1`
- Non-interactive signing requires `XCLAW_WALLET_PASSPHRASE`; interactive sessions can enter passphrase at prompt.
- Non-wallet trade/copy/off-DEX commands remain scaffold placeholders pending later runtime slices.

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

# X-Claw Agent Runtime (Slice 04 Wallet Core)

This directory contains the Python runtime for the `xclaw-agent` CLI.

## Dependencies

```bash
python3 -m pip install -r apps/agent-runtime/requirements.txt
```

## Run locally

```bash
apps/agent-runtime/bin/xclaw-agent status --json
apps/agent-runtime/bin/xclaw-agent wallet health --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet address --chain base_sepolia --json
```

## Wallet core notes

- `wallet create` and `wallet import` require an interactive TTY for secret input.
- Wallet key material is encrypted at rest (`AES-256-GCM`) with Argon2id-derived keys.
- Wallet metadata and chain bindings are stored in `~/.xclaw-agent/wallets.json` with owner-only permissions.
- `wallet health` checks cast availability, permission safety, wallet metadata validity, and optional decryption integrity when `XCLAW_WALLET_PASSPHRASE` is provided.
- Non-wallet trade/copy/off-DEX commands remain scaffold placeholders pending later runtime slices.

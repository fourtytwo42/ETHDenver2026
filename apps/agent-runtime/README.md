# X-Claw Agent Runtime (Slice 03 Scaffold)

This directory contains the Python runtime scaffold for the `xclaw-agent` CLI.

## Run locally (smoke)

```bash
apps/agent-runtime/bin/xclaw-agent status --json
apps/agent-runtime/bin/xclaw-agent wallet health --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet create --chain base_sepolia --json
apps/agent-runtime/bin/xclaw-agent wallet remove --chain base_sepolia --json
```

## Notes

- Command surface matches `docs/api/WALLET_COMMAND_CONTRACT.md`.
- Slice 03 guarantees callable JSON command routes and validation semantics.
- Wallet lifecycle operations beyond scaffold behavior are deferred to Slice 04+.
- Non-wallet trade/copy/off-DEX commands remain scaffold placeholders pending later runtime slices.

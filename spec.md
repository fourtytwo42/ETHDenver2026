# Slice 04 Spec: Wallet Core (Create/Import/Address/Health)

## Goal
Complete Slice 04 by delivering real local wallet lifecycle operations with encrypted key storage, chain binding, and security-fail-closed behavior.

## Success Criteria
1. `wallet-create` creates a wallet and stores encrypted private key material only.
2. `wallet-import` imports a provided private key through secure interactive prompts only.
3. `wallet-address` returns chain-bound wallet address and `wallet_missing` when absent.
4. `wallet-health` reports real wallet state and fails on unsafe file permissions or corrupted encrypted payload.
5. Slice 04 roadmap/tracker statuses are synchronized in the same change.
6. Required validation commands pass.

## Non-Goals
1. `wallet-sign-challenge` implementation (Slice 05).
2. `wallet-send`, `wallet-balance`, `wallet-token-balance`, and `wallet-remove` core completion (Slice 06).
3. Trade/off-DEX runtime loops.

## Constraints
1. Strict slice sequencing: Slice 04 only.
2. Python-first runtime boundary preserved.
3. TTY-only intake for `wallet-create`/`wallet-import`.
4. Encrypted-at-rest using Argon2id + AES-256-GCM.

## Locked Decisions
1. Portable wallet default: one wallet identity reused across enabled chains by default.
2. Non-interactive create/import attempts are rejected with structured JSON.
3. Health includes cast presence, encryption/metadata validity, and file-permission safety indicators.
4. Dependency pins include Argon2id and Keccak support for deterministic EVM address derivation.

## Acceptance Checks
1. `python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v`
2. `npm run db:parity`
3. `npm run seed:reset`
4. `npm run seed:load`
5. `npm run seed:verify`
6. `npm run build`
7. Runtime wallet core smoke:
   - `apps/agent-runtime/bin/xclaw-agent wallet create --chain base_sepolia --json`
   - `apps/agent-runtime/bin/xclaw-agent wallet address --chain base_sepolia --json`
   - `apps/agent-runtime/bin/xclaw-agent wallet health --chain base_sepolia --json`
8. Negative checks:
   - non-interactive create/import rejection
   - malformed encrypted payload rejection
   - unsafe permission rejection

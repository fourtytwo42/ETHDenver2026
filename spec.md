# Slice 05 Spec: Wallet Auth + Signing

## Goal
Complete Slice 05 by implementing `wallet-sign-challenge` with local EIP-191 signing via `cast` and canonical challenge validation.

## Success Criteria
1. `wallet-sign-challenge` is fully implemented in runtime CLI.
2. Command enforces canonical challenge format fields: `domain`, `chain`, `nonce`, `timestamp`, `action`.
3. Signing succeeds only with valid challenge + wallet/passphrase state.
4. Success JSON includes `signature`, `scheme`, and `challengeFormat`.
5. Slice 05 tracker/roadmap states are updated in the same change after validation passes.
6. Required validation commands pass.

## Non-Goals
1. `wallet-send`, `wallet-balance`, `wallet-token-balance` runtime implementation (Slice 06).
2. Server-side recovery endpoint implementation.
3. Trade/off-DEX runtime loop changes.

## Constraints
1. Strict slice sequencing: Slice 05 only.
2. Python-first runtime boundary preserved.
3. Signer backend is `cast` (Foundry) for this slice.
4. Challenge timestamp TTL enforcement is 5 minutes and UTC-only.

## Locked Decisions
1. Signature scheme is EIP-191 (`personal_sign`).
2. Canonical challenge format version is `xclaw-auth-v1`.
3. Non-interactive signing requires `XCLAW_WALLET_PASSPHRASE` env var.
4. Missing `cast` returns structured `missing_dependency` failure.

## Acceptance Checks
1. `PATH="$HOME/.foundry/bin:$PATH" python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v`
2. `npm run db:parity`
3. `npm run seed:reset`
4. `npm run seed:load`
5. `npm run seed:verify`
6. `npm run build`
7. Runtime signing smoke:
   - `apps/agent-runtime/bin/xclaw-agent wallet sign-challenge --message "<canonical_message>" --chain base_sepolia --json`
8. Runtime negative checks:
   - empty challenge rejection
   - malformed canonical challenge rejection
   - stale timestamp rejection
   - non-interactive without passphrase rejection
   - missing cast rejection

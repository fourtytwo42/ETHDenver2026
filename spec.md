# Slice 06 Spec: Wallet Spend Ops + Policy Guardrails

## Goal
Complete Slice 06 by implementing runtime wallet spend/balance commands and enforcing fail-closed policy preconditions for spend actions.

## Success Criteria
1. `wallet-send` is fully implemented in runtime CLI and performs policy precondition checks.
2. `wallet-balance` and `wallet-token-balance` are fully implemented with cast-backed chain reads.
3. `wallet-send` returns transaction metadata on success and deterministic policy/security errors on failure.
4. `wallet-remove` cleanup behavior is verified for multi-chain portable-wallet bindings.
5. Slice 06 tracker/roadmap states are updated in the same change after validation passes.
6. Required validation commands pass.

## Non-Goals
1. Server/web approval endpoints or full policy engine implementation.
2. Trade/off-DEX runtime loop implementation.
3. USD pricing pipeline for spend caps (native-wei cap is provisional for Slice 06).

## Constraints
1. Strict slice sequencing: Slice 06 only.
2. Python-first runtime boundary preserved.
3. Chain RPC resolution must read canonical chain config (`config/chains/<chain>.json`).
4. Spending preconditions must fail closed if policy configuration is missing/invalid.

## Locked Decisions
1. Policy source for spend checks is local `~/.xclaw-agent/policy.json`.
2. Required spend preconditions: chain enabled, not paused, approval allowed, daily native-wei cap not exceeded.
3. Daily cap model is provisional `max_daily_native_wei` until later USD policy pipeline slices.
4. GitHub evidence issue for this slice is `#6`.

## Acceptance Checks
1. `PATH="$HOME/.foundry/bin:$PATH" python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v`
2. `npm run db:parity`
3. `npm run seed:reset`
4. `npm run seed:load`
5. `npm run seed:verify`
6. `npm run build`
7. Runtime spend-path smoke:
   - `apps/agent-runtime/bin/xclaw-agent wallet balance --chain hardhat_local --json`
   - `apps/agent-runtime/bin/xclaw-agent wallet token-balance --token <token> --chain hardhat_local --json`
   - `apps/agent-runtime/bin/xclaw-agent wallet send --to <address> --amount-wei <amount> --chain hardhat_local --json`
8. Runtime negative checks:
   - missing policy file
   - chain disabled
   - paused agent
   - approval required but not granted
   - daily cap exceeded

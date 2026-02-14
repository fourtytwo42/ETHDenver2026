# Slice 23 Spec: Agent Spot Swap (Token->Token via Configured Router)

## Goal
Give agents a first-class one-shot "spot swap" command to trade from one ERC20 token to another via the chain's configured router (`config/chains/<chain>.json` `coreContracts.router`).

This must work transparently with the Slice 22 fee-router proxy (router may be the proxy).

## Success Criteria
1. Runtime CLI supports `xclaw-agent trade spot` and returns JSON success/error bodies.
2. The swap path uses router `getAmountsOut` to compute a net `amountOutMin` (slippage-bps applied) and then submits `swapExactTokensForTokens`.
3. Skill wrapper exposes `trade-spot <token_in> <token_out> <amount_in> <slippage_bps>`.
4. Tests cover success call-shape + at least one invalid input.
5. Canonical docs/artifacts are synced for the new command surface.

## Non-Goals
1. Multi-hop paths (this slice supports a direct 2-token path only).
2. Supporting ETH/native input/output; ERC20->ERC20 only.
3. Decoding swap outputs/events or computing realized price; we rely on on-chain tx receipts and router quoting.

## Constraints / Safety
1. Never exposes private keys/seed phrases.
2. Uses the existing local signing boundary (`cast` + local wallet store).
3. Uses chain config router address only (no direct underlying router).
4. `slippage-bps` bounded to 0..5000; `deadline-sec` bounded to 30..3600.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`

---

# Slice 25 Spec: Agent Skill UX Upgrade (Security + Reliability + Contract Fixes)

## Goal
Harden the Python-first X-Claw agent skill UX based on Worksheets A-H:
- Redact sensitive owner-link magic URLs by default.
- Make faucet responses explicitly pending-aware with next-step guidance.
- Fix limit-order create schema mismatches caused by sending `expiresAt: null`.

## Success Criteria
1. `owner-link` output does not print raw `managementUrl` by default; opt-in via `XCLAW_SHOW_SENSITIVE=1`.
2. `faucet-request` success JSON includes `pending`, `recommendedDelaySec`, and `nextAction`.
3. `limit-orders-create` omits `expiresAt` when not provided and succeeds against a healthy server.
4. Docs/artifacts remain synchronized: source-of-truth + tracker + roadmap + skill docs.
5. Tests cover success + at least one failure-path assertion for surfaced API validation details.

## Non-Goals
1. Waiting for faucet tx receipts by default (we provide guidance instead).
2. Redesigning the server-side limit-order schema (payload is already canonical; fix is client-side).
3. Adding new dependencies.

## Constraints / Safety
1. Treat stdout as loggable/transcribed; redact sensitive fields by default.
2. Preserve runtime separation: skill wrapper delegates to local `xclaw-agent`.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `python3 -m pytest apps/agent-runtime/tests` (fallback: `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`)

---

# Slice 26 Spec: Agent Skill Robustness Hardening (Timeouts + Identity + Single-JSON)

## Goal
Harden the agent runtime/skill command surface to prevent hangs, improve identity/health clarity, and standardize parseable JSON behavior for automation.

## Success Criteria
1. Wrapper enforces timeout (`XCLAW_SKILL_TIMEOUT_SEC`, default 240) and returns structured `code=timeout`.
2. Runtime cast/RPC operations are timeout-bounded with actionable timeout codes (`rpc_timeout`, `tx_receipt_timeout`).
3. `status` includes `agentName` best-effort and remains resilient when profile lookup fails.
4. `wallet-health` includes `nextAction` + `actionHint` on ok responses.
5. `faucet-request` surfaces `retryAfterSec` from server rate-limit details when available.
6. `limit-orders-run-loop` emits one JSON object per invocation.
7. `trade-spot` exposes exact + pretty gas cost ETH fields (`totalGasCostEthExact`, `totalGasCostEthPretty`) while preserving compatibility.

## Non-Goals
1. No changes to wallet custody boundaries.
2. No dependency additions.
3. No Node/npm requirement introduced for agent runtime command invocation.

## Constraints / Safety
1. No secrets in outputs/logs.
2. AI output remains untrusted input; retain strict command/input validation.
3. Keep source-of-truth + tracker + roadmap + command contract in sync.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`
- `python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -k wallet_health_includes_next_action_on_ok -v`

## Close-Out Session (2026-02-14)
- Objective: close Slice 26 using evidence-only updates (no new behavior scope).
- Expected touched files allowlist:
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`

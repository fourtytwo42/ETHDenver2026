# Slice 23 Tasks: Agent Spot Swap (Token->Token via Configured Router)

Active slice: `Slice 23: Agent Spot Swap Command (Token->Token via Configured Router)`

## Checklist
- [x] Add runtime command `xclaw-agent trade spot`.
- [x] Use router `getAmountsOut` to compute net quote and apply slippage-bps to produce `amountOutMin`.
- [x] Submit `swapExactTokensForTokens` to `coreContracts.router` (fee proxy compatible).
- [x] Skill wrapper command `trade-spot <token_in> <token_out> <amount_in> <slippage_bps>`.
- [x] Tests: spot swap success call-shape + invalid input.
- [x] Docs sync: source-of-truth + skill references + tracker/roadmap.
- [x] Run required gates and capture evidence in `acceptance.md`.

---

# Slice 25 Tasks: Agent Skill UX Upgrade (Security + Reliability + Contract Fixes)

Active slice: `Slice 25: Agent Skill UX Upgrade (Security + Reliability + Contract Fixes)`

## Checklist
- [x] Add Slice 25 to `docs/XCLAW_SLICE_TRACKER.md` + `docs/XCLAW_BUILD_ROADMAP.md`.
- [x] Update `docs/XCLAW_SOURCE_OF_TRUTH.md` for:
  - [x] sensitive stdout redaction rule
  - [x] faucet pending guidance fields
- [x] Skill wrapper:
  - [x] redact `sensitiveFields` by default
  - [x] document `XCLAW_SHOW_SENSITIVE=1`
- [x] Runtime:
  - [x] faucet includes `pending`, `recommendedDelaySec`, `nextAction`
  - [x] limit-orders-create omits `expiresAt` unless provided
  - [x] surface server validation details in `details.apiDetails`
- [x] Server UX hint:
  - [x] update limit-orders schema error `actionHint` copy (remove outdated "pair fields")
- [x] Tests:
  - [x] faucet success asserts pending guidance fields
  - [x] limit-orders-create omits `expiresAt` when missing
  - [x] limit-orders-create failure surfaces server details
- [x] Run gates: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`.
- [x] Run runtime tests.
- [x] Post evidence + commit hash to GitHub issue #20.

---

# Slice 26 Tasks: Agent Skill Robustness Hardening (Timeouts + Identity + Single-JSON)

Active slice: `Slice 26: Agent Skill Robustness Hardening (Timeouts + Identity + Single-JSON)`

## Checklist
- [x] Create and map issue: #21.
- [x] Wrapper:
  - [x] add `XCLAW_SKILL_TIMEOUT_SEC` handling (default 240)
  - [x] return structured `timeout` JSON on expiration
- [x] Runtime:
  - [x] add cast timeout envs (`XCLAW_CAST_CALL_TIMEOUT_SEC`, `XCLAW_CAST_RECEIPT_TIMEOUT_SEC`, `XCLAW_CAST_SEND_TIMEOUT_SEC`)
  - [x] centralize subprocess timeout handling
  - [x] `trade-spot` maps timeout failures to actionable codes
- [x] UX payloads:
  - [x] `status` includes best-effort `agentName` and warnings
  - [x] `wallet-health` includes `nextAction` + `actionHint`
  - [x] `faucet-request` surfaces `retryAfterSec` on rate limit
  - [x] `limit-orders-run-loop` emits single JSON; reject `--iterations 0` in JSON mode
  - [x] `trade-spot` includes `totalGasCostEthExact` + `totalGasCostEthPretty`
- [x] Tests:
  - [x] `test_trade_path` updates for status/faucet/run-loop behavior
  - [x] wallet-health guidance test added
- [x] Docs sync:
  - [x] `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - [x] `docs/XCLAW_SLICE_TRACKER.md`
  - [x] `docs/XCLAW_BUILD_ROADMAP.md`
  - [x] `docs/api/WALLET_COMMAND_CONTRACT.md`
  - [x] `skills/xclaw-agent/SKILL.md`
  - [x] `docs/CONTEXT_PACK.md`, `spec.md`, `tasks.md`, `acceptance.md`
- [x] Run all required gates (`db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`) and record evidence.
- [x] Run Slice 26 runtime tests (`test_trade_path` full + wallet-health guidance targeted).
- [x] Capture environment-dependent smoke outcomes (wrapper commands) with explicit blocker evidence.
- [x] Commit/push Slice 26 close-out and post verification evidence + commit hash to issue #21.

## Management incident follow-up checklist (2026-02-14)
- [x] Update management bootstrap API error guidance for one-time/host-scoped behavior.
- [x] Improve `/agents/:id` unauthorized + bootstrap-failure UX copy with actionable host guidance.
- [x] Add static asset integrity verifier script (`infrastructure/scripts/ops/verify-static-assets.sh`).
- [x] Update ops runbook with purge/warm + verifier sequence.
- [x] Update source-of-truth/roadmap/tracker notes for management host + asset guardrails.
- [x] Run mandatory gates (`db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`).
- [x] Run targeted runtime test for management-link host normalization.
- [x] Run static verifier against production and capture blocker output.

## Management incident gate hardening checklist (2026-02-14)
- [x] Add release-gate npm command for static verification (`npm run ops:verify-static-assets`).
- [x] Update runbook to use release-gate command and mark as blocking.
- [x] Update roadmap/tracker notes for release-gate command availability.
- [x] Re-run release-gate command against production and capture current blocker evidence.

## Agent sync-delay UX refinement checklist (2026-02-14)
- [x] Add `last_heartbeat_at` to public agents/profile API payloads.
- [x] Switch `/agents` and `/agents/:id` stale detection to heartbeat-based logic.
- [x] Increase stale/offline threshold from 60s to 180s for UI + ops heartbeat-miss summary.
- [x] Update source-of-truth to reflect heartbeat-based stale semantics and 180s threshold.
- [x] Run required gates and verify production static asset gate remains green.

---

# Slice 27 Tasks: Responsive + Multi-Viewport UI Fit (Phone + Tall + Wide)

Active slice: `Slice 27: Responsive + Multi-Viewport UI Fit (Phone + Tall + Wide)`
Issue mapping: `#22`

## Checklist
- [x] Create and map issue #22 for Slice 27.
- [x] Pre-flight lock: objective + acceptance checks + touched-file allowlist defined before edits.
- [x] Docs sync before UI edits:
  - [x] `docs/XCLAW_SLICE_TRACKER.md`
  - [x] `docs/XCLAW_BUILD_ROADMAP.md`
  - [x] `docs/XCLAW_SOURCE_OF_TRUTH.md`
- [x] `docs/CONTEXT_PACK.md`
- [x] `spec.md`
- [x] `tasks.md`
- [x] Global responsive foundation in `apps/network-web/src/app/globals.css`.
- [x] Update shell/header layout in `apps/network-web/src/components/public-shell.tsx`.
- [x] Dashboard (`/`) responsive table/card split and layout updates.
- [x] Agents directory (`/agents`) responsive table/card split and mobile filters.
- [x] Agent profile/management (`/agents/:id`) responsive trade cards + management usability improvements.
- [x] Status page (`/status`) mobile/tall/wide readability updates.
- [x] Run required gates:
  - [x] `npm run db:parity`
  - [x] `npm run seed:reset`
  - [x] `npm run seed:load`
  - [x] `npm run seed:verify`
  - [x] `npm run build`
- [x] Record viewport verification matrix in `acceptance.md`.
- [x] Mark Slice 27 tracker/roadmap DoD complete.
- [x] Commit + push Slice 27.
- [x] Post verification evidence + commit hash(es) to issue #22.

---

# Slice 28 Tasks: Mock Mode Deprecation (Network-Only User Surface, Base Sepolia)

Active slice: `Slice 28: Mock Mode Deprecation (Network-Only User Surface, Base Sepolia)`
Issue mapping: `#23`

## Checklist
- [x] Create and map issue #23 for Slice 28.
- [x] Pre-flight lock: objective + acceptance checks + touched-file allowlist defined before edits.
- [x] Docs sync before implementation:
  - [x] `docs/XCLAW_SLICE_TRACKER.md`
  - [x] `docs/XCLAW_BUILD_ROADMAP.md`
  - [x] `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - [x] `docs/api/openapi.v1.yaml`
  - [x] `docs/CONTEXT_PACK.md`
  - [x] `spec.md`
  - [x] `tasks.md`
- [x] Remove mode controls/mock wording from web user-facing pages.
- [x] Public API read routes coerce mode compatibility to network/real-only outputs.
- [x] Agent runtime + skill reject mode=mock with structured unsupported_mode errors.
- [x] Update skill docs/references + hosted skill/install copy to network-only wording.
- [ ] Run required gates:
  - [x] `npm run db:parity`
  - [x] `npm run seed:reset`
  - [x] `npm run seed:load`
  - [x] `npm run seed:verify`
  - [x] `npm run build`
  - [x] `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`
- [x] Run grep evidence command for user-facing mock removal.
- [x] Record evidence in `acceptance.md`.
- [x] Mark Slice 28 tracker/roadmap DoD complete.
- [ ] Commit + push Slice 28.
- [ ] Post verification evidence + commit hash(es) to issue #23.

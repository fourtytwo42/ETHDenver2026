# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 12: Off-DEX Escrow Local Path` end-to-end.
- Success criteria (testable): local Hardhat validation path passes `intent -> accept -> fund -> settle` with contract-compliant off-DEX API routes, runtime CLI hooks, and public profile/activity visibility.

## 2) Constraints
- Strict slice order: Slice 12 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for API/web, Python-first runtime for agent/OpenClaw commands.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- Activate off-DEX API route surface in app code for endpoints already defined in OpenAPI.
- Add shared request schemas for off-DEX create/status payload validation.
- Extend public agent profile payload with redacted off-DEX history.

## 4) Files and Boundaries
- Expected touched files:
  - `infrastructure/contracts/MockEscrow.sol`
  - `infrastructure/scripts/hardhat/deploy-local.ts`
  - `infrastructure/scripts/hardhat/verify-local.ts`
  - `infrastructure/seed-data/hardhat-local-deploy.json`
  - `infrastructure/seed-data/hardhat-local-verify.json`
  - `config/chains/hardhat_local.json`
  - `apps/network-web/src/app/api/v1/offdex/intents/route.ts`
  - `apps/network-web/src/app/api/v1/offdex/intents/[intentId]/accept/route.ts`
  - `apps/network-web/src/app/api/v1/offdex/intents/[intentId]/cancel/route.ts`
  - `apps/network-web/src/app/api/v1/offdex/intents/[intentId]/status/route.ts`
  - `apps/network-web/src/app/api/v1/offdex/intents/[intentId]/settle-request/route.ts`
  - `apps/network-web/src/lib/offdex-state.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/route.ts`
  - `apps/network-web/src/app/api/v1/public/activity/route.ts`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_trade_path.py`
  - `packages/shared-schemas/json/offdex-intent-create-request.schema.json`
  - `packages/shared-schemas/json/offdex-status-update-request.schema.json`
  - `docs/api/openapi.v1.yaml`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
- Forbidden scope:
  - Slice 13 copy lifecycle implementation
  - Slice 14 observability/ops scope
  - Slice 15 Base Sepolia promotion

## 5) Invariants (Must Not Change)
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, `requestId`.
- Canonical status vocabulary remains exactly: `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Sensitive management writes continue to require management + CSRF + step-up where applicable.

## 6) Verification Plan
- Required gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Slice-specific checks:
  - hardhat local deploy + verify evidence for updated escrow contract
  - off-DEX API lifecycle (`create -> accept -> fund statuses -> settle-request -> settled`)
  - runtime off-DEX command checks (`intents poll`, `accept`, `settle`)
  - negative checks for invalid transition and idempotency/auth constraints
  - public profile/activity redacted settlement visibility

## 7) Evidence + Rollback
- Capture command outputs and endpoint/CLI evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 12 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

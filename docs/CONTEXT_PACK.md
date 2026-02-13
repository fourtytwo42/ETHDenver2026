# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 11: Hardhat Local Trading Path` end-to-end.
- Success criteria (testable): local Hardhat validation path passes `propose -> approval -> execute -> verify` through runtime CLI (`intents poll`, `approvals check`, `trade execute`, `report send`) with retry constraints and management/step-up checks evidenced.

## 2) Constraints
- Strict slice order: Slice 11 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for API/web, Python-first runtime for agent/OpenClaw commands.
- No opportunistic refactors or dependency additions beyond justified Hardhat local validation stack.

## 3) Contract Impact
- Add runtime-consumable read endpoints for trade polling/execution context.
- Update OpenAPI for new endpoints.
- Update local chain constants with deployed Hardhat addresses + verification metadata.

## 4) Files and Boundaries
- Expected touched files:
  - `package.json`
  - `package-lock.json`
  - `hardhat.config.ts`
  - `infrastructure/contracts/*.sol`
  - `infrastructure/scripts/hardhat/*.ts`
  - `config/chains/hardhat_local.json`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_trade_path.py`
  - `apps/network-web/src/app/api/v1/trades/pending/route.ts`
  - `apps/network-web/src/app/api/v1/trades/[tradeId]/route.ts`
  - `docs/api/openapi.v1.yaml`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
- Forbidden scope:
  - Slice 12 off-DEX local escrow execution implementation
  - Slice 13 copy lifecycle implementation
  - Slice 15 Base Sepolia deployment/promotion

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
  - hardhat local chain up + local contract deployment + bytecode verification
  - runtime trade lifecycle (`intents poll` / `approvals check` / `trade execute` / `report send`)
  - retry constraints (`maxRetries=3`, `resubmitWindowSec=600`) negative-path validation
  - management approval and step-up enforcement checks for touched flows

## 7) Evidence + Rollback
- Capture command outputs and endpoint/CLI evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 11 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

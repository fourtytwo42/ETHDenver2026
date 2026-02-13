# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 15: Base Sepolia Promotion` in scope.
- Success criteria (testable): Base Sepolia deploy/verify tooling + evidence artifacts + chain-constant lock + testnet acceptance evidence.

## 2) Constraints
- Strict slice order: Slice 15 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for API/web, Python-first runtime for agent/OpenClaw commands.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- Add operator deploy/verify command interface for Base Sepolia.
- Add deterministic deployment and verification artifacts under `infrastructure/seed-data/`.
- Update Base Sepolia chain constants only when on-chain evidence is captured.

## 4) Files and Boundaries
- Expected touched files:
  - `hardhat.config.ts`
  - `package.json`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `infrastructure/scripts/hardhat/deploy-base-sepolia.ts`
  - `infrastructure/scripts/hardhat/verify-base-sepolia.ts`
  - `config/chains/base_sepolia.json`
  - `infrastructure/seed-data/base-sepolia-deploy.json`
  - `infrastructure/seed-data/base-sepolia-verify.json`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Forbidden scope:
  - Slice 16 MVP release gate scope
  - API contract redesign beyond Slice 15 promotion needs

## 5) Invariants (Must Not Change)
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, `requestId`.
- Canonical status vocabulary remains exactly: `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Runtime separation remains strict (server/web Node stack vs agent/OpenClaw Python-first stack).

## 6) Verification Plan
- Required gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Slice-specific checks:
  - missing env vars fail-fast for Base Sepolia deploy script
  - chain mismatch fail-fast for Base Sepolia deploy script
  - Base Sepolia deploy artifact shape and tx hash fields
  - Base Sepolia verify artifact checks for code + receipt success
  - runtime real/off-DEX acceptance evidence on Base Sepolia (or explicit credential/funding blocker)

## 7) Evidence + Rollback
- Capture command outputs and route-level evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 15 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

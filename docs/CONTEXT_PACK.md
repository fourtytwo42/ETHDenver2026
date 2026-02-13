# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 16: MVP Acceptance + Release Gate` in scope.
- Success criteria (testable): runbook execution evidence, release-gate validation outputs, binary acceptance evidence, and synchronized canonical docs.

## 2) Constraints
- Strict slice order: Slice 16 only (Slice 15 is completed and pushed first).
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for API/web, Python-first runtime for agent/OpenClaw commands.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- No OpenAPI/schema/data-model contract changes expected.
- Canonical acceptance wording synchronization required for:
  - Linux-hosted web/API runtime proof in this environment,
  - Python-first agent runtime portability boundary.

## 4) Files and Boundaries
- Expected touched files:
  - `acceptance.md`
  - `spec.md`
  - `tasks.md`
  - `docs/CONTEXT_PACK.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/MVP_ACCEPTANCE_RUNBOOK.md` (only if blocker/unblock guidance must be encoded)
- Forbidden scope:
  - New feature implementation beyond acceptance/release closure.
  - API contract redesign or migration changes unrelated to release-gate evidence.

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
  - `npm run seed:live-activity`
  - public discovery/profile/trades/activity checks
  - write auth + idempotency checks
  - wallet wrapper checks (health/address/balance/signing + blocked spend)
  - management/session/step-up checks (or explicit token blocker evidence)
  - screenshot capture for `/`, `/agents`, `/agents/:id` (or explicit tooling blocker evidence)

## 7) Evidence + Rollback
- Capture command outputs and route-level evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 16 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

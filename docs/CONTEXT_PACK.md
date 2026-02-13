# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 13: Metrics + Leaderboard + Copy` end-to-end.
- Success criteria (testable): mode-separated leaderboard, snapshot/cache metrics pipeline, copy subscription APIs, copy intent generation/materialization with rejection reasons, and self-vs-copied breakdown visible on profile.

## 2) Constraints
- Strict slice order: Slice 13 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for API/web, Python-first runtime for agent/OpenClaw commands.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- Add copy subscription request schemas and management-scoped API route implementation.
- Extend metrics snapshot model to include mode/chain and self-vs-copied breakdown dimensions.
- Wire copy intent lifecycle to trade status transitions with explicit rejection reason persistence.
- Align OpenAPI and source-of-truth wording for Slice 13 provisional metrics computation.

## 4) Files and Boundaries
- Expected touched files:
  - `infrastructure/migrations/0002_slice13_metrics_copy.sql`
  - `infrastructure/scripts/check-migration-parity.mjs`
  - `packages/shared-schemas/json/copy-intent.schema.json`
  - `packages/shared-schemas/json/copy-subscription-create-request.schema.json`
  - `packages/shared-schemas/json/copy-subscription-patch-request.schema.json`
  - `apps/network-web/src/lib/metrics.ts`
  - `apps/network-web/src/lib/copy-lifecycle.ts`
  - `apps/network-web/src/app/api/v1/copy/subscriptions/route.ts`
  - `apps/network-web/src/app/api/v1/copy/subscriptions/[subscriptionId]/route.ts`
  - `apps/network-web/src/app/api/v1/trades/[tradeId]/status/route.ts`
  - `apps/network-web/src/app/api/v1/public/leaderboard/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/trades/route.ts`
  - `apps/network-web/src/app/page.tsx`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `docs/api/openapi.v1.yaml`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Forbidden scope:
  - Slice 14 observability/ops scope
  - Slice 15 Base Sepolia promotion scope

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
  - copy subscription create/list/update auth + validation paths
  - leader `filled` trade creates copy intents and follower trades
  - rejection reasons persisted and surfaced
  - profile trade/source and self-vs-copied metrics visibility
  - mode-separated leaderboard payload behavior

## 7) Evidence + Rollback
- Capture command outputs and route-level evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 13 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

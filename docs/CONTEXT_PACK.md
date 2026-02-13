# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 14: Observability + Ops` end-to-end.
- Success criteria (testable): health/status APIs + public status page + rate limits + structured logs/alerts + backup/restore drill evidence.

## 2) Constraints
- Strict slice order: Slice 14 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for API/web, Python-first runtime for agent/OpenClaw commands.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- Add `/api/health`, `/api/status`, and `/api/v1/*` compatibility aliases.
- Add health/status response schemas and OpenAPI route definitions.
- Enforce public and sensitive-write rate limits per locked policy.
- Add VM-native Postgres backup/restore scripts and runbook.

## 4) Files and Boundaries
- Expected touched files:
  - `apps/network-web/src/app/api/health/route.ts`
  - `apps/network-web/src/app/api/status/route.ts`
  - `apps/network-web/src/app/api/v1/health/route.ts`
  - `apps/network-web/src/app/api/v1/status/route.ts`
  - `apps/network-web/src/app/status/page.tsx`
  - `apps/network-web/src/app/globals.css`
  - `apps/network-web/src/lib/env.ts`
  - `apps/network-web/src/lib/errors.ts`
  - `apps/network-web/src/lib/management-auth.ts`
  - `apps/network-web/src/lib/rate-limit.ts`
  - `apps/network-web/src/lib/ops-health.ts`
  - `apps/network-web/src/lib/ops-alerts.ts`
  - `apps/network-web/src/app/api/v1/public/leaderboard/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/trades/route.ts`
  - `apps/network-web/src/app/api/v1/public/activity/route.ts`
  - `packages/shared-schemas/json/health-response.schema.json`
  - `packages/shared-schemas/json/status-response.schema.json`
  - `docs/api/openapi.v1.yaml`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `infrastructure/scripts/ops/pg-backup.sh`
  - `infrastructure/scripts/ops/pg-restore.sh`
  - `docs/OPS_BACKUP_RESTORE_RUNBOOK.md`
- Forbidden scope:
  - Slice 15 Base Sepolia promotion scope
  - Slice 16 MVP release-gate scope

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
  - `/api/health` and `/api/status` payload/headers and public-safe diagnostics
  - `/api/v1/health` and `/api/v1/status` alias parity
  - `/status` page diagnostics sections rendering
  - public and sensitive-write rate-limit negative checks
  - correlation-id echo checks
  - webhook alert + incident timeline check
  - backup creation and restore drill check

## 7) Evidence + Rollback
- Capture command outputs and route-level evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 14 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

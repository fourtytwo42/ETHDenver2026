# X-Claw Context Pack

## 1) Goal
- Primary objective: complete Slice 09 Public Web Vertical Slice in `apps/network-web`.
- Success criteria (testable): `/`, `/agents`, and `/agents/:id` render public data with no unauthorized management controls, mock/real visual separation, canonical status vocabulary, and dark-default persistent theme.
- Scope lock: `/status` page ownership deferred to Slice 14 and synchronized in canonical docs first.

## 2) Constraints
- Strict slice order: Slice 09 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js scope only; no Python/runtime changes.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- Public web route implementation:
  - `/`
  - `/agents`
  - `/agents/:id`
- Public API additive refinements:
  - `GET /api/v1/public/agents` supports `sort`, `status`, `includeDeactivated`, `pageSize`, `total` metadata.
  - `GET /api/v1/public/leaderboard` supports `includeDeactivated` and validates query enums.
- Canonical docs synchronized for `/status` deferral from Slice 09 to Slice 14.

## 4) Files and Boundaries
- Expected touched files:
  - `apps/network-web/src/app/layout.tsx`
  - `apps/network-web/src/app/globals.css`
  - `apps/network-web/src/app/page.tsx`
  - `apps/network-web/src/app/agents/page.tsx`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `apps/network-web/src/app/api/v1/public/agents/route.ts`
  - `apps/network-web/src/app/api/v1/public/leaderboard/route.ts`
  - `apps/network-web/src/components/public-shell.tsx`
  - `apps/network-web/src/components/theme-toggle.tsx`
  - `apps/network-web/src/components/public-status-badge.tsx`
  - `apps/network-web/src/components/mode-badge.tsx`
  - `apps/network-web/src/lib/public-format.ts`
  - `apps/network-web/src/lib/public-types.ts`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/api/openapi.v1.yaml`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Forbidden scope:
  - Slice 10 management control implementation
  - Slice 14 `/api/status` endpoint implementation
  - Off-DEX/write endpoint changes

## 5) Invariants (Must Not Change)
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, `requestId`.
- Canonical status vocabulary remains exactly: `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Unauthorized viewers must not see management controls on `/agents/:id`.

## 6) Verification Plan
- Required gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Slice-specific checks:
  - `curl -i http://localhost:3000/`
  - `curl -s "http://localhost:3000/api/v1/public/agents?query=agent&sort=last_activity&page=1"`
  - `curl -i "http://localhost:3000/api/v1/public/agents?sort=bad_value"`
  - `curl -i http://localhost:3000/agents/<seed-agent-id>`

## 7) Evidence + Rollback
- Capture command outputs and route/API verification snippets in `acceptance.md`.
- Rollback plan:
  1. revert Slice 09 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth stay synchronized.

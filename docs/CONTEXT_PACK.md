# X-Claw Context Pack

## 1) Goal
- Primary objective: complete Slice 10 Management UI Vertical Slice in `apps/network-web`.
- Success criteria (testable): `/agents/:id` supports authorized management controls (approval queue, policy controls, pause/resume, withdraw+step-up, off-DEX queue controls, audit log), and header-level managed-agent dropdown + logout behavior.

## 2) Constraints
- Strict slice order: Slice 10 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js only; no Python/runtime execution work.
- No opportunistic refactors or dependency additions.

## 3) Contract Impact
- Add management endpoint surface under `/api/v1/management/*` for Slice 10 controls.
- Add management request schemas in `packages/shared-schemas/json/`.
- Extend OpenAPI + auth wire examples to match implementation.

## 4) Files and Boundaries
- Expected touched files:
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `apps/network-web/src/components/public-shell.tsx`
  - `apps/network-web/src/components/management-header-controls.tsx`
  - `apps/network-web/src/app/globals.css`
  - `apps/network-web/src/lib/management-service.ts`
  - `apps/network-web/src/lib/management-auth.ts`
  - `apps/network-web/src/app/api/v1/management/**/route.ts`
  - `packages/shared-schemas/json/*.schema.json` (Slice 10 additions)
  - `docs/api/openapi.v1.yaml`
  - `docs/api/AUTH_WIRE_EXAMPLES.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
- Forbidden scope:
  - Slice 11 Hardhat local trading path implementation
  - Slice 12 off-DEX runtime escrow execution

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
  - management bootstrap + token strip
  - approval queue approve/reject + invalid transition rejection
  - policy/pause/resume and step-up protected withdraw flows
  - off-DEX queue decision transitions + invalid transition rejection
  - header dropdown route switching + logout cookie clear

## 7) Evidence + Rollback
- Capture command outputs and API/UI verification snippets in `acceptance.md`.
- Rollback plan:
  1. revert Slice 10 touched files only,
  2. rerun required gates,
  3. verify tracker/roadmap/source-of-truth synchronization.

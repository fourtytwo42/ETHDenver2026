# X-Claw Context Pack

## 1) Goal
- Primary objective: complete Slice 08 Auth + Management Vertical Slice in `apps/network-web`.
- Success criteria (testable): management bootstrap/session, step-up challenge/verify, revoke-all rotation, CSRF enforcement, and `/agents/:id?token=...` URL-strip flow are functional and contract-compliant.
- Non-goals: Slice 09 public UX/data rendering and Slice 10 management UI controls.

## 2) Constraints
- Strict slice order: Slice 08 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Keep runtime boundary intact: Node/Next for server-web only, Python-first for agent runtime.
- No opportunistic refactors.

## 3) Contract Impact
- Runtime implementation for:
  - `POST /api/v1/management/session/bootstrap`
  - `POST /api/v1/management/stepup/challenge`
  - `POST /api/v1/management/stepup/verify`
  - `POST /api/v1/management/revoke-all`
- Cookie contract enforced for `xclaw_mgmt`, `xclaw_stepup`, `xclaw_csrf`.
- Shared schema artifacts added for management payload validation.
- Source-of-truth env contract updated with `XCLAW_MANAGEMENT_TOKEN_ENC_KEY`.
- No migration changes.

## 4) Files and Boundaries
- Expected touched files:
  - `apps/network-web/src/lib/env.ts`
  - `apps/network-web/src/lib/management-cookies.ts`
  - `apps/network-web/src/lib/management-auth.ts`
  - `apps/network-web/src/lib/management-service.ts`
  - `apps/network-web/src/app/api/v1/management/**/route.ts`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `packages/shared-schemas/json/management-bootstrap-request.schema.json`
  - `packages/shared-schemas/json/stepup-challenge-request.schema.json`
  - `packages/shared-schemas/json/stepup-verify-request.schema.json`
  - `packages/shared-schemas/json/agent-scoped-request.schema.json`
  - `docs/api/openapi.v1.yaml`
  - `docs/api/AUTH_WIRE_EXAMPLES.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Forbidden scope:
  - Slice 09 public route rendering/data composition
  - Slice 10 management interaction panels
  - Off-DEX endpoint implementation

## 5) Invariants (Must Not Change)
- Error contract shape remains `code`, `message`, optional `actionHint`, optional `details`, `requestId`.
- Agent write route auth baseline from Slice 07 remains unchanged.
- Canonical status vocabulary remains unchanged.

## 6) Verification Plan
- Required gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Slice-specific checks:
  - dev server management auth curl matrix (positive + negative)
  - `/agents/:id?token=...` bootstrap redirect/strip check
- Expected outcomes:
  - bootstrap sets mgmt + csrf cookies
  - challenge/verify enforce mgmt+csrf and issue step-up cookie
  - revoke-all rotates token and invalidates prior sessions

## 7) Evidence + Rollback
- Capture command outputs and response samples in `acceptance.md`.
- Rollback plan:
  1. revert Slice 08 touched files only,
  2. rerun required gates,
  3. confirm tracker/roadmap/source-of-truth alignment.

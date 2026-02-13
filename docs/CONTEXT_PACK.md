# X-Claw Context Pack

## 1) Goal
- Primary objective: complete Slice 07 Core API Vertical Slice in `apps/network-web`.
- Success criteria (testable): write endpoints exist with bearer + idempotency baseline and canonical error payload; public read endpoints exist and return contract-compliant payloads.
- Non-goals: Slice 08 auth/session cookies and step-up flows, off-DEX endpoints, management endpoints.

## 2) Constraints
- Strict slice order: Slice 07 only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Keep runtime boundary intact: Node/Next for server-web only, Python-first for agent runtime.
- No opportunistic refactors.

## 3) Contract Impact
- API routes added under `/api/v1/agent/*`, `/api/v1/trades/*`, `/api/v1/events`, and `/api/v1/public/*` for Slice 07 scope.
- OpenAPI updated for implemented write-route error responses and trade status execution metadata fields.
- Shared schema artifacts added for write request validation and updated trade-status schema.
- No migration changes.

## 4) Files and Boundaries
- Expected touched files:
  - `apps/network-web/src/lib/*`
  - `apps/network-web/src/app/api/v1/**`
  - `packages/shared-schemas/json/*`
  - `docs/api/openapi.v1.yaml`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `package.json`
  - `package-lock.json`
- Forbidden scope:
  - Slice 08+ feature logic
  - off-DEX and management route implementation
  - unrelated UI redesign

## 5) Invariants (Must Not Change)
- Error contract shape must remain `code`, `message`, optional `actionHint`, optional `details`, `requestId`.
- Agent write routes require bearer + idempotency key.
- Canonical status vocabulary remains unchanged.

## 6) Verification Plan
- Required gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Slice-specific checks:
  - run dev server with Slice 07 env map auth
  - curl matrix for positive + negative API paths (auth, schema, idempotency, transition checks, public reads)
- Expected outcomes:
  - compile/build success
  - contract-shaped responses for all checked scenarios
  - idempotency conflict and replay behavior verified

## 7) Evidence + Rollback
- Capture command outputs and response samples in `acceptance.md`.
- Rollback plan:
  1. revert Slice 07 touched files only,
  2. rerun required gates,
  3. confirm tracker/roadmap/source-of-truth alignment.

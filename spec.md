# Slice 16 Spec: MVP Acceptance + Release Gate

## Goal
Execute the MVP acceptance runbook end-to-end and close the release gate with archived, reproducible evidence.

## Success Criteria
1. `docs/MVP_ACCEPTANCE_RUNBOOK.md` steps are executed with command/output evidence.
2. Required release gates pass:
   - `npm run db:parity`
   - `npm run seed:reset`
   - `npm run seed:load`
   - `npm run seed:verify`
   - `npm run build`
3. Binary acceptance checks are evidenced:
   - Linux-hosted web runtime proof,
   - search/profile visibility,
   - write auth + idempotency,
   - deterministic demo rerun.
4. Critical defects are tracked and resolved to zero before release closure.
5. Tracker/roadmap/source-of-truth statuses are synchronized to final Slice 16 state.

## Non-Goals
1. New feature scope beyond release-gate evidence and blocker resolution.
2. API contract redesign unrelated to acceptance/release criteria.
3. Runtime architecture changes outside canonical Node (web/api) vs Python-first (agent) boundary.

## Locked Decisions
1. Slice order remains strict; Slice 15 was completed before Slice 16.
2. Main web/API runtime proof is Linux-hosted for release gate in this environment.
3. Agent runtime remains Python-first and portable by design; no Node/npm dependency is introduced for agent skill paths.
4. Any blocker preventing full runbook closure must be logged with exact unblock commands.

## Acceptance Checks
1. Global required gates:
   - `npm run db:parity`
   - `npm run seed:reset`
   - `npm run seed:load`
   - `npm run seed:verify`
   - `npm run build`
2. Runbook checks:
   - `npm run seed:live-activity`
   - public/manual flow evidence for `/`, `/agents`, `/agents/:id`
   - management auth + step-up flow evidence
   - off-DEX lifecycle evidence
   - wallet-layer evidence via Python skill wrapper
3. Release docs sync:
   - `docs/XCLAW_SLICE_TRACKER.md`
   - `docs/XCLAW_BUILD_ROADMAP.md`
   - `docs/XCLAW_SOURCE_OF_TRUTH.md`

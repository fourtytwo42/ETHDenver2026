# X-Claw Context Pack

## 1) Goal
- Primary objective: Complete Slice 06A (Foundation Alignment Backfill) by moving the Next.js web/API runtime to canonical `apps/network-web` before Slice 07 endpoint work.
- Success criteria (testable): canonical app path exists and is active; root scripts (`dev/build/start/lint`) target `apps/network-web`; root legacy `src/` and `public/` are removed.
- Non-goals: Slice 07 API endpoint implementation, auth/business logic changes, schema/migration changes, dependency additions.

## 2) Constraints
- Strict slice order: Slice 06A only.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md` and aligned tracker/roadmap updates in same change.
- Runtime separation must remain explicit: Node/Next.js for server/web and Python-first for agent runtime.
- Keep diffs reviewable and avoid opportunistic refactors.

## 3) Contract Impact
- Public API routes affected: none (path/location alignment only).
- Schema files affected: none.
- Migration files affected: none.
- Source-of-truth sections affected: dependency-ordered slice sequence and issue mapping (adding Slice 06A prerequisite).
- Breaking runtime behavior expected: no API behavior changes; CLI script targets change to canonical app path.

## 4) Files and Boundaries
- Expected touched files list:
  - `apps/network-web/src/**`
  - `apps/network-web/public/**`
  - `apps/network-web/next.config.ts`
  - `apps/network-web/next-env.d.ts`
  - `apps/network-web/tsconfig.json`
  - `package.json`
  - `tsconfig.json`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
- Forbidden scope:
  - Slice 07 endpoint code and auth logic
  - `docs/api/openapi.v1.yaml`
  - `infrastructure/migrations/*`
  - `apps/agent-runtime/*` implementation changes

## 5) Invariants (Must Not Change)
- API contract behavior remains unchanged.
- Agent runtime command surface and Python-first execution path remain unchanged.
- No new dependency or workspace model introduced.

## 6) Verification Plan
- Required gates:
  - `source ~/.nvm/nvm.sh && npm run db:parity`
  - `source ~/.nvm/nvm.sh && npm run seed:reset`
  - `source ~/.nvm/nvm.sh && npm run seed:load`
  - `source ~/.nvm/nvm.sh && npm run seed:verify`
  - `source ~/.nvm/nvm.sh && npm run build`
- Slice-specific checks:
  - `source ~/.nvm/nvm.sh && timeout 25s npm run dev -- --port 3100`
  - `source ~/.nvm/nvm.sh && timeout 25s npm run start -- --port 3101`
  - `test -d apps/network-web/src/app`
  - `test ! -d src`
  - `test ! -d public`
  - `apps/agent-runtime/bin/xclaw-agent status --json`
- Expected outcomes:
  - all commands exit 0 (except timeout returns 124 after successful startup log validation)
  - build/start/dev use canonical app directory
  - runtime boundary remains intact.

## 7) Evidence
- Record in `acceptance.md`:
  - command outputs and exit codes,
  - structural verification evidence,
  - tracker/roadmap/source-of-truth synchronization,
  - issue linkage to `#18`,
  - rollback plan and high-risk review note.

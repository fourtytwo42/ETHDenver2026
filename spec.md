# Slice 06A Spec: Foundation Alignment Backfill (`apps/network-web`)

## Goal
Complete Slice 06A by moving the web/API Next.js runtime to canonical `apps/network-web` and aligning scripts/tooling/docs before Slice 07.

## Success Criteria
1. Canonical app path exists at `apps/network-web` and is active.
2. Root scripts (`dev`, `build`, `start`, `lint`) target `apps/network-web`.
3. Root legacy `src/` and `public/` paths are removed.
4. Source-of-truth, roadmap, tracker, and process artifacts are synchronized for Slice 06A.
5. Required validations pass and evidence is captured in `acceptance.md`.

## Non-Goals
1. Slice 07 API endpoint implementation.
2. Any auth/session/business logic implementation.
3. API/schema/migration contract modifications.

## Constraints
1. Strict slice sequencing: complete 06A before Slice 07.
2. Preserve Node/web vs Python/agent runtime boundary.
3. Do not add dependencies or workspace toolchain changes.
4. Keep app behavior baseline equivalent after path migration.

## Locked Decisions
1. Canonical web/API location is `apps/network-web`.
2. Root scripts will call Next CLI with directory argument (`apps/network-web`).
3. Slice 06A GitHub evidence issue is `#18`.
4. `docs/XCLAW_SOURCE_OF_TRUTH.md` issue mapping and sequence include Slice 06A.

## Acceptance Checks
1. `source ~/.nvm/nvm.sh && npm run db:parity`
2. `source ~/.nvm/nvm.sh && npm run seed:reset`
3. `source ~/.nvm/nvm.sh && npm run seed:load`
4. `source ~/.nvm/nvm.sh && npm run seed:verify`
5. `source ~/.nvm/nvm.sh && npm run build`
6. `source ~/.nvm/nvm.sh && timeout 25s npm run dev -- --port 3100`
7. `source ~/.nvm/nvm.sh && timeout 25s npm run start -- --port 3101`
8. `test -d apps/network-web/src/app`
9. `test ! -d src`
10. `test ! -d public`
11. `apps/agent-runtime/bin/xclaw-agent status --json`

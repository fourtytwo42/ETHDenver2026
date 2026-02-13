# Slice 06A Tasks

Active slice: `Slice 06A: Foundation Alignment Backfill (Post-06 Prereq)`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Update `docs/CONTEXT_PACK.md`, `spec.md`, and `tasks.md` for Slice 06A scope.
- [x] Create canonical web app root `apps/network-web`.
- [x] Move root `src/` to `apps/network-web/src/`.
- [x] Move root `public/` to `apps/network-web/public/`.
- [x] Add app-local Next config/env/tsconfig for directory-mode build.
- [x] Update root scripts to run Next/lint against `apps/network-web`.
- [x] Update root TS path alias to `apps/network-web/src/*`.
- [x] Verify no remaining dependency on root legacy app paths.
- [x] Synchronize source-of-truth sequence/issue mapping for Slice 06A.
- [x] Synchronize roadmap execution order to include Slice 06A prerequisite.
- [x] Run required global validation gates.
- [x] Run slice-specific structural checks (`dev`, `start`, path assertions, agent smoke).
- [x] Update tracker Slice 06A to complete only after validations pass.
- [x] Append acceptance evidence and rollback/high-risk notes.
- [x] Create/link GitHub issue `#18`, commit, push, and post verification evidence + commit hash.

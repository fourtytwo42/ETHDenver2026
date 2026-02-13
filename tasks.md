# Slice 07 Tasks

Active slice: `Slice 07: Core API Vertical Slice`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Add server runtime primitives for env, db, redis, request-id, auth, idempotency, errors, and validation.
- [x] Add JSON schema artifacts for Slice 07 request validation.
- [x] Implement core write routes for register/heartbeat/trade-proposed/trade-status/events.
- [x] Implement public read routes for leaderboard/agents/profile/trades/activity.
- [x] Enforce bearer + idempotency baseline on write routes.
- [x] Enforce canonical error shape and trade-transition validation.
- [x] Update OpenAPI and source-of-truth artifacts touched by Slice 07 contract changes.
- [x] Run required global validation gates.
- [x] Run API curl matrix including negative-path checks.
- [x] Update process artifacts (`docs/CONTEXT_PACK.md`, `spec.md`, `tasks.md`, `acceptance.md`).
- [x] Mark Slice 07 complete in tracker/roadmap only after DB-backed positive API verification is fully unblocked.
- [ ] Post final verification evidence + commit hash to issue `#7`.

# Slice 14 Tasks

Active slice: `Slice 14: Observability + Ops`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Implement canonical health/status routes and `/api/v1` aliases.
- [x] Implement ops health aggregation utility (dependency, provider, heartbeat, queue views).
- [x] Implement ops alerts utility (structured logs, incident categories, transition alerts, webhook dispatch).
- [x] Implement Redis-backed per-minute rate limiter utility.
- [x] Enforce public read rate limits on all `/api/v1/public/*` routes and `/api/status` path.
- [x] Enforce sensitive management write limit centrally in management write auth path.
- [x] Implement `/status` diagnostics page aligned with `/api/status`.
- [x] Add health/status shared JSON schemas.
- [x] Update OpenAPI with health/status routes and `429` coverage.
- [x] Add Postgres backup/restore scripts and runbook.
- [x] Run full required validation gates and capture outputs.
- [x] Capture slice-specific functional/negative checks in acceptance evidence.
- [x] Update source-of-truth/roadmap/tracker status for Slice 14.
- [ ] Commit/push Slice 14 and post evidence + commit hash to issue `#14`.

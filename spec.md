# Slice 14 Spec: Observability + Ops

## Goal
Implement canonical Slice 14 behavior so X-Claw is operable and diagnosable through public-safe diagnostics, enforced rate limits, and recovery runbooks.

## Success Criteria
1. `GET /api/health` and `GET /api/status` are implemented and return contract-compliant payloads.
2. Compatibility aliases `GET /api/v1/health` and `GET /api/v1/status` behave consistently with canonical routes.
3. Public diagnostics page `/status` is implemented and aligned with `/api/status`.
4. Public read rate limits (`120 req/min/IP`) and sensitive management write rate limits (`10 req/min/agent/session`) are enforced with `429 rate_limited` responses.
5. Structured ops logs, incident categories, and webhook alerting on health transitions are active.
6. Nightly Postgres backup path and restore drill runbook/scripts are implemented with evidence.

## Non-Goals
1. Slice 15 Base Sepolia deployment/promotion.
2. Slice 16 release-gate stabilization and post-release monitoring window.
3. New agent-runtime trading behavior changes.

## Locked Decisions
1. Canonical health/status routes are unversioned (`/api/health`, `/api/status`) with compatibility aliases (`/api/v1/health`, `/api/v1/status`).
2. Alerts use a generic webhook target configured by environment variable.
3. Backup automation is VM-native cron + shell scripts.
4. Incident timeline persistence uses Redis capped list in MVP.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-14 matrix:
   - health/status endpoints + alias parity
   - public-safe status diagnostics (no raw RPC URLs)
   - status page rendering for summary/dependencies/providers/incidents
   - public and sensitive-write rate-limit negative checks
   - correlation-id propagation checks
   - alert transition + incident timeline checks
   - backup creation + restore drill checks

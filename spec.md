# Slice 07 Spec: Core API Vertical Slice

## Goal
Implement the first production-shape backend/API surface in `apps/network-web` for core agent writes and public reads.

## Success Criteria
1. Core write endpoints implemented:
   - `POST /api/v1/agent/register`
   - `POST /api/v1/agent/heartbeat`
   - `POST /api/v1/trades/proposed`
   - `POST /api/v1/trades/:tradeId/status`
   - `POST /api/v1/events`
2. Public read endpoints implemented:
   - `GET /api/v1/public/leaderboard`
   - `GET /api/v1/public/agents`
   - `GET /api/v1/public/agents/:agentId`
   - `GET /api/v1/public/agents/:agentId/trades`
   - `GET /api/v1/public/activity`
3. Write auth baseline enforced with bearer + idempotency key.
4. Error payload shape is canonical and consistent.

## Non-Goals
1. Slice 08 management/session/step-up/CSRF route behavior.
2. Off-DEX endpoint implementation.
3. Metrics/leaderboard pipeline hardening beyond minimal read contract.

## Locked Decisions
1. Agent auth baseline uses env map `XCLAW_AGENT_API_KEYS` (`agentId -> apiKey`) for Slice 07.
2. Public reads are DB-only and return empty/404 when data is absent.
3. Trade transition checks follow Source-of-Truth section 27.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. dev-server curl matrix for positive and negative endpoint scenarios.

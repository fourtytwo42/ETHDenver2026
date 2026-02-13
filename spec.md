# Slice 09 Spec: Public Web Vertical Slice

## Goal
Implement the public web vertical slice for `apps/network-web` on `/`, `/agents`, and `/agents/:id` with canonical visibility rules and status/mode semantics.

## Success Criteria
1. `/`, `/agents`, and `/agents/:id` render contract-appropriate public data.
2. Unauthorized users do not see management controls on `/agents/:id`.
3. Mock vs real context is explicitly labeled in leaderboard and trade/profile views.
4. Status badges use only canonical values: `active`, `offline`, `degraded`, `paused`, `deactivated`.
5. Theme system supports dark/light with dark default and browser persistence.
6. Public read API refinements are additive and OpenAPI-synchronized.

## Non-Goals
1. `/status` page implementation (deferred to Slice 14 by doc lock).
2. Authorized management control panels (Slice 10).
3. `/api/status` and observability endpoint implementation (Slice 14).

## Locked Decisions
1. `/status` remains visible in global nav but route implementation is deferred until Slice 14.
2. No dependency additions for Slice 09.
3. Public API query extensions are allowlisted and fail closed on invalid sort/status.
4. Existing management bootstrap token-strip behavior on `/agents/:id?token=...` remains active.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-09 curl/browser checks for dashboard render, agents API positive+negative behavior, and public profile visibility.

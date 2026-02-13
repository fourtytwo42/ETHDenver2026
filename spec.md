# Slice 08 Spec: Auth + Management Vertical Slice

## Goal
Implement management session bootstrap, step-up auth, revoke-all rotation, and CSRF/cookie enforcement for `apps/network-web`.

## Success Criteria
1. `POST /api/v1/management/session/bootstrap` validates token and issues management + CSRF cookies.
2. `POST /api/v1/management/stepup/challenge` requires management session + CSRF and returns one-time code.
3. `POST /api/v1/management/stepup/verify` requires management session + CSRF and issues step-up cookie.
4. `POST /api/v1/management/revoke-all` revokes sessions in locked order and rotates management token.
5. `/agents/:id?token=...` bootstrap path validates token then strips token from URL.

## Non-Goals
1. Public profile/data UX for Slice 09.
2. Management control panels for Slice 10.
3. Off-DEX and copy endpoint implementation.

## Locked Decisions
1. Management token source is DB-only (`management_tokens`) via fingerprint lookup.
2. Step-up challenge code is returned once in challenge response for MVP/manual testing.
3. Revoke-all rotates active management token and returns the new plaintext token once.
4. Sensitive-cookie `Secure` is enforced except localhost/127.0.0.1 local dev path.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-8 curl/browser matrix for bootstrap, csrf, step-up, revoke-all, and token stripping.

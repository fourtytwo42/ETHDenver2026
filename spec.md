# Slice 10 Spec: Management UI Vertical Slice

## Goal
Implement the canonical authorized management vertical slice on `/agents/:id` so authorized users can manage one agent end-to-end without violating source-of-truth scope boundaries.

## Success Criteria
1. Authorized management controls are available on `/agents/:id` for:
   - approval queue actions
   - policy controls + pause/resume
   - withdraw destination + withdraw initiation with step-up
   - off-DEX settlement queue controls (queue/state transitions only)
   - audit log panel
2. Global header shows managed-agent dropdown + logout behavior for authenticated sessions.
3. Unauthorized viewers only see public profile sections.
4. Sensitive writes enforce management + CSRF + step-up where required.
5. Canonical docs/contracts are synchronized for Slice 10 endpoint and UI additions.

## Non-Goals
1. Agent-runtime escrow execution and settlement adapters (Slice 12).
2. Hardhat local trading-path validation (Slice 11).
3. Platform-wide pause/kill-switch (out of scope).

## Locked Decisions
1. Scope source is canonical docs (`XCLAW_SOURCE_OF_TRUTH.md` + tracker/roadmap), not legacy issue text.
2. Off-DEX in Slice 10 is management queue/state controls only.
3. Withdraw in Slice 10 is control-plane + audited request path requiring step-up.
4. Existing DB schema is used; no migration unless implementation proves unavoidable.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-10 curl/browser matrix for positive and negative auth/step-up/transition paths.

# Slice 03 Spec: Agent Runtime CLI Scaffold (Done-Path Ready)

## Goal
Complete Slice 03 by making the Python-first runtime command scaffold operationally callable end-to-end through `xclaw-agent` and `xclaw_agent_skill.py` with stable JSON responses and validation errors.

## Success Criteria
1. All required wallet commands are callable on runtime CLI command surface.
2. Wrapper delegates to runtime reliably without PATH-only dependency on `xclaw-agent`.
3. Invalid wallet inputs return structured JSON errors with stable fields.
4. Slice 03 roadmap and tracker statuses are synchronized in the same change.
5. Required repo validation commands pass.

## Non-Goals
1. Real wallet lifecycle implementation (`wallet-create`, `wallet-import`, etc.) beyond scaffold behavior.
2. Trading/off-DEX execution implementation.
3. Contract/migration changes outside Slice 03 scope.

## Constraints
1. Strict slice sequencing: Slice 03 only.
2. Preserve Python-first runtime boundary.
3. No dependency additions.

## Locked Decisions
1. Wallet real operations remain deferred to Slice 04+.
2. Existing command names remain unchanged.
3. Runtime JSON errors from delegated CLI are passed through by wrapper when parseable.
4. Wrapper binary lookup order is PATH first, repo-local launcher second.

## Acceptance Checks
1. `source ~/.nvm/nvm.sh && nvm use --silent default`
2. `npm run db:parity`
3. `npm run seed:reset`
4. `npm run seed:load`
5. `npm run seed:verify`
6. `npm run build`
7. Runtime wallet command matrix commands all execute and return JSON.
8. Wrapper wallet smoke commands execute and return delegated JSON.
9. Negative checks produce `invalid_input` with exit code `2`:
   - `wallet-send bad 1`
   - `wallet-send <valid_address> abc`
   - `wallet-sign-challenge ""`
   - `wallet-token-balance bad`

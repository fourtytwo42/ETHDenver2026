# Slice 17 Spec: Deposits + Agent-Local Limit Orders

## Goal
Ship self-custody deposit visibility and agent-local limit-order execution with offline replay semantics.

## Success Criteria
1. `GET /api/v1/management/deposit` returns addresses, balances, recent deposits, and sync status.
2. Management limit-order APIs are live: create/list/cancel.
3. Agent limit-order APIs are live: pending/read + status writeback.
4. Agent runtime implements `limit-orders sync|status|run-once|run-loop` and local outbox replay.
5. `/agents/:id` management rail exposes deposit and limit-order controls.
6. Extended `infrastructure/scripts/e2e-full-pass.sh` validates deposit + limit-order + API-outage replay.

## Non-Goals
1. Partial-fill order model.
2. Custodial deposit transfer API.
3. Additional chain onboarding beyond configured chains.

## Locked Decisions
1. Deposit model is self-custody address + tracking.
2. Deposit confirmations are server-polled from chain RPC.
3. Limit orders are authored via management API/UI and executed locally by agent runtime.
4. Trigger model is simple IOC.
5. Runtime boundary remains Node/Next.js for web/API and Python-first for agent runtime.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`
- `npm run e2e:full`
- `XCLAW_E2E_SIMULATE_API_OUTAGE=1 npm run e2e:full`

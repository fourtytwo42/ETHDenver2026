# Slice 20 Spec: Owner Link + Outbound Transfer Policy + Agent Limit-Order UX + Mock-Only Reporting

## Goal
Ship Slice 20 as an agent-ops upgrade: owner-link issuance, outbound transfer policy gates, simplified agent limit-order command surface, and mock-only runtime reporting to `/events`.

## Success Criteria
1. `POST /api/v1/agent/management-link` issues short-lived one-time owner URLs.
2. `GET /api/v1/agent/transfers/policy` returns effective outbound transfer policy for runtime enforcement.
3. Runtime outbound commands (`wallet-send`, `wallet-send-token`) enforce owner transfer policy.
4. Agent limit-order APIs support `create/list/cancel` with auth ownership checks and max-10 open cap per agent+chain.
5. Runtime `trade execute` auto-reports only mock trades; real mode skips `/events`.
6. `/agents/:id` shows Owner Link panel and Outbound Transfers controls.

## Non-Goals
1. Multi-room chat or DM expansion.
2. Automated strategy orchestration changes beyond command/API surface updates.
3. On-chain escrow reintroduction.

## Locked Decisions
1. Reporting to `/events` is mock-only from runtime.
2. Owner-link issuance is agent-auth and tokenized as short-lived one-time URL.
3. Outbound transfer policy modes are `disabled`, `allow_all`, `whitelist`.
4. Limit-order UX for agents is `create`, `cancel`, `list`, `run-loop`.
5. Open limit-order cap is 10 per agent+chain.

## Acceptance Checks
- `npm run db:parity`
- `npm run db:migrate`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`

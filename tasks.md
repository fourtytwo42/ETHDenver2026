# Slice 20 Tasks

Active slice: `Slice 20: Owner Link + Outbound Transfer Policy + Agent Limit-Order UX + Mock-Only Reporting`

## Checklist
- [x] Add Slice 20 entries to tracker, roadmap, and source-of-truth issue mapping/contracts.
- [x] Add migration `0007_slice20_owner_links_transfer_policy_agent_limit_orders.sql`.
- [x] Update migration parity checker + checklist for transfer-policy table/index/enum.
- [x] Add shared schemas for owner-link and agent limit-order create/cancel payloads.
- [x] Add `POST /api/v1/agent/management-link` route.
- [x] Add `GET /api/v1/agent/transfers/policy` route.
- [x] Add `POST/GET /api/v1/limit-orders` and `POST /api/v1/limit-orders/{orderId}/cancel` agent routes.
- [x] Extend `POST /api/v1/management/policy/update` with outbound transfer fields + step-up enforcement.
- [x] Extend `GET /api/v1/management/agent-state` with outbound transfer policy payload.
- [x] Add `/agents/:id` Owner Link panel and Outbound Transfers controls.
- [x] Update runtime: mock-only reporting, owner-link command, wallet-send-token, policy-gated outbound sends.
- [x] Add agent faucet request endpoint/command (`0.05 ETH`) with once-per-UTC-day limiter.
- [x] Update runtime limit-order command surface to create/cancel/list/run-loop.
- [x] Update skill wrapper + skill docs command contract.
- [x] Update OpenAPI with Slice 20 endpoints/schemas and policy schema extensions.
- [ ] Run required gates and capture evidence in `acceptance.md`.
- [ ] Post completion evidence + commit hash to GitHub issue `#20`.

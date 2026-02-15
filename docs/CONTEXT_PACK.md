# X-Claw Context Pack

## 1) Goal (Active: Slice 32)
- Primary objective: complete `Slice 32: Per-Agent Chain Enable/Disable (Owner-Gated, Chain-Scoped Ops)`.
- Success criteria:
  - owner can enable/disable chain access per agent + per chain from `/agents/:id`
  - when disabled, agent runtime blocks trade and `wallet-send` actions with `code=chain_disabled`
  - server rejects trade/limit-order execution paths on disabled chains with structured policy errors
  - enabling chain requires step-up; disabling does not
  - source-of-truth + canonical docs remain synchronized (schemas/openapi/tracker/roadmap)
  - required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`

## 2) Constraints
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Strict slice order: Slice 32 follows completed Slice 31.
- One-site model remains fixed (`/agents/:id` public + auth-gated management).
- No dependency additions.
- Migration is required for this slice (`agent_chain_policies`).

## 3) Contract Impact
- Management write addition:
  - `POST /api/v1/management/chains/update`
- Management read change (backward compatible):
  - `GET /api/v1/management/agent-state` adds optional `chainKey`
- Agent policy read change:
  - `GET /api/v1/agent/transfers/policy` adds `chainEnabled` fields
- No auth model changes.

## 4) Files and Boundaries (Slice 32 allowlist)
- Web/API/UI:
  - `apps/network-web/src/app/api/v1/management/chains/update/route.ts`
  - `apps/network-web/src/app/api/v1/management/agent-state/route.ts`
  - `apps/network-web/src/app/api/v1/agent/transfers/policy/route.ts`
  - `apps/network-web/src/app/api/v1/trades/proposed/route.ts`
  - `apps/network-web/src/app/api/v1/trades/[tradeId]/status/route.ts`
  - `apps/network-web/src/app/api/v1/limit-orders/route.ts`
  - `apps/network-web/src/app/api/v1/limit-orders/[orderId]/status/route.ts`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
- Canonical docs/process:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/api/openapi.v1.yaml`
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Data model:
  - `infrastructure/migrations/0009_slice32_agent_chain_enable.sql`
- Shared schemas:
  - `packages/shared-schemas/json/management-chain-update-request.schema.json`

## 5) Invariants
- Status vocabulary remains exactly: `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Authorized management controls remain owner/session-gated only.
- Dark/light themes remain supported with dark default.
- Existing management functionality remains available (pause/resume, policy, approvals, limit orders, withdraw, audit).

## 6) Verification Plan
- Required gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Feature checks:
  - `/agents/:id` chain access toggle persists per chain and defaults to enabled when unset
  - trade propose is rejected when chain is disabled (`code=chain_disabled`)
  - limit-order create/fill is rejected when chain is disabled
  - runtime rejects trade + wallet-send when `chainEnabled == false` in policy payload

## 7) Evidence + Rollback
- Capture command outputs and UX evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 32 touched files only,
  2. rerun required gates,
  3. confirm chain access toggle disappears and trade paths no longer consult owner chain policy.

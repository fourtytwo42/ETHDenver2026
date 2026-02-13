# X-Claw Context Pack

## 1) Goal
- Primary objective: complete `Slice 17: Deposits + Agent-Local Limit Orders` after closing Slice 16.
- Success criteria: working management deposit flow, management-authored limit orders executed locally by agent, outage replay proof, and synchronized canonical artifacts.

## 2) Constraints
- Strict slice order: Slice 16 closed first, then Slice 17 implementation.
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Runtime boundary: Node/Next.js for web/API, Python-first for agent/OpenClaw runtime.
- No dependency additions without explicit justification.

## 3) Contract Impact
- OpenAPI additions for deposit and limit-order endpoints.
- Shared schema additions for deposit/limit-order request/response contracts.
- Data-model migration adds deposit + limit-order persistence tables.

## 4) Files and Boundaries
- API/routes:
  - `apps/network-web/src/app/api/v1/management/deposit/route.ts`
  - `apps/network-web/src/app/api/v1/management/limit-orders/route.ts`
  - `apps/network-web/src/app/api/v1/management/limit-orders/[orderId]/cancel/route.ts`
  - `apps/network-web/src/app/api/v1/limit-orders/pending/route.ts`
  - `apps/network-web/src/app/api/v1/limit-orders/[orderId]/status/route.ts`
- Runtime:
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `skills/xclaw-agent/scripts/xclaw_agent_skill.py`
- Contracts/data:
  - `infrastructure/migrations/0003_slice17_deposit_limit_orders.sql`
  - `packages/shared-schemas/json/*.schema.json` (new limit/deposit schemas)
  - `docs/api/openapi.v1.yaml`
- UX/e2e:
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `infrastructure/scripts/e2e-full-pass.sh`

## 5) Invariants
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, `requestId`.
- Canonical status vocabulary remains exactly `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Agent key custody remains local-only.

## 6) Verification Plan
- Global gates: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`.
- Runtime tests: `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`.
- E2E checks:
  - `npm run e2e:full`
  - `XCLAW_E2E_SIMULATE_API_OUTAGE=1 npm run e2e:full`

## 7) Evidence + Rollback
- Capture route/runtime/e2e outputs in `acceptance.md`.
- Rollback plan:
  1. revert Slice 17 touched files only,
  2. rerun global gates,
  3. confirm tracker/roadmap/source-of-truth consistency.

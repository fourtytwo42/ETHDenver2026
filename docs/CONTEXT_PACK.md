# X-Claw Context Pack

## 1) Goal (Active: Slice 33)
- Primary objective: complete `Slice 33: MetaMask-Like Agent Wallet UX + Simplified Approvals (Global + Per-Token)`.
- Success criteria:
  - `/agents/:id` is wallet-first (MetaMask-like header + assets + unified activity feed)
  - approvals are simplified:
    - Global Approval toggle (`approval_mode=auto|per_trade`)
    - per-token preapproval toggles stored in `allowed_tokens` and evaluated on `tokenIn` only
    - pair approvals removed from UI and active product behavior
  - `POST /api/v1/trades/proposed` sets initial status to `approved|approval_pending` using global/tokenIn preapproval policy
  - runtime `trade spot` is server-first (propose -> wait if pending -> execute only if approved; denial surfaces reason)
  - source-of-truth + canonical docs remain synchronized (schemas/openapi/tracker/roadmap)
  - required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`

## 2) Constraints
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Strict slice order: Slice 33 follows completed Slice 32.
- One-site model remains fixed (`/agents/:id` public + auth-gated management).
- No dependency additions.
- No DB migration required for this slice (reuse policy snapshot fields).

## 3) Contract Impact
- Trade write change:
  - `POST /api/v1/trades/proposed` returns initial status `approved|approval_pending` and persists that status.
- Management behavior change:
  - `POST /api/v1/management/approvals/scope` is deprecated and must not be used by UI (pair/global scopes removed from product surface).
- Runtime behavior change:
  - `trade spot` becomes server-first with propose->approve->execute behavior.
- No auth model changes.

## 4) Files and Boundaries (Slice 33 allowlist)
- Web/API/UI:
  - `apps/network-web/src/app/api/v1/trades/proposed/route.ts`
  - `apps/network-web/src/lib/copy-lifecycle.ts`
  - `apps/network-web/src/app/api/v1/management/approvals/scope/route.ts`
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
- Runtime:
  - `apps/agent-runtime/xclaw_agent/cli.py`
- Shared schemas (docs-only adjustments expected):
  - `packages/shared-schemas/json/management-policy-update-request.schema.json`

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
  - `POST /api/v1/trades/proposed` returns `status=approved` when Global Approval is ON
  - `POST /api/v1/trades/proposed` returns `status=approval_pending` when Global OFF and tokenIn is not preapproved
  - `/agents/:id` shows approvals queue and can approve/reject with a rejection reason message
  - runtime `trade spot` does not execute on-chain when server returns `approval_pending`
  - runtime `trade spot` executes only after management approves, and surfaces reason on reject

## 7) Evidence + Rollback
- Capture command outputs and UX evidence in `acceptance.md`.
- Rollback plan:
  1. revert Slice 33 touched files only,
  2. rerun required gates,
  3. confirm `trade spot` returns to direct on-chain mode and `/agents/:id` policy/approval UI returns to pre-slice behavior.

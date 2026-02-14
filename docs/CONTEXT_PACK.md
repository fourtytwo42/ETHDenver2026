# X-Claw Context Pack

## 1) Goal (Active: Slice 25)
- Primary objective: complete `Slice 25: Agent Skill UX Upgrade (Security + Reliability + Contract Fixes)`.
- Success criteria:
  - owner-link is safe-by-default (sensitive fields redacted unless explicitly opted-in)
  - faucet response is pending-aware and provides next-step guidance
  - limit-orders-create does not fail schema validation due to `expiresAt: null`
  - docs/artifacts remain synchronized (source-of-truth + tracker + roadmap + skill docs)

## 2) Constraints
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Strict slice order: Slice 25 only (no cross-slice opportunistic work).
- Runtime boundary: Node/Next.js for web/API, Python-first for agent/OpenClaw runtime.
- No new dependencies without explicit justification.
- Security-first: treat stdout as loggable; do not emit secrets/tokens by default.

## 3) Contract Impact
- Skill wrapper output hardening:
  - if response includes `sensitive=true` and `sensitiveFields`, wrapper must redact those fields by default.
- Agent runtime output additions:
  - faucet includes `pending`, `recommendedDelaySec`, `nextAction`.
- Limit orders: payload shape remains per existing schema; fix is to omit `expiresAt` when not provided.

## 4) Files and Boundaries (Slice 25 allowlist)
- Source-of-truth + slice process:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/CONTEXT_PACK.md`
- Skill wrapper:
  - `skills/xclaw-agent/scripts/xclaw_agent_skill.py`
  - `skills/xclaw-agent/SKILL.md`
- Runtime + tests:
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_trade_path.py`
- API (copy-only string change for UX hint):
  - `apps/network-web/src/app/api/v1/limit-orders/route.ts`

## 5) Invariants
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, and preserve `requestId` when provided by API.
- Canonical status vocabulary remains exactly `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Agent key custody remains local-only.

## 6) Verification Plan
- Global gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Runtime tests:
  - `python3 -m pytest apps/agent-runtime/tests` (preferred)
  - fallback: `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`
- Manual evidence (worksheets):
  - A (status/wallet identity)
  - C (faucet pending guidance + delayed dashboard check)
  - F (limit-orders-create)
  - H (owner-link redaction)

## 7) Evidence + Rollback
- Capture outputs and command evidence in `acceptance.md` (Slice 25 section).
- Rollback plan:
  1. revert Slice 25 touched files only,
  2. rerun global gates + runtime tests,
  3. confirm tracker/roadmap/source-of-truth consistency.

---

## Archive (Prior Context Packs)
- Slice 17 context pack content was superseded by Slice 25 and is intentionally removed from the active section above.

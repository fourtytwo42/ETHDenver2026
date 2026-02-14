# X-Claw Context Pack

## 1) Goal (Active: Slice 26)
- Primary objective: complete `Slice 26: Agent Skill Robustness Hardening (Timeouts + Identity + Single-JSON)`.
- Success criteria:
  - wrapper never hangs by default (timeout + structured JSON error)
  - runtime cast/RPC calls have timeouts and actionable timeout errors
  - `status` returns `agentName` best-effort (identity completeness)
  - `wallet-health` always includes `nextAction`/`actionHint`
  - faucet rate-limit responses are schedulable (`retryAfterSec`)
  - `limit-orders-run-loop` returns a single JSON object per invocation
  - trade-spot gas cost fields include exact numeric ETH (plus pretty)
  - docs/artifacts remain synchronized (source-of-truth + tracker + roadmap + contract docs + skill docs)

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

## 4) Files and Boundaries (Slice 26 allowlist)
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
- Contract docs:
  - `docs/api/WALLET_COMMAND_CONTRACT.md`

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
  - `python3 -m unittest -q`
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

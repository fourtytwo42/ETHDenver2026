# X-Claw Context Pack

## 1) Goal
- Primary objective: Complete Slice 06 (Wallet Spend Ops) by implementing runtime spend operations (`wallet-send`, `wallet-balance`, `wallet-token-balance`) and enforcing fail-closed policy preconditions before spend.
- Success criteria (testable): spend and balance commands return deterministic JSON; spend is blocked when policy preconditions fail; wallet-remove cleanup behavior remains correct with portable wallet mapping.
- Non-goals (explicitly out of scope): server/web auth endpoints, trade/off-DEX runtime loops, full approval engine and USD policy pipeline beyond Slice 06 guardrails.

## 2) Constraints
- Python-first agent runtime boundary remains intact (no Node wallet libraries in runtime/skill path).
- `cast` is canonical backend for send and balance operations.
- Command surface and JSON envelope remain canonical and backward-compatible.
- Single-slice scope: Slice 06 only.
- Spend-cap enforcement in this slice uses provisional native-wei cap (`max_daily_native_wei`) with explicit documentation note.

## 3) Contract Impact
- Public API routes affected: none.
- Schema files affected: none.
- Migration files affected: none.
- Source-of-truth sections affected: wallet spend command implementation status and provisional local spend-cap precondition model.
- Breaking change expected? No.

## 4) Files and Boundaries
- Expected touched files list:
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_wallet_core.py`
  - `apps/agent-runtime/README.md`
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
- Forbidden files/areas for this change: OpenAPI, DB migrations, server/web API behavior, Slice 07+ runtime command implementations.
- New dependencies required? No (unless runtime implementation proves unavoidable).

## 5) Invariants (Must Not Change)
- Private keys remain local and never emitted.
- No persistent plaintext secret material.
- Wrapper/runtime command names remain canonical.
- Structured JSON error contract remains `ok/code/message` with optional `actionHint`/`details`.

## 6) Verification Plan
- Commands to run:
  - `PATH="$HOME/.foundry/bin:$PATH" python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v`
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
  - runtime wallet spend/balance command matrix including policy-failure checks
- Expected outputs:
  - tests pass;
  - required npm gates exit 0;
  - send/balance/token-balance success paths return deterministic JSON payloads;
  - policy precondition failures return deterministic structured error codes.
- Rollback plan:
  - revert only Slice 06 touched files,
  - rerun validation matrix,
  - confirm tracker/roadmap/doc sync restored.

## 7) Evidence
- Record in `acceptance.md`:
  - verification command outcomes + exit codes,
  - send/balance/token-balance success and failure-path JSON evidence,
  - policy-blocked spend evidence,
  - tracker/roadmap status synchronization,
  - high-risk second-pass note and rollback steps,
  - issue mapping evidence for `#6`.

# X-Claw Context Pack

## 1) Goal
- Primary objective: Complete Slice 05 (Wallet Auth + Signing) by implementing `wallet-sign-challenge` with EIP-191 signing through `cast`.
- Success criteria (testable): runtime returns deterministic JSON for success/failure; canonical challenge format is validated; signature output is present on success; negative paths are covered by tests.
- Non-goals (explicitly out of scope): Slice 06 wallet spend/balance/remove runtime completion, server/web auth endpoints, trade/off-DEX runtime loops.

## 2) Constraints
- Python-first agent runtime boundary remains intact (no Node wallet libraries in runtime/skill path).
- `cast` is canonical signer backend for this slice.
- Command surface and JSON envelope remain canonical and backward-compatible.
- Single-slice scope: Slice 05 only.

## 3) Contract Impact
- Public API routes affected: none.
- Schema files affected: none.
- Migration files affected: none.
- Source-of-truth sections affected: behavior alignment to locked signing requirements (EIP-191 challenge flow and challenge content expectations).
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
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
- Forbidden files/areas for this change: OpenAPI, DB migrations, server/web API behavior, Slice 06+ runtime command implementations.
- New dependencies required? No.

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
  - runtime `wallet sign-challenge` success/negative CLI checks
- Expected outputs:
  - tests pass;
  - required npm gates exit 0;
  - signing success returns valid hex signature and scheme metadata;
  - invalid challenge inputs are rejected with deterministic codes.
- Rollback plan:
  - revert only Slice 05 touched files,
  - rerun validation matrix,
  - confirm tracker/roadmap/doc sync restored.

## 7) Evidence
- Record in `acceptance.md`:
  - verification command outcomes + exit codes,
  - signing success and failure-path JSON evidence,
  - tracker/roadmap status synchronization,
  - high-risk second-pass note and rollback steps,
  - issue mapping evidence for `#5`.

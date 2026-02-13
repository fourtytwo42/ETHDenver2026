# X-Claw Context Pack

## 1) Goal
- Primary objective: Complete Slice 04 (Wallet Core) by implementing real local wallet lifecycle for `wallet-create`, `wallet-import`, `wallet-address`, and `wallet-health` with encrypted-at-rest storage.
- Success criteria (testable): wallet create/import/address/health commands work via runtime CLI and wrapper contract; wallet files are encrypted with Argon2id + AES-256-GCM; non-interactive import/create is rejected; no persistent plaintext key/password artifacts.
- Non-goals (explicitly out of scope): challenge signing (Slice 05), spend/balance/remove hardening (Slice 06), trade/off-DEX runtime execution loops.

## 2) Constraints
- Stack/framework/version constraints: Python-first runtime boundary remains intact; no Node dependency added for wallet operations.
- Compatibility constraints: canonical command names and JSON envelope remain unchanged.
- Time/scope constraints: single-slice execution (Slice 04 only) after pre-step checkpoint.

## 3) Contract Impact
- Public API routes affected: none.
- Schema files affected: none.
- Migration files affected: none.
- Source-of-truth sections affected: Section 23 + Section 24 behavior alignment only (no contract expansion).
- Breaking change expected? (Yes/No): No command-surface break.

## 4) Files and Boundaries
- Expected touched files list:
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/README.md`
  - `apps/agent-runtime/requirements.txt`
  - `apps/agent-runtime/tests/test_wallet_core.py`
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
- Forbidden files/areas for this change: OpenAPI, DB migrations, trade/off-DEX runtime behavior, server/web runtime behavior.
- New dependencies required? (Yes/No + justification): Yes. Add pinned `argon2-cffi` for Argon2id KDF and `pycryptodome` for Keccak-256 address derivation.

## 5) Invariants (Must Not Change)
- Invariant 1: Private keys remain local and never emitted to stdout/stderr/logs.
- Invariant 2: No plaintext password/private-key persistence.
- Invariant 3: Wrapper/runtime command names remain canonical.
- Invariant 4: `wallet-create` and `wallet-import` fail closed in non-interactive mode.

## 6) Verification Plan
- Commands to run:
  - `python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v`
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
  - runtime wallet core checks (create/address/health/import)
  - negative checks (non-interactive create/import, malformed wallet payload, unsafe permissions)
- Expected outputs:
  - tests pass;
  - required npm gates exit 0;
  - wallet core commands return structured JSON;
  - security negative checks return deterministic rejection codes.
- Rollback plan:
  - revert only Slice 04 touched files,
  - rerun required gates + wallet command checks,
  - confirm tracker/roadmap/doc sync restored.

## 7) Evidence
- Artifacts/logs captured in `acceptance.md`:
  - pre-step checkpoint commit/push reference,
  - required command outputs and exit codes,
  - wallet security negative-path evidence,
  - roadmap + tracker status sync,
  - high-risk review note and rollback steps.

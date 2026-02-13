# X-Claw Context Pack

## 1) Goal
- Primary objective: Complete Slice 03 (Agent Runtime CLI Scaffold) by ensuring wallet command routing is callable via runtime and Python wrapper with structured JSON behavior.
- Success criteria (testable): all wallet routes callable; wrapper delegates without command-not-found in repo-local setup; invalid inputs return structured JSON errors.
- Non-goals (explicitly out of scope): real wallet lifecycle implementation (Slice 04), signing implementation (Slice 05), spend/balance implementation (Slice 06), and trading/off-DEX runtime logic.

## 2) Constraints
- Stack/framework/version constraints: Node/Next.js concerns remain in server/web runtime; agent/OpenClaw runtime remains Python-first.
- Compatibility constraints: preserve canonical command names and JSON error envelope.
- Time/scope constraints: single-slice execution (Slice 03 only).

## 3) Contract Impact
- Public API routes affected: none.
- Schema files affected: none.
- Migration files affected: none.
- Source-of-truth sections affected: none (implementation aligns to locked Section 24 command/runtime boundary).
- Breaking change expected? (Yes/No): No command-surface break; behavior refinement only.

## 4) Files and Boundaries
- Expected touched files list:
  - `docs/CONTEXT_PACK.md`
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `skills/xclaw-agent/scripts/xclaw_agent_skill.py`
  - `apps/agent-runtime/README.md`
  - `docs/api/WALLET_COMMAND_CONTRACT.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
- Forbidden files/areas for this change: chain configs, migrations, OpenAPI, business logic for trade/off-DEX/wallet real operations.
- New dependencies required? (Yes/No + justification): No.

## 5) Invariants (Must Not Change)
- Invariant 1: Do not implement real wallet create/import/sign/send/balance behavior in this slice.
- Invariant 2: No command may expose private key/seed/password material.
- Invariant 3: Runtime and wrapper command names remain canonical.

## 6) Verification Plan
- Commands to run:
  - `source ~/.nvm/nvm.sh && nvm use --silent default`
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
  - direct runtime command matrix for wallet routes
  - wrapper delegation smoke commands with `XCLAW_DEFAULT_CHAIN=base_sepolia`
  - negative input checks for invalid address/amount/token and empty challenge
- Expected outputs:
  - required npm gates exit 0;
  - wallet routes return JSON stdout;
  - scaffolded wallet routes may return `not_implemented` with structured payload;
  - invalid inputs return `ok:false`, `code:invalid_input`, exit code 2.
- Rollback plan:
  - revert only Slice 03 touched files;
  - rerun command matrix and required gates.

## 7) Evidence
- Artifacts/logs captured in `acceptance.md`:
  - required command outputs and exit codes,
  - Slice 03 file-level evidence,
  - roadmap + tracker status sync,
  - high-risk review note and rollback steps.

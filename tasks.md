# Slice 05 Tasks

Active slice: `Slice 05: Wallet Auth + Signing`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice boundary guardrails.
- [x] Install/unblock `cast` runtime dependency.
- [x] Update `docs/CONTEXT_PACK.md`, `spec.md`, and `tasks.md` for Slice 05 scope.
- [x] Implement runtime `wallet-sign-challenge` handler in `apps/agent-runtime/xclaw_agent/cli.py`.
- [x] Enforce canonical challenge shape and TTL validation.
- [x] Implement passphrase retrieval policy for signing (env first, then interactive TTY).
- [x] Integrate cast-backed signing path and signature format validation.
- [x] Add runtime tests for signing success and negative/failure paths.
- [x] Update runtime README and wallet command contract docs for Slice 05 behavior.
- [x] Run required global validation gates from AGENTS instructions.
- [x] Run task-specific wallet-sign challenge command matrix and negative checks.
- [x] Add high-risk review note + rollback plan in acceptance evidence.
- [x] Update Slice 05 status in tracker and active roadmap items in same change.
- [x] Commit, push, and post verification evidence + commit hash to issue `#5`.

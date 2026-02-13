# Slice 04 Tasks

Active slice: `Slice 04: Wallet Core (Create/Import/Address/Health)`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice boundary guardrails.
- [x] Complete pre-step checkpoint: commit+push Slice 03 state and governance rule update.
- [x] Update `docs/CONTEXT_PACK.md`, `spec.md`, and `tasks.md` for Slice 04 scope.
- [x] Implement encrypted wallet storage (Argon2id + AES-256-GCM) in runtime CLI.
- [x] Implement portable wallet chain binding model and address resolution.
- [x] Implement TTY-only `wallet-create` and `wallet-import` flows.
- [x] Upgrade `wallet-health` to real validation (permissions + ciphertext integrity + metadata).
- [x] Add Python tests for encryption/decryption, corruption, permission checks, and CLI behavior paths.
- [x] Add pinned Python dependency manifest for wallet crypto requirements.
- [x] Update runtime README and wallet command contract docs for Slice 04 behavior.
- [x] Run required global validation gates from AGENTS instructions.
- [x] Run runtime wallet command matrix and negative security-path checks.
- [x] Add high-risk review note + rollback plan in acceptance evidence.
- [x] Update Slice 04 status in tracker and active roadmap items in same change.
- [x] Commit and push Slice 04 only after all validations pass.

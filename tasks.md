# Slice 06 Tasks

Active slice: `Slice 06: Wallet Spend Ops (Send + Balance + Token Balance + Remove)`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice boundary guardrails.
- [x] Update `docs/CONTEXT_PACK.md`, `spec.md`, and `tasks.md` for Slice 06 scope.
- [ ] Implement local policy loader for `~/.xclaw-agent/policy.json` with secure-permission and schema checks.
- [ ] Implement `wallet-send` runtime handler with policy precondition guardrails and cast send integration.
- [ ] Implement `wallet-balance` runtime handler with cast balance integration.
- [ ] Implement `wallet-token-balance` runtime handler with cast call integration.
- [ ] Add daily spend ledger accounting in runtime state keyed by UTC date + chain.
- [ ] Add runtime tests for spend/balance success and policy/security failure paths.
- [ ] Add explicit wallet-remove cleanup tests for portable wallet chain unbinding/pruning behavior.
- [ ] Update runtime README and wallet command contract docs for Slice 06 behavior.
- [ ] Update source-of-truth implementation status and provisional cap model note.
- [ ] Run required global validation gates from AGENTS instructions.
- [ ] Run task-specific Hardhat-local-first wallet spend/balance verification matrix.
- [ ] Add high-risk review note + rollback plan in acceptance evidence.
- [ ] Update Slice 06 status in tracker and active roadmap items in same change.
- [ ] Create/assign issue `#6`, commit, push, and post verification evidence + commit hash to issue `#6`.

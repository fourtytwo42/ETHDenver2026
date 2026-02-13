# Slice 16 Tasks

Active slice: `Slice 16: MVP Acceptance + Release Gate`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Run required global validation gates (`db:parity`, seed reset/load/verify, build).
- [x] Run `seed:live-activity` and capture deterministic activity output evidence.
- [x] Capture public visibility evidence (directory/profile/trades/activity endpoints).
- [x] Capture write auth + idempotency negative/positive-path evidence.
- [x] Capture wallet production-layer evidence via Python skill wrapper.
- [x] Capture Base Sepolia real-trade and off-DEX settlement evidence from Slice 15 closure run.
- [ ] Capture screenshot set (`/`, `/agents`, `/agents/:id`). (blocked: headless browser runtime missing system library `libatk-1.0.so.0`)
- [ ] Capture management bootstrap + step-up success-path walkthrough. (blocked: no plaintext management bootstrap token available in this session environment)
- [~] Classify release defects and confirm `critical defects = 0` after blockers are resolved.
- [x] Sync binary acceptance wording across source-of-truth/tracker/roadmap for Linux-hosted web runtime + Python-first agent boundary.
- [ ] Mark Slice 16 complete in tracker/roadmap, commit/push, and post evidence + commit hash to issue `#16`.

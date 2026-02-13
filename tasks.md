# Slice 11 Tasks

Active slice: `Slice 11: Hardhat Local Trading Path`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Reconcile Slice 11 wording between roadmap/tracker/source-of-truth (trade-path subset here; off-DEX/copy deferred).
- [x] Add Hardhat local deployment stack (config + contracts + deploy/verify scripts).
- [x] Update `config/chains/hardhat_local.json` with deployed addresses and verification metadata.
- [x] Add agent-auth endpoints for runtime consumption:
  - [x] `GET /api/v1/trades/pending`
  - [x] `GET /api/v1/trades/{tradeId}`
- [x] Implement runtime CLI handlers for:
  - [x] `intents poll`
  - [x] `approvals check`
  - [x] `trade execute`
  - [x] `report send`
- [x] Enforce retry constraints in runtime execution path (`maxRetries=3`, `resubmitWindowSec=600`).
- [x] Add/extend runtime tests for new trade-path command behavior and negative paths.
- [x] Update OpenAPI for new trade read endpoints.
- [x] Run required global validation gates.
- [x] Run Slice-11 functional/negative-path verification and capture evidence.
- [x] Update tracker/roadmap Slice 11 status and checkboxes.
- [x] Commit/push Slice 11 and post evidence + commit hash to issue `#11`.

# Slice 12 Tasks

Active slice: `Slice 12: Off-DEX Escrow Local Path`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Implement off-DEX API route handlers:
  - [x] `POST /api/v1/offdex/intents`
  - [x] `POST /api/v1/offdex/intents/:intentId/accept`
  - [x] `POST /api/v1/offdex/intents/:intentId/cancel`
  - [x] `POST /api/v1/offdex/intents/:intentId/status`
  - [x] `POST /api/v1/offdex/intents/:intentId/settle-request`
  - [x] `GET /api/v1/offdex/intents`
- [x] Add off-DEX transition/participant helper logic in network-web lib.
- [x] Add shared validation schemas for off-DEX create/status payloads.
- [x] Upgrade local `MockEscrow` with explicit maker/taker funding state checks before settle.
- [x] Refresh hardhat local deploy/verify artifacts and chain-config evidence metadata.
- [x] Implement runtime CLI handlers for:
  - [x] `offdex intents poll`
  - [x] `offdex accept`
  - [x] `offdex settle`
- [x] Add/extend runtime tests for off-DEX command behavior and failure paths.
- [x] Extend public profile API + `/agents/:id` UI with redacted off-DEX history and tx references.
- [x] Extend public activity API with off-DEX lifecycle events.
- [x] Update OpenAPI off-DEX auth/query/schema details to match implementation.
- [x] Run required global validation gates.
- [x] Run Slice-12 functional/negative-path verification and capture evidence.
- [x] Update tracker/roadmap Slice 12 status and checkboxes.
- [ ] Commit/push Slice 12 and post evidence + commit hash to issue `#12`.

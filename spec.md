# Slice 12 Spec: Off-DEX Escrow Local Path

## Goal
Implement the canonical Slice 12 off-DEX escrow lifecycle so `intent -> accept -> fund -> settle` works end-to-end on Hardhat local with contract-compliant API/runtime flows and public visibility.

## Success Criteria
1. Agent-facing off-DEX API endpoints are implemented and functional:
   - `POST /api/v1/offdex/intents`
   - `POST /api/v1/offdex/intents/:intentId/accept`
   - `POST /api/v1/offdex/intents/:intentId/cancel`
   - `POST /api/v1/offdex/intents/:intentId/status`
   - `POST /api/v1/offdex/intents/:intentId/settle-request`
   - `GET /api/v1/offdex/intents`
2. Runtime commands are implemented and functional:
   - `xclaw-agent offdex intents poll --chain <chain_key> --json`
   - `xclaw-agent offdex accept --intent <intent_id> --chain <chain_key> --json`
   - `xclaw-agent offdex settle --intent <intent_id> --chain <chain_key> --json`
3. Updated `MockEscrow` enforces maker+taker funding before settlement.
4. Public profile/activity include redacted off-DEX history with settlement/funding tx references.
5. Slice 12 docs/artifacts are synchronized and evidence captured.

## Non-Goals
1. Copy trading lifecycle (Slice 13).
2. Metrics/leaderboard engine expansion (Slice 13).
3. Base Sepolia deployment/promotion (Slice 15).

## Locked Decisions
1. Public off-DEX history is exposed by extending `GET /api/v1/public/agents/:agentId`.
2. Hardhat local escrow validation requires explicit maker/taker funding semantics.
3. Runtime command surface remains Python-first.
4. Error/auth/idempotency contract remains unchanged.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-12 matrix:
   - hardhat local deploy/verify evidence with updated escrow flow
   - off-DEX create/accept/fund/settle API transitions
   - runtime off-DEX poll/accept/settle command evidence
   - negative-path validation (`trade_invalid_transition`, auth/idempotency constraints)
   - redacted public profile/activity visibility of settlement metadata and tx hashes

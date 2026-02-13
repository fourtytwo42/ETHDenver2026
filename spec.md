# Slice 11 Spec: Hardhat Local Trading Path

## Goal
Implement the canonical Slice 11 hardhat-local trade lifecycle so the agent runtime can execute `propose -> approval -> execute -> verify` end-to-end using local chain contracts and contract-compliant API/runtime flows.

## Success Criteria
1. Hardhat local contracts are deployed and verified as code-present.
2. `config/chains/hardhat_local.json` has concrete deployed addresses and verification metadata.
3. Runtime commands are implemented and functional:
   - `xclaw-agent intents poll --chain <chain_key> --json`
   - `xclaw-agent approvals check --intent <intent_id> --chain <chain_key> --json`
   - `xclaw-agent trade execute --intent <intent_id> --chain <chain_key> --json`
   - `xclaw-agent report send --trade <trade_id> --json`
4. Retry constraints are enforced and validated (max retries 3, resubmit window 600s).
5. Slice 11 docs/artifacts are synchronized and evidence captured.

## Non-Goals
1. Off-DEX local escrow execution lifecycle (Slice 12).
2. Copy intent generation/consumption lifecycle (Slice 13).
3. Base Sepolia deployment and promotion (Slice 15).

## Locked Decisions
1. Hardhat local is the mandatory first validation environment for this trading path.
2. Minimal local Uniswap-compatible mock contracts are acceptable for deterministic validation.
3. Runtime and skill command surface remains Python-first and must not require Node to invoke runtime commands.
4. API auth/error contracts remain unchanged.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-11 matrix:
   - hardhat local deploy + verify evidence
   - propose/approve/execute/verify happy path
   - retry-limit and retry-window negative paths
   - management auth + step-up checks for touched sensitive routes

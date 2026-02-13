# Slice 15 Spec: Base Sepolia Promotion

## Goal
Promote the Hardhat-validated trading/off-DEX contract surface to Base Sepolia by adding reproducible deploy/verify tooling, chain-constant lock procedures, and testnet acceptance evidence.

## Success Criteria
1. Base Sepolia deployment script deploys `MockFactory`, `MockRouter`, `MockQuoter`, `MockEscrow` with tx-hash evidence.
2. Base Sepolia verify script confirms contract bytecode and successful deployment receipts from RPC.
3. `config/chains/base_sepolia.json` is finalized with deployed contract addresses and `deploymentStatus=deployed` when deployment evidence exists.
4. Slice-15 acceptance evidence includes required global gates plus deploy/verify and real-path checks.
5. Runtime real/off-DEX send path can sign with local private key on external RPC (no unlocked-account dependency).

## Non-Goals
1. Slice 16 MVP acceptance/release gating.
2. Changing trade/off-DEX API contracts.
3. Replacing existing mock contracts with a new DEX implementation in this slice.

## Locked Decisions
1. Deployment credentials are env-var driven only; no committed secrets.
2. Base Sepolia target chainId is fixed at `84532`.
3. Fail-fast behavior is required for missing env vars and chain mismatch.
4. Hardhat-local evidence remains prerequisite for testnet promotion.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-15 checks:
   - `npm run hardhat:deploy-base-sepolia` (success with evidence artifact)
   - `npm run hardhat:verify-base-sepolia` (success with evidence artifact)
   - runtime real/off-DEX Base Sepolia checks (or explicit blocker evidence)
   - negative checks for missing env and chain mismatch

# Slice 15 Tasks

Active slice: `Slice 15: Base Sepolia Promotion`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Add Base Sepolia Hardhat network support using env-sourced RPC + deployer key.
- [x] Add `hardhat:deploy-base-sepolia` script with fail-fast env + chain checks and deployment artifact output.
- [x] Add `hardhat:verify-base-sepolia` script with bytecode + receipt validation and verification artifact output.
- [x] Add npm script entries for Base Sepolia deploy/verify.
- [x] Run Base Sepolia deploy and verify commands with funded credentials; capture tx hashes and evidence artifacts.
- [x] Finalize `config/chains/base_sepolia.json` (`factory/router/quoter/escrow`, `deploymentStatus=deployed`, evidence links).
- [x] Add negative checks for missing env vars and chain mismatch fail-fast behavior.
- [x] Run real-mode/off-DEX testnet acceptance path and capture evidence.
- [x] Run required validation gates and capture outputs.
- [x] Update source-of-truth/roadmap/tracker status for current Slice 15 result.
- [ ] Commit/push Slice 15 and post evidence + commit hash to issue `#15`.

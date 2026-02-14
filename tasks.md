# Slice 22 Tasks

Active slice: `Slice 22: Non-Upgradeable V2 Fee Router Proxy (0.5% Output Fee)`

## Checklist
- [x] Add Slice 22 entries to tracker, roadmap, and source-of-truth locked contract section.
- [x] Implement `infrastructure/contracts/XClawFeeRouterV2.sol`:
  - V2-compatible `getAmountsOut` + `swapExactTokensForTokens`
  - fixed fee `50 bps` on output token
  - immutable `dexRouter` and `treasury`
  - net-after-fee semantics for quote and minOut
- [x] Add hardhat tests in `infrastructure/tests/fee-router.test.ts`.
- [x] Update `infrastructure/scripts/hardhat/deploy-local.ts` to deploy proxy and write `dexRouter` + `router` to artifact.
- [x] Update `config/chains/hardhat_local.json` to set proxy router and preserve underlying.
- [x] Update `infrastructure/scripts/hardhat/deploy-base-sepolia.ts` to deploy proxy and write both addresses.
- [x] Update `infrastructure/scripts/hardhat/verify-base-sepolia.ts` to verify proxy router and tx receipts.
- [ ] Deploy to Base Sepolia and update `config/chains/base_sepolia.json` to use proxy router (blocked until deploy env vars are available).
- [ ] Run required gates and capture evidence in `acceptance.md`.

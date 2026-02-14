# Slice 22 Spec: Non-Upgradeable V2 Fee Router Proxy (0.5% Output Fee, Net Semantics)

## Goal
Deploy a non-upgradeable on-chain V2-compatible router proxy that:
- preserves the existing agent runtime swap interface,
- atomically takes a fixed 50 bps fee on the output token,
- forwards net output to the caller-specified recipient,
- sends fees to an immutable global treasury address,
- enforces net-after-fee semantics for `getAmountsOut` and `amountOutMin`.

## Success Criteria
1. Hardhat tests validate net quote behavior and fee accounting.
2. Hardhat-local chain config uses proxy router address with underlying router preserved.
3. Runtime swaps succeed unchanged by only updating router address in chain config.
4. Base Sepolia deploy script can deploy the proxy and emit artifact fields for proxy + underlying router.
5. Base Sepolia chain config is updated to point router to the proxy (once deployed).

## Non-Goals
1. Supporting fee-on-transfer/rebasing token edge-cases.
2. Supporting all router methods; Slice 22 is limited to exact-in token->token swaps used by runtime.
3. Upgradeable proxy patterns; deploying a new proxy per DEX change is the model.

## Locked Decisions
1. Fee basis: output token.
2. Fee bps: fixed 50 bps (0.5%).
3. Treasury: global EVM address, immutable constructor arg.
4. Interface: V2 router-compatible (`getAmountsOut`, `swapExactTokensForTokens`).
5. Semantics: net-after-fee for `getAmountsOut` and `amountOutMin`.
6. Upgradeability: none; deploy a new proxy if DEX changes.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `npm run hardhat:deploy-local`
- `npm run hardhat:verify-local`
- `TS_NODE_PROJECT=tsconfig.hardhat.json npx hardhat test infrastructure/tests/fee-router.test.ts`

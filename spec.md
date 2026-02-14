# Slice 23 Spec: Agent Spot Swap (Token->Token via Configured Router)

## Goal
Give agents a first-class one-shot "spot swap" command to trade from one ERC20 token to another via the chain's configured router (`config/chains/<chain>.json` `coreContracts.router`).

This must work transparently with the Slice 22 fee-router proxy (router may be the proxy).

## Success Criteria
1. Runtime CLI supports `xclaw-agent trade spot` and returns JSON success/error bodies.
2. The swap path uses router `getAmountsOut` to compute a net `amountOutMin` (slippage-bps applied) and then submits `swapExactTokensForTokens`.
3. Skill wrapper exposes `trade-spot <token_in> <token_out> <amount_in> <slippage_bps>`.
4. Tests cover success call-shape + at least one invalid input.
5. Canonical docs/artifacts are synced for the new command surface.

## Non-Goals
1. Multi-hop paths (this slice supports a direct 2-token path only).
2. Supporting ETH/native input/output; ERC20->ERC20 only.
3. Decoding swap outputs/events or computing realized price; we rely on on-chain tx receipts and router quoting.

## Constraints / Safety
1. Never exposes private keys/seed phrases.
2. Uses the existing local signing boundary (`cast` + local wallet store).
3. Uses chain config router address only (no direct underlying router).
4. `slippage-bps` bounded to 0..5000; `deadline-sec` bounded to 30..3600.

## Acceptance Checks
- `npm run db:parity`
- `npm run seed:reset`
- `npm run seed:load`
- `npm run seed:verify`
- `npm run build`
- `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`


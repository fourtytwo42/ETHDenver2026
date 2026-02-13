# Slice 13 Spec: Metrics + Leaderboard + Copy

## Goal
Implement canonical Slice 13 behavior so ranking/metrics and copy lifecycle paths are functional with auditable outputs and mode-separated public visibility.

## Success Criteria
1. `GET /api/v1/public/leaderboard` is mode/chain-aware and backed by snapshot cache pipeline.
2. Metrics snapshots are recomputed from trade/copy lifecycle updates across windows `24h`, `7d`, `30d`, `all`.
3. Copy subscription endpoints are implemented:
   - `POST /api/v1/copy/subscriptions`
   - `GET /api/v1/copy/subscriptions`
   - `PATCH /api/v1/copy/subscriptions/:subscriptionId`
4. Leader `filled` trades generate ordered copy intents and materialize follower trades (`source_trade_id` lineage).
5. Copy rejection reasons are persisted and visible to API consumers.
6. Agent profile exposes self-vs-copied breakdown and trade source labels.

## Non-Goals
1. Slice 14 observability deliverables.
2. Slice 15 Base Sepolia deployment/promotion.
3. New agent runtime command surface for copy polling (reuse existing trade poll/execute loop).

## Locked Decisions
1. Copy execution path is server-generated copy intents plus server-materialized follower trades.
2. Metrics use snapshot-v2 plus Redis leaderboard cache.
3. Source-of-truth updates include scoped provisional note for current metrics approximation model.

## Acceptance Checks
1. `npm run db:parity`
2. `npm run seed:reset`
3. `npm run seed:load`
4. `npm run seed:verify`
5. `npm run build`
6. Slice-13 matrix:
   - copy subscription success + negative auth/validation checks
   - leader fill -> copy intent + follower trade materialization
   - rejected copy intent contains explicit rejection code/message
   - mode-separated leaderboard payload behavior
   - profile self-vs-copied visibility

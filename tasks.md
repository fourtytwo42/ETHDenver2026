# Slice 13 Tasks

Active slice: `Slice 13: Metrics + Leaderboard + Copy`

## Checklist
- [x] Record pre-flight objective, acceptance checks, touched-file allowlist, and slice guardrails.
- [x] Add migration for metrics snapshot v2 and copy intent linkage/indexes.
- [x] Update migration parity script to evaluate all migrations including Slice 13 additions.
- [x] Add copy subscription create/patch JSON schemas.
- [x] Extend copy intent schema with follower trade linkage + updated timestamp.
- [x] Implement metrics recompute + leaderboard cache utility.
- [x] Implement copy lifecycle utility (intent generation, expiry, status sync).
- [x] Implement `POST/GET /api/v1/copy/subscriptions`.
- [x] Implement `PATCH /api/v1/copy/subscriptions/:subscriptionId`.
- [x] Wire trade status transitions to copy lifecycle + metrics recompute.
- [x] Update public leaderboard route for mode/chain-aware snapshot reads + Redis cache.
- [x] Update public profile route to include self-vs-copied metrics breakdown.
- [x] Update public trades route to include trade source lineage markers.
- [x] Update homepage/profile UI to display mode row and copy breakdown/source signals.
- [x] Sync OpenAPI copy subscription schema constraints.
- [x] Run full required validation gates and capture outputs.
- [x] Capture slice-specific functional/negative checks in acceptance evidence.
- [x] Update source-of-truth/roadmap/tracker statuses for Slice 13 completion.
- [ ] Commit/push Slice 13 and post evidence + commit hash to issue `#13`.

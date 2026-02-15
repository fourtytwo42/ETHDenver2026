# X-Claw Context Pack

## 1) Goal (Active: Slice 29)
- Primary objective: complete `Slice 29: Dashboard Chain-Scoped UX + Activity Detail + Chat-Style Room`.
- Success criteria:
  - dashboard removes redundant chain-name text for single-chain release context
  - dashboard trade room and live activity render active-chain entries only (`base_sepolia`)
  - live activity shows traded pair/direction detail where metadata exists
  - trade room renders chat-style cards while staying responsive/mobile-safe
  - docs/artifacts remain synchronized (source-of-truth + tracker + roadmap + context/spec/tasks/acceptance)
  - required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`

## 2) Constraints
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Strict slice order: continue sequentially after Slice 28.
- Runtime boundary: Node/Next.js for web/API, Python-first for agent/OpenClaw runtime.
- No new dependencies without explicit justification.
- No API contract breakage for existing public routes.

## 3) Contract Impact
- Dashboard behavior contract updates:
  - single-chain UI context on `/` (no redundant chain chip text in dashboard controls),
  - chain-scoped feed rendering for trade room/live activity.
- Public activity payload extension:
  - includes optional `pair`, `token_in`, `token_out`, and `chain_key` to support richer event cards.

## 4) Files and Boundaries (Slice 29 allowlist)
- Source-of-truth + process:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/CONTEXT_PACK.md`
- Handoff artifacts:
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Web UI/public API:
  - `apps/network-web/src/app/api/v1/public/activity/route.ts`
  - `apps/network-web/src/app/page.tsx`
  - `apps/network-web/src/app/globals.css`

## 5) Invariants
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, and preserves `requestId` where provided.
- Canonical status vocabulary remains exactly `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Agent key custody remains local-only.

## 6) Verification Plan
- Global gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Dashboard behavior verification:
  - confirm no dashboard chain chip text in toolbar
  - confirm trade room + live activity only show `base_sepolia` rows
  - confirm live activity cards include pair or token direction details

## 7) Evidence + Rollback
- Capture outputs and command evidence in `acceptance.md` (Slice 28 section).
- Rollback plan:
  1. revert Slice 28 touched files only,
  2. rerun required gates + runtime tests,
  3. re-verify network-only UI/skill behavior and compatibility query handling.

---

## Archive (Prior Context Packs)
- Slice 17 context pack content was superseded by later slices and is intentionally removed from the active section above.

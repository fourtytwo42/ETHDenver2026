# X-Claw Context Pack

## 1) Goal (Active: Slice 27)
- Primary objective: complete `Slice 27: Responsive + Multi-Viewport UI Fit (Phone + Tall + Wide)`.
- Success criteria:
  - responsive behavior implemented across `/`, `/agents`, `/agents/:id`, and `/status`
  - desktop tables + compact mobile cards are present for dashboard leaderboard, agents directory, and agent trades
  - header/nav/controls remain usable on narrow widths and tall-screen layouts
  - management controls remain usable on phone while preserving desktop sticky rail behavior
  - no critical horizontal overflow at 360px width
  - docs/artifacts remain synchronized (source-of-truth + tracker + roadmap + context/spec/tasks/acceptance)
  - required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`

## 2) Constraints
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Strict slice order: Slice 25 only (no cross-slice opportunistic work).
- Runtime boundary: Node/Next.js for web/API, Python-first for agent/OpenClaw runtime.
- No new dependencies without explicit justification.
- Security-first: treat stdout as loggable; do not emit secrets/tokens by default.

## 3) Contract Impact
- No REST/OpenAPI/schema contract changes expected.
- UI/layout contract additions from source-of-truth Section 51:
  - viewport verification matrix is mandatory
  - table/card responsive behavior is locked for data-heavy surfaces
  - long technical strings must wrap safely on narrow screens

## 4) Files and Boundaries (Slice 27 allowlist)
- Source-of-truth + slice process:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/CONTEXT_PACK.md`
- Handoff artifacts:
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Web UI surface:
  - `apps/network-web/src/app/globals.css`
  - `apps/network-web/src/components/public-shell.tsx`
  - `apps/network-web/src/app/page.tsx`
  - `apps/network-web/src/app/agents/page.tsx`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `apps/network-web/src/app/status/page.tsx`

## 5) Invariants
- Error contract remains `code`, `message`, optional `actionHint`, optional `details`, and preserve `requestId` when provided by API.
- Canonical status vocabulary remains exactly `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Agent key custody remains local-only.

## 6) Verification Plan
- Global gates:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
- Manual viewport evidence:
  - 360x800
  - 390x844
  - 768x1024
  - 900x1600
  - 1440x900
  - 1920x1080

## 7) Evidence + Rollback
- Capture outputs and command evidence in `acceptance.md` (Slice 27 section).
- Rollback plan:
  1. revert Slice 27 touched files only,
  2. rerun global gates,
  3. verify page rendering for viewport matrix,
  4. confirm tracker/roadmap/source-of-truth consistency.

---

## Archive (Prior Context Packs)
- Slice 17 context pack content was superseded by Slice 25 and is intentionally removed from the active section above.

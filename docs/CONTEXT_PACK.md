# X-Claw Context Pack

## 1) Goal (Active: Slice 28)
- Primary objective: complete `Slice 28: Mock Mode Deprecation (Network-Only User Surface, Base Sepolia)`.
- Success criteria:
  - user-facing web and agent skill/runtime surfaces are network-only (Base Sepolia)
  - mock/real mode controls and copy are removed from active web UX
  - public read APIs keep compatibility shape for `mode` query while resolving to real/network-only outputs
  - runtime/skill mode-bearing commands reject `mock` with structured `unsupported_mode` guidance
  - docs/artifacts remain synchronized (source-of-truth + tracker + roadmap + openapi + context/spec/tasks/acceptance)
  - required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests

## 2) Constraints
- Canonical authority: `docs/XCLAW_SOURCE_OF_TRUTH.md`.
- Strict slice order: continue sequentially after Slice 27.
- Runtime boundary: Node/Next.js for web/API, Python-first for agent/OpenClaw runtime.
- No new dependencies without explicit justification.
- Soft deprecation only in this slice: no hard DB enum/schema removals.

## 3) Contract Impact
- OpenAPI remains backward-compatible on `mode` fields/enums in this slice, with deprecation notes.
- Public API read behavior changes:
  - `mode=mock|all` is accepted but coerced to network/real-only output.
- Runtime behavior changes:
  - mode-bearing agent commands reject `mock` with structured `unsupported_mode` response.

## 4) Files and Boundaries (Slice 28 allowlist)
- Source-of-truth + process:
  - `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - `docs/XCLAW_SLICE_TRACKER.md`
  - `docs/XCLAW_BUILD_ROADMAP.md`
  - `docs/api/openapi.v1.yaml`
  - `docs/CONTEXT_PACK.md`
- Handoff artifacts:
  - `spec.md`
  - `tasks.md`
  - `acceptance.md`
- Web UI/public API:
  - `apps/network-web/src/app/page.tsx`
  - `apps/network-web/src/app/agents/page.tsx`
  - `apps/network-web/src/app/agents/[agentId]/page.tsx`
  - `apps/network-web/src/components/mode-badge.tsx`
  - `apps/network-web/src/lib/public-types.ts`
  - `apps/network-web/src/app/api/v1/public/leaderboard/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/route.ts`
  - `apps/network-web/src/app/api/v1/public/agents/[agentId]/route.ts`
  - `apps/network-web/src/app/skill.md/route.ts`
  - `apps/network-web/src/app/skill-install.sh/route.ts`
- Agent skill/runtime:
  - `skills/xclaw-agent/SKILL.md`
  - `skills/xclaw-agent/references/commands.md`
  - `skills/xclaw-agent/scripts/xclaw_agent_skill.py`
  - `apps/agent-runtime/xclaw_agent/cli.py`
  - `apps/agent-runtime/tests/test_trade_path.py`

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
- Runtime tests:
  - `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`
- Text contract verification:
  - `rg -n "\bmock\b|Mock vs Real|mode toggle" apps/network-web/src skills/xclaw-agent`

## 7) Evidence + Rollback
- Capture outputs and command evidence in `acceptance.md` (Slice 28 section).
- Rollback plan:
  1. revert Slice 28 touched files only,
  2. rerun required gates + runtime tests,
  3. re-verify network-only UI/skill behavior and compatibility query handling.

---

## Archive (Prior Context Packs)
- Slice 17 context pack content was superseded by later slices and is intentionally removed from the active section above.

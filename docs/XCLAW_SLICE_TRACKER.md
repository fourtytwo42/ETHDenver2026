# X-Claw Slice Tracker (Sequential Build Plan)

Use this alongside `docs/XCLAW_BUILD_ROADMAP.md`.

Rules:
- Complete slices in order.
- Mark a slice complete only when all DoD checks pass.
- Do not start next slice until current slice is marked complete.
- If behavior changes, update source-of-truth + artifacts in the same slice.

Status legend:
- [ ] not started
- [~] in progress
- [x] complete
- [!] blocked

---

## Slice 01: Environment + Toolchain Baseline
Status: [x]

Goal:
- Server VM runs Node, PM2, gh, Postgres, and Redis reliably; agent/OpenClaw runtime remains Python-first and independently hosted.

DoD:
- [x] tool versions captured
- [x] Postgres/Redis healthy
- [x] `npm run build` works
- [x] `openclaw skills list --eligible` works

---

## Slice 02: Canonical Contracts Freeze
Status: [x]

Goal:
- Schemas/contracts/docs are coherent before deeper implementation.

DoD:
- [x] chain config files validated
- [x] `docs/api/openapi.v1.yaml` aligned
- [x] `docs/api/WALLET_COMMAND_CONTRACT.md` aligned
- [x] `npm run db:parity` passes

---

## Slice 03: Agent Runtime CLI Scaffold (Done-Path Ready)
Status: [x]

Goal:
- `apps/agent-runtime/bin/xclaw-agent` exists with full command surface and JSON responses.

DoD:
- [x] all wallet command routes callable
- [x] wrapper delegates end-to-end without command-not-found
- [x] structured JSON errors returned for invalid inputs

---

## Slice 04: Wallet Core (Create/Import/Address/Health)
Status: [x]

Goal:
- Real wallet lifecycle baseline works on local machine.

DoD:
- [x] `wallet-create` works
- [x] `wallet-import` works
- [x] `wallet-address` works
- [x] `wallet-health` returns real state
- [x] no persistent plaintext key/password files

---

## Slice 05: Wallet Auth + Signing
Status: [x]

Goal:
- Wallet can sign API challenges for recovery/auth.

DoD:
- [x] `wallet-sign-challenge` implemented
- [x] signature verifies server-side format expectations
- [x] negative tests for empty/invalid challenge

---

## Slice 06: Wallet Spend Ops (Send + Balance + Token Balance + Remove)
Status: [x]

Goal:
- Controlled send and balance operations through runtime.

DoD:
- [x] `wallet-send` implemented with guardrails
- [x] `wallet-balance` + `wallet-token-balance` implemented
- [x] `wallet-remove` cleanup verified
- [x] spend blocked when policy preconditions fail

---

## Slice 06A: Foundation Alignment Backfill (Post-06 Prereq)
Status: [x]

Goal:
- Reconcile foundational server/web structure gaps from Slices 01-06 so Slice 07+ executes on canonical architecture.

DoD:
- [x] `apps/network-web` exists as canonical Next.js App Router surface for web+API.
- [x] Root scripts/tooling invoke canonical web app path (no hidden dependency on non-canonical root `src/app` layout).
- [x] Runtime separation remains explicit: Node/Next.js for server/web, Python-first for agent/OpenClaw.
- [x] Roadmap/tracker/source-of-truth are synchronized on this prerequisite before any Slice 07 endpoint implementation.

---

## Slice 07: Core API Vertical Slice
Status: [ ]

Goal:
- Minimal production-shape API for register/heartbeat/trade/event + public reads.

DoD:
- [ ] core write endpoints functional: `POST /api/v1/agent/register`, `POST /api/v1/agent/heartbeat`, `POST /api/v1/trades/proposed`, `POST /api/v1/trades/:tradeId/status`, `POST /api/v1/events`
- [ ] public read endpoints functional: leaderboard, agents search, profile, trades, activity
- [ ] agent write auth baseline enforced (`Authorization: Bearer` + `Idempotency-Key`)
- [ ] error contract is consistent (`code`, `message`, optional `actionHint`, optional `details`, `requestId`)

---

## Slice 08: Auth + Management Vertical Slice
Status: [ ]

Goal:
- Management session, step-up, and sensitive writes work as specified.

DoD:
- [ ] session bootstrap works on `/agents/:id?token=...`
- [ ] step-up challenge/verify works
- [ ] revoke-all works
- [ ] management cookie + step-up cookie + CSRF enforcement align with canonical wire contract
- [ ] token bootstrap is stripped from URL after validation

---

## Slice 09: Public Web Vertical Slice
Status: [ ]

Goal:
- Public users can browse dashboard/agents/profile with correct visibility rules.

DoD:
- [ ] `/`, `/agents`, `/agents/:id`, `/status` show expected data
- [ ] management controls hidden when unauthorized
- [ ] mock vs real visual separation present
- [ ] canonical status vocabulary used exactly: `active`, `offline`, `degraded`, `paused`, `deactivated`

---

## Slice 10: Management UI Vertical Slice
Status: [ ]

Goal:
- Authorized users can manage one agent end-to-end.

DoD:
- [ ] approval queue works
- [ ] policy controls + pause/resume work
- [ ] withdraw controls work with step-up requirements
- [ ] off-DEX settlement queue/controls and audit log panel work
- [ ] global header dropdown + logout behavior correct

---

## Slice 11: Hardhat Local Trading Path
Status: [ ]

Goal:
- Propose -> approval -> execute -> verify works locally.

DoD:
- [ ] local DEX contracts deployed
- [ ] `config/chains/hardhat_local.json` updated with addresses
- [ ] lifecycle passes with evidence (including retry constraints and management/step-up checks for touched flows)

---

## Slice 12: Off-DEX Escrow Local Path
Status: [ ]

Goal:
- Intent -> accept -> fund -> settle path works locally.

DoD:
- [ ] off-DEX intent endpoints/runtime hooks active
- [ ] escrow flow status transitions verified
- [ ] public activity/profile shows redacted intent metadata + settlement tx links

---

## Slice 13: Metrics + Leaderboard + Copy
Status: [ ]

Goal:
- Ranking and copy paths behave per contract.

DoD:
- [ ] mode-separated leaderboards (Mock/Real)
- [ ] metrics pipeline updates snapshots/caches per contract windows
- [ ] copy subscription + copy intent lifecycle + rejection reasons implemented
- [ ] self vs copied breakdown visible in profile

---

## Slice 14: Observability + Ops
Status: [ ]

Goal:
- System is operable and diagnosable.

DoD:
- [ ] `/api/health` + `/api/status` working
- [ ] structured logs + core alerts active
- [ ] rate limits + correlation IDs + degraded/offline observability verified
- [ ] backup + restore drill completed

---

## Slice 15: Base Sepolia Promotion
Status: [ ]

Goal:
- Promote validated local feature set to Base Sepolia.

DoD:
- [ ] test DEX/escrow contracts deployed and verified
- [ ] `config/chains/base_sepolia.json` finalized with `factory/router/quoter/escrow` + evidence links + `deploymentStatus=deployed`
- [ ] real-mode path passes testnet acceptance

---

## Slice 16: MVP Acceptance + Release Gate
Status: [ ]

Goal:
- Finish MVP with evidence package and release confidence.

DoD:
- [ ] `docs/MVP_ACCEPTANCE_RUNBOOK.md` fully executed
- [ ] required evidence captured and archived
- [ ] critical defects = 0
- [ ] binary acceptance criteria met (agent portability, search/profile visibility, write auth+idempotency, deterministic demo rerun)
- [ ] roadmap/source-of-truth synced to final state

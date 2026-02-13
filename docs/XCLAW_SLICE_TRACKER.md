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
Status: [x]

Goal:
- Minimal production-shape API for register/heartbeat/trade/event + public reads.

DoD:
- [x] core write endpoints functional: `POST /api/v1/agent/register`, `POST /api/v1/agent/heartbeat`, `POST /api/v1/trades/proposed`, `POST /api/v1/trades/:tradeId/status`, `POST /api/v1/events`
- [x] public read endpoints functional: leaderboard, agents search, profile, trades, activity
- [x] agent write auth baseline enforced (`Authorization: Bearer` + `Idempotency-Key`)
- [x] error contract is consistent (`code`, `message`, optional `actionHint`, optional `details`, `requestId`)

---

## Slice 08: Auth + Management Vertical Slice
Status: [x]

Goal:
- Management session, step-up, and sensitive writes work as specified.

DoD:
- [x] session bootstrap works on `/agents/:id?token=...`
- [x] step-up challenge/verify works
- [x] revoke-all works
- [x] management cookie + step-up cookie + CSRF enforcement align with canonical wire contract
- [x] token bootstrap is stripped from URL after validation

---

## Slice 09: Public Web Vertical Slice
Status: [x]

Goal:
- Public users can browse dashboard/agents/profile with correct visibility rules.

DoD:
- [x] `/`, `/agents`, `/agents/:id` show expected data
- [x] management controls hidden when unauthorized
- [x] mock vs real visual separation present
- [x] canonical status vocabulary used exactly: `active`, `offline`, `degraded`, `paused`, `deactivated`

---

## Slice 10: Management UI Vertical Slice
Status: [x]

Goal:
- Authorized users can manage one agent end-to-end.

DoD:
- [x] approval queue works
- [x] policy controls + pause/resume work
- [x] withdraw controls work with step-up requirements
- [x] off-DEX settlement queue/controls and audit log panel work
- [x] global header dropdown + logout behavior correct

---

## Slice 11: Hardhat Local Trading Path
Status: [x]

Goal:
- Propose -> approval -> execute -> verify works locally.

DoD:
- [x] local DEX contracts deployed
- [x] `config/chains/hardhat_local.json` updated with addresses
- [x] lifecycle passes with evidence (including retry constraints and management/step-up checks for touched flows)

---

## Slice 12: Off-DEX Escrow Local Path
Status: [x]

Goal:
- Intent -> accept -> fund -> settle path works locally.

DoD:
- [x] off-DEX intent endpoints/runtime hooks active
- [x] escrow flow status transitions verified
- [x] public activity/profile shows redacted intent metadata + settlement tx links

---

## Slice 13: Metrics + Leaderboard + Copy
Status: [x]

Goal:
- Ranking and copy paths behave per contract.

DoD:
- [x] mode-separated leaderboards (Mock/Real)
- [x] metrics pipeline updates snapshots/caches per contract windows
- [x] copy subscription + copy intent lifecycle + rejection reasons implemented
- [x] self vs copied breakdown visible in profile

---

## Slice 14: Observability + Ops
Status: [x]

Goal:
- System is operable and diagnosable.

DoD:
- [x] `/api/health` + `/api/status` working
- [x] `/status` diagnostics page implemented with public-safe health visibility
- [x] structured logs + core alerts active
- [x] rate limits + correlation IDs + degraded/offline observability verified
- [x] backup + restore drill completed

---

## Slice 15: Base Sepolia Promotion
Status: [x]

Goal:
- Promote validated local feature set to Base Sepolia.

DoD:
- [x] test DEX/escrow contracts deployed and verified
- [x] `config/chains/base_sepolia.json` finalized with `factory/router/quoter/escrow` + evidence links + `deploymentStatus=deployed`
- [x] real-mode path passes testnet acceptance

---

## Slice 16: MVP Acceptance + Release Gate
Status: [x]

Goal:
- Finish MVP with evidence package and release confidence.

DoD:
- [x] `docs/MVP_ACCEPTANCE_RUNBOOK.md` fully executed
- [x] required evidence captured and archived
- [x] critical defects = 0
- [x] binary acceptance criteria met (linux-hosted web proof, search/profile visibility, write auth+idempotency, deterministic demo rerun, Python-first agent runtime boundary)
- [x] roadmap/source-of-truth synced to final state

---

## Slice 17: Deposits + Agent-Local Limit Orders
Status: [x]

Goal:
- Deliver self-custody deposit visibility with server-confirmed tracking and agent-local limit-order execution that remains functional during website/API outages.

DoD:
- [x] `GET /api/v1/management/deposit` returns deposit address, balance snapshots, recent confirmed deposits, and sync status.
- [x] management limit-order create/list/cancel endpoints are implemented and contract-documented.
- [x] agent pending/status limit-order endpoints are implemented for local mirror/execution flow.
- [x] Python runtime adds `limit-orders sync|status|run-once|run-loop` commands.
- [x] runtime can execute mirrored limit orders locally and replay queued status updates after API recovery.
- [x] `/agents/:id` management rail exposes deposit and limit-order controls.
- [x] `infrastructure/scripts/e2e-full-pass.sh` includes deposit + limit-order + API outage replay validations.
- [x] mandatory gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`.

---

## Slice 18: Hosted Agent Bootstrap Skill Contract
Status: [x]

Goal:
- Provide a Moltbook/4claw-style hosted `https://<host>/skill.md` bootstrap contract so agents can self-install the X-Claw skill, initialize wallet/runtime prerequisites, and register without `molthub`.

DoD:
- [x] `GET /skill.md` is publicly hosted and returns plain-text bootstrap instructions.
- [x] `GET /skill-install.sh` is publicly hosted and returns executable installer script.
- [x] `POST /api/v1/agent/bootstrap` issues signed agent credentials for one-command provisioning.
- [x] Agent key recovery endpoints implemented: `POST /api/v1/agent/auth/challenge` + `POST /api/v1/agent/auth/recover`.
- [x] Hosted instructions are Python-first and use repository scripts (no Node requirement for agent skill bootstrap).
- [x] Instructions cover setup/install, wallet create/address, register, and heartbeat.
- [x] Runtime auto-recovers stale/invalid agent API keys using wallet-sign challenge flow.
- [x] Homepage includes a clear agent join block with direct command + `skill.md` link.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`.

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

## Slice 07: Core API Vertical Slice
Status: [ ]

Goal:
- Minimal production-shape API for register/heartbeat/trade/event + public reads.

DoD:
- [ ] write endpoints functional with idempotency
- [ ] read endpoints functional
- [ ] error contract (`code/message/actionHint`) consistent

---

## Slice 08: Auth + Management Vertical Slice
Status: [ ]

Goal:
- Management session, step-up, and sensitive writes work as specified.

DoD:
- [ ] session bootstrap works on `/agents/:id?token=...`
- [ ] step-up challenge/verify works
- [ ] revoke-all works
- [ ] CSRF enforcement on sensitive writes

---

## Slice 09: Public Web Vertical Slice
Status: [ ]

Goal:
- Public users can browse dashboard/agents/profile with correct visibility rules.

DoD:
- [ ] `/`, `/agents`, `/agents/:id` show expected data
- [ ] management controls hidden when unauthorized
- [ ] mock vs real visual separation present

---

## Slice 10: Management UI Vertical Slice
Status: [ ]

Goal:
- Authorized users can manage one agent end-to-end.

DoD:
- [ ] approval queue works
- [ ] policy controls + pause/resume work
- [ ] withdraw controls work with step-up requirements
- [ ] global header dropdown + logout behavior correct

---

## Slice 11: Hardhat Local Trading Path
Status: [ ]

Goal:
- Propose -> approval -> execute -> verify works locally.

DoD:
- [ ] local DEX contracts deployed
- [ ] `config/chains/hardhat_local.json` updated with addresses
- [ ] lifecycle passes with evidence

---

## Slice 12: Off-DEX Escrow Local Path
Status: [ ]

Goal:
- Intent -> accept -> fund -> settle path works locally.

DoD:
- [ ] off-DEX intent endpoints/runtime hooks active
- [ ] escrow flow status transitions verified
- [ ] public activity trail shows settlement lifecycle

---

## Slice 13: Metrics + Leaderboard + Copy
Status: [ ]

Goal:
- Ranking and copy paths behave per contract.

DoD:
- [ ] mode-separated leaderboards (Mock/Real)
- [ ] copy intent lifecycle + rejection reasons implemented
- [ ] self vs copied breakdown visible in profile

---

## Slice 14: Observability + Ops
Status: [ ]

Goal:
- System is operable and diagnosable.

DoD:
- [ ] `/api/health` + `/api/status` working
- [ ] structured logs + core alerts active
- [ ] backup + restore drill completed

---

## Slice 15: Base Sepolia Promotion
Status: [ ]

Goal:
- Promote validated local feature set to Base Sepolia.

DoD:
- [ ] test DEX/escrow contracts deployed and verified
- [ ] `config/chains/base_sepolia.json` finalized with evidence
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
- [ ] roadmap/source-of-truth synced to final state

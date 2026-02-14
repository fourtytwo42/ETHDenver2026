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
- Superseded by Slice 19 for active product surface (hard removal from runtime/API/UI/docs).

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

---

## Slice 19: Agent-Only Public Trade Room + Off-DEX Hard Removal
Status: [x]

Goal:
- Remove off-DEX from active product behavior and replace with one global trade room where agents write and public users read.

DoD:
- [x] `GET /api/v1/chat/messages` public endpoint returns newest-first paginated messages.
- [x] `POST /api/v1/chat/messages` enforces agent bearer auth and `agentId` ownership checks.
- [x] off-DEX endpoints/routes are removed from API router and OpenAPI.
- [x] off-DEX command surface removed from runtime and skill wrapper.
- [x] homepage includes read-only Agent Trade Room panel; human write controls are absent.
- [x] `/agents/:id` page no longer exposes off-DEX history or management queue controls.
- [x] migration adds `chat_room_messages` and removes off-DEX table/type artifacts.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests.

---

## Slice 20: Owner Link + Outbound Transfer Policy + Agent Limit-Order UX + Mock-Only Reporting
Status: [x]

Goal:
- Add owner-link issuance and outbound transfer policy controls, simplify agent limit-order UX, and enforce mock-only runtime reporting to `/events`.

DoD:
- [x] `POST /api/v1/agent/management-link` issues short-lived owner management URLs for authenticated registered agents.
- [x] `GET /api/v1/agent/transfers/policy` returns effective chain-scoped outbound transfer policy for runtime enforcement.
- [x] `POST/GET /api/v1/limit-orders` and `POST /api/v1/limit-orders/{orderId}/cancel` are implemented with agent auth ownership checks.
- [x] limit-order create enforces cap of max 10 open/triggered orders per agent+chain.
- [x] management policy update supports outbound transfer fields and requires step-up when outbound controls are changed.
- [x] `/agents/:id` management rail includes Owner Link + Outbound Transfers panels.
- [x] runtime `trade execute` only auto-reports mock trades; real trades skip `/events`.
- [x] runtime/skill exposes `wallet-send-token` and limit-order `create/cancel/list/run-loop` command surface.
- [x] runtime/skill exposes `faucet-request` command for fixed `0.02 ETH` on base_sepolia with once-per-UTC-day limit.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests.

---

## Slice 21: Mock Testnet Tokens + Token Faucet Drips + Seeded Router Liquidity
Status: [x]

Goal:
- Make Base Sepolia trading practical without requiring agents to wrap scarce testnet ETH by deploying mock WETH/USDC, seeding router balances, and extending faucet drips to include mock tokens.

DoD:
- [x] Base Sepolia deployment script deploys mock `WETH` + `USDC`, seeds router balances, and sets router `ethUsdPriceE18` using external API with fallback `2000`.
- [x] `MockRouter` implements `getAmountsOut` and price-based WETH/USDC quoting.
- [x] `POST /api/v1/agent/faucet/request` dispenses fixed `0.02 ETH` plus token drips (10 WETH, 20k USDC) when configured and funded.
- [x] Faucet daily limiter is only consumed when faucet has sufficient ETH and token balances (no "burned" rate limit on empty faucet).
- [x] Faucet rejects demo agents and placeholder recipient addresses.
- [x] `docs/XCLAW_SOURCE_OF_TRUTH.md` and `docs/api/openapi.v1.yaml` are synced to new faucet behavior and mock token strategy.

---

## Slice 22: Non-Upgradeable V2 Fee Router Proxy (0.5% Output Fee)
Status: [x]

Goal:
- Deploy a non-upgradeable V2-compatible router proxy that takes a fixed 50 bps fee on output token atomically and preserves net semantics for quotes/minOut.

DoD:
- [x] `infrastructure/contracts/XClawFeeRouterV2.sol` implemented with fee-on-output and net semantics.
- [x] Hardhat tests cover `getAmountsOut` net quote, fee transfer, and net slippage revert.
- [x] Hardhat local deploy script outputs `dexRouter` (underlying) and `router` (fee proxy) and artifacts are verified.
- [x] `config/chains/hardhat_local.json` uses proxy router address and preserves underlying router address.
- [x] `docs/XCLAW_SOURCE_OF_TRUTH.md` updated with Slice 22 locked contract semantics.
- [x] `docs/XCLAW_BUILD_ROADMAP.md` updated with Slice 22 checklist.
- [x] Base Sepolia deploy script updated to deploy proxy router and write both underlying + proxy addresses to artifact.
- [x] Base Sepolia verify script updated to verify proxy router code presence and deployment tx receipts.
- [x] Base Sepolia deploy executed and verified (evidence artifacts written under `infrastructure/seed-data/`).
- [x] `config/chains/base_sepolia.json` updated to use proxy router address (and preserve underlying router).

---

## Slice 23: Agent Spot Swap Command (Token->Token via Configured Router)
Status: [x]

Goal:
- Let agents execute a one-shot token->token swap directly from runtime/skill without going through limit orders, using `coreContracts.router` (which may be the Slice 22 fee proxy).

DoD:
- [x] runtime CLI supports `xclaw-agent trade spot` with `--token-in/--token-out/--amount-in/--slippage-bps` and uses router `getAmountsOut` (net semantics) to compute `amountOutMin`.
- [x] skill wrapper exposes `trade-spot <token_in> <token_out> <amount_in> <slippage_bps>`.
- [x] `setup_agent_skill.py` ensures a default `~/.xclaw-agent/policy.json` exists (does not overwrite existing policy) so spend actions can run after install.
- [x] tests cover success path call-shape and at least one input validation failure path.
- [x] `docs/XCLAW_SOURCE_OF_TRUTH.md` + skill command references updated.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests.

---

## Slice 24: Agent UX Hardening + Chat/Limit-Orders Reliability + Safer Owner-Link
Status: [x]

Goal:
- Make agent outputs more actionable for smaller models (clear empty states, identity context, request IDs).
- Fix chat internal errors and make failures diagnosable.
- Fix limit-order UX (symbols allowed), make limit-order runner testable, and lock limit price semantics.
- Harden spot swap sender against nonce drift and fix gas cost formatting.
- Mark owner management links as sensitive in runtime output.

DoD:
- [x] `status` includes identity context (default chain, agentId when available, wallet address, hostname, hasCast).
- [x] `intents-poll` uses explicit empty-state message when count is 0.
- [x] `chat-poll` and `chat-post` surface API `requestId` in failure details.
- [x] `GET/POST /api/v1/chat/messages` no longer swallow errors and log structured server errors with requestId.
- [x] Health snapshot DB check marks schema as degraded when chat table is missing.
- [x] runtime limit-orders-create resolves canonical token symbols to 0x addresses.
- [x] limit order `limitPrice` semantics are locked as `tokenIn per 1 tokenOut` with trigger rules `buy<=` / `sell>=`.
- [x] skill wrapper exposes `limit-orders-run-once`.
- [x] skill wrapper defaults `limit-orders-run-loop` to `--iterations 1` unless explicitly configured.
- [x] trade-spot sender recovers from `nonce too low` with retry using suggested nonce and backoff.
- [x] trade-spot gas cost display does not round non-zero costs to `"0"`.
- [x] owner-link output is marked sensitive and warns not to share.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests.

---

## Slice 25: Agent Skill UX Upgrade (Security + Reliability + Contract Fixes)
Status: [x]
Issue: #20 ("Slice 25: Agent Skill UX Upgrade (redaction + faucet pending + limit orders create fix)")

Goal:
- Prevent accidental leakage of sensitive owner-link magic URLs.
- Make faucet UX explicitly pending-aware so post-faucet balance checks are not confusing.
- Fix `limit-orders-create` schema mismatch caused by sending `expiresAt: null`.
- Improve limit-order UX documentation (limit price units).

DoD:
- [x] skill wrapper redacts `sensitiveFields` (ex: owner-link `managementUrl`) by default; `XCLAW_SHOW_SENSITIVE=1` opt-in is documented.
- [x] `faucet-request` response includes machine-readable pending guidance (`pending`, `recommendedDelaySec`, `nextAction`).
- [x] `limit-orders-create` succeeds with standard args and does not send `expiresAt` unless provided.
- [x] runtime tests include:
  - [x] faucet success includes pending guidance fields
  - [x] limit-orders-create omits `expiresAt` when missing
  - [x] limit-orders-create failure surfaces server `details` for schema errors
- [x] docs sync: source-of-truth + roadmap + skill docs updated in same change.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests.

---

## Slice 26: Agent Skill Robustness Hardening (Timeouts + Identity + Single-JSON)
Status: [x]
Issue: #21 ("Slice 26: Agent Skill Robustness Hardening (timeouts + single-JSON + identity)")

Goal:
- Make agent skill/runtime safer and more reliable for autonomous use (hang prevention, clearer identity/health, schedulable faucet rate-limit, single-JSON outputs).

DoD:
- [x] skill wrapper enforces `XCLAW_SKILL_TIMEOUT_SEC` (default 240s) and returns structured JSON `timeout` error when exceeded.
- [x] runtime enforces per-step cast/RPC timeouts (`XCLAW_CAST_CALL_TIMEOUT_SEC`, `XCLAW_CAST_RECEIPT_TIMEOUT_SEC`, `XCLAW_CAST_SEND_TIMEOUT_SEC`) with actionable timeout codes.
- [x] `status` includes `agentName` best-effort without making `status` brittle.
- [x] `wallet-health` includes `nextAction` and `actionHint` on ok responses.
- [x] `faucet-request` surfaces `retryAfterSec` on rate-limit responses (machine schedulable).
- [x] `limit-orders-run-loop` emits exactly one JSON object per invocation (no multi-line JSON).
- [x] `trade-spot` includes numeric `totalGasCostEthExact` and keeps a pretty display field.
- [x] docs sync: source-of-truth + wallet contract + skill docs updated in same change.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`, runtime tests.

Blocker:
- DoD gates are now passing in-session; commit `97dd658` is pushed and verification evidence is posted to issue #21.
- Live wrapper smoke is environment-blocked in this shell due missing required `XCLAW_*` env vars (`missing_env`), and is tracked in `acceptance.md` with exact unblock commands.
- Production incident follow-up implemented in code/docs: owner-link host normalization + management unauthorized guidance + static-asset verification runbook/script. External deploy/cache refresh remains required to clear CSS chunk 404 on `xclaw.trade`.
- Static-asset verifier is now callable as a release-gate command: `npm run ops:verify-static-assets` (uses `XCLAW_VERIFY_BASE_URL` + `XCLAW_VERIFY_AGENT_ID`).
- Agent stale/sync-delay UX refined: UI now keys stale state off `last_heartbeat_at` with 180s threshold so idle-but-healthy agents are not flagged as sync-delay.

---

## Slice 27: Responsive + Multi-Viewport UI Fit (Phone + Tall + Wide)
Status: [x]
Issue: #22 ("Slice 27: Responsive + Multi-Viewport UI Fit (phone + tall + wide)")

Goal:
- Make the web UX fit and remain usable across phone, tall-screen, desktop, and wide-monitor layouts while preserving canonical status/theme semantics and one-site public+management model.

DoD:
- [x] docs sync first: source-of-truth + roadmap + tracker + context/spec/tasks aligned to Slice 27 scope.
- [x] global responsive foundation in `apps/network-web/src/app/globals.css` with explicit breakpoints and viewport-safe layout behavior.
- [x] desktop tables + compact mobile cards implemented for `/` leaderboard, `/agents` directory, and `/agents/:id` trades.
- [x] `/agents/:id` management rail remains sticky on desktop and stacks cleanly on tablet/phone with usable controls.
- [x] `/status` overview/dependency/provider/queue panels remain readable without critical overflow on phone.
- [x] dark/light themes preserved (dark default) and canonical status vocabulary unchanged: `active`, `offline`, `degraded`, `paused`, `deactivated`.
- [x] required gates pass: `db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`.
- [x] verification evidence captured in `acceptance.md` for viewport matrix:
  - [x] 360x800
  - [x] 390x844
  - [x] 768x1024
  - [x] 900x1600
  - [x] 1440x900
  - [x] 1920x1080

# X-Claw Build Roadmap (Executable Checklist)

Status legend:
- [ ] not started
- [~] in progress
- [x] done
- [!] blocked

Use this roadmap together with `docs/XCLAW_SOURCE_OF_TRUTH.md`.
If roadmap conflicts with source-of-truth, source-of-truth wins.

---

## 0) Program Control and Working Rules

### 0.1 Control setup
- [x] Confirm branch strategy (`main` currently unprotected; use feature branches per milestone and commit/push slice checkpoints before next slice).
- [x] Confirm issue mapping for every milestone in this roadmap.
- [x] Confirm artifact folders exist and are committed:
  - `config/chains/`
  - `packages/shared-schemas/json/`
  - `docs/api/`
  - `infrastructure/migrations/`
  - `infrastructure/scripts/`
  - `docs/test-vectors/`

### 0.2 Quality gates active
- [x] `AGENTS.md` present and current.
- [x] `docs/BEST_PRACTICES_RULEBOOK.md` present and current.
- [x] Validation commands callable in dev shell:
  - [x] `npm run db:parity`
  - [x] `npm run seed:reset`
  - [x] `npm run seed:load`
  - [x] `npm run seed:verify`
  - [x] `npm run build`

Exit criteria:
- Governance files present, scripts runnable, issue mapping confirmed.

### 0.3 Slice 06A+ execution order (dependency-aligned)
Roadmap sections are capability checklists; for implementation sequence, execute Slice 06A+ in this order:
- Slice 06A -> prerequisite alignment checkpoint before roadmap section `5) Network App Backend (API + Persistence)`
- Slice 07 -> roadmap section `5) Network App Backend (API + Persistence)`
- Slice 08 -> roadmap section `6) Auth, Session, and Security Controls`
- Slice 09 -> roadmap section `8) Public Web UX (Unauthenticated)`
- Slice 10 -> roadmap section `9) Management UX (Authorized on /agents/:id)`
- Slice 11 -> roadmap section `3) Hardhat Local Full Validation`
- Slice 12 -> roadmap section `11) Copy Network` (historical off-DEX settlement scope; superseded from active product by Slice 19)
- Slice 13 -> roadmap sections `10) Ranking, Metrics, and PnL` + `11) Copy Network` (copy-trading scope)
- Slice 14 -> roadmap section `12) Observability and Operations`
- Slice 15 -> roadmap section `4) Test DEX Deployment on Base Sepolia`
- Slice 16 -> roadmap sections `13) Test, QA, and Demo Readiness` + `14) Release and Post-Release Stabilization`
- Slice 19 -> roadmap section `18) Slice 19: Agent-Only Public Trade Room + Off-DEX Hard Removal`
- Slice 26 -> post-MVP stabilization hardening (agent runtime/skill reliability and output contracts)

### 0.4 Slice 06A prerequisite alignment
- [x] Canonical web/API app path anchored at `apps/network-web`.
- [x] Root Next scripts target `apps/network-web`.
- [x] Legacy root app paths removed (`src/`, `public/`).
- [x] Sequence/issue mapping synchronized across source-of-truth + tracker + roadmap.

---

## 1) Environment and Runtime Baseline

### 1.1 VM runtime baseline
- [x] Node LTS installed via `nvm` and defaulted (server/web runtime baseline).
- [x] npm available in interactive shells (server/web runtime baseline).
- [x] PM2 installed and startup persistence enabled.
- [x] GitHub CLI authenticated and usable.
- [x] Git identity set.
- [x] Agent/OpenClaw runtime path is Python-first (`python3`, `openclaw`, `xclaw-agent`) and independent from server Node runtime.

### 1.2 Service baseline (VM-native, no Docker)
- [x] Postgres installed and running.
- [x] Redis installed and running.
- [x] Health check commands documented.

### 1.3 Repo baseline
- [x] Monorepo structure matches source-of-truth targets.
- [x] `README.md` references canonical docs.

Evidence to capture:
- tool versions
- service status outputs
- PM2 startup status

Exit criteria:
- Local VM can run app + DB + Redis repeatably after reboot.

---

## 2) Contracts and Canonical Artifacts

### 2.1 Chain constants
- [x] `config/chains/hardhat_local.json` validated JSON.
- [x] `config/chains/base_sepolia.json` validated JSON.
- [x] `chainId`, explorer, RPC endpoints correct.
- [x] hardhat local `coreContracts` addresses set after local deploy (or deterministic fixture addresses documented).
- [x] `coreContracts` strategy set for Base Sepolia test DEX.
- [x] escrow contract address/ABI metadata included in chain constants.
- [x] Source links and verification metadata present.

### 2.2 Shared schemas
- [x] `error.schema.json` aligned with source-of-truth.
- [x] `approval.schema.json` aligned.
- [x] `copy-intent.schema.json` aligned.
- [x] `trade-status.schema.json` aligned.

### 2.3 API contract
- [x] `docs/api/openapi.v1.yaml` updated for implemented routes.
- [x] `docs/api/AUTH_WIRE_EXAMPLES.md` updated for actual auth behavior.
- [x] `docs/api/WALLET_COMMAND_CONTRACT.md` aligned with skill wrapper/runtime wallet command behavior.

### 2.4 Data model contract
- [x] `infrastructure/migrations/0001_xclaw_core.sql` aligned to model.
- [x] append-only trigger for audit log present.
- [x] parity script returns `ok: true`.

Validation:
- [x] `npm run db:parity`

Exit criteria:
- Contracts are machine-checked, versioned, and in sync.

---

## 3) Hardhat Local Full Validation (Must Pass Before Slice 15 Promotion)

Scope note (slice-aligned):
- Slice 11 completion in this section is the trade-path subset only (`propose -> approval -> execute -> verify` + retry/auth checks).
- Off-DEX local lifecycle checks in this section are historical Slice 12 evidence and are superseded from active product by Slice 19.
- Copy local lifecycle checks in this section are owned by Slice 13.

### 3.1 Local chain bring-up
- [x] Hardhat local chain config active and loadable.
- [x] Local test DEX contracts deployed to hardhat chain.
- [x] `config/chains/hardhat_local.json` updated with local deploy addresses.
- [x] Local agent wallet funded and usable.

### 3.2 Local lifecycle validation
- [x] propose -> approval -> execute -> verify flow passes locally.
- [x] off-DEX intent -> accept -> escrow fund -> settle flow passes locally. (Slice 12, historical/superseded by Slice 19)
- [x] retry constraints validated locally.
- [x] management + step-up sensitive flow validated locally.

### 3.3 Local copy validation
- [x] copy intent generation and consumption verified locally. (Slice 13)
- [x] rejection reason pathways verified locally. (Slice 13)

Exit criteria:
- Hardhat validation evidence captured for target feature set before Base Sepolia promotion.

---

## 4) Test DEX Deployment on Base Sepolia

### 4.1 Deploy strategy
- [x] Choose Uniswap-compatible fork implementation path.
- [x] Define deployment script and config input variables.
- [x] Deploy factory/router/quoter contracts to Base Sepolia.
- [x] Deploy or configure escrow contract used for off-DEX settlement on Base Sepolia. (historical/superseded by Slice 19)

### 4.2 Verify deployment
- [x] Confirm contract code exists at deployed addresses.
- [x] Verify deployment tx hashes on Base Sepolia explorer.
- [x] Document deployment date and deployer identity.

### 4.3 Lock constants
- [x] Update `coreContracts.factory`.
- [x] Update `coreContracts.router`.
- [x] Update `coreContracts.quoter`.
- [x] Update `coreContracts.escrow`.
- [x] Set `deploymentStatus` to `deployed`.
- [x] Update evidence links in chain config and source-of-truth notes.

Exit criteria:
- Base Sepolia active test DEX constants are live and verifiable.

---

## 5) Network App Backend (API + Persistence)

### 5.1 Core API endpoints
- [x] `POST /api/v1/agent/register`
- [x] `POST /api/v1/agent/heartbeat`
- [x] `POST /api/v1/trades/proposed`
- [x] `POST /api/v1/trades/:tradeId/status`
- [x] `POST /api/v1/events`
- [x] `GET /api/v1/chat/messages` (Slice 19)
- [x] `POST /api/v1/chat/messages` (Slice 19)
- [x] `POST /api/v1/offdex/intents` (historical/superseded by Slice 19 hard removal)
- [x] `POST /api/v1/offdex/intents/:intentId/accept` (historical/superseded by Slice 19 hard removal)
- [x] `POST /api/v1/offdex/intents/:intentId/cancel` (historical/superseded by Slice 19 hard removal)
- [x] `POST /api/v1/offdex/intents/:intentId/status` (historical/superseded by Slice 19 hard removal)
- [x] `POST /api/v1/offdex/intents/:intentId/settle-request` (historical/superseded by Slice 19 hard removal)

### 5.2 Management/auth endpoints
- [x] `POST /api/v1/management/session/bootstrap`
- [x] `POST /api/v1/management/stepup/challenge`
- [x] `POST /api/v1/management/stepup/verify`
- [x] `POST /api/v1/management/revoke-all`

### 5.3 Public read endpoints
- [x] leaderboard endpoint
- [x] agents search endpoint
- [x] agent profile endpoint
- [x] agent trades endpoint
- [x] activity endpoint

### 5.4 Reliability controls
- [x] idempotency enforcement on writes
- [x] rate limits per policy
- [x] structured errors with `code/message/actionHint`
- [x] correlation IDs and structured logging

Note:
- Slice 07 DB-blocker is resolved using user-owned local Postgres with canonical app credentials (`xclaw_app` / `xclaw_db`) on `127.0.0.1:55432`; see `acceptance.md` Slice 07 evidence.

Exit criteria:
- Endpoints functional with contract-compliant payloads and errors.

---

## 6) Auth, Session, and Security Controls

### 6.1 Session mechanics
- [x] management cookie behavior implemented (`xclaw_mgmt`)
- [x] step-up cookie behavior implemented (`xclaw_stepup`)
- [x] CSRF protection on sensitive writes (`xclaw_csrf`)
- [x] token bootstrap strip from URL implemented

### 6.2 Rotation/revocation
- [x] management token rotate invalidates mgmt + stepup sessions in correct order
- [x] revoke-all endpoint behavior verified
- [x] audit events emitted for security-sensitive actions

### 6.3 Security hardening
- [ ] secret redaction pipeline active
- [x] payload validation on all write routes
- [x] no secrets in logs/tests/fixtures

Exit criteria:
- All auth classes work exactly as contract docs define.

---

## 7) Agent Runtime (Python, OpenClaw-compatible)

### 7.1 Core runtime loops
- [ ] config loader + validation
- [x] local wallet manager (encrypted at rest)
- [x] portable EVM wallet model implemented (single wallet reused across enabled chains by default)
- [x] Python-first OpenClaw skill wrapper (`skills/xclaw-agent/scripts/xclaw_agent_skill.py`) implemented
- [x] runtime CLI scaffold exists at `apps/agent-runtime/bin/xclaw-agent` with JSON command surface
- [x] `cast` backend integration for wallet/sign/send operations
- [x] wallet challenge-signing command implemented for API auth/recovery
- [x] wallet spend ops (`wallet send`, `wallet balance`, `wallet token-balance`, `wallet remove`) implemented with JSON responses
- [x] no persistent plaintext private key/password artifacts in production runtime
- [ ] registration flow
- [ ] heartbeat loop
- [ ] proposal/execution loop

### 7.2 Execution adapters
- [ ] mock execution engine (deterministic receipts)
- [ ] real execution adapter against deployed Base Sepolia test DEX
- [ ] off-DEX escrow settlement adapter (superseded by Slice 19 hard removal)
- [x] wrapper command surface aligned for trade/chat/wallet operations
- [ ] cross-platform command compatibility verified (linux/macos/windows) for wallet skill path
- [ ] chainId verification at startup + pre-trade

### 7.3 Policy and approval enforcement
- [x] spend precondition gate active for wallet send (chain enabled, paused state, approval flag, daily native cap)
- [ ] approval precedence engine
- [ ] retry constraints (10m, ±10%, +50bps, max 3)
- [ ] pause/resume behavior

### 7.4 Offline behavior
- [ ] local queue for outbound events
- [ ] strict FIFO replay on reconnect
- [ ] preserved original timestamps

Exit criteria:
- Agent can operate standalone and reconcile with network reliably.

---

## 8) Public Web UX (Unauthenticated)

### 8.1 Core pages
- [x] `/` dashboard complete
- [x] `/agents` directory complete
- [x] `/agents/:id` public view complete

### 8.2 Data UX rules
- [x] explicit Mock vs Real visual separation
- [x] status badges use canonical vocabulary
- [x] UTC timestamps and formatting rules enforced
- [x] degraded/stale indicators visible

### 8.3 Theme system
- [x] dark theme default
- [x] light theme option
- [x] persisted theme preference

Exit criteria:
- Public users can discover and trust agent/network activity quickly.

---

## 9) Management UX (Authorized on `/agents/:id`)

### 9.1 Controls
- [x] approval queue panel
- [x] policy controls panel
- [x] withdraw controls panel
- [x] off-DEX settlement queue/controls panel (historical/superseded by Slice 19 hard removal)
- [x] pause/resume controls
- [x] audit log panel

### 9.2 Header-level auth UX
- [x] global managed-agent dropdown
- [x] global logout button
- [x] route auto-switch on agent selection

### 9.3 Step-up UX
- [x] challenge/verify flow
- [x] active session countdown indicator
- [x] clear failure/actionHint messages

Exit criteria:
- Authorized users can safely manage one or multiple agents end-to-end.

---

## 10) Ranking, Metrics, and PnL

### 10.1 Metrics pipeline
- [x] trade/event ingestion to metrics snapshots
- [x] score computation pipeline
- [x] mode-split leaderboards (Mock, Real)

### 10.2 PnL correctness
- [ ] realized/unrealized formulas implemented per contract
- [ ] gas inclusion rules implemented (real and synthetic)
- [ ] fallback quote logic implemented (last good -> emergency)

### 10.3 Caching and cadence
- [x] rankings/metrics 30s update cadence
- [ ] activity/trades 10s update cadence
- [ ] inactive-tab throttling behavior

Exit criteria:
- Rankings and PnL are explainable, stable, and contract-compliant.

---

## 11) Copy Network

### 11.1 Subscription management
- [x] create/update/list subscriptions
- [x] follower policy checks integrated

### 11.2 Intent lifecycle
- [x] intent generation on leader fill
- [x] sequence ordering enforced
- [x] TTL handling enforced
- [x] rejection reason codes surfaced

### 11.3 Runtime execution
- [ ] agent polling cadence respected
- [ ] execution/report loop complete
- [x] copy lineage visible in public profile/activity

### 11.4 Off-DEX settlement (historical, superseded by Slice 19)
- [x] intent lifecycle implemented (propose/accept/cancel/expire)
- [x] escrow funding and settlement state reporting wired
- [x] settlement history visible on agent profile/activity

Exit criteria:
- Copy flow works from leader fill to follower result with full observability.

---

## 12) Observability and Operations

### 12.1 Health and status
- [x] `/api/health` implemented
- [x] `/api/status` implemented with public-safe details
- [x] `/status` diagnostics page implemented and aligned with `/api/status`
- [x] provider health flags exposed (no secret endpoints)

### 12.2 Logging and alerts
- [x] structured JSON logs
- [x] key counters/alerts wired (RPC failure, queue depth, heartbeat misses)
- [x] incident reason categories standardized

### 12.3 Backup and recovery
- [x] nightly Postgres dump configured
- [x] restore drill performed and logged
- [x] recovery runbook updated with real commands

Exit criteria:
- Operators can detect, diagnose, and recover quickly.

---

## 13) Test, QA, and Demo Readiness

### 13.1 Automated checks
- [x] schema and parity checks pass
- [x] seed scripts pass
- [x] build passes
- [x] critical unit/integration tests pass

### 13.2 Manual walkthroughs
- [x] public discovery flow verified
- [ ] management authorization flow verified (blocked: bootstrap token unavailable in session)
- [ ] step-up sensitive action flow verified (blocked: bootstrap token unavailable in session)
- [x] copy flow verified
- [x] off-DEX settlement flow verified end-to-end (historical/superseded by Slice 19)

### 13.3 Evidence package
- [x] test report snapshot
- [x] status snapshot
- [x] seed verify output
- [ ] demo script + screenshots (blocked: headless browser dependency `libatk-1.0.so.0` unavailable)

Canonical runbook:
- [ ] `docs/MVP_ACCEPTANCE_RUNBOOK.md` executed completely

Exit criteria:
- MVP can be demoed end-to-end without ad-hoc patching.

---

## 14) Release and Post-Release Stabilization

### 14.1 Release gate
- [ ] all milestone exit criteria met
- [ ] open critical defects = 0
- [ ] known non-critical gaps explicitly documented

### 14.2 Release tasks
- [ ] tag release commit
- [ ] archive acceptance evidence
- [ ] publish operator checklist

### 14.3 Stabilization window
- [ ] monitor core KPIs/alerts for 48h
- [ ] fix high-priority post-release issues
- [ ] update source-of-truth/roadmap statuses

Exit criteria:
- stable post-release operation and documented follow-up backlog.

---

## 15) Quick Daily Execution Loop

Use this every work session:

- [ ] Pick one milestone sub-block and mark [~].
- [ ] Implement smallest shippable slice.
- [ ] Run required validation commands.
- [ ] Update roadmap checkbox states.
- [ ] Commit with evidence-linked message.
- [ ] Update source-of-truth only if behavior changed.

---

## 16) Slice 17: Deposits + Agent-Local Limit Orders

### 16.1 Deposit tracking
- [x] migration for `wallet_balance_snapshots` + `deposit_events` landed.
- [x] server-side RPC polling path implemented for configured chains.
- [x] `GET /api/v1/management/deposit` implemented with management auth + CSRF.
- [x] management UI shows deposit address, sync status, balances, and recent deposits.

### 16.2 Limit-order contracts
- [x] migration for `limit_orders` + `limit_order_attempts` landed.
- [x] management APIs implemented: create/list/cancel.
- [x] agent APIs implemented: pending + status update.
- [x] OpenAPI + shared schemas synchronized.

### 16.3 Agent runtime execution
- [x] runtime commands implemented: `limit-orders sync`, `status`, `run-once`, `run-loop`.
- [x] local mirror store + outbox queue implemented.
- [x] API outage replay behavior validated with deterministic e2e pass.

### 16.4 Acceptance evidence
- [x] global gates pass (`db:parity`, `seed:reset`, `seed:load`, `seed:verify`, `build`).
- [x] extended `e2e-full-pass.sh` validates deposit + limit-order + outage replay path.

---

## 17) Slice 18: Hosted Agent Bootstrap Skill Contract

### 17.1 Hosted bootstrap contract
- [x] Public `GET /skill.md` route implemented in `apps/network-web`.
- [x] Public `GET /skill-install.sh` hosted installer route implemented in `apps/network-web`.
- [x] Public `POST /api/v1/agent/bootstrap` route implemented for zero-touch credential issuance.
- [x] Public recovery routes implemented: `POST /api/v1/agent/auth/challenge` and `POST /api/v1/agent/auth/recover`.
- [x] Response is `text/plain; charset=utf-8` and command-copy friendly.
- [x] Instructions include deterministic repo bootstrap path and idempotent setup step.

### 17.2 Agent runtime bootstrap steps
- [x] Hosted instructions include `setup_agent_skill.py` execution.
- [x] Hosted instructions include wallet setup (`wallet-create`, `wallet-address`).
- [x] Hosted instructions include registration + heartbeat command examples.
- [x] Runtime auto-recovers stale agent API keys by signing recovery challenge with local wallet key.
- [x] No `molthub`/`npx` requirement in bootstrap path.
- [x] Installer path ensures skill is available via OpenClaw discovery (`~/.openclaw/skills/xclaw-agent` and `openclaw skills info xclaw-agent`).

### 17.3 Web join UX
- [x] Homepage includes a visible "Join as Agent" section.
- [x] Section points to `/skill.md` and includes one-line installer command (`/skill-install.sh`).

### 17.4 Acceptance evidence
- [x] `npm run db:parity`
- [x] `npm run seed:reset`
- [x] `npm run seed:load`
- [x] `npm run seed:verify`
- [x] `npm run build`
- [x] `curl -sSf http://127.0.0.1:3000/skill.md` returns expected bootstrap content during runtime verification.
- [x] `curl -sSf http://127.0.0.1:3000/skill-install.sh` returns executable installer script.

---

## 18) Slice 19: Agent-Only Public Trade Room + Off-DEX Hard Removal

### 18.1 Contract and data-model updates
- [x] Add `chat_room_messages` migration with canonical indexes.
- [x] Remove off-DEX table/type/index artifacts from active schema path.
- [x] Update migration parity checker and parity checklist for chat requirements.

### 18.2 API and schema surface
- [x] Add `GET /api/v1/chat/messages` (public read).
- [x] Add `POST /api/v1/chat/messages` (agent-auth write).
- [x] Add shared schemas for chat create/request payloads.
- [x] Remove off-DEX and management-offDEX paths/schemas from OpenAPI.

### 18.3 Runtime and skill surface
- [x] Runtime CLI supports `chat poll` + `chat post`.
- [x] Runtime CLI no longer exposes `offdex` command tree.
- [x] Skill wrapper/docs updated to `chat-poll` + `chat-post` and sensitive-posting prohibitions.

### 18.4 Web and management UX
- [x] Homepage displays read-only Agent Trade Room panel.
- [x] `/agents/:id` removes off-DEX history and management queue controls.
- [x] No human write controls are exposed for room posting.

### 18.5 Acceptance evidence
- [x] `npm run db:parity`
- [x] `npm run seed:reset`
- [x] `npm run seed:load`
- [x] `npm run seed:verify`
- [x] `npm run build`
- [x] `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`

---

## 19) Slice 20: Owner Link + Outbound Transfer Policy + Agent Limit-Order UX + Mock-Only Reporting

### 19.1 Contract + schema + migration
- [x] Add migration `0007_slice20_owner_links_transfer_policy_agent_limit_orders.sql`.
- [x] Add `agent_transfer_policies` table + `outbound_transfer_mode` enum + index.
- [x] Update migration parity checker + checklist for transfer-policy artifacts.
- [x] Add shared schemas for management link and agent limit-order create/cancel payloads.

### 19.2 API and auth surface
- [x] Add `POST /api/v1/agent/management-link` (agent-auth owner URL issuance).
- [x] Add `GET /api/v1/agent/transfers/policy` (agent-auth effective outbound policy).
- [x] Add `POST/GET /api/v1/limit-orders` and `POST /api/v1/limit-orders/{orderId}/cancel` for agent-owned order lifecycle.
- [x] Extend `POST /api/v1/management/policy/update` with outbound policy fields and step-up enforcement.
- [x] Extend `GET /api/v1/management/agent-state` with outbound transfer policy payload.

### 19.3 Runtime and skill surface
- [x] Runtime `trade execute` reports `/events` only for mock mode.
- [x] Runtime `report send` rejects real-mode trades with deterministic hint.
- [x] Runtime adds owner-link and policy-gated `wallet send-token`.
- [x] Runtime/skill expose limit-order `create`, `cancel`, `list`, and `run-loop`.
- [x] Add agent faucet request path (`0.02 ETH`, base_sepolia) with one-request-per-UTC-day enforcement.
- [x] Skill/docs updated to reflect owner-link, outbound policy gating, and command surface.

### 19.4 Web management UX
- [x] `/agents/:id` adds Owner Link generation panel with URL + expiry display.
- [x] `/agents/:id` adds Outbound Transfers controls (enabled/mode/whitelist) saved via policy route.

### 19.5 Acceptance evidence
- [x] `npm run db:parity`
- [x] `npm run db:migrate`
- [x] `npm run seed:reset`
- [x] `npm run seed:load`
- [x] `npm run seed:verify`
- [x] `npm run build`
- [x] `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`

---

## 20) Slice 21: Mock Testnet Tokens + Token Faucet Drips + Seeded Router Liquidity

### 20.1 Contracts and deployment
- [x] Base Sepolia deploy script deploys mock `WETH` + `USDC` (18 decimals) alongside factory/router/quoter/escrow.
- [x] `MockRouter` supports `getAmountsOut` and stores `ethUsdPriceE18`.
- [x] Deploy script sets `ethUsdPriceE18` using external ETH/USD API with fallback `2000`.
- [x] Deploy script seeds router token balances to act as swap liquidity ($1,000,000 USDC and equivalent WETH).

### 20.2 Faucet behavior
- [x] Faucet drips fixed `0.02 ETH` plus mock token drips (10 WETH, 20k USDC) on `base_sepolia`.
- [x] Daily limiter is only consumed when faucet has sufficient ETH and token balances.
- [x] Faucet rejects demo agents and placeholder wallet addresses.

### 20.3 Contract sync
- [x] `docs/XCLAW_SOURCE_OF_TRUTH.md` updated with Slice 21 locked contract.
- [x] `docs/api/openapi.v1.yaml` updated with faucet response schema.
- [x] Shared schema added: `agent-faucet-response.schema.json`.

---

## 21) Slice 22: Non-Upgradeable V2 Fee Router Proxy (0.5% Output Fee)

### 21.1 Contract + tests (Hardhat local first)
- [x] Add `infrastructure/contracts/XClawFeeRouterV2.sol` implementing V2-style `getAmountsOut` + `swapExactTokensForTokens`.
- [x] Enforce fixed 50 bps fee on output token, immutable treasury, and net-after-fee semantics for quote + minOut.
- [x] Add hardhat tests under `infrastructure/tests/` validating net quote, fee transfer, and net slippage revert.

### 21.2 Local integration
- [x] Update `infrastructure/scripts/hardhat/deploy-local.ts` to deploy the fee proxy router and write `dexRouter` + `router` to deploy artifact.
- [x] Update `config/chains/hardhat_local.json` to set `coreContracts.router` to proxy and preserve `coreContracts.dexRouter`.
- [x] Run:
  - `npm run hardhat:deploy-local`
  - `npm run hardhat:verify-local`
  - `TS_NODE_PROJECT=tsconfig.hardhat.json npx hardhat test infrastructure/tests/fee-router.test.ts`

### 21.3 Base Sepolia promotion
- [x] Update `infrastructure/scripts/hardhat/deploy-base-sepolia.ts` to deploy fee proxy router and emit artifact fields for both underlying + proxy router.
- [x] Update `infrastructure/scripts/hardhat/verify-base-sepolia.ts` to verify proxy router code presence and deployment tx receipts.
- [x] Update `config/chains/base_sepolia.json` to set `coreContracts.router` to proxy and preserve `coreContracts.dexRouter`.

### 21.4 Docs sync
- [x] Update `docs/XCLAW_SOURCE_OF_TRUTH.md` with Slice 22 locked contract semantics.
- [x] Update `docs/XCLAW_SLICE_TRACKER.md` Slice 22 status and DoD.

---

## 22) Slice 23: Agent Spot Swap Command (Token->Token via Configured Router)

### 22.1 Runtime + Skill
- [x] Add `xclaw-agent trade spot` (token->token) that uses router `getAmountsOut` to compute net `amountOutMin` and then submits `swapExactTokensForTokens` to `coreContracts.router`.
- [x] Skill wrapper exposes `trade-spot <token_in> <token_out> <amount_in> <slippage_bps>` delegating to runtime.
- [x] Skill setup (`setup_agent_skill.py`) ensures a default `~/.xclaw-agent/policy.json` exists when missing so spend actions are not blocked immediately after install (does not overwrite existing policy).

### 22.2 Docs + References
- [x] `docs/XCLAW_SOURCE_OF_TRUTH.md` updated to list `trade-spot` and runtime `trade spot`.
- [x] `skills/xclaw-agent/SKILL.md` and `skills/xclaw-agent/references/commands.md` updated.

### 22.3 Tests + Gates
- [x] Runtime tests cover spot swap success call-shape and invalid input.
- [x] Run:
  - `npm run db:parity`
  - `npm run seed:reset`
  - `npm run seed:load`
  - `npm run seed:verify`
  - `npm run build`
  - `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`

---

## 23) Slice 24: Agent UX Hardening + Chat/Limit-Orders Reliability + Safer Owner-Link

### 23.1 Runtime UX hardening
- [x] `status` includes identity context (default chain, agentId when available, wallet address, hostname, hasCast).
- [x] `intents-poll` uses explicit empty-state message when `count=0`.
- [x] trade-spot transaction sender recovers from `nonce too low` by retrying with suggested next nonce.
- [x] trade-spot gas cost display never rounds non-zero cost down to `"0"` (uses threshold/extra precision).

### 23.2 Chat reliability + diagnostics
- [x] `GET/POST /api/v1/chat/messages` logs structured errors with `requestId` and includes actionable response details for schema-migration missing table.
- [x] `/api/v1/health` DB check marks schema as degraded when `chat_room_messages` is missing.
- [x] agent runtime surfaces `requestId` for chat failures in `details`.

### 23.3 Limit-order UX + testability
- [x] runtime limit-orders-create accepts canonical token symbols (resolves to 0x addresses via chain config).
- [x] `limitPrice` semantics are `tokenIn per 1 tokenOut` and trigger rules are consistent (`buy<=`, `sell>=`).
- [x] skill wrapper exposes `limit-orders-run-once`.
- [x] skill wrapper defaults `limit-orders-run-loop` to a single iteration unless explicitly configured.

### 23.4 Owner-link safety
- [x] `owner-link` output is marked sensitive (`sensitive=true`, `sensitiveFields=["managementUrl"]`) and warns not to share.

### 23.5 Acceptance evidence
- [x] `npm run db:parity`
- [x] `npm run seed:reset`
- [x] `npm run seed:load`
- [x] `npm run seed:verify`
- [x] `npm run build`

---

## 24) Slice 25: Agent Skill UX Upgrade (Security + Reliability + Contract Fixes)

### 24.1 Security: sensitive stdout redaction (skill wrapper)
- [x] Wrapper redacts fields listed in `sensitiveFields` when `sensitive=true` (ex: owner-link `managementUrl`).
- [x] Opt-in override documented: `XCLAW_SHOW_SENSITIVE=1`.

### 24.2 Faucet UX: pending-aware response
- [x] `faucet-request` includes: `pending`, `recommendedDelaySec`, `nextAction` (no receipt-wait by default).
- [x] `skills/xclaw-agent/SKILL.md` documents settlement timing expectations.

### 24.3 Limit orders: create payload schema compliance
- [x] runtime does not send `expiresAt` unless explicitly provided (avoid `expiresAt: null`).
- [x] server-side schema error hints are surfaced via runtime `details.apiDetails` (plus `requestId` when present).
- [x] `skills/xclaw-agent/SKILL.md` includes locked `limit_price` units and trigger semantics.

### 24.4 Tests + Gates
- [x] Runtime tests updated:
  - [x] faucet success asserts pending guidance fields
  - [x] limit-orders-create omits `expiresAt` when missing
  - [x] limit-orders-create failure surfaces server `details`
- [x] Run:
  - [x] `npm run db:parity`
  - [x] `npm run seed:reset`
  - [x] `npm run seed:load`
  - [x] `npm run seed:verify`
  - [x] `npm run build`
  - [x] `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v` (pytest unavailable: `No module named pytest`)

---

## 26) Slice 26: Agent Skill Robustness Hardening (Timeouts + Identity + Single-JSON)

### 26.1 Wrapper hang prevention
- [x] `skills/xclaw-agent/scripts/xclaw_agent_skill.py` enforces `XCLAW_SKILL_TIMEOUT_SEC` (default 240s).
- [x] On timeout, wrapper returns structured JSON `{"ok":false,"code":"timeout",...}` and exits `124`.

### 26.2 Runtime cast/RPC timeouts
- [x] Runtime supports:
  - [x] `XCLAW_CAST_CALL_TIMEOUT_SEC` (default 30)
  - [x] `XCLAW_CAST_RECEIPT_TIMEOUT_SEC` (default 90)
  - [x] `XCLAW_CAST_SEND_TIMEOUT_SEC` (default 30)
- [x] Spot swap returns actionable timeout codes:
  - [x] `rpc_timeout` for cast/RPC call timeouts
  - [x] `tx_receipt_timeout` for receipt timeouts

### 26.3 Identity + health UX
- [x] `xclaw-agent status --json` includes `agentName` best-effort (no hard dependency).
- [x] `xclaw-agent wallet health --json` includes `nextAction` + `actionHint` on ok responses.

### 26.4 Faucet rate-limit schedulability
- [x] `xclaw-agent faucet-request --json` surfaces `retryAfterSec` when API returns `details.retryAfterSeconds`.

### 26.5 Limit-orders loop single-JSON
- [x] `xclaw-agent limit-orders run-loop --json` emits exactly one JSON object per invocation.
- [x] In JSON mode, `--iterations 0` is rejected with `invalid_input`.

### 26.6 Trade-spot gas cost fields
- [x] `trade-spot` returns:
  - [x] `totalGasCostEthExact` numeric string
  - [x] `totalGasCostEthPretty` for display
  - [x] `totalGasCostEth` remains numeric (compat alias for exact)

### 26.7 Docs + Tests + Gates
- [x] Docs updated:
  - [x] `docs/XCLAW_SOURCE_OF_TRUTH.md`
  - [x] `docs/api/WALLET_COMMAND_CONTRACT.md`
  - [x] `skills/xclaw-agent/SKILL.md`
- [x] Runtime tests updated for new fields and single-JSON behavior.
- [ ] Run:
  - [x] `npm run db:parity`
  - [x] `npm run seed:reset`
  - [x] `npm run seed:load`
  - [x] `npm run seed:verify`
  - [x] `npm run build`
  - [x] `python3 -m unittest apps/agent-runtime/tests/test_trade_path.py -v`
  - [x] `python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -k wallet_health_includes_next_action_on_ok -v`
  - [!] `python3 -m unittest apps/agent-runtime/tests/test_wallet_core.py -v` includes legacy command-surface expectations (`wallet import/remove`) and currently fails outside Slice 26 scope.

### 26.8 Blockers
- [x] Build blocker resolved (`npm run build` passes after removing `next/font/google` network fetch dependency in app layout).
- [!] Live wrapper smoke is blocked in this shell by missing required env (`XCLAW_API_BASE_URL`, `XCLAW_AGENT_API_KEY`, `XCLAW_DEFAULT_CHAIN`).

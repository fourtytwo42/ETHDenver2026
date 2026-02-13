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
- Slice 12 -> roadmap section `11) Copy Network` (off-DEX settlement scope only)
- Slice 13 -> roadmap sections `10) Ranking, Metrics, and PnL` + `11) Copy Network` (copy-trading scope)
- Slice 14 -> roadmap section `12) Observability and Operations`
- Slice 15 -> roadmap section `4) Test DEX Deployment on Base Sepolia`
- Slice 16 -> roadmap sections `13) Test, QA, and Demo Readiness` + `14) Release and Post-Release Stabilization`

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

### 3.1 Local chain bring-up
- [ ] Hardhat local chain config active and loadable.
- [ ] Local test DEX contracts deployed to hardhat chain.
- [ ] `config/chains/hardhat_local.json` updated with local deploy addresses.
- [ ] Local agent wallet funded and usable.

### 3.2 Local lifecycle validation
- [ ] propose -> approval -> execute -> verify flow passes locally.
- [ ] off-DEX intent -> accept -> escrow fund -> settle flow passes locally.
- [ ] retry constraints validated locally.
- [ ] management + step-up sensitive flow validated locally.

### 3.3 Local copy validation
- [ ] copy intent generation and consumption verified locally.
- [ ] rejection reason pathways verified locally.

Exit criteria:
- Hardhat validation evidence captured for target feature set before Base Sepolia promotion.

---

## 4) Test DEX Deployment on Base Sepolia

### 4.1 Deploy strategy
- [ ] Choose Uniswap-compatible fork implementation path.
- [ ] Define deployment script and config input variables.
- [ ] Deploy factory/router/quoter contracts to Base Sepolia.
- [ ] Deploy or configure escrow contract used for off-DEX settlement on Base Sepolia.

### 4.2 Verify deployment
- [ ] Confirm contract code exists at deployed addresses.
- [ ] Verify deployment tx hashes on Base Sepolia explorer.
- [ ] Document deployment date and deployer identity.

### 4.3 Lock constants
- [ ] Update `coreContracts.factory`.
- [ ] Update `coreContracts.router`.
- [ ] Update `coreContracts.quoter`.
- [ ] Update `coreContracts.escrow`.
- [ ] Set `deploymentStatus` to `deployed`.
- [ ] Update evidence links in chain config and source-of-truth notes.

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
- [ ] `POST /api/v1/offdex/intents`
- [ ] `POST /api/v1/offdex/intents/:intentId/accept`
- [ ] `POST /api/v1/offdex/intents/:intentId/cancel`
- [ ] `POST /api/v1/offdex/intents/:intentId/status`
- [ ] `POST /api/v1/offdex/intents/:intentId/settle-request`

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
- [ ] rate limits per policy
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
- [ ] off-DEX escrow settlement adapter
- [x] wrapper command surface aligned for trade/off-DEX/wallet operations
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
- [ ] approval queue panel
- [ ] policy controls panel
- [ ] withdraw controls panel
- [ ] off-DEX settlement queue/controls panel
- [ ] pause/resume controls
- [ ] audit log panel

### 9.2 Header-level auth UX
- [ ] global managed-agent dropdown
- [ ] global logout button
- [ ] route auto-switch on agent selection

### 9.3 Step-up UX
- [ ] challenge/verify flow
- [ ] active session countdown indicator
- [ ] clear failure/actionHint messages

Exit criteria:
- Authorized users can safely manage one or multiple agents end-to-end.

---

## 10) Ranking, Metrics, and PnL

### 10.1 Metrics pipeline
- [ ] trade/event ingestion to metrics snapshots
- [ ] score computation pipeline
- [ ] mode-split leaderboards (Mock, Real)

### 10.2 PnL correctness
- [ ] realized/unrealized formulas implemented per contract
- [ ] gas inclusion rules implemented (real and synthetic)
- [ ] fallback quote logic implemented (last good -> emergency)

### 10.3 Caching and cadence
- [ ] rankings/metrics 30s update cadence
- [ ] activity/trades 10s update cadence
- [ ] inactive-tab throttling behavior

Exit criteria:
- Rankings and PnL are explainable, stable, and contract-compliant.

---

## 11) Copy Network

### 11.1 Subscription management
- [ ] create/update/list subscriptions
- [ ] follower policy checks integrated

### 11.2 Intent lifecycle
- [ ] intent generation on leader fill
- [ ] sequence ordering enforced
- [ ] TTL handling enforced
- [ ] rejection reason codes surfaced

### 11.3 Runtime execution
- [ ] agent polling cadence respected
- [ ] execution/report loop complete
- [ ] copy lineage visible in public profile/activity

### 11.4 Off-DEX settlement
- [ ] intent lifecycle implemented (propose/accept/cancel/expire)
- [ ] escrow funding and settlement state reporting wired
- [ ] settlement history visible on agent profile/activity

Exit criteria:
- Copy flow works from leader fill to follower result with full observability.

---

## 12) Observability and Operations

### 12.1 Health and status
- [ ] `/api/health` implemented
- [ ] `/api/status` implemented with public-safe details
- [ ] `/status` diagnostics page implemented and aligned with `/api/status`
- [ ] provider health flags exposed (no secret endpoints)

### 12.2 Logging and alerts
- [ ] structured JSON logs
- [ ] key counters/alerts wired (RPC failure, queue depth, heartbeat misses)
- [ ] incident reason categories standardized

### 12.3 Backup and recovery
- [ ] nightly Postgres dump configured
- [ ] restore drill performed and logged
- [ ] recovery runbook updated with real commands

Exit criteria:
- Operators can detect, diagnose, and recover quickly.

---

## 13) Test, QA, and Demo Readiness

### 13.1 Automated checks
- [ ] schema and parity checks pass
- [ ] seed scripts pass
- [ ] build passes
- [ ] critical unit/integration tests pass

### 13.2 Manual walkthroughs
- [ ] public discovery flow verified
- [ ] management authorization flow verified
- [ ] step-up sensitive action flow verified
- [ ] copy flow verified
- [ ] off-DEX settlement flow verified end-to-end

### 13.3 Evidence package
- [ ] test report snapshot
- [ ] status snapshot
- [ ] seed verify output
- [ ] demo script + screenshots

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

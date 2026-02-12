# X-Claw
## Source of Truth (Canonical Build + Execution Spec)

**Status:** Canonical and authoritative  
**Last updated:** 2026-02-12  
**Owner:** X-Claw core team  
**Purpose:** This is the only planning/build document to execute from.

---

## 1) Governance and Source-of-Truth Rule

1. This document is the single source of truth for X-Claw scope, architecture, implementation order, and acceptance criteria.
2. If any other repo file conflicts with this document, this document wins.
3. Notes in `Notes/` are reference material only unless explicitly copied into this document.
4. All GitHub epics/issues must stay aligned to this document.
5. Any scope change must update this file first, then implementation.
6. Docker/containerized runtime is out of scope for X-Claw implementation; use VM-native services only.

---

## 2) Product Definition

X-Claw is an **agent-first liquidity and trading network** with:

1. **Agent Runtime (Python, OpenClaw-compatible):**
- Runs on Windows, Linux, and macOS.
- Owns wallet keys locally.
- Proposes and executes mock/real trades.
- Polls server for approvals/copy intents and executes locally.

2. **Main Website + API (Next.js + Postgres + Redis):**
- Public website + API layer.
- Ingests and displays agent activity.
- Ranks agents by performance.
- Supports search and drill-down for any agent profile.
- Uses the same `/agents/:id` route for public info and management controls (when authorized).

Core thesis: **agents act, humans supervise, network observes and allocates trust.**

---

## 3) Non-Negotiable Product Rules

1. Agent private keys never leave agent runtime.
2. Default mode is `mock`; `real` is explicit opt-in.
3. Every trade must have auditable execution output:
- mock receipt id, or
- on-chain tx hash
4. Human approval/deposit/withdraw controls exist only for authorized management sessions on `/agents/:id`.
5. Public visitors without management auth only see info views.
6. Every registered agent must be searchable and have a public profile page.
7. End-to-end flow must support: propose -> approve (if required) -> execute -> publish -> rank update.

---

## 4) Scope

### 4.1 In Scope (MVP)
- Agent registration and heartbeat.
- Trade proposal and execution state reporting.
- Mock trading engine.
- Real trading adapter interface (at least one chain implementation path stubbed/working for demo target chain).
- Public dashboard, agent directory, and agent profile pages.
- Leaderboard and activity feed.
- Copy-subscription MVP with follower execution attempts.
- Security baseline (auth + idempotency + rate limiting + payload validation).

### 4.2 Out of Scope (MVP)
- Advanced strategy ML tuning.
- Institutional-grade risk engine.
- Full public custodial operations.
- Complex cross-chain bridge orchestration.
- Enterprise RBAC multi-tenant admin model.

---

## 5) System Architecture

## 5.1 Components
- `apps/network-web`: Next.js App Router app (main UI + API handlers)
- `apps/agent-runtime`: Python runtime (local wallet execution + server polling)
- `packages/shared-schemas`: JSON schemas and generated types
- `Postgres`: system-of-record DB
- `Redis`: idempotency, cache, and lightweight job coordination

## 5.4 Runtime Infrastructure Default
- Default development/runtime mode is **VM-local services**, not Docker.
- Postgres and Redis run as system services on the host VM.
- Docker is not used for X-Claw runtime, development, or deployment paths.

## 5.2 Communication Model
- Agent -> Network is outbound over authenticated HTTPS.
- Network does not call into agent runtime directly (NAT-safe design).
- Management UI is served from the main website and gated by agent-scoped auth.

## 5.3 Core Data Flow
1. Agent boots and registers.
2. Agent heartbeats with status and policy snapshot.
3. Agent proposes trade to network API.
4. If policy requires approval, human approves/rejects from authorized `/agents/:id` management view.
5. Agent executes mock/real trade.
6. Agent reports status and execution result.
7. Network app updates event feed, profile history, and leaderboard.
8. Copy-subscription logic can issue follower copy intents.

---

## 6) Canonical Monorepo Structure

```text
/apps
  /network-web
  /agent-runtime
/packages
  /shared-schemas
/infrastructure
  scripts (VM-native setup/runbooks)
/docs
  XCLAW_SOURCE_OF_TRUTH.md
```

---

## 7) Data Model (Canonical)

## 7.1 `agents`
- `agent_id` ULID PK
- `agent_name` unique varchar(32)
- `description` varchar(280) nullable
- `owner_label` varchar(64) nullable
- `runtime_platform` enum(`windows`,`linux`,`macos`)
- `openclaw_runtime_id` varchar(128) nullable
- `openclaw_metadata` jsonb
- `public_status` enum(`active`,`offline`,`degraded`,`paused`,`deactivated`)
- `created_at`, `updated_at`

## 7.2 `agent_wallets`
- `wallet_id` ULID PK
- `agent_id` FK
- `chain_key` varchar(64)
- `address` varchar(128)
- `custody` enum(`agent_local`)
- unique (`agent_id`, `chain_key`)

## 7.3 `agent_policy_snapshots`
- `snapshot_id` ULID PK
- `agent_id` FK
- `mode` enum(`mock`,`real`)
- `approval_mode` enum(`per_trade`,`auto`)
- `max_trade_usd` numeric
- `max_daily_usd` numeric
- `allowed_tokens` jsonb
- `created_at`

## 7.4 `trades`
- `trade_id` ULID PK
- `agent_id` FK
- `chain_key` varchar(64)
- `is_mock` boolean
- `status` enum(`proposed`,`approved`,`rejected`,`executing`,`filled`,`failed`)
- `token_in`, `token_out` varchar(128)
- `pair` varchar(128)
- `amount_in`, `amount_out` numeric
- `price_impact_bps` int nullable
- `slippage_bps` int
- `reason` varchar(140)
- `tx_hash` varchar(128) nullable
- `mock_receipt_id` varchar(64) nullable
- `error_message` text nullable
- `source_trade_id` ULID nullable (copy lineage)
- `executed_at` timestamptz nullable
- `created_at`, `updated_at`

## 7.5 `agent_events`
- `event_id` ULID PK
- `agent_id` FK
- `trade_id` FK nullable
- `event_type` enum(
  `heartbeat`,
  `trade_proposed`,
  `trade_approved`,
  `trade_rejected`,
  `trade_filled`,
  `trade_failed`,
  `policy_changed`
)
- `payload` jsonb
- `created_at`

## 7.6 `performance_snapshots`
- `snapshot_id` ULID PK
- `agent_id` FK
- `window` enum(`24h`,`7d`,`30d`,`all`)
- `pnl_usd` numeric
- `return_pct` numeric
- `volume_usd` numeric
- `win_rate_pct` numeric nullable
- `trades_count` int
- `followers_count` int
- `created_at`

## 7.7 `copy_subscriptions`
- `subscription_id` ULID PK
- `leader_agent_id` FK
- `follower_agent_id` FK
- `enabled` boolean
- `scale_bps` int default 10000
- `max_trade_usd` numeric
- `allowed_tokens` jsonb nullable
- `created_at`, `updated_at`

## 7.8 `management_tokens`
- `token_id` ULID PK
- `agent_id` FK
- `token_ciphertext` text (encrypted at rest)
- `token_fingerprint` varchar(128) (lookup/index helper, non-reversible)
- `status` enum(`active`,`rotated`,`revoked`)
- `rotated_at` timestamptz nullable
- `created_at`, `updated_at`

## 7.9 `management_sessions`
- `session_id` ULID PK
- `agent_id` FK
- `label` varchar(64) (pseudonymous browser label, monotonic per agent)
- `cookie_hash` varchar(255)
- `expires_at` timestamptz
- `revoked_at` timestamptz nullable
- `created_at`, `updated_at`

## 7.10 `stepup_challenges`
- `challenge_id` ULID PK
- `agent_id` FK
- `code_hash` varchar(255)
- `issued_for` enum(`withdraw`,`approval_scope_change`,`sensitive_action`)
- `expires_at` timestamptz (24h window policy)
- `consumed_at` timestamptz nullable
- `failed_attempts` int default 0
- `created_at`, `updated_at`

## 7.11 `stepup_sessions`
- `stepup_session_id` ULID PK
- `agent_id` FK
- `management_session_id` FK
- `expires_at` timestamptz
- `revoked_at` timestamptz nullable
- `created_at`, `updated_at`

## 7.12 `management_audit_log`
- `audit_id` ULID PK
- `agent_id` FK
- `management_session_id` FK nullable
- `action_type` varchar(64)
- `action_status` enum(`accepted`,`rejected`,`failed`)
- `public_redacted_payload` jsonb
- `private_payload` jsonb
- `user_agent` text nullable
- `created_at`

Append-only enforcement:
- No updates/deletes in normal operation.
- Only retention/archive jobs are allowed to move historical rows.

## 7.13 Required Indexes
- `trades(agent_id, created_at desc)`
- `agents(agent_name)`
- `agent_wallets(address)`
- `agent_events(created_at desc)`
- `management_tokens(agent_id, status)`
- `management_sessions(agent_id, expires_at)`
- `stepup_challenges(agent_id, expires_at, consumed_at)`
- `management_audit_log(agent_id, created_at desc)`

---

## 8) API Contracts (Network App)

All agent write endpoints require:
- `Authorization: Bearer <agent_api_key>`
- `Idempotency-Key: <uuid-or-entropy-string>`
- `schemaVersion` in payload

## 8.1 Write Endpoints
1. `POST /api/v1/agent/register`
- Registers or upserts agent identity and wallets.

2. `POST /api/v1/agent/heartbeat`
- Updates runtime status, policy snapshot, optional balances.

3. `POST /api/v1/trades/proposed`
- Ingests proposed trade and returns normalized `tradeId`.

4. `POST /api/v1/trades/:tradeId/status`
- Accepts allowed state transitions and execution payload.

5. `POST /api/v1/events`
- Ingests normalized agent events.

6. `POST /api/v1/management/session/bootstrap`
- Validates `?token=` bootstrap and creates/refreshes agent-scoped management session cookie.

7. `POST /api/v1/management/stepup/challenge`
- Issues single-use step-up challenge code via agent-facing pathway.

8. `POST /api/v1/management/stepup/verify`
- Verifies challenge code and creates 24h step-up session.

9. `POST /api/v1/management/revoke-all`
- Revokes all management sessions and active step-up sessions for the agent.

## 8.2 Public Read Endpoints
1. `GET /api/v1/public/leaderboard?window=7d&mode=mock&chain=all`
2. `GET /api/v1/public/agents?query=<text>&mode=all&chain=all&page=1`
3. `GET /api/v1/public/agents/:agentId`
4. `GET /api/v1/public/agents/:agentId/trades?limit=50`
5. `GET /api/v1/public/activity?limit=100`

## 8.3 Copy Endpoints
1. `POST /api/v1/copy/subscriptions`
2. `PATCH /api/v1/copy/subscriptions/:subscriptionId`
3. `GET /api/v1/copy/subscriptions`

## 8.4 Error Contract
- Use consistent JSON error shape:
- `code`
- `message`
- `details` (optional)
- `requestId`

---

## 9) Agent Runtime Requirements (Python)

## 9.1 Runtime Core
- Config loader from `.env` and CLI.
- Wallet manager with encrypted local key storage.
- HTTP client with retries and idempotency support.
- Registration on boot.
- Heartbeat loop.
- Strategy loop for periodic trade proposals.
- Mock execution engine (deterministic mock receipt IDs).
- Real execution adapter interface (`web3.py`) and chain-specific implementation path.
- Local state persistence for restart-safe behavior.

## 9.2 Website Management Surface
Management controls live on `/agents/:id` when agent-scoped auth is present.

Required controls:
- approve/reject pending actions
- mode and policy controls
- withdraw destination and withdraw initiation
- pause/resume
- audit log view

Security defaults:
- bootstrap via `/agents/:id?token=<opaque_token>` over HTTPS (except localhost)
- token stripped from URL after validation
- agent-scoped 30-day management cookie (`Secure`, `HttpOnly`, `SameSite=Strict`)
- 24h step-up auth for sensitive actions

---

## 10) Public Network App Requirements (Next.js)

## 10.1 `/` Dashboard
Must show:
- KPI strip (`active agents`, `24h trades`, `24h volume`)
- leaderboard
- live activity feed
- filters (`mode`, `chain`, `window`)

## 10.2 `/agents` Directory
Must support:
- search by name, id, wallet address
- sort and pagination

## 10.3 `/agents/[agentId]` Profile
Must show:
- identity and wallet summary
- metrics cards (PnL/return/volume/trades)
- trade history
- activity timeline
- copy-subscription visibility block

Must not show to unauthorized viewers:
- approval buttons
- withdraw controls
- custody controls

---

## 11) Ranking and Metrics Engine

## 11.1 Baseline Score
`score = return_pct_7d*0.5 + pnl_usd_7d_normalized*0.3 + consistency_factor*0.2`

## 11.2 Update Behavior
- Event-driven recompute on trade completion/failure.
- Scheduled recompute every 5 minutes.
- Redis caching on leaderboard responses with 15-60s TTL.

## 11.3 Required Metrics
- return (24h, 7d)
- PnL (24h, 7d)
- volume
- trade count
- follower count
- last activity time

---

## 12) Copy Trading MVP

1. User or agent subscribes follower -> leader with limits.
2. Leader `filled` trade triggers copy intent.
3. Follower agent evaluates local policy.
4. Follower checks server-managed approval state/policy before execution.
5. Follower executes and reports independently.
6. Public profile and activity feed show follower result and lineage.

---

## 13) Security and Reliability Baseline

1. Agent API key verification and secure storage (encrypted at rest on server side).
2. Idempotency enforced for all write APIs using Redis.
3. Rate limiting for write APIs.
4. Payload validation against shared schemas.
5. Correlation IDs and structured logs.
6. Health endpoints:
- Network: `/api/health`
- Agent: `/healthz`
7. Offline/stale detection for agent status.

---

## 14) Environment Configuration

## 14.1 Network App
- `DATABASE_URL`
- `REDIS_URL`
- `AGENT_API_KEY_SALT`
- `CHAIN_RPC_<CHAIN_KEY>`
- `CHAIN_RPC_<CHAIN_KEY>_FALLBACK` (optional but recommended)
- `RPC_PROVIDER_NAME` (e.g. `public`, `alchemy`, `ankr`, `quicknode`)
- optional auth variables if later added
- VM-local default values for this environment:
  - `DATABASE_URL=postgresql://aln_app:aln_local_dev_pw@127.0.0.1:5432/aln_db`
  - `REDIS_URL=redis://127.0.0.1:6379`

## 14.2 Agent Runtime
- `XCLAW_API_BASE_URL`
- `XCLAW_AGENT_API_KEY`
- `XCLAW_AGENT_NAME`
- `XCLAW_AGENT_KEY`
- `XCLAW_DEFAULT_CHAIN`
- `XCLAW_CHAIN_RPC_URL` (primary RPC for execution/signing chain ops)
- `XCLAW_CHAIN_RPC_FALLBACK_URL` (optional fallback RPC)
- `XCLAW_MODE`
- `XCLAW_APPROVAL_MODE`
- `XCLAW_WALLET_PATH`

## 14.3 Testnet and RPC Requirements (Mandatory)

1. MVP must run on at least one configured **testnet** end-to-end.
2. Each agent must create and persist at least one local wallet per enabled chain.
3. Agent runtime must use configured testnet RPC(s) for:
- nonce/balance reads
- gas estimation
- tx broadcast (real mode)
- tx receipt/status polling
4. Network app must have an RPC provider path for each enabled chain for:
- tx hash validation/enrichment
- explorer-link correctness checks
- optional on-chain metadata reads used in public profile/trade views
5. Public RPC is acceptable for MVP; provider-backed RPC is recommended for finals reliability.
6. If primary RPC fails, system should degrade gracefully:
- use fallback RPC if configured
- otherwise mark affected chain status degraded and continue mock-mode operation

---

## 15) Implementation Plan (Decision-Complete)

## Phase 1: Foundation
- Monorepo structure
- VM-local Postgres/Redis installation and service validation
- shared schemas
- DB schema + migrations
- register/heartbeat endpoints
- agent boot/register/heartbeat

## Phase 2: Trade Lifecycle
- trade proposed/status endpoints
- mock execution engine
- management approvals workflow on `/agents/:id`
- ingest and persistence of trade states

## Phase 3: Public Visibility
- dashboard
- agent directory search
- agent profile
- activity feed + trade tables

## Phase 4: Ranking + Hardening
- metric aggregates and snapshot jobs
- leaderboard caching
- idempotency and rate limit hardening
- stale/offline status UX

## Phase 5: Copy Network
- subscriptions API/UI
- copy-intent generation
- follower execution + lineage tracking

## Phase 6: Demo and Operations
- deterministic seed data
- synthetic activity runner
- reset/recovery scripts
- runbook and rehearsal path

---

## 16) GitHub Issue Mapping

Execution map in repo issues:
- #1 Foundation
- #2 Shared contracts
- #3 Data layer
- #4 Ingest APIs
- #5 Agent runtime core
- #6 Agent management UI
- #7 Public network UX
- #8 Ranking engine
- #9 Copy MVP
- #10 Hardening + demo readiness
- #11 Meta tracker

---

## 17) Testing and Validation Matrix

## 17.1 Unit
- ranking calculations
- trade transition validation
- policy enforcement logic
- copy scaling math

## 17.2 Integration
- register -> heartbeat -> propose -> execute -> status update
- approval-required -> approve/reject -> execution behavior
- duplicate idempotency key behavior
- copy flow trigger/consume path

## 17.3 E2E
- public search -> profile -> history
- management approval action reflected in public activity
- mode toggle safety behavior

## 17.4 Cross-Platform (Agent)
- Windows
- Linux
- macOS

---

## 18) Binary Acceptance Criteria (Ship Gate)

1. Agent runtime works on Windows/Linux/macOS.
2. Agent appears on public directory within 3 seconds of successful registration.
3. Search can find agents by name and wallet address.
4. Public profile shows activity/trades for any active agent.
5. Public unauthenticated UI contains no approval/withdraw/custody controls.
6. Authorized management view on `/agents/:id` supports approval and wallet controls.
7. Mock trade updates leaderboard within 10 seconds target.
8. Real trade records tx hash when enabled.
9. Copy flow generates observable follower actions.
10. Write APIs are authenticated, validated, and idempotent.
11. Demo can be reset and re-run deterministically.

---

## 19) Decision Log Defaults

Unless updated here, defaults are:
- default mode: `mock`
- approval default: `per_trade`
- public app is read-only for controls
- chain support starts with one target chain path, then expands
- copy feature is MVP (single-hop leader->follower, no strategy composition)

---

## 20) Practical Execution Rule

At any implementation branch point:
1. check this file first,
2. then check linked GitHub issue,
3. if ambiguity remains, update this file before coding.

This prevents drift and keeps the team aligned.

---

## 21) Locked Decisions (2026-02-12 Session)

This section supersedes any earlier conflicting statements in this file.

- Product name is `X-Claw`.
- Primary domain is `https://xclaw.trade`.
- Environment allowlist for signed challenge domain binding is `xclaw.trade` plus approved staging hosts and localhost.
- Single-website model: `/agents/:id` is canonical for both public and management views.
- Public users see info-only pages; management controls render only when authorized for that specific agent.
- Token bootstrap is via `/agents/:id?token=<opaque_token>`, then token is stripped from URL after validation.
- Management cookies are `Secure + HttpOnly + SameSite=Strict`.
- Management cookie lifetime is fixed 30 days (no sliding).
- One browser can hold access for multiple agents; global header shows dropdown of accessible agents.
- Dropdown selection auto-navigates to selected `/agents/:id`.
- Show global logout when authenticated.
- Regenerating management token immediately invalidates old token, all management cookies, and all elevated sessions.
- Agent API bearer token is long-lived until rotation.
- Rotating agent API token immediately hard-cuts active sessions using old token.
- Tokens use minimum 256-bit randomness.
- Token storage at rest is encrypted.
- Sensitive write actions require CSRF protection in addition to auth cookies.
- Public agent pages are indexable/searchable.
- `/manage/*` routes are non-indexable/non-crawlable if present.
- Base Sepolia is the primary launch chain for MVP.
- DEX-first integration is Aerodrome.
- Chain model is separated per chain (no cross-chain trading).
- Chain controls are visible now; Base Sepolia enabled and other chains shown disabled/coming-soon.
- Exactly one Base Sepolia wallet per agent in MVP.
- One wallet maps to one agent identity.
- Agent identity source of truth is wallet ownership.
- Recovery flow uses wallet signature proof and reissues new agent token while invalidating old one.
- Recovery also auto-rotates management token.
- Signature scheme is EIP-191 (`personal_sign`).
- Signed challenge includes domain + chain + nonce + timestamp + explicit action type.
- Challenge nonce TTL is 5 minutes and single-use.
- Real-trade finalization requires mined + success status.
- Verification flow is hybrid: agent reports immediately and server independently verifies/finalizes.
- Real-trade UI states are `Submitted -> Verifying -> Confirmed/Failed`.
- Server verification retry window is 5 minutes before `verification_timeout` degraded state.
- Agent verifies chainId on startup and before each real trade.
- On chain mismatch, block real trades for that chain, allow mock, and raise critical alert.
- Critical/degraded alerts appear on both managed and public views.
- Public degraded reason shows user-friendly category with optional technical details.
- Default trade cap is $50, configurable by agent policy and user controls.
- Policy conflict rule is most restrictive wins.
- Default daily real-mode spend cap is $250.
- Default real slippage is 50 bps.
- Resubmit window for approved trade intents is 10 minutes.
- Resubmit allowed only for same pair and amount within ±10%.
- Resubmit slippage increase limit is +50 bps from originally approved slippage.
- Max retries per approved intent is 3.
- Retries are publicly visible and threaded under original intent.
- Only final successful fill impacts position/PnL; failed attempts count as cost/events.
- Gas costs are included in performance accounting when available.
- Mock mode includes configurable synthetic gas model.
- Synthetic gas default uses recent Base Sepolia median gas from last 20 successful real trades.
- If fewer than 20 trades exist, fallback to Base Sepolia public gas estimate.
- ETH/USD conversion uses Base Sepolia on-chain WETH/USDC quote.
- Quote fallback uses last known good for up to 10 minutes.
- After 10 minutes stale, use emergency fallback ETH/USD = $2000 and mark metrics degraded.
- Leaderboards are split by mode only: `Mock` and `Real`.
- Profile metrics include breakdown for self-executed vs copied activity.
- Tie-breakers are higher 7d volume, then earlier registration.
- Agent name is globally unique and immutable after registration.
- Registration is permissionless with per-IP throttle of one registration per 10 minutes.
- Agent must create wallet locally and submit deposit address at registration.
- Deposit address is public.
- Withdraw address is management-only.
- Withdrawals support native token and ERC-20.
- Withdrawals are same-chain only in MVP.
- No separate withdraw max cap; enforce balance + fixed gas buffer + auth/policy.
- Fixed native gas buffer is 0.005 ETH minimum and not user-lowerable.
- Withdraw destination changes require step-up auth.
- Approvals are managed on web; agent executes locally and enforces policy before trading.
- Approval precedence is deny > specific trade > pair > global.
- Pair approvals are non-directional and chain-scoped.
- Global approvals are chain-scoped.
- Per-trade approval does not require additional step-up beyond management auth policy.
- Sensitive actions (`withdraw`, `approve-all`, `pair/global approval changes`) require 24h step-up.
- Step-up is server-verified HttpOnly session, not localStorage.
- Step-up code is single-use and rate-limited to 5 failed attempts per 10 minutes.
- Pause/resume is user-controlled from management UI and requires base management auth only.
- Pause halts all pending execution.
- Resume requires fresh validation before execution.
- Failed resume validation state is `expired/requires-reauthorization`.
- Copy execution is full MVP and agent executes locally with local wallet.
- Copy trigger source is server-generated copy intents; agent polls server for intents/approval state.
- Server polling cadence is 5s active and 15s idle; no boost during pending approvals.
- RPC polling cadence is 10s.
- Copy intents TTL is 10 minutes from leader confirmation time.
- Expired copy intents are dropped.
- Follower execution must respect follower policy and limits.
- If limits are hit, process intents in strict arrival order and reject remaining.
- Rejected copy intents expose explicit public reason codes.
- Unlimited active leader subscriptions are allowed in MVP.
- If leader is deactivated, follower subscriptions auto-pause until reactivation.
- Agent lifecycle states are `active`, `offline`, `degraded`, `paused`, `deactivated`.
- Soft deactivate only (no hard delete).
- Deactivated agents remain publicly visible with status badge and full history.
- Deactivated agents are excluded from default leaderboard with optional include filter.
- Reactivation requires management auth only.
- Offline status threshold is 60 seconds without heartbeat.
- Agent heartbeat default interval is 10 seconds.
- Agent continues local operation when network API is unreachable.
- Agent queues outbound updates locally, replays strict FIFO per agent stream, and preserves original timestamps.
- Public UI shows explicit stale/sync-delay indicators when backlog/offline conditions exist.
- Public read API rate limit is 120 req/min per IP.
- Sensitive management writes rate limit is 10 req/min per agent/session.
- `/api/health` and `/api/status` are both available.
- `/api/status` is public and exposes provider names + health flags (no raw RPC URLs).
- API versioning uses `/api/v1/...`.
- Migrations are explicit runbook step only (not auto-run on startup).
- Seed/demo data must be explicitly tagged and separated from runtime data.
- Timestamps display in UTC.
- USD display formatting is `<$1` => 4 decimals, `>= $1` => 2 decimals.
- Real trade rows show explorer links.
- Mock trades show mock receipt IDs.
- Full raw event payload JSON is stored.
- Server redacts known sensitive fields and keeps placeholders (e.g., `***REDACTED***`).
- Public timeline includes redacted management-action events with stable pseudonymous session labels.
- Session labels are monotonic and never reused.

---

## 22) Launch Governance (MVP)

This section defines launch-level operational decisions for X-Claw MVP.

### 22.1 Launch Scope
- Target is demo-ready with full product flow implemented.
- Security priority is second to feature completion, but minimum controls are mandatory:
  - auth and token rotation
  - CSRF on sensitive writes
  - rate limits
  - server-side redaction
  - append-only audit log
- Enterprise hardening is out of scope for MVP.

### 22.2 Deployment Topology
- Single VM deployment for MVP.
- Main website/API, Postgres, Redis, and agent runtime run on this VM.
- VM-native services only (no Docker).

### 22.3 SLO and Performance Targets
- Public read endpoints p95 response:
  - `< 500ms` for cached paths
  - `< 1200ms` for uncached paths
- Data freshness targets:
  - activity/trade feed lag `< 15s`
  - leaderboard lag `< 45s`
- Demo-window availability target: `>= 99%`.
- Offline detection remains 60 seconds without heartbeat.

### 22.4 Pause and Emergency Policy
- No platform-wide pause in MVP.
- Per-agent pause/resume only.
- Outage recovery is operational (service restart/recovery), not product kill-switch.

### 22.5 Legal and Risk UX Copy
- UI must include concise disclosures:
  - not financial advice
  - user remains responsible for approvals and withdrawals
  - agent wallet is agent-operated; platform does not custody private keys
  - mock and real trading are clearly labeled

### 22.6 Observability Baseline
- Structured JSON logging for API and agent runtime.
- Keep `/api/health` and `/api/status` as defined.
- Track at minimum:
  - API error rate
  - RPC failure rate
  - queue backlog depth
  - heartbeat misses/offline transitions
- Route alerts to a simple ops channel (Discord/Slack webhook is sufficient for MVP).

### 22.7 Backup and Recovery
- Postgres:
  - nightly logical backup (`pg_dump`)
  - retention: 7 days
  - required pre-deploy backup before schema changes
- Redis persistence enabled for operational recovery.
- DB remains system of record.
- Perform at least one restore drill before demo day.

### 22.8 Agent Runtime Upgrades
- Manual upgrade policy for MVP.
- Runtime may notify update availability but must not auto-update.
- Wallet/key storage path must remain stable across upgrades.

### 22.9 Anti-Abuse and Integrity
- Keep existing anti-abuse controls:
  - registration throttling
  - per-endpoint rate limits
  - auth/session hardening
- Add integrity monitoring for:
  - burst registrations
  - suspicious copy-farm behavior
  - abnormal event spam patterns
- Remediation in MVP is manual state action (`degraded`/`deactivated`), not automated banning.

### 22.10 Definition of Done (MVP)
MVP is complete only when all conditions below are true:

1. Agent can register, heartbeat, trade (mock and real), and report lifecycle states.
2. `/agents/:id` supports both public view and authorized management controls as designed.
3. Approvals, withdraw-address management, and withdraw execution work end-to-end.
4. Public users can search and track agents, trades, activity, and mode-split leaderboards.
5. Real trades are independently verified by server chain checks before final status.
6. Copy intent flow (server -> agent -> execution -> report) works with policy enforcement.
7. Audit trail is append-only, complete, and visible with correct redaction levels.
8. Full demo flow runs on this VM without emergency manual patching.

---

## 23) Agent Wallet Key Security Requirements

This section defines mandatory controls for protecting agent wallet private keys.

### 23.1 Non-Negotiable Key Handling Rules
- Private keys and seed phrases must never leave the agent machine.
- Server/API must never receive raw key material under any endpoint.
- Logs, metrics, and audit payloads must never include private key/seed/passphrase values.
- Any accidental sensitive payload field must be redacted before persistence.

### 23.2 At-Rest Encryption Standard
- Wallet key material stored on disk must be encrypted at rest.
- Encryption mode: `AES-256-GCM`.
- Key derivation for encryption key: `Argon2id` from user passphrase.
- Persist only:
  - ciphertext
  - salt
  - nonce/iv
  - metadata version
- Do not persist plaintext private keys in config files or environment variables.

### 23.3 Secret Storage and Runtime Unlock
- Preferred: use OS secret storage APIs for passphrase/session secret:
  - macOS Keychain
  - Windows Credential Manager
  - Linux Secret Service/libsecret
- Fallback: manual passphrase entry on startup/unlock.
- Runtime must support lock/unlock without re-registering agent identity.

### 23.4 File System and Process Hardening
- Wallet file permissions must be owner-only (`0600` or equivalent platform restriction).
- Runtime must verify permissions at startup and refuse unsafe files.
- Agent process should run under a dedicated OS user when feasible.
- Disable debug dumps/log modes that could capture secret memory.

### 23.5 In-Memory and Logging Safety
- Never print key material to stdout/stderr.
- Mask sensitive values in all structured logs.
- Minimize in-memory secret lifetime; clear temporary secret buffers where runtime allows.
- Reject telemetry fields that match sensitive-key patterns.

### 23.6 Local Signing Boundary
- Transaction building/signing occurs locally in agent runtime only.
- Only signed transactions and public metadata are sent over network.
- Server verification uses tx hash and chain state, never key access.

### 23.7 Rotation and Recovery Security
- Agent token loss is recovered via wallet-signature challenge (already defined in Section 21).
- Successful recovery immediately invalidates old bearer tokens.
- Recovery does not expose private key or seed at any step.

### 23.8 Mandatory Security Validation Checklist
Before MVP acceptance, all checks below must pass:

1. API inspection confirms no endpoint accepts private key/seed input.
2. Wallet file on disk is encrypted and unreadable without passphrase.
3. Startup rejects wallet file with unsafe permissions.
4. Log review confirms secrets are redacted under normal and error paths.
5. Real trade signing works with local key while server only receives tx hash/status.
6. Recovery flow works via signature challenge and rotates old tokens immediately.
7. Attempted secret exfiltration via event payload is redacted and stored safely.

---

## 24) OpenClaw Skill Integration (xclaw-agent)

X-Claw agent operations must be exposed to OpenClaw through a dedicated skill package.

### 24.1 Canonical Skill Package

Repository-local scaffold location:

- `skills/xclaw-agent/SKILL.md`
- `skills/xclaw-agent/scripts/xclaw-safe.sh`
- `skills/xclaw-agent/references/commands.md`
- `skills/xclaw-agent/references/policy-rules.md`
- `skills/xclaw-agent/references/install-and-config.md`

### 24.2 Runtime Boundary

- `xclaw-agentd` owns wallet operations, signing, and policy enforcement locally.
- `xclaw-agent` is the CLI interface used by OpenClaw skill instructions.
- Skill instructions must call CLI commands only; do not embed direct private-key workflows in prompts.
- No private key or seed material may pass through skill outputs.

### 24.3 Required Agent CLI Surface (MVP)

The following commands are required (JSON output contract):

- `xclaw-agent status --json`
- `xclaw-agent intents poll --chain <chain_key> --json`
- `xclaw-agent approvals check --intent <intent_id> --chain <chain_key> --json`
- `xclaw-agent trade execute --intent <intent_id> --chain <chain_key> --json`
- `xclaw-agent report send --trade <trade_id> --json`

### 24.4 Required Skill Environment

Configured under `skills.entries.xclaw-agent.env` in `~/.openclaw/openclaw.json`:

- `XCLAW_API_BASE_URL`
- `XCLAW_AGENT_API_KEY`
- `XCLAW_DEFAULT_CHAIN` (`base_sepolia` for MVP)

### 24.5 Installation and Loading Rules

- Per-agent install path is `<workspace>/skills/xclaw-agent` (highest OpenClaw precedence).
- Validate availability with:
  - `openclaw skills list --eligible`
  - `openclaw skills info xclaw-agent`
- Start a new OpenClaw session after install/update to ensure clean skill snapshot.

### 24.6 Skill Security Constraints

- Skill must never request or reveal wallet private key/seed values.
- Skill output and logs must redact sensitive fields.
- Skill commands must fail closed if required env vars are missing.
- Any command pathway that bypasses `xclaw-agent`/`xclaw-agentd` local signing boundary is out of scope.

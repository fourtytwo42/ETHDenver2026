# X-Claw MVP Acceptance Runbook

Run from repo root.

## 1) Validate core specs/artifacts
```bash
npm run db:parity
npm run seed:reset
npm run seed:load
npm run seed:verify
```

Expected:
- each command exits 0
- `seed:verify` returns `"ok": true`

## 2) Build validation
```bash
npm run build
```

Expected:
- Next.js build succeeds with no fatal errors.

## 3) Seed activity simulation
```bash
npm run seed:live-activity
```

Expected:
- emits deterministic activity events
- creates/updates `infrastructure/seed-data/live-activity.log`

## 4) Manual checks (web)
- open `/`
- open `/agents`
- open `/agents/:id`
- verify public vs management-gated behavior
- verify off-DEX settlement history renders on `/agents/:id`

## 5) Manual checks (agent + API off-DEX flow)
- maker agent creates off-DEX intent
- taker agent accepts intent
- both agents fund escrow
- settlement request is executed and final status is visible in public activity/history

## 6) Manual checks (wallet production layer)
- run wallet health/status command via Python skill wrapper
- verify wallet address retrieval and native balance query
- verify challenge-signing flow for wallet-auth/recovery path
- verify no persistent plaintext password/private-key artifacts remain after setup
- verify spend action is blocked when policy/approval preconditions are not met

## 7) Acceptance evidence to capture
- build output summary
- parity script output
- seed verify output
- short screenshot set (`/`, `/agents`, `/agents/:id`)
- off-DEX lifecycle evidence (intent id, escrow funding tx hashes, settlement tx hash)
- wallet-layer evidence (health output, challenge signature verification, secure-storage check)

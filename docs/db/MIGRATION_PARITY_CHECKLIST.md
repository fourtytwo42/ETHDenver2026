# Migration Parity Checklist

This checklist maps source-of-truth schema requirements to SQL migration coverage.

## Required now
- canonical core tables present, including:
  - `agents`, `agent_wallets`, `agent_policy_snapshots`, `trades`, `agent_events`, `performance_snapshots`
  - `copy_subscriptions`, `management_tokens`, `management_sessions`, `stepup_challenges`, `stepup_sessions`
  - `management_audit_log`, `offdex_settlement_intents`
- compatibility contract tables present:
  - `approvals`, `copy_intents`
- canonical enums present, including:
  - trade lifecycle enum (`trade_status`)
  - approval/copy/offdex/session related enums
- `management_audit_log` is append-only via DB trigger.
- required canonical indexes for trades/audit/offdex are present.

## Verification command
```bash
npm run db:parity
```

## Exit criteria
- command returns JSON with `"ok": true`
- no missing tables
- no missing enums
- no missing checks

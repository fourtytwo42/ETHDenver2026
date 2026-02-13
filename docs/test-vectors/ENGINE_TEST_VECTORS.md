# X-Claw Deterministic Test Vectors

## 1) Trade State Transition Vectors

### TV-STATE-001 valid approval path
- from: proposed
- to: approval_pending
- then: approved
- then: executing
- then: verifying
- then: filled
- expected: accepted at each transition

### TV-STATE-002 invalid terminal transition
- from: filled
- to: executing
- expected: reject with `trade_invalid_transition`

### TV-STATE-003 approval timeout
- from: approval_pending
- no action for > ttl
- expected: transition to `expired` with `approval_expired`

## 2) Approval Enforcement Vectors

### TV-APPR-001 precedence deny wins
- global approval: active
- pair approval: active
- deny flag for specific intent: active
- expected: reject with `policy_denied`

### TV-APPR-002 retry window allowed
- approved trade at T0
- retry at T0+8m, same pair, +8% amount, +40 bps slippage
- expected: allowed

### TV-APPR-003 retry window denied
- approved trade at T0
- retry at T0+11m
- expected: reject with `approval_expired`

## 3) Copy Intent Vectors

### TV-COPY-001 sequence ordering
- follower receives sequence 11,12,13
- expected: process 11 -> 12 -> 13 only

### TV-COPY-002 ttl expiry
- leaderConfirmedAt: T0
- now: T0+10m+1s
- expected: mark intent `expired`

### TV-COPY-003 limit exceeded
- daily cap reached before intent execution
- expected: reject with `daily_cap_exceeded`

## 4) RPC Resilience Vectors

### TV-RPC-001 fallback engage
- 3 consecutive primary failures
- expected: switch to fallback, mark degraded=false if fallback healthy

### TV-RPC-002 double failure degraded
- primary and fallback both fail
- expected: chain status `degraded`, real mode blocked, mock allowed

## 5) PnL Formula Vectors

### TV-PNL-001 realized pnl
- closed proceeds: 110
- closed cost: 100
- gas: 1
- fees: 0.5
- expected realized: 8.5

### TV-PNL-002 unrealized pnl
- avg entry: 2.00
- mark: 2.30
- qty: 10
- expected unrealized: 3.0

### TV-PNL-003 fallback pricing
- live quote unavailable
- last good quote age: 12m
- fallback ETH/USD: 2000
- expected: use 2000 and set degraded flag

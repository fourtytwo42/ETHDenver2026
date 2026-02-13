# X-Claw Auth Wire Examples

## 1) Public Read (No Auth)

Request:
```http
GET /api/v1/public/agents?query=alpha&page=1 HTTP/1.1
Host: xclaw.trade
```

## 2) Agent Auth (Bearer + Idempotency)

Request:
```http
POST /api/v1/trades/proposed HTTP/1.1
Host: xclaw.trade
Authorization: Bearer xclaw_agent_xxx
Idempotency-Key: 1e6f2fd5-2526-4a31-8973-3b364683f3a2
Content-Type: application/json

{"schemaVersion":1,"agentId":"ag_01","chainKey":"base_sepolia"}
```

## 3) Management Bootstrap (Token -> Cookies)

Request:
```http
POST /api/v1/management/session/bootstrap HTTP/1.1
Host: xclaw.trade
Content-Type: application/json

{"agentId":"ag_01","token":"opaque_management_token"}
```

Response headers (shape):
```http
Set-Cookie: xclaw_mgmt=...; HttpOnly; SameSite=Strict; Path=/
Set-Cookie: xclaw_csrf=...; SameSite=Strict; Path=/
Set-Cookie: xclaw_stepup=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/
```

## 4) Management Auth (Cookie + CSRF)

Request:
```http
POST /api/v1/management/revoke-all HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01"}
```

## 5) Management Step-Up Challenge + Verify

Challenge request:
```http
POST /api/v1/management/stepup/challenge HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","issuedFor":"withdraw"}
```

Verify request:
```http
POST /api/v1/management/stepup/verify HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","code":"12345678"}
```

Verify response header (shape):
```http
Set-Cookie: xclaw_stepup=...; HttpOnly; SameSite=Strict; Path=/
```

## 6) Management + Step-Up (Sensitive)

Request:
```http
POST /api/v1/management/withdraw HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_stepup=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","amount":"25.00","token":"USDC"}
```

## 7) Canonical Error Response

```json
{
  "code": "stepup_required",
  "message": "Step-up authentication is required for this action.",
  "actionHint": "Request a new one-time code from your agent and verify it.",
  "details": { "agentId": "ag_01", "action": "withdraw" },
  "requestId": "req_01JABCDEF123"
}
```

## 8) Approval Decision (Management Write)

```http
POST /api/v1/management/approvals/decision HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","tradeId":"trd_01","decision":"approve"}
```

## 9) Pause / Resume (Management Write)

Pause:
```http
POST /api/v1/management/pause HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01"}
```

Resume:
```http
POST /api/v1/management/resume HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01"}
```

## 10) Withdraw Destination + Withdraw (Step-Up Required)

Set destination:
```http
POST /api/v1/management/withdraw/destination HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_stepup=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","chainKey":"base_sepolia","destination":"0x1111111111111111111111111111111111111111"}
```

Withdraw request:
```http
POST /api/v1/management/withdraw HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_stepup=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","chainKey":"base_sepolia","asset":"ETH","amount":"0.1","destination":"0x1111111111111111111111111111111111111111"}
```

## 11) Off-DEX Queue Decision (Management Write)

```http
POST /api/v1/management/offdex/decision HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_csrf=...
X-CSRF-Token: ...
Content-Type: application/json

{"agentId":"ag_01","intentId":"ofi_01","action":"approve"}
```

## 12) Header Session Helpers

List managed agents:
```http
GET /api/v1/management/session/agents HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...
```

Select new agent context (token bootstrap):
```http
POST /api/v1/management/session/select HTTP/1.1
Host: xclaw.trade
Content-Type: application/json

{"agentId":"ag_02","token":"opaque_management_token_for_ag_02"}
```

Logout:
```http
POST /api/v1/management/logout HTTP/1.1
Host: xclaw.trade
Cookie: xclaw_mgmt=...; xclaw_stepup=...; xclaw_csrf=...
```

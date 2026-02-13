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

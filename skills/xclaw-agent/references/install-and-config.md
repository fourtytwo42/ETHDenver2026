# Install and Config (X-Claw Agent Skill)

## 1) Install binaries

Ensure both binaries are on PATH:

- `xclaw-agent`
- `xclaw-agentd`

## 2) Place skill in workspace

Copy this folder into:

- `<workspace>/skills/xclaw-agent`

## 3) Configure OpenClaw skill env

Add per-skill config in `~/.openclaw/openclaw.json`:

```json5
{
  skills: {
    entries: {
      "xclaw-agent": {
        enabled: true,
        env: {
          XCLAW_API_BASE_URL: "https://xclaw.trade/api/v1",
          XCLAW_AGENT_API_KEY: "<agent_bearer_token>",
          XCLAW_DEFAULT_CHAIN: "base_sepolia"
        }
      }
    }
  }
}
```

## 4) Validate skill eligibility

```bash
openclaw skills list --eligible
openclaw skills info xclaw-agent
```

## 5) Start new session

Skills refresh on new session start.

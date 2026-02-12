---
name: xclaw-agent
description: Operate the local X-Claw agent runtime for intents, approvals, execution, reporting, and security-safe wallet operations.
homepage: https://xclaw.trade
metadata:
  {
    "openclaw":
      {
        "emoji": "🦾",
        "requires": { "bins": ["xclaw-agent"] },
        "primaryEnv": "XCLAW_AGENT_API_KEY",
      },
  }
---

# X-Claw Agent

Use this skill to operate a local X-Claw agent runtime safely.

## Security Rules

- Never request, print, or export private keys or seed phrases.
- Never place secrets in prompts or logs.
- Use the local `xclaw-agent` CLI only; do not bypass with ad-hoc RPC-signing scripts.

## Required Environment

- `XCLAW_API_BASE_URL`
- `XCLAW_AGENT_API_KEY`
- `XCLAW_DEFAULT_CHAIN` (MVP: `base_sepolia`)

## Quick Start

Check runtime health:

```bash
{baseDir}/scripts/xclaw-safe.sh status
```

Poll server intents:

```bash
{baseDir}/scripts/xclaw-safe.sh intents-poll
```

Check approval state for an intent:

```bash
{baseDir}/scripts/xclaw-safe.sh approval-check <intent_id>
```

Execute trade intent:

```bash
{baseDir}/scripts/xclaw-safe.sh trade-exec <intent_id>
```

Report execution result:

```bash
{baseDir}/scripts/xclaw-safe.sh report-send <trade_id>
```

## References

- Command contract: `references/commands.md`
- Approval and policy rules: `references/policy-rules.md`
- Install and configuration: `references/install-and-config.md`

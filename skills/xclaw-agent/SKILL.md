---
name: xclaw-agent
description: Operate the local X-Claw agent runtime for intents, approvals, execution, reporting, and security-safe wallet operations.
homepage: https://xclaw.trade
metadata:
  {
    "openclaw":
      {
        "emoji": "🦾",
        "requires": { "bins": ["python3", "xclaw-agent"] },
        "primaryEnv": "XCLAW_AGENT_API_KEY",
      },
  }
---

# X-Claw Agent

Use this skill to operate a local X-Claw agent runtime safely.

## Security Rules

- Never request, print, or export private keys or seed phrases.
- Never place secrets in prompts or logs.
- Use the Python-first wrapper (`scripts/xclaw_agent_skill.py`) which delegates to local `xclaw-agent`.
- Do not bypass with ad-hoc RPC-signing scripts.

## Required Environment

- `XCLAW_API_BASE_URL`
- `XCLAW_AGENT_API_KEY`
- `XCLAW_DEFAULT_CHAIN` (MVP: `base_sepolia`)

## Quick Start

Check runtime health:

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py status
```

Poll server intents:

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py intents-poll
```

Check approval state for an intent:

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py approval-check <intent_id>
```

Execute trade intent:

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py trade-exec <intent_id>
```

Report execution result:

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py report-send <trade_id>
```

Off-DEX intent actions:

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py offdex-intents-poll
python3 {baseDir}/scripts/xclaw_agent_skill.py offdex-accept <intent_id>
python3 {baseDir}/scripts/xclaw_agent_skill.py offdex-settle <intent_id>
```

Wallet actions (delegated to runtime CLI):

```bash
python3 {baseDir}/scripts/xclaw_agent_skill.py wallet-create
python3 {baseDir}/scripts/xclaw_agent_skill.py wallet-address
```

## References

- Command contract: `references/commands.md`
- Approval and policy rules: `references/policy-rules.md`
- Install and configuration: `references/install-and-config.md`

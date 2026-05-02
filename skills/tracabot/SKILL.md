---
name: tracabot
description: DKG-powered OpenClaw Telegram fraud intelligence skill with scan, explain, digest, watchlist, appeal, and review tools.
user-invocable: true
tags: [openclaw, telegram, dkg-v10, fraud-detection, shared-memory]
version: 0.1.0
author: brxtrac
---

# tracabot OpenClaw Skill

tracabot exposes its Telegram fraud intelligence as OpenClaw-callable JSON tools while the live Telegram bot remains the autonomous moderation runtime.

## Tools

- `scan_target`: local heuristics plus DKG Shared Memory risk scoring. No Telegram action is executed.
- `explain_event`: structured evidence for a tracabot event.
- `get_watchlist`: local active watches, temp mutes, and review items. Local-only.
- `get_digest`: 24h operator triage summary. Local-only.
- `query_campaigns`: fraud campaign clusters from local memory.
- `submit_appeal`: writes a correction request to DKG Shared Memory.
- `review_event`: writes an uphold/overturn decision to DKG Shared Memory.

## CLI Bridge

```bash
node ./bin/tracabot-skill.js scan_target '{"telegramUserId":"8388593201","text":"SangMata rename alert"}'
node ./bin/tracabot-skill.js get_digest '{}'
node ./bin/tracabot-skill.js explain_event '{"eventId":"<event-id>"}'
```

## DKG Policy

Evidence-backed reports, findings, bans, restrictions, campaigns, appeals, and reviews can be written to DKG through the OpenClaw adapter. Plain watchlist monitoring, digest generation, and watchlist reads remain local-only.

## Guardrails

The skill tools do not ban Telegram users directly. Telegram enforcement remains inside the bot runtime where admin identity, bot permissions, and chat context can be verified.

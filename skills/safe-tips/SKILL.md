---
name: safe-tips
description: Generates varied, short, daily educational messages about staying safe on Telegram ("staying on trac", DM scams, verification, etc.). Used sparingly by Tracabot for proactive community protection.
user-invocable: true
---

# Safe Tips Generator

LLM-powered (via OpenClaw) generator for low-volume, high-value community education posts.

Core tool (exposed via the main tracabot skill): `generate_safe_tip`

Usage (CLI or agent):
```
npm run skill -- generate_safe_tip '{}'
```

Recommended cadence: at most once per 24h per chat (enforced by the bot), only when conversation mode is active and current risk is low.

The generated sentence is always different, calm, protective but never alarmist. Topics rotate naturally across DM impersonation, seed phrases, verification, official channels, etc.

The live Tracabot bot calls this skill (with fallback) in `maybePostDailySafeTip` and logs the result as a `safe_tip` conversation artefact.

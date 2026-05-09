---
name: unsafe-chat-monitor
description: Monitor Telegram chat events for unsafe, scam, spam, phishing, impersonation, and scam-advertisement signals using OpenClaw plus DKG v10 working memory.
---

# Unsafe Chat Monitor

Use this skill when an OpenClaw agent needs to inspect a Telegram message or chat event for scam risk without directly performing Telegram enforcement.

## Tool

Call the TRACaBot OpenClaw skill tool:

```bash
node ./bin/tracabot-skill.js monitor_chat_event '{"telegramUserId":"123","username":"suspect","text":"verify wallet to claim airdrop","adminVerified":false}'
```

## Memory Policy

- Unsafe, scam, spam, phishing, scam advertisement, impersonation, giveaway, wallet-drain, and investment-lure events are written to DKG v10 Shared Memory through the OpenClaw DKG adapter.
- Verified Context Graph publication is reserved for hard evidence when `adminVerified` is true, or when confidence is very high.
- Weak or ambiguous observations should remain reviewable working memory and must not be treated as verified public evidence.
- Telegram bans, restrictions, deletes, and join challenges stay inside the Telegram bot runtime because they require bot admin permissions and chat context.

---
name: tracabot_ban_guard
description: Telegram enforcement guard for bans and restrictions with DKG evidence logging.
user-invocable: false
tags: [telegram, moderation, ban, restrictions, dkg]
version: 0.1.1
author: brxtrac
---

# tracabot Ban Guard

Ban Guard is the enforcement layer inside the Telegram bot runtime.

## Behavior

- `/ban` is restricted to configured admins or Telegram chat admins.
- Reply-based `/ban` bans the target and deletes the replied scam message when the bot has delete rights.
- Replying to SangMata rename alerts bans the extracted Telegram user ID.
- Auto-ban requires high confidence, bot ban rights, and admin/bot suppression checks.
- Auto-restrict handles medium-confidence risks when configured.

## DKG Logging

Executed bans and evidence-backed restrictions are written through the OpenClaw DKG adapter. Ban evidence includes confidence, scam type, DKG references, deletion status for the replied message, and moderation provenance.

## Guardrails

Never auto-act against Telegram admins or bot accounts. If rights are missing, alert admins and preserve local/DKG evidence instead of failing silently.

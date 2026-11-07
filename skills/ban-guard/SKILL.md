---
name: tracabot_ban_guard
description: Telegram enforcement guard for bans and restrictions with DKG evidence logging.
user-invocable: false
tags: [telegram, moderation, ban, restrictions, dkg]
version: 1.0.0
author: brxtrac
---

# tracabot Ban Guard

Ban Guard is the enforcement layer inside the Telegram bot runtime.

## Behavior

- Native admin bans are the default ingestion path. When the bot is a group administrator and receives a live `chat_member` ban transition, it records the enforcement event without requiring `/ban`.
- Telegram Bot API limits: no Recent Actions, no admin log, no pre-install backfill, and no unstated admin reason. Missing reasons are labeled `reason not provided`.
- When the bot already observed messages from the same user and chat before a live ban, it may attach up to 8 messages from the previous 60 minutes as `recent pre-ban context; causal link unverified`. These are never the claimed ban reason. Classify only with deterministic local signals (`unknown`, `behavior`, `spam`, `suspected_scam`, `suspected_campaign`), keep harassment/threat severity visible, and never upgrade a ban to `confirmed_scam` from context alone. Raw text stays local; public summaries carry categories and bounded indicators only.
- `/ban` is optional and restricted to configured admins or Telegram chat admins.
- Reply-based `/ban` bans the target and deletes the replied scam message when the bot has delete rights.
- Replying to SangMata rename alerts bans the extracted Telegram user ID.
- Auto-ban requires high confidence, bot ban rights, and admin/bot suppression checks.
- Join removal is separate and off by default. With `TRACABOT_JOIN_AUTO_REMOVE=true`, only fresh, unretracted, exact stable-identity `confirmed_scam`/admin-upheld evidence from a trusted layer can remove. A creator-curator attestation counts only after a fresh, signed status read verifies the pinned Ed25519 key, exact Telegram subject, fraud/scam classification, confidence, independent roots, issue/expiry, and active (not revoked) status. Display names, aliases, admin bans alone, behavior flags, model outputs, campaign association, fork source strings/booleans, Verified Memory membership alone, and untrusted fork reports can only produce a silent local flag.
- Banned users can start a private chat and send `/appeal`; the bot looks up only their own local ban cases. Group admins resolve appeals in private or group scope. Overturn is a local correction with retrying Telegram unban and does not revoke a creator-curator global record.
- Private `/start` exposes Protection controls, Status, Recent automatic bans, and Appeals only for groups where the caller is a current Telegram admin; bot owners do not bypass group administration. Pausing future join removals is per group and separate from reversing an existing automatic ban. Override / allow return records a group-scoped local correction and requests safe unban without a member appeal; failed unbans expose Retry unban. Resume cannot enable env-disabled auto-removal, widen the chat allowlist, restore missing bot rights, or change trusted layers.
- Auto-restrict handles medium-confidence risks when configured.

## DKG Logging

Executed bans and evidence-backed restrictions are written through the OpenClaw DKG adapter. Ban evidence includes confidence, scam type, DKG references, deletion status for the replied message, and moderation provenance. Live native admin bans with provenance may be auto-promoted as `admin_enforcement` only; they are not confirmed scams.

Join protection checks and auto-removals are local/private audit records by default. Opt-in creator submissions are bounded observations and never raw message text or a confirmed label. A retraction or correction suppresses older blocking evidence.

## Guardrails

Never auto-act against Telegram admins or bot accounts. If rights are missing, alert admins and preserve local/DKG evidence instead of failing silently.

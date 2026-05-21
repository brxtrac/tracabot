---
name: tracabot
description: DKG-powered OpenClaw Telegram fraud intelligence skill with scan, unsafe chat monitoring, explain, digest, watchlist, appeal, and review tools.
user-invocable: true
tags: [openclaw, telegram, dkg-v10, fraud-detection, shared-memory]
version: 0.1.1
author: brxtrac
---

# tracabot OpenClaw Skill

tracabot exposes its Telegram fraud intelligence as OpenClaw-callable JSON tools while the live Telegram bot remains the autonomous moderation runtime.

## Tools

- `scan_target`: local heuristics plus DKG Shared Memory risk scoring. No Telegram action is executed.
- `monitor_chat_event`: classify unsafe/scam/spam/phishing/scam-advertisement chat events and write evidence-backed observations to DKG Shared Memory. Context Graph publication is limited to admin-verified or very-high-confidence cases.
- `explain_event`: structured evidence for a tracabot event.
- `get_watchlist`: local active watches, temp mutes, and review items. Local-only.
- `get_digest`: 24h operator triage summary. Local-only.
- `query_campaigns`: fraud campaign clusters from local memory.
- `submit_appeal`: writes a correction request to DKG Shared Memory.
- `review_event`: writes an uphold/overturn decision to DKG Shared Memory.

## CLI Bridge

```bash
node ./bin/tracabot-skill.js scan_target '{"telegramUserId":"8388593201","text":"SangMata rename alert"}'
node ./bin/tracabot-skill.js monitor_chat_event '{"telegramUserId":"8388593201","text":"official support says verify wallet now","adminVerified":false}'
node ./bin/tracabot-skill.js get_digest '{}'
node ./bin/tracabot-skill.js explain_event '{"eventId":"<event-id>"}'
```

## Autonomous Learning Loop

TRACaBot writes benign, ambiguous, weak-report, and false-positive chat snippets as local WM drafts while it listens to Telegram. OpenClaw can autonomously curate those drafts with:

```bash
node ./bin/openclaw-learning-loop.js --once
node ./bin/openclaw-learning-loop.js --dry-run
```

Run without flags to keep polling. Tune with:

- `TRACABOT_LEARNING_LOOP_INTERVAL_MS` - default `300000`.
- `TRACABOT_LEARNING_LOOP_LIMIT` - default `25` drafts per pass.

The loop reads local `conversation_artifact` drafts with `lifecycle_stage: working_memory_draft`, calls `sort_conversation_artifact`, then appends `learning_draft_processed` so each draft is sorted once. Committed artifacts get a `commit_receipt_id` and can enter DKG Shared Memory. Low-quality artifacts stay local-only as WM drafts.

## DKG Policy

Evidence-backed unsafe chat observations, reports, findings, bans, restrictions, campaigns, appeals, and reviews can be written to DKG through the OpenClaw adapter. Plain watchlist state, digest generation, and watchlist reads remain local-only.

Events follow the lifecycle in `docs/TRACABOT_ONTOLOGY.md`: `observed`, `shared_memory`, `admin_reviewed`, `verified_memory`, and `campaign_summary`. Skill callers should pass community scope fields when available: `communityId`, `communityName`, `communityType`, and `policyId`.

Conversation-learning artifacts use a draft -> commit -> share flow:

- Draft: OpenClaw can call `sort_conversation_artifact` with loose or ambiguous chat context. Low-quality or unverified material stays local-only as `working_memory_draft` with `publication_status: working_memory` and `commit_policy: draft_only`.
- Commit: Human/admin verification, or the artifact-quality policy gate, stamps the artifact with `commit_receipt_id`, `commit_policy`, and `commit_authority`.
- Share: Only commit-stamped artifacts are written to DKG Shared Memory. The DKG write carries the commit receipt so other agents can trace who or what authorized promotion.
- Publish/VM: Context Graph publication remains a higher gate for admin-verified or very-high-confidence knowledge; ordinary conversation learning must not publish directly.

The live Telegram bot listens to chats itself and records local WM drafts for benign/non-fraud conversation flows. OpenClaw does not directly listen to Telegram unless an external OpenClaw agent calls this skill with chat text. Both paths use the same OpenClaw DKG adapter boundary for DKG reads/writes.

## Guardrails

The skill tools do not ban Telegram users directly. Telegram enforcement remains inside the bot runtime where admin identity, bot permissions, and chat context can be verified.

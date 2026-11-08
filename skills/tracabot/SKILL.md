---
name: tracabot
description: DKG-powered OpenClaw Telegram fraud intelligence skill with scan, unsafe chat monitoring, explain, digest, watchlist, appeal, and review tools.
user-invocable: true
tags: [openclaw, telegram, dkg-v10, fraud-detection, shared-memory]
version: 1.0.0
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
- `submit_appeal`: records a local-only private appeal/correction. It never writes to DKG Shared Memory.
- `review_event`: writes an uphold/overturn decision for one existing referenced finding. The producer resolves the reviewed subject and target chat from that finding and never falls back to the reviewer; missing or ambiguous references are rejected.

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

Evidence-backed unsafe chat observations, reports, findings, bans, restrictions, campaigns, and review decisions can be written to DKG through the OpenClaw adapter. Private appeals and appeal resolutions stay local-only. Provenance-backed native Telegram admin bans are ingested by the bot runtime as `admin_enforcement`, not as confirmed scams; missing reasons are labeled `reason not provided`. A live ban may include bounded same-user/same-chat messages observed before it as `recent pre-ban context; causal link unverified`; classification is evidence-based suspicion only, and raw text stays local. Plain watchlist state, digest generation, and watchlist reads remain local-only.

Events follow the lifecycle in `docs/TRACABOT_ONTOLOGY.md`: `observed`, `shared_memory`, `admin_reviewed`, `verified_memory`, and `campaign_summary`. Skill callers should pass community scope fields when available: `communityId`, `communityName`, `communityType`, and `policyId`.

Conversation-learning artifacts use a draft -> commit -> share flow:

- Draft: OpenClaw can call `sort_conversation_artifact` with loose or ambiguous chat context. Low-quality or unverified material stays local-only as `working_memory_draft` with `publication_status: working_memory` and `commit_policy: draft_only`.
- Commit: Human/admin verification, or the artifact-quality policy gate, stamps the artifact with `commit_receipt_id`, `commit_policy`, and `commit_authority`.
- Share: Only commit-stamped artifacts are written to DKG Shared Memory. The DKG write carries the commit receipt so other agents can trace who or what authorized promotion.
- Publish/VM: Context Graph publication remains a higher gate for admin-verified or very-high-confidence knowledge; ordinary conversation learning must not publish directly.

The live Telegram bot listens to chats itself and records local WM drafts for benign/non-fraud conversation flows. OpenClaw does not directly listen to Telegram unless an external OpenClaw agent calls this skill with chat text. Both paths use the same OpenClaw DKG adapter boundary for DKG reads/writes.

## Guardrails

- Telegram is the only implemented adapter. Discord and other platforms are not implemented.
- Core join protection is deterministic and works with `TRACABOT_LLM_PROVIDER=off`; no model output can authorize a ban.
- The live bot resolves an effective per-group mode from Telegram membership: admin protection only when `getChatMember` shows a group administrator, otherwise observer. Observer mode reviews actual join service messages and visible messages, logs locally, and can never ban, restrict, delete, unban, or challenge by any route. It does not claim comprehensive ban/join history, Recent Actions, pre-install bans, or unstated reasons. `my_chat_member` changes refresh the mode immediately; destructive calls re-check live rights so a stale cached admin state cannot authorize a ban after demotion.
- Observer groups are quiet by default. `TRACABOT_OBSERVER_ADVISORIES=true` is the single explicit opt-in for at most one bounded, cooldown-limited, evidence-backed advisory per six hours when group sends are permitted. Advisories never include target names, private text, or a definitive scam label. Admin groups retain the existing notification policy, and observer quiet never disables evidence checking, local logging, or consent-gated graph submission.
- The live bot runs an exact stable-identity background check on genuine joins. Default behavior is silent observe/log. Automatic removal requires `TRACABOT_JOIN_AUTO_REMOVE=true` plus fresh, unretracted confirmed fraud/scam evidence with authenticated approval provenance. By default only same-chat local admin review qualifies; shared/verified-graph records are flag-only because the installed adapter cannot prove authenticated publisher approval. A creator-curator attestation qualifies only after a fresh signed status read from the pinned creator Ed25519 key confirms exact subject, fraud/scam classification, confidence, independent roots, issue/expiry, and active status. Admin bans, behavior flags, display names, aliases, write authorization, model confidence, campaign association, fork source strings/booleans, and Verified Memory membership alone are not confirmed fraud.
- Banned users can start a private chat and send `/appeal`. The bot lists only that user's own local ban cases. Telegram does not allow bot-initiated DMs; the user must start the chat. Only actual admins of the affected group can uphold or overturn from private or group scope. Overturn is local-only, records a correction, retries an idempotent unban, and never revokes the creator-curator global record.
- Current group admins get private `/start` buttons for Protection controls, Status, Recent automatic bans, and Appeals. These views are live-admin-scoped; configured owners without group admin status see no group details. Pause/resume affects future automatic join removals only and cannot override env-disabled auto-removal, chat allowlists, trusted layers, or missing rights. Reversing a specific auto-ban is a separate Override / allow return action with local correction and safe unban retry; no member appeal is required.
- Cross-community evidence is read-only context. This skill does not perform cross-community guilty-by-association enforcement.
- Opt-in creator submissions must use `TRACABOT_SUBMIT_SHARED_EVIDENCE=true` plus a scoped token. Never submit raw message text, screenshots, credentials, or reporter identity. Do not write to a live graph from tests.
- The skill tools do not ban Telegram users directly. Telegram enforcement remains inside the bot runtime where admin identity, bot permissions, and chat context can be verified.

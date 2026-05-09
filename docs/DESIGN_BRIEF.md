# TRACaBot Design Brief

## Problem

Telegram fraud moderation is fragmented. Scam reports, bans, suspicious wallets, fake support accounts, and appeal outcomes usually remain trapped inside one group. Fraudsters reuse the same Telegram IDs, aliases, wallet addresses, domains, and message patterns across communities before moderators can coordinate.

TRACaBot turns those moderation artifacts into agent-readable knowledge. It observes Telegram activity, scores risk locally, queries DKG v10 Shared Memory for prior evidence, takes Telegram actions when confidence and permissions allow, and writes evidence-backed outcomes back to the `tracabot` Context Graph for reuse by other communities and OpenClaw agents.

## Target User

- Telegram community admins protecting crypto, DePIN, AI, NFT, and open-source communities.
- OpenClaw operators who want fraud intelligence tools callable outside Telegram.
- Future context-oracle builders who need structured, provenance-rich scam indicators.

## Product Workflow

1. A Telegram event arrives: join, message, report, SangMata rename alert, scan, or ban command.
2. TRACaBot extracts actor IDs, usernames, aliases, wallets, domains, scam patterns, and message context.
3. Local heuristics detect impersonation, phishing, fake airdrops, wallet-drain lures, investment testimonials, partnership lures, and admin-copycat rename behavior.
4. The bot queries DKG v10 Shared Memory through OpenClaw's DKG adapter for cross-community evidence.
5. The risk engine combines local and DKG confidence while guarding against report-only snowballing.
6. Low-confidence observations stay local. Low-risk joins can be challenged only when the bot is a Telegram group admin with restriction rights. Medium-confidence items can be deleted/restricted. High-confidence items can be deleted/banned.
7. Evidence-backed unsafe chat observations, reports, bans, restrictions, campaigns, appeals, and review decisions are written to DKG Shared Memory. High-confidence reports/findings/bans, admin-verified reviews, and very-high-confidence unsafe chat events are eligible for Context Graph publication.

## Memory Layers

TRACaBot currently uses two operational memory layers:

- Local working memory: bounded JSONL event store and in-memory Telegram context used for drafts, watchlists, review queues, digests, join challenges, and non-evidence monitoring. Plain `/watch`, `/unwatch`, `/watchlist`, `/digest`, and join-challenge housekeeping remain local-only.
- DKG v10 Shared Memory: evidence-backed artifacts written through `DkgDaemonClient.share` using the OpenClaw DKG adapter. Unsafe chat observations with concrete evidence are shared as collaborative working memory; only admin-verified or very-high-confidence observations are eligible for publication.

The repository did not find a confirmed public Working Memory-specific method exposed by the locally available OpenClaw adapter package. The integration therefore uses local operational working memory plus DKG Shared Memory through the supported adapter interface. If a public Working Memory adapter method becomes available, draft scan notes, campaign candidates, and review drafts can be routed there without changing the evidence schema.

## DKG v10 Primitives

- Context Graph: `tracabot`.
- Entity: Telegram actors, wallets, domains, events, campaigns, reports, reviews.
- Knowledge Asset-shaped events: high-confidence fraud findings, accepted reports, unsafe chat events, and bans include `http://dkg.io/ontology#KnowledgeAsset` typing.
- UAL: returned by OpenClaw DKG adapter writes and used in `/why`, `/stats sources`, and skill outputs.
- SHARE: evidence-backed events are written to Shared Memory.
- PUBLISH: qualifying high-confidence event roots are promoted with `publishSharedMemory`.
- Integration: `skills/tracabot/skill.json` exposes OpenClaw-callable tools.
- Curator authority: the configured TRACaBot/OpenClaw runtime holds authority for `createContextGraph`, `share`, `query`, and targeted `publishSharedMemory` operations.

## OpenClaw Integration

TRACaBot uses OpenClaw in two ways:

- Runtime DKG boundary: official DKG/OpenClaw adapter setup using `@origintrail-official/dkg-adapter-openclaw` / `DkgDaemonClient` against the local DKG v10 daemon for Context Graph creation, Shared Memory writes, Shared Memory queries, and targeted publication.
- Skill surface: `skills/tracabot/skill.json` and `bin/tracabot-skill.js` expose JSON tools for OpenClaw agents: `scan_target`, `monitor_chat_event`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, and `review_event`.
- Conversational surface: optional OpenClaw LLM inheritance lets the standalone TRACaBot Telegram bot draft scam-safety replies using the locally configured OpenClaw OAuth/model/gateway. Replies are topic-gated and evidence-bound.

Telegram enforcement stays inside the bot runtime because it requires chat context, admin identity checks, and bot permissions. OpenClaw skill tools and LLM replies can reason, explain, summarize, appeal, and review without bypassing Telegram safeguards.

## LLM-Wiki / Autoresearch Mapping

Fraud defense is a collaborative knowledge workflow: communities produce claims, evidence, counter-evidence, and corrections. TRACaBot maps that into agent-readable wiki-like artifacts:

- Reports and bans become structured evidence entries with provenance.
- Repeated scam domains, wallets, and text fingerprints become campaign clusters.
- Appeals and reviews are correction artifacts rather than silent rewrites.
- OpenClaw agents can retrieve, explain, and build on these artifacts through skill tools.

This advances the LLM-Wiki/autoresearch direction by turning moderation events into reusable, queryable, contested knowledge rather than isolated chat actions.

## Promotion Path

1. Local observation: messages, watchlist entries, weak reports, and digest state remain local working memory.
2. Evidence-backed Shared Memory: unsafe chat observations, accepted reports, fraud findings, restrictions, campaigns, appeals, and reviews are shared through DKG v10.
3. Context Graph publication: high-confidence accepted reports, high-confidence findings, bans, admin-verified reviews, and very-high-confidence unsafe chat events are promoted with targeted `publishSharedMemory` calls.
4. Verified Memory readiness: upheld bans, repeated campaigns, and reviewed evidence can later be promoted into Verified Memory or consumed by context oracles. Overturned reviews and appeals provide negative/correction signals for the same trust gradient.

## Context Oracle Readiness

Events are shaped for downstream oracle consumption with structured predicates rather than raw text only:

- `telegramUserId`, `targetTelegramUserId`, `username`, `targetUsername`, `actorAlias`.
- `wallet`, `scamDomain`, `scamPattern`, `campaignKey`, `relatedEventId`.
- `confidence`, `localConfidence`, `dkgConfidence`, `reviewDecision`, `targetEventId`.
- `restrictedUntil`, `actionDurationSeconds`, `sangmataOldName`, `sangmataNewName`.

An oracle can later reason over these fields to decide whether an actor, wallet, domain, or campaign has matured from shared evidence into verified fraud intelligence.

## Scaling Plan

- Multi-community support: configure `TRACABOT_COMMUNITY_ID`, optional `TRACABOT_COMMUNITY_NAME`, `TRACABOT_COMMUNITY_TYPE`, and `TRACABOT_POLICY_ID` per deployment. These fields are written to DKG events for provenance and policy-aware scoring.
- OpenClaw workflows: use skill tools for scanning, unsafe event monitoring, report review, appeals, campaign summaries, and operator digests. Skills do not execute Telegram enforcement directly.
- MCP integrations: coding and operations agents should query the `tracabot` Context Graph for campaign evidence, ontology fields, and review tasks before modifying policy or publishing durable decisions.
- Verified Memory discipline: publish only admin-verified, very-high-confidence, upheld, or repeated-campaign evidence. Weak reports and plain watchlist state remain local or Shared Memory.

## Security Notes

- Runtime egress: `api.telegram.org` and the configured DKG node, default `http://127.0.0.1:9200`.
- DKG operations: `createContextGraph`, `share`, `query`, `publishSharedMemory`.
- Secrets: `TELEGRAM_BOT_TOKEN`, `DKG_AUTH_TOKEN`, and adapter credentials remain in environment files.
- No preinstall/postinstall scripts and no remote code evaluation.
- Plain watchlist monitoring is local-only and not shared to DKG.
- Join-challenge starts, failures, solves, and expirations are local-only; only validated evidence-backed fraud/moderation artifacts are shared to DKG.
- Public Telegram replies redact internal UALs, event IDs, graph names, OpenClaw endpoint/model details, and admin setup details.
- Telegram enforcement requires configured admin or Telegram chat-admin identity plus bot rights.

## Maintenance Commitment

Maintainer: brxtrac. Support window: at least six months after registry acceptance, including security fixes, DKG adapter compatibility updates, and documentation updates for install/demo workflows.

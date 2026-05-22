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

TRACaBot currently uses three operational memory layers:

- Local working memory: bounded JSONL event store and in-memory Telegram context used for drafts, watchlists, review queues, digests, join challenges, and non-evidence monitoring. Plain `/watch`, `/unwatch`, `/watchlist`, `/digest`, and one-off join-challenge housekeeping remain local-only.
- DKG v10 Working Memory: when supported by the installed OpenClaw adapter, `createAssertion`, `writeAssertion`, and `promoteAssertion` stage evidence in DKG Working Memory before selected roots move to Shared Working Memory.
- DKG v10 Shared Working Memory: evidence-backed artifacts promoted through the assertion lifecycle, with `share` retained as a compatibility fallback for older adapter builds. Unsafe chat observations with concrete evidence are shared as collaborative working memory; only admin-verified or very-high-confidence observations are eligible for publication.

The runtime `/status` command reports whether the current adapter exposes Working Memory assertions, Shared Working Memory fallback writes, Verified Memory publish, and query capability.

## DKG v10 Primitives

- Context Graph: `tracabot`.
- Entity: Telegram actors, wallets, domains, events, campaigns, reports, reviews.
- Knowledge Asset-shaped events: high-confidence fraud findings, accepted reports, unsafe chat events, and bans include `http://dkg.io/ontology#KnowledgeAsset` typing.
- UAL: returned by OpenClaw DKG adapter writes and used in `/why`, `/stats sources`, and skill outputs.
- SHARE: evidence-backed events are written to Shared Memory.
- PUBLISH: qualifying high-confidence event roots are promoted with `publishSharedMemory`.
- Integration: `skills/tracabot/skill.json` exposes OpenClaw-callable tools.
- Curator authority: the configured TRACaBot/OpenClaw runtime holds authority for `createContextGraph`, assertion lifecycle operations, `share`, `query`, and targeted `publishSharedMemory` operations.

## Bounty Scope Compliance

TRACaBot is intended for OriginTrail DKG v10 Bounty Program Round 1, Section 5. It is in scope because it does both required things:

- It reads from and writes to DKG v10 Shared Memory on a v10 node through the official OpenClaw DKG adapter setup. The adapter is used as the HTTP client boundary to the local authenticated node API; TRACaBot does not patch the DKG node, load code into the daemon, or import internal v10 packages such as `@origintrail-official/dkg-core`, `-storage`, `-chain`, `-publisher`, `-query`, or `-agent`.
- It connects DKG Working Memory and Shared Working Memory to an OpenClaw-compatible agent workflow that advances LLM-Wiki/autoresearch: Telegram communities and OpenClaw agents produce structured, provenance-rich fraud knowledge that can be queried, reviewed, corrected, clustered, and promoted.

It also matches the priority integration target in Section 5: OpenClaw. TRACaBot exposes an OpenClaw skill manifest and JSON bridge, and its DKG runtime boundary follows the official DKG/OpenClaw adapter setup.

Round 1 out-of-scope exceptions are addressed as follows:

- Not Verified-Memory-only: the primary product loop is Shared Memory read/write; Verified Memory publish is a downstream high-confidence path.
- No endorsement/voting UI: appeals and reviews are agent/admin commands, not UI voting buttons.
- No publisher-side Conviction or staking UX.
- No DKG v9 dependency.
- No Curator bypass: `SHARE` and `PUBLISH` use the configured runtime's DKG authority against the local node.
- No internal node imports, node source patching, or daemon plugin loading.

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
2. Evidence-backed Shared Working Memory: unsafe chat observations, accepted reports, fraud findings, restrictions, campaigns, appeals, and reviews are staged through the DKG assertion lifecycle when available and shared through DKG v10. `channel_observation` shares bounded raw text only for high-confidence public channel abuse, not ordinary scam discussion.
3. Context Graph publication: high-confidence accepted reports, high-confidence findings, bans, admin-verified reviews, and very-high-confidence unsafe chat events are promoted with targeted `publishSharedMemory` calls.
4. Verified Memory readiness: upheld bans, repeated campaigns, and reviewed evidence can be promoted into Verified Memory or consumed by context oracles. Overturned reviews and appeals provide negative/correction signals for the same trust gradient.

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
- DKG operations: `createContextGraph`, `createAssertion`, `writeAssertion`, `promoteAssertion`, `share`, `query`, `publishSharedMemory`.
- Secrets: `TELEGRAM_BOT_TOKEN`, `DKG_AUTH_TOKEN`, and adapter credentials remain in environment files.
- No preinstall/postinstall scripts and no remote code evaluation.
- Plain watchlist monitoring is local-only and not shared to DKG.
- Join-challenge starts, solves, and one-off expirations are local-only. Repeated challenge-failure clusters can be shared as aggregate onboarding-abuse intelligence; validated evidence-backed fraud/moderation artifacts remain the primary DKG writes.
- Public Telegram replies redact internal UALs, event IDs, graph names, OpenClaw endpoint/model details, and admin setup details.
- Telegram enforcement requires configured admin or Telegram chat-admin identity plus bot rights.

## Maintenance Commitment

Maintainer: brxtrac. Support window: at least six months after registry acceptance, including security fixes, DKG adapter compatibility updates, and documentation updates for install/demo workflows.

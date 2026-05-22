# Bounty Reference

Submitted for OriginTrail DKG v10 Bounty Program Round 1 (`cfi-dkgv10-r1`): Working and Shared Memory integrations for LLM-Wiki/autoresearch agents, with OpenClaw as a priority target under Section 5.

## Summary

tracabot is a live OpenClaw-compatible Telegram anti-scam agent. It detects phishing, fake airdrops, investment testimonial scams, support/admin impersonation, join-then-rename impersonators, off-platform DM impersonators, suspicious moderation events, and low-risk joins that must verify with a DKG Knowledge Asset challenge, then writes structured scam knowledge to DKG v10 Shared Working Memory in the `tracabot` Context Graph.

It now also exposes a concrete OpenClaw skill surface through `skills/tracabot/skill.json` and `bin/tracabot-skill.js`, allowing OpenClaw agents to call scan, explain, watchlist, digest, campaign, appeal, and review tools directly as JSON.

TRACaBot also supports bounded conversational safety replies in Telegram. It keeps its own standalone Telegram token while optionally inheriting local OpenClaw OAuth/model/gateway configuration for LLM-drafted answers to scam-safety questions. If OpenClaw chat access is unavailable, it falls back to deterministic evidence templates.

The differentiator is the shared persistent memory loop: one community's accepted report, DM scam report, fraud finding, or ban becomes queryable DKG intelligence for every other community running tracabot against the same Context Graph. A bad actor who tests a scam in one channel or in private DMs can be flagged elsewhere by Telegram user ID, username/display-name alias, reported alias, wallet, domain, or scam pattern before repeating the attack.

Telegram commands are registered on startup:

- `/scan`: check a user, wallet, or replied message for scam risk.
- `/report`: report a suspicious user, wallet, or message to DKG.
- `/dmreport`: report off-platform DM impersonation scams to DKG Shared Memory when accepted.
- `/ban`: ban a replied user and publish ban evidence.
- `/stats`: show recent fraud checks and detections, including `/stats campaigns` for repeated scam waves.
- `/why`: explain a tracabot event decision using local evidence, DKG source refs, Shared Memory write metadata, and publish status.
- `/watch` and `/unwatch`: admin-only scrutiny controls that accept replies, SangMata rename alerts, numeric Telegram IDs, or usernames, then boost scoring without banning by themselves.
- `/watchlist`: admin-only local queue of active watches, temporary mutes, and pending review items.
- `/challenge on|off|status`: admin-only per-chat join challenge toggle.
- `/appeal`: submit a correction or appeal to DKG Shared Memory.
- `/review`: admin-only upheld/overturned review decision written to DKG.
- `/digest`: summarize recent actions, reports, watches, appeals, reviews, and campaign signals.
- Join challenge: low-risk new members verify with a DKG Knowledge Asset UAL or configured Knowledge Asset Q&A; challenge state, per-chat overrides, and failed attempts remain local-only and do not pollute DKG.

OpenClaw skill tools are also available: `scan_target`, `monitor_chat_event`, `sort_conversation_artifact`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, and `review_event`.

## DKG v10 Fit

- Memory layers: local operational working memory, DKG v10 Working Memory assertion staging when available, and DKG v10 Shared Working Memory.
- Public interface: official DKG/OpenClaw adapter setup using `DkgDaemonClient` against the local DKG v10 daemon.
- Primitives: Context Graph, Assertion, Entity, Integration, Knowledge Asset, Knowledge Collection, UAL.
- Publication model: high-confidence fraud findings, accepted high-confidence reports, and executed bans are automatically published to the Context Graph with targeted adapter publish calls for the event root. There is no curator-controlled promotion step.
- Cross-community propagation: `share` writes evidence-backed findings to Shared Memory with actor IDs, aliases, wallets, domains, patterns, campaign signals, confidence, evidence, target metadata, restriction expiry, review decisions, and moderation outcome; `query` reads the same graph with `includeSharedMemory: true` before scoring new joins, first posts, `/scan`, and `/report` targets. Plain watchlist monitoring and weak reports stay local-only.
- Adapter status: the current DKG/OpenClaw adapter exposes `createAssertion`, `writeAssertion`, and `promoteAssertion` for Working Memory to Shared Working Memory flow; `share` remains supported as a compatibility fallback.
- Section 5 scope: TRACaBot reads from and writes to DKG v10 Shared Memory through a supported public interface boundary and connects that memory to an OpenClaw-compatible agent workflow for LLM-Wiki/autoresearch-style collaborative knowledge.
- Exceptions respected: not Verified-Memory-only, no endorsement/voting UI, no Conviction/staking UX, no DKG v9 dependency, no Curator bypass, no internal DKG v10 package imports, no DKG node source patching, and no daemon-side code loading.
- Governance loop: `/why`, `/appeal`, and `/review` make decisions explainable and correctable while preserving an auditable DKG trail instead of silently rewriting moderation history.

## Verification

Local OpenClaw mini PC verification:

```text
dkg status
Version: 10.0.0-rc.9

dkg status
Node: tracabot
Role: edge
Network: DKG V10 Testnet
PeerId: 12D3KooWQm9sJCkUTU7kRXsNQttHaYTQV4ZjR8QaBNVUMqVMLC6R

npm run test:commands
Core command paths exercised: /stats, /scan, /report, /ban
Graph: did:dkg:context-graph:tracabot/_shared_memory
RetrievedIntel: riskScore 100, reportsAcrossCommunities 4
```

Tests and audit:

```text
npm test
164 tests passed

npm audit --omit=dev
found 0 vulnerabilities
```

Telegram runtime:

```text
Bot command loop verified with stubbed Telegram API and live DKG v10 read/write calls. The live deployment runs as @tracethembot with public replies redacted to avoid exposing internal DKG/OpenClaw/admin details.
```

## Security Attestation

I attest that this code is my own work or properly licensed, contains no intentional backdoors, uses no dynamic remote code loading, and has no preinstall or postinstall scripts. Network egress is declared as `api.telegram.org` plus the configured local DKG node. DKG write authority is limited to Context Graph creation, Shared Memory writes, Shared Memory queries, and targeted auto-publishing of qualifying high-confidence fraud events through the configured Curator-authorized runtime.

## Maintenance

Maintainer: brxtrac  
Support window: at least six months after registry acceptance.

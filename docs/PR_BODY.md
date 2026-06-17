# Bounty Reference

Submitted for OriginTrail DKG v10 Bounty Program Round 1 (`cfi-dkgv10-r1`): Working and Shared Memory integrations for LLM-Wiki/autoresearch agents, with OpenClaw as a priority target under Section 5.

## Summary

tracabot is a live OpenClaw-compatible Telegram anti-scam agent. It detects phishing, fake airdrops, investment testimonial scams, support/admin impersonation, join-then-rename impersonators, off-platform DM impersonators, suspicious moderation events, and low-risk joins that must verify with a DKG Knowledge Asset challenge, then writes structured scam knowledge to DKG v10 Shared Working Memory in the `tracabot` Context Graph.

It now also exposes a concrete OpenClaw skill surface through `skills/tracabot/skill.json` and `bin/tracabot-skill.js`, allowing OpenClaw agents to call scan, explain, watchlist, digest, campaign, appeal, and review tools directly as JSON.

TRACaBot also supports bounded conversational safety replies in Telegram. It keeps its own standalone Telegram token while optionally inheriting local OpenClaw OAuth/model/gateway configuration for LLM-drafted answers to scam-safety questions. If OpenClaw chat access is unavailable, it falls back to deterministic evidence templates.

The differentiator is the shared persistent memory loop: one community's accepted report, DM scam report, fraud finding, or ban becomes queryable DKG intelligence for every other community running tracabot against the same Context Graph. A bad actor who tests a scam in one channel or in private DMs can be flagged elsewhere by Telegram user ID, username/display-name alias, reported alias, wallet, domain, or scam pattern before repeating the attack.

Current Telegram commands registered on startup:

- `/start`: opens the inline TRACaBot protection menu for stats, reviews, explanations, enforcement history, and settings.
- `/scan`: checks a user, Telegram ID, wallet, replied user, or replied SangMata rename alert against local heuristics and DKG Shared Memory.
- `/report`: queues suspicious replied messages, usernames, wallets, links, forwarded DMs, screenshots, or natural-language evidence for admin review.
- `/ban`: admin-only command that bans a replied user or supported SangMata rename target when the bot has Telegram ban rights, then logs evidence.
- `/mute`: admin-only command that temporarily restricts a replied or mentioned user.

Stats, campaigns, sources, pending reviews, settings/status, recent enforcement actions, event explanations, and per-chat join challenge toggles are available through `/start` menu buttons rather than separate public slash commands. Admins can also reply naturally to review alerts with explicit verdicts such as "confirm scam" or "reject as not a scam"; non-admin corrections are logged as appeals. Low-risk new members can be gated by the optional DKG Knowledge Asset join challenge; challenge state, per-chat overrides, and one-off failed attempts remain local-only unless repeated abuse qualifies as aggregate shared-memory intelligence.

OpenClaw skill tools are also available: `scan_target`, `monitor_chat_event`, `sort_conversation_artifact`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, `review_event`, `decide_artefact_action`, and `generate_safe_tip`.

## DKG v10 Fit

- Memory layers: local operational working memory, DKG v10 Working Memory assertion staging when available, and DKG v10 Shared Working Memory.
- Public interface: official DKG/OpenClaw adapter setup using `DkgDaemonClient` against the local DKG v10 daemon.
- Primitives: Context Graph, Assertion, Entity, Integration, Knowledge Asset, Knowledge Collection, UAL.
- Publication model: high-confidence fraud findings, accepted high-confidence reports, and executed bans are automatically published to the Context Graph with targeted adapter publish calls for the event root. There is no curator-controlled promotion step.
- Cross-community propagation: `share` writes evidence-backed findings to Shared Memory with actor IDs, aliases, wallets, domains, patterns, campaign signals, confidence, evidence, target metadata, restriction expiry, review decisions, and moderation outcome; `query` reads the same graph with `includeSharedMemory: true` before scoring new joins, first posts, `/scan`, and `/report` targets. Plain watchlist monitoring and weak reports stay local-only.
- Adapter status: the current DKG/OpenClaw adapter exposes `createAssertion`, `writeAssertion`, and `promoteAssertion` for Working Memory to Shared Working Memory flow; `share` remains supported as a compatibility fallback.
- Section 5 scope: TRACaBot reads from and writes to DKG v10 Shared Memory through a supported public interface boundary and connects that memory to an OpenClaw-compatible agent workflow for LLM-Wiki/autoresearch-style collaborative knowledge.
- Exceptions respected: not Verified-Memory-only, no endorsement/voting UI, no Conviction/staking UX, no DKG v9 dependency, no Curator bypass, no internal DKG v10 package imports, no DKG node source patching, and no daemon-side code loading.
- Governance loop: Explain Event in the `/start` menu, natural-language admin review replies, non-admin appeal logging, and OpenClaw `explain_event` / `submit_appeal` / `review_event` tools make decisions explainable and correctable while preserving an auditable DKG trail instead of silently rewriting moderation history.

## Verification

Live DKG v10 / OpenClaw adapter verification:

```text
dkg status
Version: 10.0.0-rc.17

dkg status
Node: tracabot
Role: edge
Network: DKG V10 Testnet
PeerId: 12D3KooWQm9sJCkUTU7kRXsNQttHaYTQV4ZjR8QaBNVUMqVMLC6R

npm run test:commands
Core command paths exercised: /start menu, /scan, /report, /ban, /mute, review callbacks, stats/campaign/review panels, natural-language review replies
Graph: did:dkg:context-graph:tracabot/_shared_memory
RetrievedIntel: riskScore 100, reportsAcrossCommunities 4
```

Review and governance paths are covered in the automated test suite, including non-admin appeal logging, admin review callbacks, reply-based review inference from bot alerts, false-positive suppression after overturns, `/start` review queues, and visible persistent review confirmations.

Tests and audit:

```text
npm test
240 tests passed

npm audit --omit=dev
found 0 vulnerabilities
```

Telegram runtime:

```text
Bot command loop verified with stubbed Telegram API and live DKG v10 read/write calls. The live deployment runs as @tracethembot with public replies redacted to avoid exposing internal DKG/OpenClaw/admin details.
```

Demo assets:

- Recorded walkthrough: https://github.com/brxtrac/tracabot/blob/main/docs/demo/tracabot-demo.mp4
- Demo cover image: https://github.com/brxtrac/tracabot/blob/main/docs/demo/tracabot-demo-cover.jpg
- Repeatable demo script: https://github.com/brxtrac/tracabot/blob/main/docs/DEMO.md

## Security Attestation

I attest that this code is my own work or properly licensed, contains no intentional backdoors, uses no dynamic remote code loading, and has no preinstall or postinstall scripts. Network egress is declared as `api.telegram.org` plus the configured local DKG node. DKG write authority is limited to Context Graph creation, Shared Memory writes, Shared Memory queries, and targeted auto-publishing of qualifying high-confidence fraud events through the configured Curator-authorized runtime.

The registry install points to the published provenance-backed `tracabot@1.0.0` package, while the source, design brief, and demo links are pinned to the final reviewed commit for this PR.

## Maintenance

Maintainer: brxtrac  
Support window: at least six months after registry acceptance.

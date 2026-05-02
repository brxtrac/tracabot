# Bounty Reference

Submitted for OriginTrail DKG v10 Bounty Program Round 1 (`cfi-dkgv10-r1`): Working and Shared Memory integrations for LLM-Wiki/autoresearch agents, with OpenClaw as a priority target.

## Summary

tracabot is an OpenClaw-compatible Telegram Shieldy-style anti-scam agent. It detects phishing, fake airdrops, investment testimonial scams, support/admin impersonation, join-then-rename impersonators, and suspicious moderation events, then writes structured scam knowledge to DKG v10 Shared Memory in the `tracabot` Context Graph.

It now also exposes a concrete OpenClaw skill surface through `skills/tracabot/skill.json` and `bin/tracabot-skill.js`, allowing OpenClaw agents to call scan, explain, watchlist, digest, campaign, appeal, and review tools directly as JSON.

The differentiator is the shared persistent memory loop: one community's accepted report, fraud finding, or ban becomes queryable DKG intelligence for every other community running tracabot against the same Context Graph. A bad actor who tests a scam in one channel can be flagged elsewhere by Telegram user ID, username/display-name alias, wallet, or scam pattern before repeating the attack.

Telegram commands are registered on startup:

- `/scan`: check a user, wallet, or replied message for scam risk.
- `/report`: report a suspicious user, wallet, or message to DKG.
- `/ban`: ban a replied user and publish ban evidence.
- `/stats`: show recent fraud checks and detections, including `/stats campaigns` for repeated scam waves.
- `/why`: explain a tracabot event decision using local and DKG evidence.
- `/watch` and `/unwatch`: admin-only scrutiny controls that accept replies, SangMata rename alerts, numeric Telegram IDs, or usernames, then boost scoring without banning by themselves.
- `/watchlist`: admin-only local queue of active watches, temporary mutes, and pending review items.
- `/appeal`: submit a correction or appeal to DKG Shared Memory.
- `/review`: admin-only upheld/overturned review decision written to DKG.
- `/digest`: summarize recent actions, reports, watches, appeals, reviews, and campaign signals.

OpenClaw skill tools are also available: `scan_target`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, and `review_event`.

## DKG v10 Fit

- Memory layers: local operational working memory plus DKG v10 Shared Memory.
- Public interface: OpenClaw DKG adapter (`DkgDaemonClient`) against the local DKG daemon.
- Primitives: Context Graph, Assertion, Entity, Integration, Knowledge Asset, Knowledge Collection, UAL.
- Publication model: high-confidence fraud findings, accepted high-confidence reports, and executed bans are automatically published to the Context Graph with targeted adapter publish calls for the event root. There is no curator-controlled promotion step.
- Cross-community propagation: `share` writes evidence-backed findings to Shared Memory with actor IDs, aliases, wallets, domains, patterns, campaign signals, confidence, evidence, target metadata, restriction expiry, review decisions, and moderation outcome; `query` reads the same graph with `includeSharedMemory: true` before scoring new joins, first posts, `/scan`, and `/report` targets. Plain watchlist monitoring and weak reports stay local-only.
- Adapter status: this repository did not confirm a separate public Working Memory-specific method exposed by the locally importable OpenClaw adapter. Draft/monitoring state therefore stays in local JSONL working memory, while collaborative evidence uses supported DKG Shared Memory adapter calls.
- Governance loop: `/why`, `/appeal`, and `/review` make decisions explainable and correctable while preserving an auditable DKG trail instead of silently rewriting moderation history.

## Verification

Local OpenClaw mini PC verification:

```text
dkg --version
10.0.0-rc.1-dev.1777554347.b80a299

dkg status
Node: tracabot
Role: edge
Network: f81f9df2e9604fca
PeerId: 12D3KooWQm9sJCkUTU7kRXsNQttHaYTQV4ZjR8QaBNVUMqVMLC6R

npm run test:commands
Core command paths exercised: /stats, /scan, /report, /ban
Graph: did:dkg:context-graph:tracabot/_shared_memory
RetrievedIntel: riskScore 100, reportsAcrossCommunities 4
```

Tests and audit:

```text
npm test
73 tests passed

npm audit --omit=dev
found 0 vulnerabilities
```

Telegram runtime:

```text
Bot command loop verified with stubbed Telegram API and live DKG v10 read/write calls.
```

## Security Attestation

I attest that this code is my own work or properly licensed, contains no intentional backdoors, uses no dynamic remote code loading, and has no preinstall or postinstall scripts. Network egress is declared as `api.telegram.org` plus the configured local DKG node. DKG write authority is limited to Context Graph creation, Shared Memory writes, Shared Memory queries, and targeted auto-publishing of qualifying high-confidence fraud events.

## Maintenance

Maintainer: brxtrac  
Support window: at least six months after registry acceptance.

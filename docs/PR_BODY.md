# Bounty Reference

Submitted for OriginTrail DKG v10 Bounty Program Round 1 (`cfi-dkgv10-r1`): Working and Shared Memory integrations for LLM-Wiki/autoresearch agents, with OpenClaw as a priority target.

## Summary

tracabot is an OpenClaw-compatible Telegram Shieldy-style anti-scam agent. It detects phishing, fake airdrops, investment testimonial scams, support/admin impersonation, join-then-rename impersonators, and suspicious moderation events, then writes structured scam knowledge to DKG v10 Shared Memory in the `tracabot` Context Graph.

The differentiator is the shared persistent memory loop: one community's accepted report, fraud finding, or ban becomes queryable DKG intelligence for every other community running tracabot against the same Context Graph. A bad actor who tests a scam in one channel can be flagged elsewhere by Telegram user ID, username/display-name alias, wallet, or scam pattern before repeating the attack.

Telegram commands are registered on startup:

- `/scan`: check a user, wallet, or replied message for scam risk.
- `/report`: report a suspicious user, wallet, or message to DKG.
- `/ban`: ban a replied user and publish ban evidence.
- `/stats`: show recent fraud checks and detections, including `/stats campaigns` for repeated scam waves.
- `/why`: explain a tracabot event decision using local and DKG evidence.
- `/watch` and `/unwatch`: admin-only scrutiny controls that prefer reply-based clickable Telegram mentions and boost scoring without banning by themselves.
- `/appeal`: submit a correction or appeal to DKG Shared Memory.
- `/review`: admin-only upheld/overturned review decision written to DKG.
- `/digest`: summarize recent actions, reports, watches, appeals, reviews, and campaign signals.

## DKG v10 Fit

- Memory layers: Working Memory and Shared Memory.
- Public interface: OpenClaw DKG adapter (`DkgDaemonClient`) against the local DKG daemon.
- Primitives: Context Graph, Assertion, Entity, Integration, Knowledge Asset, Knowledge Collection, UAL.
- Publication model: high-confidence fraud findings, accepted high-confidence reports, and executed bans are automatically published to the Context Graph with targeted adapter publish calls for the event root. There is no curator-controlled promotion step.
- Cross-community propagation: `share` writes every accepted finding to Shared Memory with actor IDs, aliases, wallets, domains, patterns, campaign signals, confidence, evidence, and moderation outcome; `query` reads the same graph with `includeSharedMemory: true` before scoring new joins, first posts, `/scan`, and `/report` targets.
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
60 tests passed

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

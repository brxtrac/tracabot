# Design Brief: tracabot

Submitted for: OriginTrail DKG v10 Bounty Program Round 1  
Author: brxtrac  
Repository: https://github.com/brxtrac/tracabot  
Tag: cfi-dkgv10-r1

## Problem

Telegram communities are common targets for fake airdrops, phishing links, admin impersonation, and support scams. Existing moderation bots mostly operate with local rules and local memory. They do not give agents a shared, queryable, provenance-preserving substrate for scam knowledge that can improve across communities.

tracabot turns Telegram moderation into agent-native knowledge work. Each detection, report, and moderation action becomes structured knowledge that another agent can query, inspect, and eventually promote.

## Target User

The primary user is a Telegram group admin running OpenClaw on a server or mini PC. The admin wants a practical Shieldy-style anti-scam bot, but with DKG v10 memory so detections are not trapped in one chat.

Secondary users are other OpenClaw, Hermes, or custom agents that consume the `tracabot` Context Graph as shared scam intelligence.

## Integration Shape

tracabot is a standalone Node.js service and OpenClaw-compatible agent package. It uses only public interfaces:

- Telegram Bot API for polling, replies, and `banChatMember`.
- OpenClaw official DKG adapter setup through `dkg openclaw setup`.
- OpenClaw `DkgDaemonClient` adapter calls for Context Graph, Shared Memory, publish, and query operations.

No internal DKG packages or node-daemon patches are used.

## DKG v10 Memory Layers

tracabot focuses on Round 1 collaborative memory using local operational working memory plus DKG v10 Shared Memory.

Working Memory:

- The agent analyzes messages immediately and persists detections locally as JSONL audit events.
- Local events contain evidence, confidence, actor, chat, timestamp, and the agent DID.

Shared Memory:

- Events are written to `tracabot` with the OpenClaw DKG adapter Shared Memory API.
- The agent queries Shared Memory before scoring a user, wallet, or scam pattern so cross-community reports can influence local decisions.
- At 85% confidence, the agent publishes a high-confidence `fraud_finding` Knowledge Asset-shaped event and either bans immediately with Telegram admin rights or reports the full DKG evidence to group admins.

Context Graph Publishing:

- High-confidence fraud findings, accepted high-confidence reports, and executed bans automatically call the adapter's targeted Shared Memory publish flow for the event URI.
- Publishing is targeted to the event that just qualified, so unrelated Shared Memory is not flushed.
- There is no curator-controlled promotion step; qualifying memory is published automatically as soon as it meets policy.

## v10 Primitives Used

- Context Graph: `tracabot`.
- Integration: standalone contributor-owned service with registry metadata.
- Auto-publish policy: high-confidence fraud memory is published to the Context Graph as soon as it qualifies.
- Entity: Telegram user, Telegram chat, scam report, moderation action.
- Knowledge Asset: high-value reports shaped as reusable fraud intelligence.
- Knowledge Collection: batches of related reports, such as a campaign or impersonation wave.
- SHARE: OpenClaw adapter Shared Memory write.
- PUBLISH: targeted OpenClaw adapter Shared Memory publish for qualifying event roots.

## LLM-Wiki And Autoresearch Fit

tracabot creates a living scam knowledge graph. Agents can ask:

- Has this username or Telegram ID appeared in other communities?
- Which scam types are increasing this week?
- What evidence supported a previous ban?
- Which reports have enough confidence and evidence to publish automatically?

That is the LLM-Wiki loop: agents read, write, revise, and verify a shared knowledge substrate instead of relying on private chat logs.

## Promotion Path

1. A Telegram message is analyzed and stored as local operational working memory.
2. High-confidence or manually submitted reports are written to Shared Memory.
3. Reports or findings that meet the high-confidence threshold are automatically published to the Context Graph.
4. Agents can summarize evidence, cluster related reports into a Knowledge Collection, and reuse the published memory.
5. Published Context Graph outputs become oracle-ready scam reputation inputs.

The current data model already includes stable event URIs, timestamps, creators, confidence, scam type, actor identifiers, and evidence lists, so promotion does not require a schema rewrite.

## Security Notes

Secrets remain in `.env` or local OpenClaw config and are excluded by `.gitignore`.

Declared network egress:

- `api.telegram.org`.
- Configured DKG node URL, default `http://127.0.0.1:9200`.

Declared DKG operations:

- OpenClaw adapter Context Graph create.
- OpenClaw adapter Shared Memory write.
- OpenClaw adapter targeted Shared Memory publish.
- OpenClaw adapter DKG query with Shared Memory included.

No preinstall or postinstall scripts are used. No dynamic code loading is used. The package has zero runtime dependencies.

## Demo

The repository includes `npm run demo`, which writes a realistic scam detection into DKG v10 Shared Memory without needing a Telegram group. It also includes `npm run test:commands`, which exercises `/stats`, `/scan`, `/report`, `/ban`, writes the resulting events to `did:dkg:context-graph:tracabot/_shared_memory`, auto-publishes qualifying evidence, and queries the new evidence back from DKG.

## Maintenance

Maintainer: brxtrac  
Support window: at least six months after registry acceptance  
License: MIT

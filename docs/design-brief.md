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

Secondary users are other OpenClaw, Hermes, or custom agents that consume the `claw-shield-intel` Context Graph as shared scam intelligence.

## Integration Shape

tracabot is a standalone Node.js service and OpenClaw-compatible agent package. It uses only public interfaces:

- Telegram Bot API for polling, replies, and `banChatMember`.
- DKG v10 CLI subprocesses for Context Graph and Shared Memory operations.
- OpenClaw official DKG adapter setup through `dkg openclaw setup`.

No internal DKG packages or node-daemon patches are used.

## DKG v10 Memory Layers

tracabot focuses on Round 1 Working and Shared Memory.

Working Memory:

- The agent analyzes messages immediately and persists detections locally as JSONL audit events.
- Local events contain evidence, confidence, actor, chat, timestamp, and the agent DID.

Shared Memory:

- Events are written to `claw-shield-intel` with `dkg shared-memory write`.
- The agent queries Shared Memory before scoring a user, wallet, or scam pattern so cross-community reports can influence local decisions.
- At 85% confidence, the agent publishes a high-confidence `fraud_finding` Knowledge Asset-shaped event and either bans immediately with Telegram admin rights or reports the full DKG evidence to group admins.

Verified Memory:

- tracabot does not automatically call `PUBLISH`.
- High-value reports are shaped for later Curator-controlled promotion to Verified Memory.

## v10 Primitives Used

- Context Graph: `claw-shield-intel`.
- Integration: standalone contributor-owned service with registry metadata.
- Curator: future promotion authority for `PUBLISH` and SHARE governance.
- Entity: Telegram user, Telegram chat, scam report, moderation action.
- Knowledge Asset: promoted high-value reports in later Verified Memory workflows.
- Knowledge Collection: batches of related reports, such as a campaign or impersonation wave.
- SHARE: `dkg shared-memory write`.
- PUBLISH: documented promotion path only, not automatic in Round 1.

## LLM-Wiki And Autoresearch Fit

tracabot creates a living scam knowledge graph. Agents can ask:

- Has this username or Telegram ID appeared in other communities?
- Which scam types are increasing this week?
- What evidence supported a previous ban?
- Which reports are mature enough for Curator review?

That is the LLM-Wiki loop: agents read, write, revise, and verify a shared knowledge substrate instead of relying on private chat logs.

## Promotion Path

1. A Telegram message is analyzed and stored as local Working Memory.
2. High-confidence or manually submitted reports are written to Shared Memory.
3. Repeated reports across communities become candidates for Curator review.
4. A Curator can ask the agent to summarize evidence, cluster related reports into a Knowledge Collection, and propose `PUBLISH`.
5. Verified Memory outputs become oracle-ready scam reputation inputs.

The current data model already includes stable event URIs, timestamps, creators, confidence, scam type, actor identifiers, and evidence lists, so promotion does not require a schema rewrite.

## Security Notes

Secrets remain in `.env` or local OpenClaw config and are excluded by `.gitignore`.

Declared network egress:

- `api.telegram.org`.
- Configured DKG node URL, default `http://127.0.0.1:9200`.

Declared DKG operations:

- `dkg context-graph create`.
- `dkg shared-memory write`.
- `dkg query --include-shared-memory`.

No preinstall or postinstall scripts are used. No dynamic code loading is used. The package has zero runtime dependencies.

## Demo

The repository includes `npm run demo`, which writes a realistic scam detection into DKG v10 Shared Memory without needing a Telegram group. It also includes `npm run test:commands`, which exercises `/stats`, `/scan`, `/report`, `/ban`, writes the resulting events to `did:dkg:context-graph:claw-shield-intel/_shared_memory`, and queries the new evidence back from DKG Shared Memory.

## Maintenance

Maintainer: brxtrac  
Support window: at least six months after registry acceptance  
License: MIT

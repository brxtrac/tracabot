---
name: tracabot_global_intel
description: Queries DKG v10 Shared Memory and Context Graph evidence before local Telegram fraud decisions.
user-invocable: false
tags: [dkg-v10, shared-memory, context-graph, fraud-intelligence]
version: 0.1.0
author: brxtrac
---

# tracabot Global Intel

Global Intel is the DKG-backed memory layer used by tracabot before scoring actors, wallets, domains, and scam patterns.

## Queries

- Telegram user IDs.
- Usernames and display-name aliases.
- Wallet addresses.
- Scam domains.
- Scam pattern indicators.
- Prior fraud findings, reports, bans, and moderation outcomes.

## Risk Use

Credible DKG evidence boosts risk, but report-only evidence does not snowball into bans by itself. Strong local evidence or high-confidence DKG evidence is required for enforcement.

## Context Graph

The default graph is `tracabot`. Shared Memory is queried with `includeSharedMemory: true`; high-confidence findings can be promoted into the Context Graph through `publishSharedMemory`.

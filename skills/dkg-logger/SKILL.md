---
name: tracabot_dkg_logger
description: Writes evidence-backed tracabot fraud knowledge to DKG v10 via the OpenClaw DKG adapter.
user-invocable: false
tags: [origintrail, dkg-v10, openclaw, shared-memory, provenance]
version: 0.1.0
author: brxtrac
---

# tracabot DKG Logger

The logger is implemented by `src/dkg-client.js` and uses `@origintrail-official/dkg-adapter-openclaw` through `DkgDaemonClient`.

## Writes

- Evidence-backed reports.
- Fraud findings.
- Executed bans and restrictions.
- Fraud campaign clusters.
- Appeals and review decisions.

Plain watchlist monitoring, weak reports, and local digest/watchlist reads are not written to DKG.

## Structured Fields

Events include provenance, Telegram IDs, aliases, target keys, wallets, domains, scam patterns, confidence, evidence, review decisions, restriction expiry, campaign keys, and related event IDs.

## Publication

High-confidence findings, accepted high-confidence reports, and bans are eligible for targeted `publishSharedMemory` promotion into the `tracabot` Context Graph.

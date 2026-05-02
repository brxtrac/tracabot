---
name: tracabot_scam_analyzer
description: Local Telegram fraud heuristic analyzer used before DKG-backed moderation decisions.
user-invocable: false
tags: [telegram, scam-detection, fraud, heuristics]
version: 0.1.0
author: brxtrac
---

# tracabot Scam Analyzer

This skill document describes the local analyzer behind `scan_target`, `/scan`, `/report`, joins, first posts, and proactive moderation.

## Signals

- Fake support/admin impersonation.
- Wallet drain, airdrop, seed phrase, giveaway, and phishing language.
- Investment testimonial and VC/partnership lures.
- Admin-like rename/copycat behavior after joining.
- Suspicious domains, wallets, and repeated scam patterns.

## Output

The analyzer returns structured risk fields: `is_scam`, `confidence`, `scam_type`, `evidence`, and `recommended_action`. DKG confidence is combined later by the risk engine.

## Guardrails

The analyzer alone does not ban. Enforcement requires Telegram permission checks, admin/bot safeguards, and evidence-backed risk thresholds.

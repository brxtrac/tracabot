# Registry Entry Draft

## Package

- Name: `tracabot`
- Version: `0.1.0`
- Repository: `https://github.com/brxtrac/tracabot`
- Commit: `6741e649c5be43c05da09585846af4fefce4b76a`
- License: MIT
- Category: OpenClaw agent integration, Telegram safety, DKG v10 Shared Memory
- Tags: `openclaw`, `dkg-v10`, `shared-memory`, `telegram`, `anti-scam`, `context-graph`, `llm-wiki`, `autoresearch`

## Summary

TRACaBot is a live OpenClaw-compatible Telegram anti-scam agent. It detects phishing, fake airdrops, investment scams, admin/support impersonation, suspicious rename behavior, scam domains, scam wallets, repeated campaign patterns, and low-risk joins that must prove DKG familiarity with a Knowledge Asset UAL challenge. Evidence-backed reports, findings, restrictions, reviews, appeals, campaigns, and bans are written to DKG v10 Shared Memory under the `tracabot` Context Graph. High-confidence accepted reports, fraud findings, and executed bans are promoted through targeted Context Graph publication.

## Interfaces

- Telegram Bot API runtime: `bin/tracabot.js`.
- OpenClaw skill manifest: `skills/tracabot/skill.json`.
- OpenClaw JSON bridge: `tracabot-skill` / `bin/tracabot-skill.js`.
- Optional conversational safety bridge: read-only local OpenClaw OAuth/model/gateway discovery for bounded scam-safety replies.
- DKG boundary: official DKG/OpenClaw adapter setup using `DkgDaemonClient` against the configured local DKG v10 daemon URL.

## DKG Operations

- `createContextGraph` for the configured graph, default `tracabot`.
- `share` for evidence-backed DKG v10 Shared Memory writes.
- `query` with Shared Memory enabled for cross-community evidence lookup.
- `publishSharedMemory` for targeted publication of qualifying high-confidence event roots.

## Memory Policy

- Local working memory: JSONL audit log, watchlist state, digest state, weak reports, join-challenge state, and monitoring-only watch/unwatch actions.
- Shared Memory: accepted reports, fraud findings, restrictions, bans, campaigns, appeals, and reviews with structured evidence.
- Context Graph publication: high-confidence accepted reports, high-confidence findings, and executed bans.

The repository did not confirm a separate public OpenClaw adapter method dedicated to DKG v10 Working Memory. Until that API is available, operational drafts stay local and collaborative evidence uses the supported Shared Memory adapter calls.

## Egress

- `api.telegram.org` for polling, message replies, deletes, restrictions, and bans.
- Configured DKG node URL, default `http://127.0.0.1:9200`.
- Optional local OpenClaw gateway, default `http://127.0.0.1:18789`, for LLM-drafted scam-safety replies. External LLM egress is only used if an operator explicitly sets `TRACABOT_LLM_BASE_URL`.

## Write Authority

The runtime operator controls the Telegram bot token, DKG adapter endpoint, and any DKG auth token. Telegram enforcement requires bot admin permissions plus either configured TRACaBot admin identity or Telegram chat-admin identity for manual `/ban` and `/review`.

## Security

- No preinstall or postinstall scripts.
- No dynamic remote code loading.
- Secrets remain in `.env`, service environment files, or OpenClaw local configuration.
- OpenClaw OAuth/API information is discovered read-only from local OpenClaw config when `TRACABOT_LLM_PROVIDER=auto`; it is not copied into TRACaBot `.env` or displayed by `/status`.
- Network egress and DKG operations are documented in `SECURITY.md`.
- Production audit command: `npm audit --omit=dev`.
- Public Telegram replies redact internal DKG UALs, event IDs, graph names, OpenClaw endpoint/model details, and admin setup details. Detailed provenance remains available through controlled local/admin explainability paths.

## Maintainer

- Maintainer: brxtrac
- Support window: at least six months after registry acceptance.

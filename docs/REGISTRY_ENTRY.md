# Registry Entry Draft

## Package

- Name: `tracabot`
- Version: `0.1.1`
- Repository: `https://github.com/brxtrac/tracabot`
- Commit: pinned to the final submission commit in the `dkg-integrations` registry PR
- npm: `https://www.npmjs.com/package/tracabot/v/0.1.1`
- License: MIT
- Category: OpenClaw priority integration, Telegram safety, DKG v10 Shared Memory
- Tags: `openclaw`, `dkg-v10`, `shared-memory`, `telegram`, `anti-scam`, `context-graph`, `llm-wiki`, `autoresearch`

## Summary

TRACaBot is a live OpenClaw-compatible Telegram anti-scam agent and DKG v10 Bounty Round 1 Section 5 fit. It detects phishing, fake airdrops, investment scams, admin/support impersonation, suspicious rename behavior, scam domains, scam wallets, repeated campaign patterns, off-platform DM impersonators, and low-risk joins that must prove DKG familiarity with a Knowledge Asset challenge. Evidence-backed reports, findings, restrictions, reviews, appeals, campaigns, DM scam reports, high-confidence channel observations, and bans are written to DKG v10 Shared Memory under the `tracabot` Context Graph. High-confidence accepted reports, fraud findings, and executed bans are promoted through targeted Context Graph publication.

Scope basis: TRACaBot reads/writes DKG v10 Shared Memory through the official OpenClaw DKG adapter setup, connects that memory to an OpenClaw-compatible agent workflow, and does not target Verified Memory alone.

## Interfaces

- Telegram Bot API runtime: `bin/tracabot.js`.
- OpenClaw skill manifest: `skills/tracabot/skill.json`.
- OpenClaw JSON bridge: `tracabot-skill` / `bin/tracabot-skill.js`.
- Optional conversational safety bridge: read-only local OpenClaw OAuth/model/gateway discovery for bounded scam-safety replies.
- DKG boundary: official DKG/OpenClaw adapter setup using `DkgDaemonClient` against the configured local DKG v10 daemon URL. This is the public-interface boundary; TRACaBot does not import internal DKG v10 packages, patch node source, or load code into the daemon.

## DKG Operations

- `createContextGraph` for the configured graph, default `tracabot`.
- `createAssertion`, `writeAssertion`, and `promoteAssertion` for Working Memory staging and Shared Working Memory promotion when adapter-supported.
- `share` as a compatibility fallback for evidence-backed DKG v10 Shared Memory writes.
- `query` with Shared Memory enabled for cross-community evidence lookup.
- `publishSharedMemory` for targeted publication of qualifying high-confidence event roots.

## Memory Policy

- Local working memory: JSONL audit log, watchlist state, digest state, weak reports, join-challenge state, challenge configuration overrides, and monitoring-only watch/unwatch actions.
- Shared Memory: accepted reports, DM scam reports, fraud findings, restrictions, bans, campaigns, appeals, reviews, and selective `channel_observation` events with structured evidence. Admin review decisions can be entered by replying directly to the bot's review alert and remain visible in Telegram for auditability. Bounded raw `message_text` is shared only for high-confidence public channel abuse such as scam channel promos, outside token/coin promos, fake airdrops, wallet/domain lures, investment-profit spam, or admin/support DM impersonation.
- Context Graph publication: high-confidence accepted reports, high-confidence findings, executed bans, admin-reviewed decisions, and qualifying repeated campaign summaries.

Draft artifacts start in local working memory, then the OpenClaw learning loop can commit high-quality artifacts into DKG Shared Working Memory through the same adapter boundary. Low-quality or uncommitted material stays local.

## Egress

- `api.telegram.org` for polling, message replies, deletes, restrictions, and bans.
- Configured DKG node URL, default `http://127.0.0.1:9200`.
- Optional local OpenClaw gateway, default `http://127.0.0.1:18789`, for LLM-drafted scam-safety replies. External LLM egress is only used if an operator explicitly sets `TRACABOT_LLM_BASE_URL`.

## Write Authority

The runtime operator controls the Telegram bot token, DKG adapter endpoint, and any DKG auth token. Telegram enforcement requires bot admin permissions plus either configured TRACaBot admin identity or Telegram chat-admin identity for manual `/ban` and `/review`.

DKG `SHARE` and `PUBLISH` operations use the configured runtime's Curator-authorized node/API token. The integration does not bypass Context Graph authority or perform publisher-side Conviction/staking UX.

## Security

- No preinstall or postinstall scripts.
- npm publish uses GitHub Actions provenance (`npm publish --provenance --access public`).
- No dynamic remote code loading.
- No internal DKG v10 package imports, node daemon patches, or daemon-side code loading.
- No endorsement/voting UI; review/appeal flows are agent/admin command surfaces.
- Secrets remain in `.env`, service environment files, or OpenClaw local configuration.
- OpenClaw OAuth/API information is discovered read-only from local OpenClaw config when `TRACABOT_LLM_PROVIDER=auto`; it is not copied into TRACaBot `.env` or displayed by `/status`.
- Network egress and DKG operations are documented in `SECURITY.md`; external LLM egress is disabled by default and must be declared if an operator sets `TRACABOT_LLM_BASE_URL`.
- Production audit command: `npm audit --omit=dev`.
- Public Telegram replies redact internal DKG UALs, event IDs, graph names, OpenClaw endpoint/model details, and admin setup details. Detailed provenance remains available through controlled local/admin explainability paths.

## Maintainer

- Maintainer: brxtrac
- Support window: at least six months after registry acceptance.

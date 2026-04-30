# tracabot

tracabot is an OpenClaw-compatible Telegram anti-scam agent for OriginTrail DKG v10. It watches Telegram communities, detects scam and impersonation patterns, stores a local audit log, and writes scam knowledge to a DKG v10 Context Graph through the public `dkg` CLI.

The default Context Graph is `claw-shield-intel`. Events are written to DKG v10 Shared Memory with provenance fields that can later be promoted through Curator-controlled Verified Memory workflows.

## What It Does

- Detects Telegram scam patterns: fake airdrops, urgency language, phishing links, and admin/support impersonation.
- Supports `/scan`, `/report`, `/ban`, `/stats`, reply-thread risk checks, and `@tracabot is @username a fraudster?`.
- Checks every observed message and Telegram join event against DKG v10 Shared Memory before deciding.
- Applies the Shieldy action path at 85% confidence: ban immediately when the bot has Telegram admin rights, otherwise alert admins with DKG evidence and message context.
- Proactively rescans observed users on a configurable interval.
- Writes scam detections, reports, and moderation actions to DKG v10 Shared Memory with `dkg shared-memory write`.
- Queries DKG Shared Memory before scoring a user, wallet, or scam pattern, so reports from other communities can raise confidence.
- Keeps a persistent JSONL audit log for retry, review, and demo workflows.
- Runs as a normal Node.js service and keeps secrets outside Git.

## Telegram Commands

- `/scan` checks a user, wallet, or replied message for scam risk and replies with DKG evidence.
- `/report` reports a suspicious user, wallet, or message to DKG Shared Memory; high-confidence reports also publish a reusable fraud finding.
- `/ban` bans a replied user when the bot has Telegram admin rights and publishes ban evidence to DKG.
- `/stats` shows recent fraud checks, high-confidence findings, event types, and risk types.

## DKG v10 Verification

This repository was verified on the local OpenClaw mini PC with:

```bash
dkg --version
# 10.0.0-rc.1-dev.1777554347.b80a299

dkg status
# Node: BRX, Role: edge, PeerId: 12D3KooWQm9sJCkUTU7kRXsNQttHaYTQV4ZjR8QaBNVUMqVMLC6R

npm run demo
# Writing to shared memory: 10/10 quads
# Share operation: swm-1777560651535-gq4j3e9f
# Graph: did:dkg:context-graph:claw-shield-intel/_shared_memory
```

The demo event was queried back from Shared Memory:

```json
{
  "s": "https://tracabot.org/ontology#event/2158c19a-1168-45f4-a79e-0ac9a35379fc",
  "type": "\"impersonation\""
}
```

## Install

Prerequisites:

- Node.js 22.20.0 or newer.
- DKG v10 CLI installed: `npm install -g @origintrail-official/dkg`.
- A running DKG v10 node: `dkg start`.
- Telegram bot token from BotFather.
- OpenClaw if you want the OpenClaw memory adapter enabled.

```bash
git clone https://github.com/valcyclovir/tracabot.git
cd tracabot
npm install --package-lock-only
cp .env.example .env
```

Edit `.env` locally:

```bash
TELEGRAM_BOT_TOKEN=...
TRACABOT_CONTEXT_GRAPH=claw-shield-intel
TRACABOT_AUTO_BAN=true
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_PROACTIVE_SCAN_MINUTES=30
TRACABOT_STORE_PATH=./data/tracabot-events.jsonl
```

Start manually:

```bash
npm start
```

Run the DKG write demo without Telegram:

```bash
npm run demo
```

## OpenClaw Setup

The official DKG v10 OpenClaw setup command was used on the target server:

```bash
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

It installed the DKG node skill into the OpenClaw workspace, enabled `adapter-openclaw`, and set `plugins.slots.memory` to `adapter-openclaw`.

## Service Deployment

The deployed OpenClaw mini PC runs:

```bash
systemctl status tracabot.service
```

with:

```ini
WorkingDirectory=/root/claw-shield-dkg-starter
EnvironmentFile=/root/claw-shield-dkg-starter/.env
ExecStart=/usr/bin/node /root/claw-shield-dkg-starter/bin/tracabot.js
Restart=always
```

## Security

- No token or wallet secret is committed.
- No runtime dependencies, no install scripts, no dynamic code loading.
- Network egress is limited to `api.telegram.org` and the configured DKG node.
- DKG writes use `context-graph create` and `shared-memory write`; DKG reads use `query --include-shared-memory`.
- `PUBLISH` to Verified Memory is intentionally not automatic; it belongs to Curator-controlled promotion.

## Tests

```bash
npm test
npm audit --omit=dev
```

Current result: tests pass and production audit reports zero vulnerabilities.

## Bounty Reference

Submitted for OriginTrail DKG v10 Bounty Program Round 1: Working and Shared Memory integrations for LLM-Wiki/autoresearch agents, with OpenClaw as a priority target.

Maintenance commitment: valcyclovir will support this integration for at least six months after registry acceptance.

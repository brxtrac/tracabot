# TRACaBot

TRACaBot is an OpenClaw + Telegram + OriginTrail DKG v10 Shieldy-style anti-scam bot. It monitors Telegram communities, detects scam patterns, records local working memory, and writes evidence-backed fraud intelligence to DKG v10 Shared Memory so other communities and agents can query reusable scam context.

The default Context Graph is `claw-shield-intel`. TRACaBot writes Shared Memory events with provenance, local/DKG confidence, reporter metadata, scam type, wallet/pattern indicators, and moderation outcomes. Verified Memory `PUBLISH` is intentionally not automatic; high-confidence events are shaped for later curator review.

## Why It Exists

Telegram scam moderation usually stays trapped inside one chat. TRACaBot turns each meaningful scan, report, and moderation action into structured fraud knowledge that can be queried across communities. A new group can ask whether a username, wallet, or scam pattern has appeared elsewhere before deciding whether to warn, report, or ban.

## Commands

- `/scan` checks a user, wallet, or replied message against local heuristics and DKG Shared Memory, then returns a friendly risk verdict.
- `/report` accepts evidence-backed reports, applies duplicate/rate-limit/reporter checks, and writes accepted reports to DKG Shared Memory.
- `/ban` is restricted to configured admins or Telegram chat admins; it bans replied users only when the bot has Telegram ban rights and logs full evidence.
- `/stats` returns readable DKG aggregate activity for recent fraud events, high-confidence findings, risk types, and action guidance.

## DKG v10 Integration

TRACaBot uses the public `dkg` CLI only:

- `dkg context-graph create` to ensure the configured Context Graph exists.
- `dkg shared-memory write` to write reports, findings, and moderation evidence.
- `dkg query --include-shared-memory` to read cross-community evidence before scoring a target.

The bot separates local analysis confidence from DKG confidence. Report-only evidence does not automatically snowball into high-confidence bans; DKG evidence must be credible, and non-admin reports cannot directly trigger a Telegram ban.

## Security Model

- Secrets stay in `.env` or service environment files and are ignored by Git.
- Manual `/ban` requires a configured admin or Telegram chat admin.
- `/report` includes duplicate checks, reporter rate limits, self-report rejection, and evidence requirements.
- Telegram API calls have request timeouts.
- DKG writes use `execFile`, not shell interpolation.
- Accepted DKG evidence is structured and bounded; rejected/weak reports are local-only.
- Verified Memory publishing is curator-controlled and not automatic.

## Requirements

- Node.js `>=22.20.0`
- OriginTrail DKG v10 CLI
- Running DKG v10 node or OpenClaw DKG setup
- Telegram bot token from BotFather

Useful references:

- OriginTrail docs: https://docs.origintrail.io/
- DKG key concepts and UALs: https://docs.origintrail.io/dkg-key-concepts
- DKG agent setup and services: https://docs.origintrail.io/
- OpenClaw project: https://github.com/openclaw/openclaw
- Bounties & rewards: https://docs.origintrail.io/contribute-to-the-dkg/bounties-and-rewards
- Future integration registry PR target: https://github.com/OriginTrail/dkg-integrations

## Install

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
cp .env.example .env
```

Edit `.env`:

```bash
TELEGRAM_BOT_TOKEN=your-bot-token
TRACABOT_ADMINS=123456789,@your_admin_username
TRACABOT_CONTEXT_GRAPH=claw-shield-intel
TRACABOT_AUTO_BAN=true
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_PROACTIVE_SCAN_MINUTES=30
TRACABOT_TELEGRAM_TIMEOUT_MS=30000
TRACABOT_STORE_PATH=./data/tracabot-events.jsonl
```

Start manually:

```bash
npm start
```

Run the DKG write/read demo without Telegram:

```bash
npm run demo
```

Run tests:

```bash
npm test
npm audit --omit=dev
npm run test:commands
```

## OpenClaw Setup

On the OpenClaw mini PC, the DKG v10 OpenClaw setup command can be used before running TRACaBot:

```bash
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

Example systemd unit:

```ini
[Service]
Type=simple
WorkingDirectory=/root/tracabot
EnvironmentFile=/root/tracabot/.env
ExecStart=/usr/bin/node /root/tracabot/bin/tracabot.js
Restart=always
RestartSec=5
User=root
```

## Bounty Readiness

TRACaBot is prepared for the DKG v10 bounty phase 1 as a Working Memory + Shared Memory integration for Telegram/OpenClaw anti-fraud intelligence. It uses public DKG interfaces, includes tests for command behavior and abuse controls, verifies DKG read/write flows through `npm run test:commands`, avoids automatic Verified Memory publishing, and keeps bounty registry submission as a later step.

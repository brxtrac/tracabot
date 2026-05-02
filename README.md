# TRACaBot

TRACaBot is an OpenClaw + Telegram + OriginTrail DKG v10 intelligent anti-scam bot. It monitors Telegram communities, detects scam patterns, records local working memory, and writes evidence-backed fraud intelligence to DKG v10 Shared Memory so all instances of TRACaBot can query reusable scam context and apply it on their respective communities. Imagine a Telegram anti-scam bot that updates real time with knowledge from all communities to create a safe environment for users to exchange. 

The default Context Graph is `tracabot`. Every community running TRACaBot against that Context Graph contributes to the same DKG v10 Shared Memory layer. TRACaBot writes events with provenance, local/DKG confidence, stable Telegram IDs, usernames/display-name aliases, reporter metadata, scam type, wallet/pattern indicators, and moderation outcomes. High-confidence fraud findings, accepted high-confidence reports, and executed bans are automatically published from Shared Memory into the Context Graph so other communities can query them immediately.

## Why It Exists

Telegram scam moderation usually stays trapped inside one chat. TRACaBot turns each meaningful scan, report, and moderation action into structured fraud knowledge that can be queried across communities. If a fraudster is banned or reported in one channel, another TRACaBot instance can flag the same Telegram user ID, reused username/display-name alias, wallet, or scam pattern when that actor appears elsewhere.

## Commands

- `/scan` checks a user, Telegram ID, wallet, replied user, or replied SangMata rename alert against local heuristics and DKG Shared Memory, then returns a friendly risk verdict.
- `/report` accepts replied reports and bare `@username` reports, analyzes replied or recently observed Telegram context for scam patterns like support-DM lures and admin impersonation, applies duplicate/rate-limit/reporter checks, and writes accepted reports to DKG Shared Memory.
- `/ban` is restricted to configured admins or Telegram chat admins; it bans replied users or users extracted from replied SangMata rename alerts only when the bot has Telegram ban rights and logs full evidence.
- `/stats` returns readable DKG aggregate activity for recent fraud events, high-confidence findings, risk types, and action guidance.
- `/stats campaigns` shows repeated domains, wallets, scam patterns, or text fingerprints from recent local memory.
- `/why <event-id>` explains the local and DKG evidence behind a tracabot decision.
- `/watch` and `/unwatch` are admin-only scrutiny controls when replying to a user or SangMata rename alert; `/watch <telegram-id>`, `/watch @user`, `/unwatch <telegram-id>`, and `/unwatch @user` also work. ID/reply-based use creates a clickable Telegram mention and boosts future risk scoring without banning by itself.
- `/watchlist` is admin-only and shows local active watches, temporary mutes, and pending review items for follow-up.
- `/appeal <event-id> reason` records a correction request to DKG Shared Memory.
- `/review <event-id> uphold|overturn reason` is admin-only and writes a DKG review decision for future audits and false-positive correction.
- `/digest` summarizes recent bans, restrictions, reports, watches, appeals, reviews, and campaign signals.
- `/help` explains commands, autonomous thresholds, safeguards, and the DKG shared-memory loop for admins.

## DKG v10 Integration

TRACaBot uses OpenClaw's DKG adapter as its DKG boundary. The adapter talks to the local DKG daemon at `DKG_NODE_URL` and keeps TRACaBot aligned with the same DKG service OpenClaw uses:

- `DkgDaemonClient.createContextGraph` ensures the configured Context Graph exists.
- `DkgDaemonClient.share` writes reports, findings, and moderation evidence to Shared Working Memory.
- `DkgDaemonClient.publishSharedMemory` automatically publishes eligible high-confidence fraud memory into the Context Graph.
- `DkgDaemonClient.query` reads shared DKG evidence before scoring a target.

This cross-community loop is the core product behavior: observe locally, write structured evidence to DKG Shared Memory, auto-publish high-confidence events, then let every other TRACaBot instance query the same graph before the fraudster can repeat the attack in a different channel.

TRACaBot also ships an OpenClaw skill interface in `skills/tracabot/skill.json` and a JSON CLI bridge, `tracabot-skill`, so OpenClaw agents can call the same fraud intelligence without going through Telegram. Skill tools include `scan_target`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, and `review_event`.

The bot separates local analysis confidence from DKG confidence. Report-only evidence does not automatically snowball into high-confidence bans; DKG evidence must be credible, and non-admin reports cannot directly trigger a Telegram ban. Plain watchlist monitoring stays local-only; DKG writes are reserved for evidence-backed actions, reports, campaigns, appeals, reviews, restrictions, and bans.

TRACaBot applies graduated autonomous enforcement by default: low-confidence events are logged, medium-confidence events can be deleted and restricted, and high-confidence events can be deleted and banned. It also writes and queries scam domains in DKG Shared Memory, so a phishing or Telegram lure domain seen in one community can be flagged in another. Repeated domains, wallets, scam patterns, or text fingerprints are clustered into local campaign signals and can be written as `fraud_campaign` DKG events when the same wave repeats.

There is no curator-controlled promotion step in TRACaBot. Once an event meets the high-confidence publish policy, the bot immediately asks the OpenClaw DKG adapter to publish that event root. If the publish step fails, the Shared Memory write is kept and the error is recorded for audit.

## Security Model

- Secrets stay in `.env` or service environment files and are ignored by Git.
- Manual `/ban` requires a configured admin or Telegram chat admin.
- `/report` includes duplicate checks, reporter rate limits, self-report rejection, and evidence requirements.
- Telegram API calls have request timeouts.
- DKG reads/writes go through the OpenClaw DKG adapter HTTP client, not shell interpolation.
- Accepted DKG evidence is structured and bounded; duplicate, rate-limited, targetless, and no-pattern reports are local-only.
- Reporter reputation is tracked locally from accepted/high-confidence reports so consistently helpful reporters receive more trust without letting them bypass duplicate or rate-limit controls.
- High-confidence eligible fraud memory is auto-published with a targeted OpenClaw adapter `publishSharedMemory` call.
- Appeal, review, and watchlist events are evidence-backed DKG writes so operators can explain or correct decisions without silently mutating history.

## Requirements

- Node.js `>=22.20.0`
- Running DKG v10 node with OpenClaw DKG adapter setup
- Telegram bot token from BotFather

## Install

1. Install and set up DKG/OpenClaw on the host:

```bash
npm install -g @origintrail-official/dkg
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

2. Create a Telegram bot in BotFather, copy its token, invite it to your group, and grant it admin rights for deleting messages, restricting users, and banning users.

3. Install TRACaBot:

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
cp .env.example .env
```

4. Edit `.env`:

```bash
TELEGRAM_BOT_TOKEN=your-bot-token
TRACABOT_ADMINS=123456789,@your_admin_username
TRACABOT_CONTEXT_GRAPH=tracabot
TRACABOT_DKG_MODE=openclaw-adapter
TRACABOT_AUTO_BAN=true
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_AUTO_DELETE=true
TRACABOT_AUTO_RESTRICT=true
TRACABOT_WARN_THRESHOLD=60
TRACABOT_RESTRICT_THRESHOLD=75
TRACABOT_BAN_THRESHOLD=90
TRACABOT_PROACTIVE_SCAN_MINUTES=30
TRACABOT_TELEGRAM_TIMEOUT_MS=30000
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_STORE_PATH=./data/tracabot-events.jsonl
```

5. Start manually:

```bash
npm start
```

6. Optional systemd service: create a unit with `WorkingDirectory=/root/tracabot`, `EnvironmentFile=/root/tracabot/.env`, and `ExecStart=/usr/bin/node /root/tracabot/bin/tracabot.js`, then run `sudo systemctl daemon-reload` and `sudo systemctl enable --now tracabot.service`.

Run the DKG write/read demo without Telegram:

```bash
npm run demo
```

Run OpenClaw skill tools directly:

```bash
npm run skill -- scan_target '{"telegramUserId":"8388593201","text":"possible support impersonation"}'
npm run skill -- get_digest '{}'
npm run skill -- get_watchlist '{"filter":"all"}'
```

Run tests:

```bash
npm test
npm audit --omit=dev
npm run test:commands
```

## OpenClaw Setup

The DKG v10 OpenClaw setup command can be used before running TRACaBot:

```bash
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

The OpenClaw-facing skill manifest lives at `skills/tracabot/skill.json`. The CLI entrypoint is `node ./bin/tracabot-skill.js <tool> <json-input>` and returns JSON suitable for OpenClaw agent tooling.

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

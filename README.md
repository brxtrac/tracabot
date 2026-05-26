# TRACaBot

TRACaBot is an OpenClaw + Telegram + OriginTrail DKG v10 intelligent anti-scam bot. It monitors Telegram communities, detects scam patterns, records local working memory, and writes evidence-backed fraud intelligence to DKG v10 Shared Memory so every TRACaBot instance can query reusable scam context and apply it in its own community. Think of it as a Telegram anti-scam agent that updates with knowledge from all participating communities instead of forcing every group to defend itself alone.

The default Context Graph is `tracabot`. Every community running TRACaBot against that Context Graph contributes to the same DKG v10 Shared Memory layer. TRACaBot writes events with provenance, local/DKG confidence, stable Telegram IDs, usernames/display-name aliases, reporter metadata, scam type, wallet/pattern indicators, and moderation outcomes. High-confidence fraud findings, accepted high-confidence reports, and executed bans are automatically published from Shared Memory into the Context Graph so other communities can query them immediately.

## Quick Start For Testers

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
cp .env.example .env
npm test
npm run demo
npm run skill -- get_digest '{}'
```

For full human and agent testing paths, see `docs/TESTING.md`. The canonical design brief is `docs/DESIGN_BRIEF.md`.

## Why It Exists

Telegram scam moderation usually stays trapped inside one chat. TRACaBot turns each meaningful scan, report, and moderation action into structured fraud knowledge that can be queried across communities. If a fraudster is banned or reported in one channel, another TRACaBot instance can flag the same Telegram user ID, reused username/display-name alias, wallet, or scam pattern when that actor appears elsewhere.

Existing Telegram moderation tools such as Shieldy, Miss Rose, and similar bots are useful for basic spam filters, captchas, and admin commands, but they were not built for the agent era. They do not keep persistent cross-community memory, do not build reusable evidence, do not reason over scam campaigns across channels, and do not expose agentic workflows for review, correction, or shared intelligence.

TRACaBot is designed for communities that want persistent and verifiable protection instead of isolated bot actions. It is especially relevant for the OriginTrail ecosystem as DKG grows into infrastructure for fighting AI harm: our own community channels, holders, contributors, and newcomers should be protected by the same verifiable memory principles we are building for others.

Telegram is one of the most active social surfaces for many Web3 and AI communities. TRACaBot turns that surface into a practical DKG onboarding point: new participants can see how Working Memory, Shared Working Memory, and evidence-backed trust gradients can secure real communication rather than only reading about DKG in abstract terms.

## Commands

- `/scan` checks a user, Telegram ID, wallet, replied user, or replied SangMata rename alert against local heuristics and DKG Shared Memory, then returns a friendly risk verdict.
- `/report` accepts replied reports and bare `@username` reports, analyzes replied or recently observed Telegram context for scam patterns like support-DM lures and admin impersonation, applies duplicate/rate-limit/reporter checks, and writes accepted reports to DKG Shared Memory.
- `/dmreport` records off-platform Telegram DM impersonation scams when the suspect has not joined the group or has no `@username`. Use it with a name, claimed role/title, community/project, request made, wallet/link, or screenshot caption; accepted reports are written to DKG Shared Memory for cross-community warnings.
- `/ban` is restricted to configured admins or Telegram chat admins; it bans replied users or users extracted from replied SangMata rename alerts only when the bot has Telegram ban rights and logs full evidence.
- `/stats` returns readable DKG aggregate activity for recent fraud events, high-confidence findings, risk types, and action guidance.
- `/stats campaigns` shows repeated domains, wallets, scam patterns, or text fingerprints from recent local memory.
- `/why <event-id>` explains the local and DKG evidence behind a tracabot decision, including Shared Memory write metadata and publish status when available.
- `/watch` and `/unwatch` are admin-only scrutiny controls when replying to a user or SangMata rename alert; `/watch <telegram-id>`, `/watch @user`, `/unwatch <telegram-id>`, and `/unwatch @user` also work. ID/reply-based use creates a clickable Telegram mention and boosts future risk scoring without banning by itself.
- `/watchlist` is admin-only and shows local active watches, temporary mutes, and pending review items for follow-up.
- `/challenge on|off|status` is admin-only and toggles the new-user DKG join challenge per chat without restarting the bot.
- `/appeal <event-id> reason` records a correction request to DKG Shared Memory.
- `/review [@user|event-id] uphold|overturn reason` is admin-only and writes a DKG review decision for future audits and false-positive correction. Reply-based review inference also works.
- `/digest` summarizes recent bans, restrictions, reports, watches, appeals, reviews, and campaign signals.
- `/status` is admin-only and shows DKG reachability, DKG/OpenClaw adapter version/capabilities, Telegram permissions, thresholds, learning policy, and conversational mode status without exposing secrets.
- `/help` explains commands, autonomous thresholds, safeguards, and the DKG shared-memory loop for admins.

## Community Workflow

Community members can use TRACaBot without needing admin permissions:

- Reply to a suspicious message with `/scan` to get a risk verdict before engaging.
- Reply with `/report` when a message, username, wallet, or link looks like a scam. Accepted reports become evidence-backed DKG Shared Memory; weak or duplicate reports stay local-only.
- Use `/dmreport` for scam DMs, fake support accounts, or impersonators who contact members outside the group.
- Use `/why <event-id>` when TRACaBot returns an event ID and you want to understand the evidence behind a decision.
- Use `/appeal <event-id> reason` if you think a report, restriction, or ban was wrong.

## Admin Workflow

Admins keep enforcement guarded and auditable:

- Use `/ban` only as a reply to a scammer, scam message, or supported SangMata rename alert. The bot must have Telegram ban rights.
- Use `/watch` for suspicious accounts that should receive extra scrutiny but should not be banned yet.
- Use `/watchlist` to see watched users, temporary mutes, and pending review items.
- Use `/review [@user|event-id] uphold|overturn reason` to resolve appeals or false positives. Review decisions are written to DKG Shared Memory.
- Use `/stats`, `/stats campaigns`, and `/digest` to understand recent detections, repeated scam waves, and recommended follow-up.
- Use `/status` to verify bot permissions, DKG/OpenClaw adapter versions and memory capabilities, thresholds, learning policy, and conversational mode without exposing secrets.

## Campaign Summaries

TRACaBot clusters repeated domains, wallets, scam patterns, and message fingerprints into `fraud_campaign` events. Campaign summaries are only published when they have at least two evidence-backed roots, such as accepted reports, high-confidence findings, restrictions, bans, appeals, or reviews. Weak local detections and prior campaign summaries cannot become campaign evidence roots by themselves.

Published campaign summaries include the campaign key, event count, affected community IDs, evidence root IDs, repeated domains, wallets, and patterns. This lets another TRACaBot instance query the same Context Graph and recognize a repeated scam wave before it spreads further.

## DKG Join Challenge

TRACaBot can replace generic captcha bots with a DKG-native onboarding gate. When `TRACABOT_JOIN_CHALLENGE=true`, low-risk new members are muted until they verify with a Knowledge Asset or configured Knowledge Asset Q&A in DM, then normal chat permissions are restored.

The default-friendly mode is Q&A: publish `docs/TRACABOT_CHALLENGE_ASSET.md` as a DKG Knowledge Asset, set `TRACABOT_JOIN_CHALLENGE_ASSET_URL` to its DKG Explorer link, and configure `TRACABOT_JOIN_CHALLENGE_QA_BANK` with rotating questions whose answers are visible in the asset. The bot posts the asset link in the group, asks one question, and asks the user to DM the answer. Answers are normalized for case, punctuation, and spacing.

If Q&A is not configured, TRACaBot falls back to the Knowledge Asset address challenge: the group prompt asks the user to open `https://dkg.origintrail.io/`, pick any Knowledge Asset address starting with `did:dkg:`, and DM it to the bot. TRACaBot can validate that address against the live DKG before restoring permissions, then explains in DM what Knowledge Assets mean for trusted, shared AI memory.

A Knowledge Asset is a verifiable data item on the Decentralized Knowledge Graph. The challenge gives new members a practical first interaction with DKG while TRACaBot continues checking shared scam memory for high-risk joins, impersonators, and scam patterns.

High-risk joins still bypass the challenge and go directly to the configured risk action. Raw challenge starts, failed attempts, solves, and one-off expirations stay local-only. Repeated challenge failure patterns by stable Telegram ID or normalized alias can be written to DKG Shared Memory as aggregate onboarding-abuse intelligence and surfaced in `/stats campaigns` and `/digest`; evidence-backed scam findings and enforcement outcomes remain the primary events written to DKG Shared Memory.

## DKG v10 Integration

TRACaBot uses the official DKG/OpenClaw adapter setup as its DKG boundary. `DkgDaemonClient` points at the local DKG v10 daemon at `DKG_NODE_URL` and keeps TRACaBot aligned with the same DKG service OpenClaw uses:

- `DkgDaemonClient.createContextGraph` ensures the configured Context Graph exists.
- `DkgDaemonClient.createAssertion`, `writeAssertion`, and `promoteAssertion` stage evidence in DKG Working Memory and promote selected roots to Shared Working Memory when available.
- `DkgDaemonClient.share` remains the compatibility fallback for DKG v10 Shared Memory writes when an older adapter lacks assertion lifecycle methods.
- `DkgDaemonClient.publishSharedMemory` automatically publishes only eligible high-confidence or admin-reviewed fraud memory into Verified Memory.
- `DkgDaemonClient.query` reads shared DKG evidence before scoring a target.

TRACaBot maps Telegram moderation onto the DKG v10 memory model as a trust gradient:

- Working Memory: daily communication artifacts, weak signals, local watch notes, review queues, join-challenge state, and draft conversation artifacts that the agent should remember but not yet share.
- Shared Working Memory: moderate to high-risk evidence that should help related communities, including accepted reports, impersonation patterns, suspicious domains, reused wallets, appeals, admin reviews, and campaign signals.
- Verified Memory readiness: high-confidence or admin-reviewed evidence, such as confirmed impersonation attempts, bans, accepted reports, and false-positive corrections, is shaped so it can later be published or consumed by context oracles without rewriting the data model.

This cross-community loop is the core product behavior: observe locally, write structured evidence to DKG Shared Memory, auto-publish high-confidence events, then let every other TRACaBot instance query the same graph before the fraudster can repeat the attack in a different channel.

TRACaBot's event ontology and lifecycle are documented in `docs/TRACABOT_ONTOLOGY.md`. The lifecycle is `observed -> shared_memory -> admin_reviewed -> verified_memory -> campaign_summary`; runtime events include community scope (`communityId`, optional `communityName`, `communityType`) and `policyId` so multiple communities can share one Context Graph without losing policy provenance.

TRACaBot also ships an OpenClaw skill interface in `skills/tracabot/skill.json` and a JSON CLI bridge, `tracabot-skill`, so OpenClaw agents can call the same fraud intelligence without going through Telegram. Skill tools include `scan_target`, `monitor_chat_event`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, and `review_event`.

OpenClaw can also call `sort_conversation_artifact` to classify scam, spam, phishing, weak-report, warning, benign contrast, or false-positive conversation material. High-quality artifacts are written as `conversation_artifact` events to DKG v10 Shared Memory for LLM-Wiki-style learning, but they do not trigger autonomous enforcement by themselves.

For autonomous LLM-Wiki-style learning, run `node ./bin/openclaw-learning-loop.js` beside the Telegram bot. TRACaBot keeps listening to Telegram and drafting local WM artifacts; the OpenClaw loop drains those drafts through `sort_conversation_artifact`, stamps committed artifacts with `commit_receipt_id`, and writes only committed artifacts to DKG Shared Memory. Use `--once` for a single pass or `--dry-run` to inspect pending draft inputs. Tune with `TRACABOT_LEARNING_LOOP_INTERVAL_MS` and `TRACABOT_LEARNING_LOOP_LIMIT`.

TRACaBot can also run in conversational safety mode. It keeps its own standalone Telegram bot token, but can read local OpenClaw OAuth/model/gateway configuration to draft scam-safety replies through the same OpenClaw LLM account already configured on the host. If OpenClaw chat access is unavailable, TRACaBot falls back to deterministic evidence-based safety templates. Conversation is limited to scam/fraud/wallet-safety questions and proactive scam warnings; LLM text never executes Telegram bans, deletes, restrictions, or DKG writes by itself.

Local JSONL state is the bot's operational working memory for weak reports, watchlist state, digest state, join-challenge state, and ambiguous monitoring-only actions. Unsafe chat events with concrete evidence are written to DKG v10 Shared Memory through the OpenClaw adapter as collaborative evidence memory; only admin-verified or very-high-confidence events are published as Verified Memory.

`channel_observation` events increase DKG v10 Shared Memory for spam/scam/fraud pattern analysis without capturing normal discussion. TRACaBot writes bounded raw `message_text` only for high-confidence public messages that look like real channel abuse: new-member scam channel promos, outside coin/token promotions, scam domains/wallets, fake airdrops, investment-profit lures, or admin/support impersonators asking users to DM. General discussion about scam coins or scam prevention stays local and is not shared as raw DKG text.

The bot separates local analysis confidence from DKG confidence. Report-only evidence does not automatically snowball into high-confidence bans; DKG evidence must be credible, and non-admin reports cannot directly trigger a Telegram ban. Plain watchlist monitoring stays local-only; DKG writes are reserved for evidence-backed unsafe chat observations, actions, reports, campaigns, appeals, reviews, restrictions, and bans.

TRACaBot applies graduated autonomous enforcement by default: low-confidence events are logged, medium-confidence events can be deleted and restricted, and high-confidence events can be deleted and banned. It also writes and queries scam domains in DKG Shared Memory, so a phishing or Telegram lure domain seen in one community can be flagged in another. Repeated domains, wallets, scam patterns, or text fingerprints are clustered into local campaign signals and can be written as `fraud_campaign` DKG events when the same wave repeats.

Conversation artifact logging is controlled by `TRACABOT_WM_ARTIFACTS`, `TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE`, `TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS`, `TRACABOT_WM_ARTIFACT_REDACT`, and `TRACABOT_WM_ARTIFACT_SHARE_LOW_CONFIDENCE`. By default, raw identifiers are redacted and low-quality artifacts stay local.

TRACaBot treats DKG Shared Memory as collaborative evidence memory and Context Graph publication as verified/high-confidence memory. Once an event meets the publish policy through admin verification or very high confidence, the bot asks the OpenClaw DKG adapter to publish that event root. If the publish step fails, the Shared Memory write is kept and the error is recorded for audit.

Transient DKG Shared Memory write failures such as temporary network errors, timeouts, 429s, and 5xx responses are retried before the bot gives up. If DKG remains unavailable, Telegram moderation continues and the local event is retained with `dkg_error` so admins can audit the downtime without losing the moderation trail.

## Security Model

- Secrets stay in `.env` or service environment files and are ignored by Git.
- Manual `/ban` requires a configured admin or Telegram chat admin.
- `/report` includes duplicate checks, reporter rate limits, self-report rejection, and evidence requirements.
- Telegram API calls have request timeouts.
- DKG reads/writes go through the OpenClaw DKG adapter HTTP client, not shell interpolation.
- Accepted DKG evidence is structured and bounded; duplicate, rate-limited, targetless, and no-pattern reports are local-only.
- Reporter reputation is tracked locally from accepted/high-confidence reports so consistently helpful reporters receive more trust without letting them bypass duplicate or rate-limit controls.
- High-confidence or admin-verified eligible fraud memory is published with a targeted OpenClaw adapter `publishSharedMemory` call.
- Appeal and review events are evidence-backed DKG writes so operators can explain or correct decisions without silently mutating history. Plain watchlist state remains local-only.

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

2. Create and configure a Telegram bot:

```text
Open @BotFather
/newbot
Choose a display name and username
Copy the token into TELEGRAM_BOT_TOKEN
/setcommands
```

Paste this command list into BotFather:

```text
scan - Check scam risk for a user, wallet, message, or SangMata alert
report - Report suspicious evidence to shared DKG memory
dmreport - Report off-platform DM impersonation scams
ban - Ban a replied target when admin safeguards pass
stats - Show recent fraud intelligence and source activity
why - Explain evidence behind a tracabot event
watch - Locally watch a user, ID, username, or SangMata target
unwatch - Remove a local watch target
watchlist - Show active watches, mutes, and review items
challenge - Turn new-user join challenge on or off
appeal - Submit a correction request for an event
review - Admin review decision for an event
digest - Summarize recent actions and campaign signals
status - Admin status for DKG, permissions, and conversation mode
help - Show tracabot commands and safeguards
```

Invite the bot to your group and grant admin rights for deleting messages, restricting users, and banning users.

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
TRACABOT_CHANNEL_MEMORY=true
TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE=80
TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS=1000
TRACABOT_AUTO_BAN=true
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_AUTO_DELETE=true
TRACABOT_AUTO_RESTRICT=true
TRACABOT_WARN_THRESHOLD=60
TRACABOT_RESTRICT_THRESHOLD=75
TRACABOT_BAN_THRESHOLD=90
TRACABOT_PROACTIVE_SCAN_MINUTES=30
TRACABOT_TELEGRAM_TIMEOUT_MS=30000
TRACABOT_DKG_QUERY_TIMEOUT_MS=4000
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_STORE_PATH=./data/tracabot-events.jsonl
TRACABOT_CONVERSATIONAL=true
TRACABOT_LLM_PROVIDER=auto
TRACABOT_LLM_BASE_URL=
TRACABOT_LLM_API_KEY=
TRACABOT_LLM_MODEL=
OPENCLAW_CONFIG_PATH=
TRACABOT_CONVERSATION_MIN_CONFIDENCE=60
TRACABOT_PROACTIVE_REPLY_THRESHOLD=75
TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS=60
TRACABOT_CONVERSATION_MAX_CHARS=700
TRACABOT_JOIN_CHALLENGE=false
TRACABOT_JOIN_CHALLENGE_MODE=qa
TRACABOT_JOIN_CHALLENGE_ASSET_URL=
TRACABOT_JOIN_CHALLENGE_QA_BANK=[]
TRACABOT_JOIN_CHALLENGE_TTL_SECONDS=120
TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS=3
TRACABOT_JOIN_CHALLENGE_ACTION=kick
TRACABOT_JOIN_CHALLENGE_DELETE_ON_PASS=true
TRACABOT_JOIN_CHALLENGE_DELETE_BAD_ATTEMPTS=true
TRACABOT_JOIN_CHALLENGE_DKG_VALIDATE=true
```

5. Start manually:

```bash
npm start
```

6. Optional systemd service: create a unit with `WorkingDirectory=/root/tracabot`, `EnvironmentFile=/root/tracabot/.env`, and `ExecStart=/usr/bin/node /root/tracabot/bin/tracabot.js`, then run `sudo systemctl daemon-reload` and `sudo systemctl enable --now tracabot.service`.

```ini
[Unit]
Description=TRACaBot Telegram anti-scam agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/tracabot
EnvironmentFile=/root/tracabot/.env
ExecStart=/usr/bin/node /root/tracabot/bin/tracabot.js
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tracabot.service
sudo systemctl status tracabot.service
```

Run the DKG write/read demo without Telegram:

```bash
npm run demo
```

Run OpenClaw skill tools directly:

```bash
npm run skill -- scan_target '{"telegramUserId":"8388593201","text":"possible support impersonation"}'
npm run skill -- monitor_chat_event '{"telegramUserId":"8388593201","text":"official support says verify wallet now","adminVerified":false}'
npm run skill -- get_digest '{}'
npm run skill -- get_watchlist '{"filter":"all"}'
```

Run tests:

```bash
npm test
npm audit --omit=dev
npm run test:commands
```

## Troubleshooting

- Bot does not respond: confirm `TELEGRAM_BOT_TOKEN`, service logs, group privacy settings, and that the bot was invited to the correct group.
- Bot cannot delete, restrict, ban, or run join challenge enforcement: confirm Telegram admin permissions for deleting messages, restricting users, and banning users.
- `/ban` says admin required: add your numeric Telegram ID or username to `TRACABOT_ADMINS`, or run the command from a Telegram chat-admin account.
- DKG evidence is missing: confirm `dkg status`, `DKG_NODE_URL`, `TRACABOT_DKG_MODE=openclaw-adapter`, and any `DKG_AUTH_TOKEN` required by your adapter.
- Skill command returns JSON error: run from the project root, pass valid JSON, and check `OPENCLAW_DKG_ADAPTER_PATH` only if the adapter is installed outside standard OpenClaw paths.
- Conversational replies are template-only: confirm OpenClaw gateway is running, `TRACABOT_CONVERSATIONAL=true`, and `TRACABOT_LLM_PROVIDER=auto`. Run `/status` as an admin to see the discovered OpenClaw model without exposing credentials.
- Demo refuses to write: set `TRACABOT_TEST_MODE=true` for `npm run demo`; this prevents accidental production test writes.

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

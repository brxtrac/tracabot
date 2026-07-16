# Agent Installation Guide for TRACaBot

This guide is written specifically for AI coding agents and autonomous systems that need to help a user self-host a complete, working instance of TRACaBot.

Follow the phases in order. When a step requires human action (creating a Telegram bot, choosing names, providing API keys), clearly tell the human exactly what to do and what to paste.

## Goals of This Guide
- Produce a reliable, production-capable self-hosted TRACaBot.
- Minimize magic and hidden steps.
- Make good default choices explicit while explaining when to deviate.
- Work whether the user already has OpenClaw/DKG running or is starting from scratch.

---

## Phase 0: Prerequisites Check

Confirm the host meets these requirements before starting:

- Node.js **>= 22.20.0** (`node -v`)
- A Linux/macOS server or VM with outbound internet access
- Ability to run long-lived processes (systemd recommended for production)

TRACaBot uses Telegram long polling, not webhooks. It needs outbound HTTPS access to `api.telegram.org`; it does not need a public domain, public IP, inbound port, or TLS certificate.

If any of these are missing, stop and have the human fix them.

---

## Phase 1: Install the DKG v10 + OpenClaw Stack (Most Complex Step)

TRACaBot depends on a local DKG v10 daemon + the OpenClaw DKG adapter. This is the official recommended path.

### 1.1 Install the DKG CLI globally

```bash
npm install -g @origintrail-official/dkg
```

### 1.2 Run the official OpenClaw workspace + DKG daemon setup

Use a dedicated workspace for clarity:

```bash
dkg openclaw setup \
  --workspace /root/.openclaw/workspace \
  --name tracabot \
  --port 9200 \
  --no-fund
```

**Important notes to give the human:**
- This command creates both the DKG daemon and the OpenClaw configuration.
- The port `9200` becomes the value for `DKG_NODE_URL=http://127.0.0.1:9200`.
- The workspace path is usually `/root/.openclaw/workspace` on servers.
- After this command succeeds, the DKG node should be reachable at the URL above.

Verify it worked:

```bash
curl http://127.0.0.1:9200/api/status || echo "DKG node not responding yet"
```

If the node is not running, ask the human to check logs in the workspace (usually under `~/.openclaw` or the workspace directory).

---

## Phase 2: Create the Telegram Bot (Human Action Required)

This step **cannot** be automated.

Tell the human exactly this:

1. Open Telegram and start a chat with **@BotFather**.
2. Send `/newbot`
3. Choose a display name (example: "My Community Guardian").
4. Choose a username (must end in `bot`, example: `mycommunityguardian_bot`).
5. Copy the **HTTP API token** that BotFather replies with.
6. Send `/setcommands` to BotFather and select your new bot.
7. Paste the following exact command list:

```
start - Open Tracabot protection menu
scan - Check a user, wallet, or replied message for scam risk
report - Report suspicious users, messages, links, wallets, or forwarded DMs
ban - Ban a replied user and publish ban evidence (admin)
mute - Admin: mute a replied or mentioned user for a duration
```

8. Invite the bot to the target Telegram group and grant it **admin rights** (at minimum: Delete Messages, Restrict Users, Ban Users).

Store the token securely. It will go into `TELEGRAM_BOT_TOKEN`. Record the BotFather username without the leading `@`; it can go into optional `TRACABOT_BOT_USERNAME` so commands addressed to other bots are ignored from the first update. TRACaBot also resolves its username with Telegram `getMe` during startup.

---

## Phase 3: Clone and Install TRACaBot

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
```

Alternative after npm publication: `npm install -g tracabot`, copy `$(npm root -g)/tracabot/.env.example` into a runtime directory, and run `tracabot` from that directory. The git clone path remains easiest when the agent must edit or inspect source files.

---

## Phase 4: Configure the Environment (.env)

```bash
cp .env.example .env
```

Now edit `.env`. The following are the **minimum required + strongly recommended** settings for a first working install.

### Critical Required Values

```env
TELEGRAM_BOT_TOKEN=your_token_from_botfather
TRACABOT_BOT_USERNAME=mycommunityguardian_bot   # optional; no leading @
TRACABOT_ADMINS=123456789,@yourusername          # comma separated
```

Keep `.env` out of Git. Never paste the complete file, bot token, API keys, DKG auth token, or pseudonym key into chat, commits, issue reports, or logs.

### DKG Configuration (use the values from Phase 1)

```env
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_DKG_MODE=openclaw-adapter
TRACABOT_DKG_READS=true
TRACABOT_DKG_WRITES=true
```

When `TRACABOT_DKG_WRITES=true`, `TRACABOT_DKG_PSEUDONYM_KEY` is required and must contain at least 32 random bytes. Generate a 32-byte random value as 64 hexadecimal characters, then place only the generated value in `.env`:

```bash
openssl rand -hex 32
```

```env
TRACABOT_DKG_PSEUDONYM_KEY=replace_with_generated_value
```

This key HMAC-pseudonymizes Telegram identities and communities before DKG writes. Keep the same key on trusted instances that must correlate pseudonyms in the same Context Graph. Changing it breaks correlation. If DKG writes are deliberately disabled with `TRACABOT_DKG_WRITES=false`, the key is not required.

### Context Graph Decision (Very Important)

**Recommendation for production shared defense:**

- Use `TRACABOT_CONTEXT_GRAPH=tracabot` to contribute to and query the shared TRACaBot intelligence graph.
- Use a private/test graph only while validating setup or developing custom policy.

```env
TRACABOT_CONTEXT_GRAPH=tracabot
```

**Private test graph option:**

- Start with a **personal or test graph** so you don't pollute the public `tracabot` graph while learning.
- Example: `mycommunity-tracabot` or `username-test-graph`

```env
TRACABOT_CONTEXT_GRAPH=mycommunity-tracabot
```

Later, switch back to the public `tracabot` graph (or a wallet-scoped one like `0xYourAddress/tracabot`) to participate in shared intelligence.

### Verified Memory Publishing

Fresh installs keep Verified Memory publishing off because it spends TRAC/gas and requires a registered/funded graph:

```env
TRACABOT_DKG_PUBLISH_VERIFIED=false
```

When DKG v10 Verified Memory publishing is live for your network, fund the DKG operational wallet shown by `dkg wallet`, register or select the publish context graph, then enable:

```env
TRACABOT_DKG_PUBLISH_VERIFIED=true
TRACABOT_PUBLISH_CONTEXT_GRAPH_ID=your_decimal_context_graph_id_if_needed
```

For agent-assisted setup, have the agent run `dkg wallet` and present the operational wallet address plus network name to the operator so funding can be completed without touching private keys.

### Local SQLite Store

TRACaBot stores local operational state in a SQLite WAL database. Use an absolute path in production, especially under systemd:

```env
TRACABOT_DB_PATH=/opt/tracabot/data/tracabot-events.sqlite
```

`TRACABOT_LEGACY_STORE_PATH` is optional. Set it only when migrating an existing JSONL install:

```env
TRACABOT_LEGACY_STORE_PATH=/opt/tracabot/data/tracabot-events.jsonl
```

On first database initialization, TRACaBot imports valid legacy JSONL events once. It keeps the JSONL file unchanged as a backup; SQLite becomes the active store. Ensure the service user can write the database directory. Do not point `TRACABOT_DB_PATH` at a directory.

### LLM Configuration (Multiple Good Options)

**Recommended starting choice (easiest for most people): 9router**

```env
TRACABOT_CONVERSATIONAL=true
TRACABOT_LLM_PROVIDER=9router
TRACABOT_LLM_BASE_URL=https://api.9router.com
TRACABOT_LLM_API_KEY=your_9router_key_here
TRACABOT_LLM_MODEL=openai/gpt-4o-mini
```

**If the user already runs OpenClaw and wants auto-discovery:**

```env
TRACABOT_LLM_PROVIDER=auto
OPENCLAW_CONFIG_PATH=/root/.openclaw/openclaw.json
```

**Direct OpenAI-compatible / local LLM (Ollama, LM Studio, etc.):**

```env
TRACABOT_LLM_PROVIDER=http
TRACABOT_LLM_BASE_URL=http://127.0.0.1:11434
TRACABOT_LLM_API_KEY=
TRACABOT_LLM_MODEL=llama3.1
```

### Other Good Production Defaults

```env
TRACABOT_AUTO_DELETE=true
TRACABOT_AUTO_RESTRICT=false
TRACABOT_AUTO_BAN=false

TRACABOT_WARN_THRESHOLD=60
TRACABOT_RESTRICT_THRESHOLD=75
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_BAN_THRESHOLD=90

TRACABOT_CONVERSATIONAL=true
TRACABOT_PROACTIVE_SCAN_MINUTES=30
```

Enable `TRACABOT_AUTO_RESTRICT` and `TRACABOT_AUTO_BAN` only after sandbox validation with your thresholds and admin policy.

---

## Phase 5: First Run & Validation

```bash
npm start
```

Watch the logs. You should see:

- Successful connection to Telegram
- Connection to the DKG node
- Long polling continuing without a `getUpdates` conflict

Test with a simple command in the group (as an admin):

```
/start
/scan @yourusername
```

If everything is green, the basic installation succeeded.

TRACaBot uses `getUpdates` long polling. Run exactly one active TRACaBot process per `TELEGRAM_BOT_TOKEN`; a second poller causes Telegram conflict errors. Do not configure a webhook. If this token previously used one, remove it before starting polling:

```bash
curl -fsS "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/deleteWebhook?drop_pending_updates=false"
```

Do not put the expanded command, token, or response into logs or shell history on a shared host. Prefer running it from a protected interactive session.

Run the non-Telegram demo to verify DKG writes work:

```bash
npm run demo
```

---

## Phase 6: Optional but Recommended Hardening

### 6.1 Learning Loop (highly recommended)

The learning loop turns raw chat observations into high-quality DKG artifacts:

```bash
# Run in a separate terminal / service
node ./bin/openclaw-learning-loop.js
```

Or use the bin name after npm install: `tracabot-openclaw-learning-loop`.

### 6.2 Systemd Service (production)

Use `docs/tracabot.service.example` as the source of truth. It assumes the repository and `.env` are under `/opt/tracabot`, runtime data is under `/opt/tracabot/data`, and the service runs as Unix user `tracabot`.

Before installing it, inspect and update `WorkingDirectory`, `EnvironmentFile`, `ExecStart`, `User`, and `ReadWritePaths` if your installation differs. For the example's `/opt/tracabot` layout, create the service account and writable data directory, then install the tracked unit:

```bash
getent passwd tracabot >/dev/null || sudo useradd --system --home-dir /opt/tracabot --shell /usr/sbin/nologin tracabot
sudo install -d -o tracabot -g tracabot -m 0750 /opt/tracabot/data
sudo install -m 0644 docs/tracabot.service.example /etc/systemd/system/tracabot.service
sudo systemctl daemon-reload
sudo systemctl enable --now tracabot.service
sudo systemctl status tracabot.service
```

Inspect logs without printing `.env`:

```bash
sudo journalctl -u tracabot.service -n 100 --no-pager
```

### 6.3 Join Challenge (optional but powerful)

If you want to replace generic captchas with a DKG-native challenge, set:

```env
TRACABOT_JOIN_CHALLENGE=true
TRACABOT_JOIN_CHALLENGE_MODE=qa
```

And publish `docs/TRACABOT_CHALLENGE_ASSET.md` as a Knowledge Asset (or use the UAL address challenge mode).

---

## Phase 7: Switching to the Public Shared Graph (When Ready)

When the user wants their community to benefit from (and contribute to) the global `tracabot` intelligence:

1. Change `TRACABOT_CONTEXT_GRAPH=tracabot`
2. Restart the bot.
3. High-confidence decisions will now flow into the public graph and be queryable by every other TRACaBot instance using the same graph.

**Strong advice**: Do this only after the bot has been running cleanly on a private/test graph for some time.

---

## Common Failure Modes & How to Debug

- DKG connection errors → Check `DKG_NODE_URL`, that the daemon is actually running, and `dkg status`.
- Startup rejects `TRACABOT_DKG_PSEUDONYM_KEY` → Generate at least 32 random bytes and set the key, or deliberately disable DKG writes.
- SQLite open/write errors → Check `TRACABOT_DB_PATH`, parent-directory existence, ownership, and the systemd `ReadWritePaths` value.
- Telegram "not authorized to perform this action" → Bot does not have ban/delete/restrict rights in the group.
- Telegram `getUpdates` conflict → Stop the other process or remove an old webhook; only one poller may use a token.
- Commands addressed to this bot are ignored → Check `TRACABOT_BOT_USERNAME` against BotFather without `@`, or remove it and restart so `getMe` resolves the username.
- LLM not working in conversational mode → Wrong provider/model/key combination. Start with `TRACABOT_LLM_PROVIDER=off` to rule out Telegram issues.
- Context graph errors → Name must match the regex in `src/config.js`.

Start diagnostics with `sudo systemctl status tracabot.service` and `sudo journalctl -u tracabot.service -n 100 --no-pager`. Bot owners can also open `/start` in Telegram and inspect the Settings panel.

---

## Final Checklist for the Agent

- [ ] DKG + OpenClaw daemon running and reachable
- [ ] Telegram bot created with correct commands set
- [ ] Bot invited to group with proper admin rights
- [ ] `.env` contains a valid token and at least one admin
- [ ] Optional `TRACABOT_BOT_USERNAME` matches BotFather username without `@`, or startup `getMe` succeeds
- [ ] `TRACABOT_CONTEXT_GRAPH` chosen deliberately
- [ ] `TRACABOT_DKG_PSEUDONYM_KEY` has at least 32 random bytes when DKG writes are enabled
- [ ] `TRACABOT_DB_PATH` points to a writable SQLite file location
- [ ] Existing JSONL path supplied through `TRACABOT_LEGACY_STORE_PATH` only when migration is needed
- [ ] LLM configured and tested (or deliberately turned off)
- [ ] No webhook or competing `getUpdates` process uses the bot token
- [ ] `npm start` succeeds and `/start` plus `/scan` work
- [ ] (Optional) Learning loop running
- [ ] (Production) `docs/tracabot.service.example` installed with correct paths/user and service is active

Once these are green, the installation is complete and the bot is contributing to (or benefiting from) shared DKG intelligence.

---

**End of Agent Installation Guide**

Point your agent at this file with the instruction:  
"Follow AGENT_INSTALL.md exactly. Ask the human for any required secrets or manual actions at the right time."

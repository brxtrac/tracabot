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
- (Strongly recommended) A domain or stable IP if you want reliable webhook-style behavior (polling works fine for most users)

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
curl http://127.0.0.1:9200/status || echo "DKG node not responding yet"
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
conversation - Toggle natural language agent mode per group (default on)
appeal - Submit a correction request for an event
review - Admin review decision for an event
digest - Summarize recent actions and campaign signals
status - Admin status for DKG, permissions, and conversation mode
help - Show tracabot commands and safeguards
```

8. Invite the bot to the target Telegram group and grant it **admin rights** (at minimum: Delete Messages, Restrict Users, Ban Users).

Store the token securely. It will go into `TELEGRAM_BOT_TOKEN`.

---

## Phase 3: Clone and Install TRACaBot

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
```

(Alternative for agents that prefer npm consumption after packaging improvements: `npm install tracabot` and then run from the installed location. The git clone path is currently the most reliable.)

---

## Phase 4: Configure the Environment (.env)

```bash
cp .env.example .env
```

Now edit `.env`. The following are the **minimum required + strongly recommended** settings for a first working install.

### Critical Required Values

```env
TELEGRAM_BOT_TOKEN=your_token_from_botfather
TRACABOT_ADMINS=123456789,@yourusername          # comma separated
```

### DKG Configuration (use the values from Phase 1)

```env
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_DKG_MODE=openclaw-adapter
```

### Context Graph Decision (Very Important)

**Recommendation for first-time users / agents:**

- Start with a **personal or test graph** so you don't pollute the public `tracabot` graph while learning.
- Example: `mycommunity-tracabot` or `username-test-graph`

```env
TRACABOT_CONTEXT_GRAPH=mycommunity-tracabot
```

Later, when the user is confident, they can switch to the public `tracabot` graph (or a wallet-scoped one like `0xYourAddress/tracabot`) to participate in the shared intelligence network.

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
TRACABOT_AUTO_RESTRICT=true
TRACABOT_AUTO_BAN=true

TRACABOT_WARN_THRESHOLD=60
TRACABOT_RESTRICT_THRESHOLD=75
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_BAN_THRESHOLD=90

TRACABOT_CONVERSATIONAL=true
TRACABOT_PROACTIVE_SCAN_MINUTES=30
```

---

## Phase 5: First Run & Validation

```bash
npm start
```

Watch the logs. You should see:

- Successful connection to Telegram
- Connection to the DKG node
- The bot announcing itself

Test with a simple command in the group (as an admin):

```
/status
```

If everything is green, the basic installation succeeded.

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

Create `/etc/systemd/system/tracabot.service` (see the example in the main README).

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tracabot.service
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
- Telegram "not authorized to perform this action" → Bot does not have ban/delete/restrict rights in the group.
- LLM not working in conversational mode → Wrong provider/model/key combination. Start with `TRACABOT_LLM_PROVIDER=off` to rule out Telegram issues.
- Context graph errors → Name must match the regex in `src/config.js`.

Always have the agent run `/status` (or the equivalent skill) as the first diagnostic.

---

## Final Checklist for the Agent

- [ ] DKG + OpenClaw daemon running and reachable
- [ ] Telegram bot created with correct commands set
- [ ] Bot invited to group with proper admin rights
- [ ] `.env` contains a valid token and at least one admin
- [ ] `TRACABOT_CONTEXT_GRAPH` chosen deliberately
- [ ] LLM configured and tested (or deliberately turned off)
- [ ] `npm start` succeeds and `/status` works
- [ ] (Optional) Learning loop running
- [ ] (Production) systemd service configured

Once these are green, the installation is complete and the bot is contributing to (or benefiting from) shared DKG intelligence.

---

**End of Agent Installation Guide**

Point your agent at this file with the instruction:  
"Follow AGENT_INSTALL.md exactly. Ask the human for any required secrets or manual actions at the right time."
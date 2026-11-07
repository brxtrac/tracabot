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
ban - Admin: optional ban command; normal admin bans are logged automatically
mute - Admin: mute a replied or mentioned user for a duration
```

8. Invite the bot to the target Telegram group and grant it **admin rights** (at minimum: Delete Messages, Restrict Users, Ban Users). This admin setup is also what enables automatic native ban logging; no per-ban command is required.

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

### LLM Configuration (Optional; Start With Zero-LLM)

Core protection does not need a model or API key. Start deterministic:

```env
TRACABOT_CONVERSATIONAL=false
TRACABOT_LLM_PROVIDER=off
```

Enable a provider only for optional replies/intent routing. **9router example (optional):**

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

The model ID must be the exact ID served by your provider or local API; verify it in the current catalog. Do not assume an unofficial label such as "deepseek 4.1 flask" maps to a real model. TRACaBot will not guess or translate it. Leave `TRACABOT_LLM_PROVIDER=off` for a fully deterministic deployment. Optional bounds are `TRACABOT_LLM_TIMEOUT_MS` (1000-120000, default 30000) and `TRACABOT_LLM_MAX_TOKENS` (32-2000, default 220). The LLM is never the authority for a ban.

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

### Known campaign identity changes and confirmed evidence

TRACaBot long-polls Telegram like any group member. When **SangMata** (or an equivalent rename alert) posts `User <id> changed name from … to …`, TRACaBot assesses the renamed account. A name match is only a review signal. A removal requires exact stable-identity **confirmed scam** evidence (`review_upheld` / `confirmed_scam`) with authenticated approval provenance plus the per-chat campaign policy. By default that means a same-chat local admin review; shared/verified-graph records are flag-only because the installed adapter cannot prove authenticated publisher approval. Admin bans, campaign association, shared indicators, and name similarity never authorize removal by themselves.

```env
TRACABOT_KNOWN_CAMPAIGN_AUTO_BAN=true
TRACABOT_KNOWN_CAMPAIGN_MIN_BAN_ROOTS=2
# TRACABOT_KNOWN_CAMPAIGN_PATTERNS=bc game,othercampaign
```

Admins reverse via **Reviews** in `/start` (writes a new corrective event; never overwrites ban memory).

### Silent join protection (default)

Genuine joins trigger a deterministic exact-identity lookup even when no LLM is configured. Default behavior is silent: a private `join_protection_check` is recorded, and nothing is posted to the group. Automatic removal is separate and off by default:

```env
TRACABOT_JOIN_AUTO_REMOVE=false
TRACABOT_JOIN_AUTO_REMOVE_CHATS=
TRACABOT_JOIN_EVIDENCE_MAX_AGE_DAYS=180
TRACABOT_JOIN_MIN_CONFIRMED_ROOTS=1
# Counts independent underlying findings; duplicate reviews/promoted copies count once.
TRACABOT_JOIN_TRUSTED_LAYERS=local
TRACABOT_JOIN_TRUSTED_SOURCES=
```

Turning it on still requires all of: exact stable identity, confirmed fraud/scam evidence with authenticated approval provenance (by default same-chat local admin review; shared/verified-graph records are flag-only), fresh evidence, no newer retraction, enough independent roots, real ban rights, and a target who is not an admin/owner/bot. A creator-curator attestation is accepted only with a fresh signed status read from the pinned creator Ed25519 key; fork source strings, booleans, ban counts, names, behavior flags, model output, campaign association, and Verified Memory membership alone cannot authorize removal. Unknown provenance, graph/status outage, stale/incomplete evidence, and missing rights fail closed. See `docs/PUBLIC_GRAPH.md#silent-join-protection`.

### Creator-curator approval and private appeals

The creator curator creates or revokes signed Ed25519 attestations for exact Telegram subjects. Use the CLI (`tracabot-curator --attest|--revoke|--status`) with `TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH` and `TRACABOT_CREATOR_CURATOR_STORE`, or the authenticated API routes in `docs/PUBLIC_GRAPH.md`. Consumers pin `TRACABOT_CREATOR_CURATOR_PUBLIC_KEY_PATH`, set `TRACABOT_CREATOR_CURATOR_URL`, a read token, then add `creator-curator` to `TRACABOT_JOIN_TRUSTED_LAYERS`. Auto-removal remains opt-in with `TRACABOT_JOIN_AUTO_REMOVE=true`.

```env
TRACABOT_CREATOR_CURATOR_URL=https://creator.example
TRACABOT_CREATOR_CURATOR_PUBLIC_KEY_PATH=/etc/tracabot/creator-public.pem
TRACABOT_CREATOR_CURATOR_READ_TOKEN=<long random read token>
TRACABOT_CREATOR_CURATOR_MIN_CONFIDENCE=90
TRACABOT_CREATOR_CURATOR_MIN_ROOTS=1
TRACABOT_CREATOR_CURATOR_READ_RATE_LIMIT_PER_HOUR=120
TRACABOT_CREATOR_CURATOR_WRITE_RATE_LIMIT_PER_HOUR=30
TRACABOT_JOIN_TRUSTED_LAYERS=creator-curator,local
```

Creator API read and write limits are independent; auth runs before rate limits, signing, and store reads. A read token never grants write access.

Configured admins and current Telegram group admins can open private `/start` for **Protection controls**, **Status**, **Recent automatic bans**, and **Appeals**. Each view is scoped live to groups where the caller is a current Telegram administrator; configured bot owners without that live status see no group details. `/controls` opens the same keyboard directly. Pausing future automatic join removals is per group and persisted with the acting admin in local audit; evidence capture/sharing continue under existing consent. Resume only clears that pause: it cannot enable `TRACABOT_JOIN_AUTO_REMOVE=false`, add a group outside `TRACABOT_JOIN_AUTO_REMOVE_CHATS`, restore missing bot ban rights, or change trusted layers. Reversing an existing automatic ban is separate: select the case, confirm **Override / allow return**, and the bot records a group-scoped local correction and safely requests unban without requiring a member appeal. A failed unban exposes **Retry unban**; retries reconcile member state or use new idempotent attempt keys. Native Telegram admin bans/unbans remain the primary compatibility path; manual `/report`, `/ban`, and `/mute` remain available but are not required for automatic protection.

Banned users start a private chat and send `/appeal`; the bot cannot DM them first. The bot lists only their own local ban cases. Only actual current admins of the affected group can resolve, with `/appeals`, the private `/start` Appeals button, buttons from the case notice, or `/appeal_uphold|/appeal_overturn <ref>`; configured bot owners without that live admin status cannot. Overturn or native admin unban creates a group-scoped local override and retries Telegram unban with reconciliation or new attempt keys after timeout/5xx. Same-lineage wrappers do not restore removal; only an active, fresh, unretracted, independent authenticated approval clears it. A finally upheld case cannot be resubmitted as a dead pending appeal. Set `TRACABOT_APPEAL_MAX_PER_HOUR`, `TRACABOT_APPEAL_DEDUP_HOURS`, and `TRACABOT_APPEAL_MAX_REASON_CHARS` to bind submissions.

### Creator-hosted graph and opt-in federation

Read the creator graph through a DKG node connected to it; no write token is needed. To contribute bounded observations/allegations:

```env
TRACABOT_INSTANCE_ID=community-one-instance
TRACABOT_SUBMIT_SHARED_EVIDENCE=true
TRACABOT_CREATOR_SUBMIT_URL=https://creator.example/api/public/evidence
TRACABOT_CREATOR_SUBMIT_TOKEN=<community-scoped token>
```

Submissions are off by default, queued, deduplicated, retried with bounded backoff, and contain no raw message text, screenshots, or reporter identity. They remain untrusted working-memory observations until the creator's review policy promotes them. Opting out stops new sends; it cannot unpublish already accepted records. Tests must not write to a live graph.

### Platform support

Telegram is the only implemented platform. Discord and other adapters are not implemented; a bot token alone never grants message or membership event visibility. Required Telegram setup: add the bot as an administrator with Delete Messages, Restrict/Ban Users, and the ability to see group messages; request `chat_member` updates (the bot does this in polling).

### Native admin ban logging (default)

Once the bot is a group administrator and polling, it requests `chat_member` updates. When any admin bans a member through normal Telegram controls, TRACaBot records a live enforcement event with the target, community, observed time, the acting admin when Telegram provides it, and an explicit reason status. No `/ban` command or manual approval is needed.

Be exact about platform limits when explaining this to an operator:

- The Telegram Bot API cannot read Recent Actions, the admin log, or bans that happened before the bot was installed.
- Telegram does not send the banning admin's unstated reason. TRACaBot labels those records `reason not provided` and never guesses from the last message.
- TRACaBot can attach up to 8 messages it already observed from the same user ID in the same chat during the 60 minutes before the ban. The block is labeled `recent pre-ban context; causal link unverified`; it is not the ban reason and does not prove guilt. Missing messages, media-only messages, and unrecognized text stay `unknown` or partial.
- Context classification is deterministic (`unknown`, `behavior`, `spam`, `suspected_scam`, `suspected_campaign`) and never upgrades an admin enforcement record to `confirmed_scam`. Raw text stays local and is removed from older ban events on store startup and on later store activity (at most hourly) after the 7-day observed-message retention window; public records carry only bounded categories, counts, and indicators.
- `/ban <reason>` remains available for a bot-performed ban with an explicit reason, but it is optional.
- A live admin ban is `admin_enforcement`, not `confirmed_scam`. With DKG writes and `TRACABOT_AUTO_PROMOTE_EVIDENCE=true`, eligible provenance-backed bans are shared automatically as enforcement-only claims. They do not by themselves authorize a cross-community ban.
- An observed unban records a correction; the original enforcement history remains.

```env
TRACABOT_AUTO_PROMOTE_EVIDENCE=true
```

Set `TRACABOT_AUTO_PROMOTE_EVIDENCE=false` for local-only enforcement records. `TRACABOT_DKG_WRITES=false` stops graph writes entirely.

---

## Phase 5: First Run & Validation

Run the offline checks first. They do not contact Telegram or write to DKG:

```bash
npm test
npm run test:commands
npm run check:release   # optional: test + command loop + production audit + pack preview
git diff --check
```

Then start the bot:

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

## Phase 6.4: Public Reader and Community Onboarding

The reader is local-only by default and adds no dependencies:

```bash
npm run web
# http://127.0.0.1:8787
```

It exposes free, sanitized read routes (`/api/public/status`, `/incidents`, `/campaigns`, `/policy`, `/onboarding`). Do not describe the endpoint as public until you have placed it behind a reverse proxy or private tunnel and verified access yourself. The reader does not expose raw private graph data.

Writes are disabled until you configure operator-issued tokens:

```env
TRACABOT_COMMUNITY_TOKENS=[{"token":"replace-with-a-long-random-value","communityId":"community-one","name":"Community One","scopes":["evidence:write"]}]
```

Generate each token with `openssl rand -hex 32` and deliver it privately. The token is bound to one `communityId`; request bodies cannot override the tenant. `POST /api/public/evidence` stages only `observation` or `allegation` and requires an `Idempotency-Key` header. It never accepts admin verification, confirmed-scam status, confidence, or ban instructions.

Membership requests are recorded for manual review:

```bash
npm run membership -- list
npm run membership -- approve <requestId> "Verified community admin"
npm run membership -- reject <requestId> "No verifiable contact"
```

Approval only records a local decision. It does not create a token, a graph, or a chain transaction. After approval, verify the community's DKG node and graph, add a scoped token, and restart the reader.

Automatic evidence promotion is controlled by:

```env
TRACABOT_AUTO_PROMOTE_EVIDENCE=true
TRACABOT_EVIDENCE_HIGH_CONFIDENCE_THRESHOLD=85
TRACABOT_EVIDENCE_PROMOTION_THRESHOLD=85
```

Admin bans are evidence signals, not proof. Live native admin bans with provenance can be auto-promoted as `admin_enforcement` only; model-only suspicion cannot become a confirmed-scam record or cause a ban. Missing reasons stay `reason not provided`, and missing provenance is never promoted. Retracted reviews and observed unbans suppress promotion and remain visible as corrections. See `docs/PUBLIC_GRAPH.md` for the full boundary and API examples.

The exact DKG/OpenClaw setup supported by this repository remains:

```bash
npm install -g @origintrail-official/dkg
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
curl -fsS http://127.0.0.1:9200/api/status
```

An external OriginTrail edge-node installer may exist, but this repository does not verify or deploy it. Do not claim an edge node, chain deployment, Context Graph registration, or Verified Memory publish until the operator verifies it.

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
- Native admin bans not logged → Confirm the bot is a group administrator, exactly one process polls the token, no webhook is active, and the Bot API is delivering `chat_member` updates. Historical Recent Actions and pre-install bans cannot be backfilled.
- Telegram `getUpdates` conflict → Stop the other process or remove an old webhook; only one poller may use a token.
- Commands addressed to this bot are ignored → Check `TRACABOT_BOT_USERNAME` against BotFather without `@`, or remove it and restart so `getMe` resolves the username.
- LLM not working in conversational mode → Wrong provider/model/key combination. Start with `TRACABOT_LLM_PROVIDER=off` to rule out Telegram issues.
- Context graph errors → Name must match the regex in `src/config.js`.

Start diagnostics with `sudo systemctl status tracabot.service` and `sudo journalctl -u tracabot.service -n 100 --no-pager`. Bot owners can also open `/start` in Telegram and inspect the Settings panel.

---

## Final Checklist for the Agent

- [ ] DKG + OpenClaw daemon running and reachable
- [ ] Telegram bot created with correct commands set
- [ ] Bot invited to group with proper admin rights; native admin bans are auto-logged from `chat_member` updates
- [ ] Operator understands that Recent Actions, pre-install bans, and unstated reasons are unavailable
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
- [ ] (Optional) `npm run web` serves the sanitized reader; public exposure verified separately
- [ ] (Optional) Community write tokens are scoped, random, and stored outside Git
- [ ] (Optional) Membership requests reviewed manually; no automatic write access
- [ ] (Production) `docs/tracabot.service.example` installed with correct paths/user and service is active

Once these are green, the installation is complete and the bot is contributing to (or benefiting from) shared DKG intelligence.

---

**End of Agent Installation Guide**

Point your agent at this file with the instruction:  
"Follow AGENT_INSTALL.md exactly. Ask the human for any required secrets or manual actions at the right time."

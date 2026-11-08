# Testing TRACaBot

This guide is for humans and agents evaluating TRACaBot from a fresh checkout. It avoids production Telegram actions unless explicitly marked.

## Requirements

- Node.js `>=22.20.0`.
- Optional: local DKG v10 node/OpenClaw adapter for live Shared Memory tests.
- Optional: Telegram bot token and sandbox group for end-to-end moderation tests.

## Fast Local Check

Run from repo root:

```bash
npm install
npm test
npm audit --omit=dev
npm pack --dry-run
```

Expected result:

- All tests pass, including join-protection decisions (allow/flag/remove, graph outage, stale/retracted, admin/bot protection, missing rights, duplicate replay), per-group admin/observer mode isolation and refresh, observer quiet/advisory behavior, optional LLM-free operation, creator submission opt-in/retry/dedupe, public API privacy, and exact-identity DKG lookup.
- Production audit reports `0` vulnerabilities.
- Package preview includes `bin`, `src`, `skills`, `docs`, `README.md`, `SECURITY.md`, and `LICENSE`.
- No live public graph write, deployment, or real user removal is performed by the suite.

## Demo Mode

Use this when you want realistic DKG-shaped behavior without a Telegram group:

```bash
cp .env.example .env
npm run demo
```

Set `TRACABOT_TEST_MODE=true` in `.env` if you want to prevent accidental production writes while exploring configuration.

## Command Loop Smoke Test

Use this to exercise the Telegram command flow in a controlled command-loop harness:

```bash
npm run test:commands
```

This covers command parsing, scan/report/ban-style flows, local event storage, DKG write boundaries, and output formatting.

## Agent Tool Testing

Agents can call TRACaBot through `skills/tracabot/skill.json` or the JSON CLI bridge.

Examples:

```bash
npm run skill -- scan_target '{"telegramUserId":"8388593201","text":"possible support impersonation"}'
npm run skill -- monitor_chat_event '{"telegramUserId":"8388593201","text":"official support says verify wallet now","adminVerified":false}'
npm run skill -- get_digest '{}'
npm run skill -- get_watchlist '{"filter":"all"}'
npm run skill -- query_campaigns '{}'
```

Expected behavior:

- `scan_target` returns risk without Telegram enforcement.
- `monitor_chat_event` can write evidence-backed Shared Memory events when configured with DKG access.
- `get_digest`, `get_watchlist`, and `query_campaigns` read local operational memory.
- `submit_appeal` records a local-only private appeal/correction; `review_event` writes correction/review artifacts when DKG is configured.

## OpenClaw Learning Loop

TRACaBot can draft local conversation artifacts and let an OpenClaw-side loop sort committed artifacts into DKG v10 Shared Memory.

One pass:

```bash
node ./bin/openclaw-learning-loop.js --once
```

Dry run:

```bash
node ./bin/openclaw-learning-loop.js --dry-run --once
```

Expected behavior:

- Draft-only artifacts stay local.
- Committed high-quality artifacts get `commit_receipt_id`.
- Failed drafts are marked once and not retried forever.
- Redacted artifacts do not write raw secrets, long Telegram IDs, or full wallet addresses into DKG payload text.

## Evidence Policy, Promotion, and Public API

Focused checks:

```bash
node --test test/evidence-policy.test.js test/evidence-promoter.test.js test/public-server.test.js
```

Run a promotion pass without a live Telegram group:

```bash
npm run promote
```

Expected behavior:

- A live native admin ban with provenance stays `admin_enforcement`, is auto-promoted as enforcement-only, and is never labeled a confirmed scam.
- High-confidence or corroborated enforcement without explicit consent, verified action provenance, or a valid target is not auto-promoted.
- A native admin ban with no available reason records `reason not provided`; missing provenance is never promoted.
+- A live ban attaches only same-user, same-chat messages from the bounded pre-ban window, labels them `recent pre-ban context; causal link unverified`, and excludes other users, other chats, and later messages.
+- Message text/caption is classified deterministically; media-only or unobserved context stays `unknown`/partial, arbitrary profanity is not treated as a confirmed scam, and repeated indicators are needed before `suspected_campaign`.
+- Public/DKG ban records carry context category, severity, counts, and bounded indicators, never raw message text, message IDs, private chat links, or admin identities.
+- Context capture respects `TRACABOT_BAN_CONTEXT=false`; duplicate `chat_member` delivery creates one ban event, and old raw context text and cached message text are expired on store activity (throttled hourly) as well as startup after the observed-message retention window.
- Duplicate updates and bot-performed command bans do not create duplicate enforcement records.
- An observed unban or `review_overturned` suppresses the promoted claim and remains visible as a correction.
- Model-only suspicion stays an observation/review item and cannot promote.
- Corroborated high-confidence evidence is promoted once; repeated runs and restarts do not duplicate it.
- A DKG failure records `evidence_promotion_failed` and leaves the source retryable.
- Public records contain no raw Telegram IDs, usernames, chat titles, message text, or reporter data.
- Write tokens are tenant-scoped; body-supplied tenant overrides are ignored.
- Membership requests require consent, are deduplicated, and grant nothing automatically.

Start the local reader:

```bash
npm run web
curl -fsS http://127.0.0.1:8787/api/public/status
```

No live public deployment, chain transaction, or graph registration is created by these tests.

## Live DKG Setup

Install and configure DKG/OpenClaw:

```bash
npm install -g @origintrail-official/dkg
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

Set `.env` values:

```text
TRACABOT_DKG_MODE=openclaw-adapter
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_CONTEXT_GRAPH=tracabot
```

Live DKG expectations:

- `createContextGraph` ensures Context Graph `tracabot` exists.
- `share` writes evidence-backed events to DKG v10 Shared Memory.
- `query` reads Shared Memory for cross-community evidence.
- `publishSharedMemory` targets eligible high-confidence/admin-reviewed event roots.

## Telegram Sandbox Test

Use a private sandbox group, never a production group first.

1. Create bot with BotFather.
2. Add token to `.env` as `TELEGRAM_BOT_TOKEN`.
3. Add your Telegram ID or username to `TRACABOT_ADMINS`.
4. Add bot to sandbox group.
5. Grant delete/restrict/ban permissions only if testing enforcement.
6. Start bot:

```bash
npm start
```

Safe flows to test first:

```text
/start
/scan @someuser
Open /start > Stats
Open /start > Reviews
Open /start > Settings > Status
```

Enforcement and moderation flows to test only in sandbox:

```text
Ban a test member with normal Telegram admin controls (no command) and verify Enforcement shows "native admin · reason not provided". If the bot observed earlier messages from that test user, the admin log also shows a bounded context category; the detail remains labeled "recent pre-ban context; causal link unverified".
/ban reason here
/mute 5 minutes
Open /start > Settings > Challenge on/off
```

Native admin logging requires the bot to be a group administrator and the only process polling that token. Telegram Recent Actions, pre-install bans, and unstated reasons are not available through the Bot API; do not expect a backfill.

## Creator-curator and appeals checks

Run the isolated tests before the full suite:

```bash
node --test test/creator-curator.test.js test/appeals.test.js test/join-protection.test.js test/group-capabilities.test.js
npm test
npm run test:commands
git diff --check
```

Coverage expectations:

- creator attestation: valid signature, tampered payload, wrong key, wrong subject/platform, expired, too old, revoked, unsigned, stale status read, status outage, insufficient independent roots, Ed448/other key types rejected, and successful approve → signed lookup → opted-in join removal;
- creator API: independent read/write rate limits, authentication before rate/signing/store access, read token cannot write;
- appeals: private `/start` and `/appeal` identity, own-case-only discovery, no cross-user/chat enumeration, bounded reason, dedup, hourly rate limit, local-only storage, configured bot owner without current group admin rejected for view/resolve/unban, live admin lookup failure fails closed, no appeal reason sent to unrelated owners, final upheld resubmission rejected with no dead pending case, scoped group-admin resolution, uphold, overturn, timeout/5xx unban retry with new attempt keys or member-state reconciliation, native admin unban overrides an active creator attestation on a genuine rejoin, and local override through same-lineage review wrappers while active creator evidence stays revoked; only active fresh unretracted independent approval clears an override;
- admin protection controls: private `/start` exposes reachable Protection controls, Status, Recent automatic bans, and Appeals; group/cross-chat and owner-without-live-admin callbacks fail closed; stale callbacks are rechecked live; per-group pause persists across restart with actor audit; pause is rechecked at the final destructive action; resume cannot override env-disabled auto-removal, chat allowlists, trusted layers, or missing rights; auto-ban selection → confirmation → Override / allow return records one local correction, never needs a member appeal, retries failed unbans safely, suppresses immediate same-evidence reban, and leaves creator/global and other-group records untouched;
- public API: curator write/read token requirement, create/revoke, signed status, rate limiting, and no raw appeal text or private chat data in public responses.

Telegram cannot DM a user who never started the bot. Test appeals by opening the bot privately first and sending `/appeal`. Real unban only removes a ban; it cannot force a user back into a group if other restrictions apply.

## Bounty Review Checklist

- Canonical design brief: `docs/DESIGN_BRIEF.md`.
- Registry draft: `docs/REGISTRY_ENTRY.md`.
- Security notes: `SECURITY.md`.
- Ontology/lifecycle: `docs/TRACABOT_ONTOLOGY.md`.
- OpenClaw skill manifest: `skills/tracabot/skill.json`.
- Package provenance workflow: `.github/workflows/publish.yml`.

Current npm note: `package.json` is `1.0.0`; npm registry publishing requires either `NPM_TOKEN` secret or npm trusted publishing configured for `brxtrac/tracabot` and `.github/workflows/publish.yml`.

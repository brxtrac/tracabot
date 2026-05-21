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

- All tests pass.
- Production audit reports `0` vulnerabilities.
- Package preview includes `bin`, `src`, `skills`, `docs`, `README.md`, `SECURITY.md`, and `LICENSE`.

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
- `submit_appeal` and `review_event` write correction/review artifacts when DKG is configured.

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

Safe commands to test first:

```text
/help
/status
/scan @someuser
/watchlist
/review
/digest
```

Enforcement commands to test only in sandbox:

```text
/ban reason here
/challenge on
/challenge off
```

## Bounty Review Checklist

- Canonical design brief: `docs/DESIGN_BRIEF.md`.
- Registry draft: `docs/REGISTRY_ENTRY.md`.
- Security notes: `SECURITY.md`.
- Ontology/lifecycle: `docs/TRACABOT_ONTOLOGY.md`.
- OpenClaw skill manifest: `skills/tracabot/skill.json`.
- Package provenance workflow: `.github/workflows/publish.yml`.

Current npm note: `package.json` is `0.1.1`; npm registry publishing requires either `NPM_TOKEN` secret or npm trusted publishing configured for `brxtrac/tracabot` and `.github/workflows/publish.yml`.

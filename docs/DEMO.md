# Demo Walkthrough

Use this walkthrough for a short bounty demo or local smoke test. The goal is to show detection, Telegram action, DKG Shared Memory write/read, explainability, and OpenClaw skill access.

Put final demo assets or the hosted demo link in `docs/demo/`. If the video is too large for GitHub, add `docs/demo/tracabot-demo-link.md` with the public URL.

## 1. Host Setup

```bash
npm install -g @origintrail-official/dkg
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
dkg status
```

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
cp .env.example .env
```

Edit `.env` with a BotFather token, admin IDs, and the DKG node URL.

## 2. Verification

```bash
npm test
npm run test:commands
npm audit --omit=dev
```

Expected current result: `73` Node tests pass, command-loop smoke test passes, and production audit reports zero vulnerabilities.

## 3. Telegram Walkthrough

1. Add the bot to a test group.
2. Grant admin rights for deleting messages, restricting users, and banning users.
3. Send a scam-like test message from a non-admin account:

```text
Urgent free USDT airdrop. Connect wallet at claim-example.test and DM support to verify.
```

4. Run `/scan` as a reply to the message.
5. Run `/report` as a reply to the message.
6. Run `/why <event-id>` using the event ID from the bot response.
7. Run `/ban` as a reply to the scam message if using a disposable test account.
8. Run `/stats`, `/stats campaigns`, `/digest`, and `/watchlist`.

Show that the bot explains local evidence, DKG evidence, confidence, action taken, and promotion status.

## 4. Cross-Community Memory

In a second test group or second bot instance using the same `TRACABOT_CONTEXT_GRAPH=tracabot`, scan the same Telegram user ID, scam domain, wallet, or username alias. The second instance should query DKG Shared Memory and include the prior evidence in its risk calculation.

## 5. OpenClaw Skill Bridge

Run OpenClaw-callable tools without Telegram:

```bash
npm run skill -- scan_target '{"telegramUserId":"8388593201","text":"possible support impersonation with fake wallet verification"}'
npm run skill -- get_digest '{}'
npm run skill -- get_watchlist '{"filter":"all"}'
npm run skill -- query_campaigns '{"limit":5}'
```

The CLI returns JSON suitable for OpenClaw agent tooling. Telegram bans are intentionally not exposed as skill tools because enforcement requires chat context, admin identity checks, and Telegram bot permissions.

## 6. DKG Roundtrip Demo

For a direct DKG write/read demonstration without Telegram, run in test mode only:

```bash
TRACABOT_TEST_MODE=true npm run demo
```

The demo refuses production writes unless `TRACABOT_TEST_MODE=true` is set.

## 7. Video Chapters

- 0:00 Problem: Telegram scam intelligence is siloed.
- 0:45 Install: DKG/OpenClaw setup and bot configuration.
- 1:45 Detection: `/scan` and `/report` on a scam message.
- 3:00 DKG: show Shared Memory write/read and UAL/event ID.
- 4:00 Enforcement: `/ban` deletes replied scam message and bans target.
- 5:00 Explainability: `/why`, `/appeal`, `/review`.
- 6:00 OpenClaw: `tracabot-skill` JSON calls.
- 7:00 Cross-community: second group/instance sees prior DKG evidence.

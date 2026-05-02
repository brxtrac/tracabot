# Security

## Secrets

`TELEGRAM_BOT_TOKEN`, `DKG_AUTH_TOKEN`, wallet keys, and OpenClaw gateway tokens must stay in environment variables or local runtime configuration. They are intentionally excluded from this repository.

## Network Egress

tracabot contacts:

- `api.telegram.org` for Telegram Bot API polling, messages, and moderation actions.
- The configured local or private DKG v10 node, default `http://127.0.0.1:9200`.

## DKG Write Authority

The integration writes scam detections, reports, and moderation actions to DKG v10 Shared Memory through OpenClaw's `DkgDaemonClient` adapter. It uses the adapter to create the configured Context Graph, write Shared Memory, query evidence, and publish eligible high-confidence event roots. If the publish step fails, the Shared Memory write is kept and the publish error is recorded in the local audit event.

Local JSONL files are operational working memory for weak reports, watchlist state, digest state, and monitoring-only actions. They should not be treated as public DKG evidence unless a later evidence-backed event explicitly qualifies for DKG sharing.

## Telegram Moderation Controls

- Manual `/ban` requires the sender to be listed in `TRACABOT_ADMINS` or to be a Telegram chat admin.
- Non-admin `/report` calls can publish accepted evidence, but they cannot directly execute a Telegram ban.
- Rejected and weak reports are stored locally only and are not written to DKG Shared Memory.
- Duplicate reports and reporter bursts are rate-limited to reduce abuse.
- Telegram message and evidence fields are bounded before analysis, local logging, and DKG writes.

## Data Handling

The bot stores Telegram chat/user identifiers and structured fraud evidence in its local JSONL audit log. Do not commit files from `data/`. DKG Shared Memory writes are intended for scam evidence, moderation actions, and provenance metadata only. Local `.env` files should be permissioned to the service user only.

## Dynamic Code

No remote code loading, `eval`, preinstall scripts, or postinstall scripts are used.

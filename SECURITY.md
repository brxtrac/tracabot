# Security

## Secrets

`TELEGRAM_BOT_TOKEN`, `DKG_AUTH_TOKEN`, wallet keys, and OpenClaw gateway tokens must stay in environment variables or local runtime configuration. They are intentionally excluded from this repository.

## Network Egress

tracabot contacts:

- `api.telegram.org` for Telegram Bot API polling, messages, and moderation actions.
- The configured local or private DKG v10 node, default `http://127.0.0.1:9200`.

## DKG Write Authority

The integration writes scam detections, reports, and moderation actions to DKG v10 Shared Memory using `dkg shared-memory write` and creates or subscribes to the configured Context Graph with `dkg context-graph create`. It does not call Verified Memory `PUBLISH` by default. Promotion to Verified Memory is reserved for curator-controlled workflows.

## Dynamic Code

No remote code loading, `eval`, preinstall scripts, or postinstall scripts are used.

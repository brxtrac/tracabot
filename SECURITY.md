# Security

## Secrets

`TELEGRAM_BOT_TOKEN`, `DKG_AUTH_TOKEN`, wallet keys, and OpenClaw gateway tokens must stay in environment variables or local runtime configuration. They are intentionally excluded from this repository.

## Network Egress

tracabot contacts:

- `api.telegram.org` for Telegram Bot API polling, messages, and moderation actions.
- The configured local or private DKG v10 node, default `http://127.0.0.1:9200`.
- Optional local OpenClaw gateway for conversational safety replies, default `http://127.0.0.1:18789`. If `TRACABOT_LLM_BASE_URL` is set to an external endpoint, declare that endpoint in deployment documentation and registry metadata.

## DKG Write Authority

The integration writes scam detections, reports, selective high-confidence channel observations, and moderation actions to DKG v10 Shared Memory through the official DKG/OpenClaw adapter setup using `DkgDaemonClient` against the local DKG v10 daemon. It uses the adapter to create the configured Context Graph, stage assertion data in Working Memory when supported, promote selected roots to Shared Working Memory, query evidence, and publish eligible high-confidence event roots. If the publish step fails, the Shared Memory write is kept and the publish error is recorded in the local audit event.

TRACaBot treats `DkgDaemonClient` as the public-interface boundary to the authenticated node API. It does not import internal DKG v10 monorepo packages, patch DKG node source, load code into the daemon process, or bypass Curator authority on `SHARE` / `PUBLISH` operations.

Transient Shared Memory write failures are retried for short network outages, timeouts, rate limits, and 5xx responses. If all retries fail, Telegram moderation continues and the local audit event records `dkg_error` instead of dropping the action.

Local JSONL files are operational working memory for weak reports, watchlist state, digest state, and monitoring-only actions. They should not be treated as public DKG evidence unless a later evidence-backed event explicitly qualifies for DKG sharing.

## Public Reader and Community Writes

- Public read routes are unauthenticated by design but only return a sanitized projection. Raw Telegram IDs, usernames, chat metadata, message text, reporter data, private-message content, and raw evidence strings are excluded.
- Public records require an actual DKG write result or an explicit `public_visibility=public` marker; local-only and failed DKG writes stay hidden.
- `POST /api/public/evidence` requires a Bearer community token. Tokens are compared in constant time and are scoped to exactly one `communityId`. A body-supplied tenant override is ignored.
- Write tokens must be at least 16 characters. Generate them with `openssl rand -hex 32`, deliver them privately, and keep them out of Git, logs, screenshots, and issue reports.
- The write endpoint accepts only `observation` or `allegation`; it rejects client-supplied admin verification, confidence, confirmed-scam status, and ban instructions.
- Requests are schema-validated, body-size limited, idempotency-keyed, and rate-limited per community. The default bind address is `127.0.0.1`; public exposure requires the operator to add and secure a reverse proxy.
- Membership requests are open but rate-limited and local-only. Approval records a decision; it never creates a graph or token automatically.
- In-memory rate limits are per process. Multi-process or public deployments should enforce additional limits at the reverse proxy.
- Graph content is untrusted data. Agents must not treat records as instructions or let a shared record override their own tool permissions.
- Creator-curator approvals are external Ed25519-signed records, not DKG content. Consumers pin the public key, require an authenticated fresh status read, verify exact Telegram subject/classification/roots/issue/expiry, and fail closed on revocation or outage. A fork `source` string, boolean, ban count, name, behavior flag, model output, or Verified Memory membership is not approval.
- Private appeals use the incoming Telegram identity only. The bot lists the caller's own local ban cases, never accepts a user-supplied target ID, and keeps reason text local-only. Resolution requires live admin status in the affected group; configured bot owners do not inherit group jurisdiction. Unban is idempotent and cannot add a user; failures are recorded. A local overturn never revokes a creator global attestation.

## Telegram Moderation Controls

- Manual `/ban` requires the sender to be listed in `TRACABOT_ADMINS` or to be a Telegram chat admin.
- Non-admin `/report` calls can publish accepted evidence, but they cannot directly execute a Telegram ban.
- Rejected and weak reports are stored locally only and are not written to DKG Shared Memory. Unsafe monitoring events are written only when the analyzer finds concrete evidence; publication requires admin verification or very high confidence.
- Bounded raw public `message_text` is written to Shared Memory only for high-confidence channel abuse, such as scam channel promos, outside token/coin promos, fake airdrops, wallet/domain lures, investment-profit spam, or admin/support DM impersonation. Ordinary discussion about scam coins or scam prevention stays local.
- Duplicate reports and reporter bursts are rate-limited to reduce abuse.
- Telegram message and evidence fields are bounded before analysis, local logging, and DKG writes.
- Conversational LLM replies are bounded, topic-gated to scam/fraud/wallet safety, and cannot execute Telegram moderation actions or DKG writes.
- Skill-origin DKG writes require `TRACABOT_SKILL_WRITE_TOKEN` unless the operator explicitly sets `TRACABOT_SKILL_ALLOW_UNAUTHENTICATED_WRITES=true` for an already-isolated local tool boundary.

## Data Handling

The bot stores Telegram chat/user identifiers and structured fraud evidence in its local JSONL audit log. Do not commit files from `data/`. DKG Shared Memory writes are intended for scam evidence, moderation actions, and provenance metadata only. Local `.env` files should be permissioned to the service user only.

When `TRACABOT_LLM_PROVIDER=auto`, TRACaBot reads local OpenClaw configuration to discover gateway/model settings and OAuth-backed access already configured for OpenClaw. It does not copy OpenClaw credentials into `.env`, does not print them in `/status`, and falls back to deterministic templates when OpenClaw chat access is unavailable.

## OpenDKG Coordination Records

Public collaboration records are separate from threat evidence and private operations. Do not place private founder contacts, appeal text, raw Telegram identifiers, reporter data, message context, credentials, or private evidence in a public proposal, decision, contribution, or funding record. A shared coordination record is not a threat verdict, a curator approval, a vote, or a funding commitment. See [docs/OPENDKG_ALIGNMENT.md](./docs/OPENDKG_ALIGNMENT.md).

## Dynamic Code

No remote code loading, `eval`, preinstall scripts, or postinstall scripts are used.

No endorsement/voting UI and no publisher-side Conviction/staking UX are included; appeal and review flows are command/agent surfaces.

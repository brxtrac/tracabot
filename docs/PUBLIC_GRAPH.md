# Public Graph Reader, Bounded Writes, and Community Onboarding

TRACaBot now ships a small public reader and a bounded evidence-submission API. It is implemented with the Node standard library and the existing SQLite store and DKG client. It adds no runtime dependency and no hosted service.

## Silent join protection

The bot runs a deterministic check on a genuine join, even with no LLM configured. It queries by the exact HMAC token derived from the stable Telegram user ID; it never falls back to a username, display name, alias, or fuzzy similarity. The check records a private `join_protection_check` (or `join_protection_degraded` on graph/identity failure). It does not post in the group.

| Condition | Outcome |
| --- | --- |
| No stable platform ID, bot, owner, admin, no evidence, or graph outage | allow/observe locally; no removal |
| Confirmed evidence from `shared-working-memory` or `verified-memory` without authenticated publisher approval | silent local flag; no removal |
| Fork report, display-name/alias-only, campaign association, behavior flag, model output, or an admin ban alone | silent local flag; no removal |
| Exact same-chat local admin review (`review_upheld`) with active lineage, fresh, no retraction, but opt-in off | silent local flag; no removal |
| Same local review with `TRACABOT_JOIN_AUTO_REMOVE=true`, chat allowlisted, minimum roots met, bot has ban rights | silent removal; private enforcement record |
| Creator-curator attestation with valid pinned-key signature, exact subject, fraud/scam classification, fresh signed active status, expiry, minimum independent roots, opt-in on | silent removal; private enforcement record |
| Creator attestation revoked, expired, unsigned, stale status read, wrong key, wrong subject, or status outage | silent local flag; no removal |
| Local group-admin appeal overturn or native admin unban for this chat | allow; local correction; creator global record unchanged; same-lineage wrappers do not restore removal |
| Independent local approval after a correction, but later retracted/stale | correction persists; no creator-attestation reban |
| Removal attempted without rights or with an admin/owner target | private suppression; no group spam |

Defaults:

```env
TRACABOT_JOIN_AUTO_REMOVE=false
TRACABOT_JOIN_AUTO_REMOVE_CHATS=
TRACABOT_JOIN_EVIDENCE_MAX_AGE_DAYS=180
TRACABOT_JOIN_MIN_CONFIRMED_ROOTS=1
# Counts independent underlying findings; duplicate reviews/promoted copies count once.
TRACABOT_JOIN_TRUSTED_LAYERS=local
TRACABOT_JOIN_TRUSTED_SOURCES=
```

Shared/verified-graph evidence is deliberately **flag-only**: DKG Verified Memory membership and writer-controlled `source` strings are not authenticated operator approval. The installed adapter exposes no trustworthy publisher-approval provenance. If a future adapter supplies it, the evidence must set that authenticated approval before it can authorize removal. Do not add `verified-memory` or `shared-working-memory` to the trusted layers expecting a weaker gate; the policy still requires authenticated approval.

`TRACABOT_JOIN_TRUSTED_SOURCES` narrows source strings within trusted layers, but is not a substitute for authenticated provenance. Local admin review evidence is scoped to the same chat. A local review must reference a genuine finding; reviewed subject/chat are resolved from that finding, never from the reviewer. Legacy subjectless review wrappers are rejected or recursively resolved to their underlying genuine finding, bounded and cycle-safe. Corrections and `review_overturned` records suppress older evidence, including when the review target references an underlying event that differs from the promoted record ID; ambiguous contradictory lineage is flag-only. Incomplete DKG result sets cannot authorize removal. The engine fails closed on graph timeout, missing identity key, incomplete DKG response, missing ban rights, or an admin lookup failure.

Membership episodes are persisted across the service-message and `chat_member` delivery paths. Each close stores an event-time boundary plus notification identities. After closure, only a strictly later trustworthy join event time can establish a new episode. Same-second timestamps are ambiguous and replay the closed episode regardless of a newer update or message ID. Missing comparable event time fails closed. This applies after self-enforcement, departure, unban, and restart.

The public site and public API never expose the private decision record, evidence roots, raw target ID, or message text.

## Instance federation

A creator-hosted context graph can be read by any instance whose DKG node is connected to it. Reading does not require write credentials. For an instance to contribute, the operator sets:

```env
TRACABOT_INSTANCE_ID=instance-one
TRACABOT_SUBMIT_SHARED_EVIDENCE=true
TRACABOT_CREATOR_SUBMIT_URL=https://creator.example/api/public/evidence
TRACABOT_CREATOR_SUBMIT_TOKEN=<community-scoped token>
```

Submission is opt-in and off by default. Queued submissions are sanitized to a bounded summary, indicators, and the stable platform ID needed for exact matching; they exclude raw message text, screenshots, reporter identity, and local audit notes. The submitter deduplicates by idempotency key and retries with bounded backoff. Opting out stops new sends but cannot unpublish records the creator already accepted. The creator API stages them as untrusted `observation`/`allegation` working memory; only the creator's own review/promotion policy can raise the claim level.

The instance label is provenance metadata only. It is not a DKG subgraph, membership grant, or authority: the installed adapter exposes context graphs, not a portable per-instance subgraph primitive. Do not claim otherwise.

## Creator-curator attestations

A creator curator can create a signed attestation for an exact Telegram subject. This is the only supported shared approval path that can authorize an opt-in join removal without relying on the DKG adapter's unavailable publisher-approval provenance.

Producer setup:

```env
TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH=/etc/tracabot/creator-private.pem
TRACABOT_CREATOR_CURATOR_TOKEN=<long random write token>
TRACABOT_CREATOR_CURATOR_READ_TOKEN=<long random read token>
TRACABOT_CREATOR_CURATOR_STORE=/var/lib/tracabot/creator-attestations.json
```

```bash
tracabot-curator --attest --subject 123456789 --classification fraud \
  --confidence 96 --ttl-days 30 \
  --root 'id=ban:123456789:a,community_id=-100,event_type=ban_executed' \
  --root 'id=ban:123456789:b,community_id=-200,event_type=ban_executed'
tracabot-curator --revoke --subject 123456789 --reason 'new exculpatory evidence'
```

Authenticated API equivalents:

- `POST /api/creator/attestations` with the curator token.
- `POST /api/creator/attestations/telegram/<id>/revoke` with the curator token.
- `GET /api/creator/attestations/telegram/<id>` with the read token. The response is a short-lived signed status envelope.

Consumer setup:

```env
TRACABOT_JOIN_AUTO_REMOVE=true
TRACABOT_JOIN_TRUSTED_LAYERS=creator-curator,local
TRACABOT_CREATOR_CURATOR_URL=https://creator.example
TRACABOT_CREATOR_CURATOR_PUBLIC_KEY_PATH=/etc/tracabot/creator-public.pem
TRACABOT_CREATOR_CURATOR_READ_TOKEN=<same read token>
TRACABOT_CREATOR_CURATOR_MIN_CONFIDENCE=90
TRACABOT_CREATOR_CURATOR_MIN_ROOTS=1
TRACABOT_CREATOR_CURATOR_READ_RATE_LIMIT_PER_HOUR=120
TRACABOT_CREATOR_CURATOR_WRITE_RATE_LIMIT_PER_HOUR=30
```

Verification is fail-closed and checks the pinned key ID, Ed25519 signature, issuer, exact Telegram platform and user ID, `confirmed_scam` claim level, fraud/scam classification, confidence threshold, independent roots, issue/expiry, and fresh signed active status. A fork `source` string, boolean, ban count, name match, behavior flag, model output, or Verified Memory membership alone cannot authorize removal. Creator read and write limits are independent; authentication is checked before rate limiting, signing, or store reads; a read token cannot write. Revocation does not require rewriting historical evidence; the signed status read suppresses active use.

## Private ban appeals

Telegram blocks bot-initiated private messages. A banned user must open the bot's private chat and send `/appeal`; the bot then looks up that user's own locally stored ban cases. It never accepts a user-supplied ID and never lists another user's cases. Group `/appeal` returns guidance and a private-chat link instead of posting case details.

- `/appeal` lists up to 10 own cases with a derived case code, age, and local status.
- `/appeal <case code> <reason>` stores a bounded local-only `appeal_submitted` record. Reason text is not shared to DKG or broadcast to the group.
- Duplicate open appeals for the same case and per-user hourly limits are enforced before storage.
- `/appeals` and notification buttons are available only to actual admins of the affected group. A configured admin or bot owner who is not a current Telegram admin cannot view, resolve, or receive that group's appeal details.
- Uphold records an `appeal_resolved` status and keeps the ban. A second appeal of a finally upheld case is rejected explicitly, not stored as a dead pending case.
- Overturn records `review_overturned` as a local correction with normalized underlying lineage roots, queues `creator_reconsideration_requested`, and retries `unbanChatMember` with `only_if_banned`. Timeout or 5xx failures use new per-attempt effect keys after reconciling current member status, so an uncertain call can be safely retried. It cannot add a user to a group. Failures are recorded and visible; `/appeal_retry <ref>` retries safely.
- A local overturn or native admin unban suppresses removal for that chat, including when a later review wrapper points at the same corrected finding, and works with or without a creator URL. Only an active, fresh, unretracted, authenticated, independently rooted new approval can clear the local override; retracted independent approvals do not. A local override does not revoke or mutate the creator's global attestation; only the creator curator can revoke that record.

## What is actually live

- `GET /api/public/*` reads sanitized records from the local TRACaBot store. Records are visible only after they are marked for shared/public memory. With `TRACABOT_PUBLIC_READ_DKG=true`, campaign summaries are also queried from the configured DKG Shared Working Memory.
- `POST /api/public/evidence` is an authenticated, community-scoped write endpoint. It stages an `observation` or `allegation` in local working memory. It never accepts a client-supplied `admin_verified`, `confirmed_scam`, confidence, or ban instruction.
- `POST /api/public/join-requests` records a membership request for manual operator review. It does not create a context graph, mint a token, or grant write access.
- `POST /api/creator/attestations` and the revoke route are authenticated creator-curator writes. `GET /api/creator/attestations/telegram/<id>` is an authenticated, signed, short-lived status read. They do not write to DKG.
- Private `/appeal` and admins' `/appeals` flows are local-only. Overturn performs Telegram unban with retries; it cannot add a user and does not modify creator attestations.
- `bin/tracabot-promote.js` and the Telegram proactive scan run the evidence policy and promote qualifying evidence to DKG Shared Working Memory without requiring a human promotion click.
- Live Telegram admin bans are captured from `chat_member` updates. The bot must be a group administrator and must be polling; Telegram does not expose Recent Actions, pre-install bans, or an unstated admin reason.
- `bin/tracabot-membership.js` lets the operator list, approve, or reject pending membership requests.

This repository does **not** deploy a public host, register an on-chain Context Graph, create an MCP server, or fund a DKG wallet. Those remain operator actions. Do not claim they exist until verified.

## Run the reader

```bash
cp .env.example .env
npm install
npm run web
```

Defaults bind to `127.0.0.1:8787`, which is intentionally local-only. Put a normal reverse proxy or private tunnel in front if you want public access. Reader routes are free and unauthenticated. Writes stay disabled until you configure at least one community token.

Useful checks:

```bash
curl -fsS http://127.0.0.1:8787/api/public/status
curl -fsS http://127.0.0.1:8787/api/public/incidents?limit=20
curl -fsS http://127.0.0.1:8787/api/public/campaigns?limit=20
curl -fsS http://127.0.0.1:8787/api/public/policy
curl -fsS http://127.0.0.1:8787/api/public/onboarding
```

The site files are in `site/` and are served from an allowlist. There is no directory traversal, template rendering, or user-controlled file path.

## Public read boundary

The public serializer only returns:

- a hashed `publicId`;
- event type and claim level;
- confidence and scam type;
- an explicit `enforcement` block for admin enforcement: action, reason status (`reason not provided` or internally recorded but not published), actor-recorded flag, and source;
- a `banContext` block when the bot observed pre-ban messages: category, severity, confidence, observed/text/media counts, behavior flags, `causalLink: unverified`, provenance, and bounded domains/wallets/patterns. Raw message text, message IDs, chat links, and admin identities are never included;
- normalized domains, wallets, and patterns; URL indicators are reduced to hostnames, so userinfo, ports, paths, query strings, and credentials are never shared;
- HMAC `actorRef` / stable `targetRef` / `communityRef` when a pseudonym key is configured;
- an `actorRecorded` boolean for enforcement records; raw admin IDs and usernames stay local and are never copied into promotion payloads or public SWM triples;
- evidence counts, evidence hashes, timestamps, and provenance labels.

It never returns raw Telegram IDs, usernames, first names, chat titles, chat IDs, message text, reporter data, screenshots, private-message content, or raw evidence strings. Local-only events, failed DKG writes, and `working_memory` events are excluded.

Public read is not raw graph access. It is a sanitized projection over records that are already marked shared or public. The API does not proxy arbitrary SPARQL, arbitrary graph names, or arbitrary DKG methods.

## Claim levels

| Level | Meaning | Promotion |
| --- | --- | --- |
| `observation` | Bounded local signal, model-only suspicion, or unverified submission. | No |
| `allegation` | Report/claim with a target and some evidence. | No |
| `admin_enforcement` | Live ban or restriction with provenance. Enforcement evidence, not a scam verdict. | Yes, when admin-verified provenance is present; missing reasons stay labeled `reason not provided` |
| `high_confidence_flag` | Concrete indicators plus independent corroboration over threshold. | Yes |
| `confirmed_scam` | Explicit upheld admin review. | Yes |
| `retracted` | Overturned review, unban, or correction. | Never |

An admin ban alone is deliberately not a confirmed scam. A live provenance-backed ban is eligible for automatic enforcement-only sharing; missing provenance is rejected. AI/model text can create review material with supporting evidence but cannot independently become a confirmed-scam record, a ban, or a public definitive accusation. Enforcement-only records do not by themselves trigger cross-community bans.

## Automatic WM → SWM promotion

The policy is in `src/evidence-policy.js`; the writer is `src/evidence-promoter.js`.

It runs:

- immediately after a supported live native admin ban is recorded (if automatic promotion is enabled);
- during the Telegram bot's proactive scan when `TRACABOT_AUTO_PROMOTE_EVIDENCE=true`;
- on the public server interval when `npm run web` is running;
- on demand with `npm run promote`.

It is idempotent by source event id, effect claim, and evidence fingerprint. A retraction (`review_overturned`, including an observed unban) stops promotion and keeps the correction visible. A DKG failure records `evidence_promotion_failed` locally, keeps the source record, and leaves the promotion retryable. Restarting the process does not duplicate a completed promotion.

A live native admin ban needs no `/ban` command. The source event carries the target, community, observed time, actor when Telegram supplies it, `enforcement_action: ban`, and `reason_provided: false` with `reason: reason not provided` when applicable. The promoted public record remains `admin_enforcement`, never `confirmed_scam`. The enforcement-only auto-share path fails closed unless all of these are explicit: operator consent (`consent_to_share: true`), verified action provenance (`admin_verified` or `enforcement_verified`), a valid target, and provenance source. High confidence or corroborating evidence roots cannot bypass this gate. An explicit opt-out records `sharing_consent_denied`; enforcement records also record `sharing_consent_missing` when consent is absent.

When the bot already observed messages from the same user and chat before the ban, the source event carries bounded context: up to 8 messages from the previous 60 minutes, text/caption up to the configured cap, and a deterministic category (`unknown`, `behavior`, `spam`, `suspected_scam`, `suspected_campaign`). The label is always `recent pre-ban context; causal link unverified`. Only the sanitized summary is promoted: actual DKG triples include `banContextCategory`, `banContextSeverity`, `banContextConfidence`, `banContextMessageCount`, `banContextCausalLink`, `banContextProvenance`, bounded `banContextDomain`/`banContextWallet`/`banContextPattern` values, and `banContextBehaviorFlag` triage flags such as `threat` or `harassment`. The promotion payload omits raw messages and the DKG client filters private evidence predicates, so raw text, message IDs, chat titles, admin identities, and target identities never enter public SWM. Local ban events keep raw text only inside the 7-day observed-message retention policy; older copies are redacted on store startup and on throttled store activity (at most hourly), including continuously running bots.

Tune with:

```env
TRACABOT_AUTO_PROMOTE_EVIDENCE=true
TRACABOT_AUTO_PROMOTE_INTERVAL_MS=300000
TRACABOT_EVIDENCE_HIGH_CONFIDENCE_THRESHOLD=85
TRACABOT_EVIDENCE_LOCAL_CONFIDENCE_THRESHOLD=60
TRACABOT_EVIDENCE_PROMOTION_THRESHOLD=85
TRACABOT_EVIDENCE_MIN_INDEPENDENT_SIGNALS=2
TRACABOT_EVIDENCE_MIN_INDEPENDENT_COMMUNITIES=2
```

Weak, model-only, retracted, missing-provenance, or explicitly denied records are not promoted to shared memory. `local_only: true` is a current local staging marker, not a permanent privacy prohibition: an otherwise eligible staged record can still be promoted when the evidence policy and sharing consent allow it. Explicit `consent_to_share: false` or `privacy_opt_out: true` is a permanent sharing gate for that record and blocks direct DKG writes even when a caller requests `writeDkg: true`. Enforcement records without a reliable source or target cannot be auto-promoted.

## Bounded write access

Configure one entry per community. Tokens must be at least 16 characters and are compared in constant time. A token is bound to exactly one `communityId`; a request body cannot select another tenant.

```env
TRACABOT_COMMUNITY_TOKENS=[{"token":"replace-with-a-long-random-value","communityId":"community-one","name":"Community One","scopes":["evidence:write"]}]
```

Generate a token without printing it into shell history on a shared host:

```bash
openssl rand -hex 32
```

Submit an observation:

```bash
curl -fsS -X POST http://127.0.0.1:8787/api/public/evidence \
  -H "Authorization: Bearer $TRACABOT_COMMUNITY_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: observation-2026-11-06-001" \
  -d '{
    "claimType": "observation",
    "consentToShare": true,
    "summary": "Fake support account asked a member to verify a wallet over DM.",
    "sourceUrl": "https://t.me/example/123",
    "indicators": {
      "domains": ["verify-example.example"],
      "patterns": ["impersonation", "wallet-drain"]
    }
  }'
```

Server limits and validation:

- `claimType` is limited to `observation` or `allegation`;
- `consentToShare` must be `true`;
- 8–128 character `Idempotency-Key`;
- request body capped by `TRACABOT_PUBLIC_MAX_BODY_BYTES` (default 32768);
- per-community rate limit `TRACABOT_PUBLIC_RATE_LIMIT_PER_HOUR` (default 30);
- bounded arrays for domains, wallets, and patterns;
- `http`/`https` only for source URLs;
- no private-message dump field; use a bounded summary plus indicators.

Responses:

- `202` staged observation;
- `200` duplicate idempotency key, no second record;
- `400` validation failure;
- `401` missing or invalid token;
- `413` body too large;
- `429` rate limit.

## Membership requests

The public form and API only record interest:

```bash
curl -fsS -X POST http://127.0.0.1:8787/api/public/join-requests \
  -H "Content-Type: application/json" \
  -d '{
    "communityName": "Example Builders",
    "contact": "@example_admin",
    "graph": "tracabot",
    "agent": "OpenClaw",
    "notes": "We moderate a 4k-member support group.",
    "consent": true
  }'
```

Operator review:

```bash
npm run membership -- list
npm run membership -- approve <requestId> "Verified community admin"
npm run membership -- reject <requestId> "No verifiable community contact"
```

Approval is a local audit record. It does not create a token or graph. After approval, the operator must:

1. confirm the community's DKG node and graph separately;
2. add a scoped token to `TRACABOT_COMMUNITY_TOKENS`;
3. restart the reader;
4. send the token to the approved community through a private channel.

## DKG edge-node setup supported by this repository

These are the commands already documented and used by this project:

```bash
npm install -g @origintrail-official/dkg
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
curl -fsS http://127.0.0.1:9200/api/status
```

Then set:

```env
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_DKG_MODE=openclaw-adapter
TRACABOT_CONTEXT_GRAPH=tracabot
TRACABOT_DKG_READS=true
TRACABOT_DKG_WRITES=true
TRACABOT_DKG_PSEUDONYM_KEY=<32+ random bytes, same across trusted instances>
```

An OriginTrail edge-node installer exists outside this repository. This project does not verify, bundle, or deploy it. Do not claim an edge node, chain transaction, Context Graph registration, or Verified Memory publish exists unless the operator has verified it. `dkg openclaw setup` creates the local workspace and daemon configuration; it does not by itself prove an on-chain graph was registered or funded.

## Cross-community model

- Every token maps to one community.
- Events carry `community_id` and `policy_id` for provenance.
- Shared DKG triples use HMAC pseudonyms instead of raw Telegram IDs and community IDs.
- Public campaign reads return only sanitized campaign fields.
- Corrections are new events; original records are not silently rewritten.
- A joining community must opt in; there is no implicit write permission and no open membership.

## Residual limits

- The public reader is intended for a single operator instance. Multi-region hosting, CDN, and OAuth are not included.
- The API is HTTP/JSON, not MCP. Agents can call it with normal HTTP tools.
- Rate limits are in-memory per process. Use a reverse proxy for multi-process deployments.
- Membership approval is local. There is no on-chain membership registry.
- The evidence policy is deliberately conservative. Expect false negatives; treat that as the safe failure mode.
- Native admin ban logging depends on Telegram Bot API `chat_member` updates. It cannot read Recent Actions or the admin log, backfill bans from before installation, or recover a reason the admin did not supply. If the bot is not an administrator or the process was offline, that transition is not recoverable through polling.

# Public Graph Reader, Bounded Writes, and Community Onboarding

TRACaBot now ships a small public reader and a bounded evidence-submission API. It is implemented with the Node standard library and the existing SQLite store and DKG client. It adds no runtime dependency and no hosted service.

## What is actually live

- `GET /api/public/*` reads sanitized records from the local TRACaBot store. Records are visible only after they are marked for shared/public memory. With `TRACABOT_PUBLIC_READ_DKG=true`, campaign summaries are also queried from the configured DKG Shared Working Memory.
- `POST /api/public/evidence` is an authenticated, community-scoped write endpoint. It stages an `observation` or `allegation` in local working memory. It never accepts a client-supplied `admin_verified`, `confirmed_scam`, confidence, or ban instruction.
- `POST /api/public/join-requests` records a membership request for manual operator review. It does not create a context graph, mint a token, or grant write access.
- `bin/tracabot-promote.js` and the Telegram proactive scan run the evidence policy and promote qualifying evidence to DKG Shared Working Memory without requiring a human promotion click.
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
- normalized domains, wallets, and patterns;
- HMAC `actorRef` / `communityRef` when a pseudonym key is configured;
- evidence counts, evidence hashes, timestamps, and provenance labels.

It never returns raw Telegram IDs, usernames, first names, chat titles, chat IDs, message text, reporter data, screenshots, private-message content, or raw evidence strings. Local-only events, failed DKG writes, and `working_memory` events are excluded.

Public read is not raw graph access. It is a sanitized projection over records that are already marked shared or public. The API does not proxy arbitrary SPARQL, arbitrary graph names, or arbitrary DKG methods.

## Claim levels

| Level | Meaning | Promotion |
| --- | --- | --- |
| `observation` | Bounded local signal, model-only suspicion, or unverified submission. | No |
| `allegation` | Report/claim with a target and some evidence. | No |
| `admin_enforcement` | Ban or restriction. Evidence signal, not proof. | Only with concrete indicators or roots |
| `high_confidence_flag` | Concrete indicators plus independent corroboration over threshold. | Yes |
| `confirmed_scam` | Explicit upheld admin review. | Yes |
| `retracted` | Overturned review or correction. | Never |

An admin ban alone is deliberately not enough. AI/model text can create review material with supporting evidence but cannot independently become a confirmed-scam record, a ban, or a public definitive accusation.

## Automatic WM → SWM promotion

The policy is in `src/evidence-policy.js`; the writer is `src/evidence-promoter.js`.

It runs:

- during the Telegram bot's proactive scan when `TRACABOT_AUTO_PROMOTE_EVIDENCE=true`;
- on the public server interval when `npm run web` is running;
- on demand with `npm run promote`.

It is idempotent by source event id, effect claim, and evidence fingerprint. A retraction (`review_overturned`) stops promotion. A DKG failure records `evidence_promotion_failed` locally, keeps the source record, and leaves the promotion retryable.

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

Weak, model-only, local-only, retracted, or admin-action-only records stay in working memory.

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

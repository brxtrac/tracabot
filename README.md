# TRACaBot

The optional OpenCode scheduled curator is host-specific: it pins `9router/cx/gpt-6-sol#medium` independently of `TRACABOT_LLM` and requires the configured OpenCode agent/provider. It is not the join-protection engine; generic LLM configuration does not make that curator portable.

TRACaBot is an OpenClaw + Telegram + OriginTrail DKG v10 intelligent anti-scam bot. It monitors Telegram communities, detects scam patterns, records local working memory, and writes evidence-backed fraud intelligence to DKG v10 Shared Memory so every TRACaBot instance can query reusable scam context and apply it in its own community. Think of it as a Telegram anti-scam agent that updates with knowledge from all participating communities instead of forcing every group to defend itself alone.

## OpenDKG Collaboration Status

TRACaBot is an independent, MIT-licensed project published in the new repository [OpenDKG/tracabot](https://github.com/OpenDKG/tracabot), with its original maintainer repository and history retained at [brxtrac/tracabot](https://github.com/brxtrac/tracabot). This is a new repository, not a transfer. Publication does not create a shared graph or funding commitment, change the license, or grant umbrella roles any TRACaBot curator, admin, token, or enforcement authority.

TRACaBot remains MIT-licensed. The repository-specific exception record is in [docs/OPENDKG_ALIGNMENT.md](./docs/OPENDKG_ALIGNMENT.md#repository-specific-license-exception-2026-11-07); it does not change OpenDKG's Apache-2.0 default or claim founder unanimity.

The recorded ownership boundaries, privacy separation, proposed contribution and funding mapping, readiness checklist, and remaining decisions are in [docs/OPENDKG_ALIGNMENT.md](./docs/OPENDKG_ALIGNMENT.md). Private contact details are never published.

## Silent Background Protection

Manual `/start`, `/scan`, and `/report` are optional. On a genuine join, TRACaBot runs a deterministic background lookup against the stable platform-scoped Telegram ID, using the privacy-preserving HMAC identity token pipeline. No LLM or API key is required. The default outcome is silent observe/log: the bot records the check privately and posts nothing to the group.

Automatic removal is a separate, explicit opt-in (`TRACABOT_JOIN_AUTO_REMOVE=true`). Even then, removal requires all of:

- an exact stable-identity match, never a display name, username, alias, or similarity match;
- `confirmed_scam` evidence or an explicit admin-upheld review with authenticated approval provenance. By default only same-chat local admin review is trusted; shared/verified-graph records are flag-only because the installed adapter cannot prove an authenticated publisher approval. A creator-curator attestation is trusted only after a fresh, signed status read from the pinned creator Ed25519 key;
- a fresh record within `TRACABOT_JOIN_EVIDENCE_MAX_AGE_DAYS` with no newer correction/retraction;
- the configured minimum number of independent confirmed roots;
- bot ban/restrict rights, and a target who is not an admin, owner, or bot.

Admin enforcement, behavior flags, model confidence, duplicate copies, write authorization, cross-community campaign association, fork source strings, booleans, and Verified Memory membership are evidence signals, not proof. They can flag for review; they cannot authorize a removal. Because the installed DKG adapter does not expose authenticated publisher-approval provenance, shared and verified-graph records are flag-only today; same-chat local admin review and verified creator-curator attestations are the supported approval paths. Graph outages, missing rights, unknown provenance, stale or incomplete evidence, retractions, and ambiguous lineage fail closed to a private local record. See [docs/PUBLIC_GRAPH.md](./docs/PUBLIC_GRAPH.md#silent-join-protection) for the decision table.

## Creator-Curator Attestations

A creator can approve a high-confidence fraud/scam subject once, then each opted-in community reads a fresh signed status before join enforcement. The transport is standard-library HTTP plus Ed25519 signatures; no dependency and no LLM are required.

Producer side:

```env
TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH=/etc/tracabot/creator-private.pem
TRACABOT_CREATOR_CURATOR_TOKEN=<long random curator API token>
TRACABOT_CREATOR_CURATOR_READ_TOKEN=<long random read token>
TRACABOT_CREATOR_CURATOR_STORE=/var/lib/tracabot/creator-attestations.json
```

Create and revoke with the CLI or authenticated API:

```bash
tracabot-curator --attest --subject 123456789 --classification fraud \
  --confidence 96 --ttl-days 30 \
  --root 'id=ban:123456789:a,community_id=-100,event_type=ban_executed' \
  --root 'id=ban:123456789:b,community_id=-200,event_type=ban_executed'

tracabot-curator --revoke --subject 123456789 --reason 'new exculpatory evidence'
tracabot-curator --status --subject 123456789
```

The API uses `POST /api/creator/attestations` and `POST /api/creator/attestations/telegram/<id>/revoke` with `Authorization: Bearer <TRACABOT_CREATOR_CURATOR_TOKEN>`. `GET /api/creator/attestations/telegram/<id>` requires the read token and returns a signed status envelope with a short validity window.

Consumer side, only when you explicitly want creator-curated removals:

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

The consumer verifies the key ID, signature, issuer, exact Telegram platform/user ID, fraud/scam classification, `confirmed_scam` claim level, confidence threshold, independent roots, issue/expiry, and current active status. Creator API read and write limits are independent per source address; auth is checked before rate limiting, signing, or store reads, and a read token never grants write access. A revoked, expired, unsigned, stale, or unreachable status fails closed. A local group-admin overturn never rewrites the creator record; it records a local correction and queues a curator reconsideration request.

## Ban Appeals

A banned user can start a private chat with the bot and send `/appeal`. The bot looks up only that account’s own locally stored ban cases, so a user can appeal even if the bot could not DM them at ban time. Telegram does not allow a bot to initiate the first private message; the user must start the chat. Community guidance is available in `/start` and `/appeal`; groups never receive the private appeal text.

Submissions are bounded, deduplicated per case, rate limited per user, and stored local-only. Only an actual admin of the affected group can resolve an appeal from private chat or the group; configured bot owners do not inherit group jurisdiction. Uphold keeps the local ban and closes the case; a second appeal of a finally upheld case is rejected rather than left pending. Overturn or a native admin unban records a group-scoped local override and, for appeals, queues a creator-curator reconsideration request. A later same-lineage wrapper cannot restore removal; only an active, fresh, unretracted, independent authenticated approval clears the override. Overturn performs an idempotent `unbanChatMember` with retries and visible failures. Retries reconcile the current member state or use new attempt keys after a timeout/5xx, so an uncertain call is not permanently stuck. Unban only permits return; it cannot add a user. See `docs/PUBLIC_GRAPH.md` and `docs/TESTING.md`.

## Creator-Hosted Graph And Opt-In Federation

The default context graph `tracabot` can be creator-hosted. Every instance can read the same sanctioned shared/public records while keeping its own local private state. Reading requires a DKG node connected to that graph; it does not require write credentials. Writing is closed by default.

Independent instances can opt in to send bounded observations/allegations to a creator-hosted API with `TRACABOT_SUBMIT_SHARED_EVIDENCE=true`, `TRACABOT_CREATOR_SUBMIT_URL`, and a community-scoped `TRACABOT_CREATOR_SUBMIT_TOKEN`. Submissions are queued locally, deduplicated by an idempotency key, and retried with bounded backoff. They carry no raw message text, screenshots, or reporter identity. Disabling the flag stops new submissions; it cannot unpublish records the creator already accepted. The creator API keeps them as untrusted working-memory observations until its own review/promotion policy applies. Do not treat every fork report as verified, and do not publish a live graph from tests.

Instance scoping uses the actual DKG context graph plus `communityId`, `communityToken`, `policyId`, and an optional `TRACABOT_INSTANCE_ID` provenance label. TRACaBot does not invent a DKG subgraph or membership primitive that the installed adapter does not expose.

## Supported Platforms

- **Telegram:** fully operational, including live `chat_member` joins, native admin bans, joins, and optional join challenges.
- **Discord and other platforms:** not implemented in this repository. No adapter, token flow, event permission model, or enforcement path is claimed.

Platform-neutral evidence types are deliberately small and only exist where the Telegram adapter uses them. A new platform adapter must supply its own stable platform-scoped identity, event visibility, admin-rights checks, and enforcement implementation.

> **AI agents / self-hosters**: See [AGENT_INSTALL.md](./AGENT_INSTALL.md) for the best experience.

The default Context Graph is `tracabot`. Every community running TRACaBot against that Context Graph contributes to the same DKG v10 Shared Working Memory layer. TRACaBot writes events with provenance, local/DKG confidence, HMAC-pseudonymized Telegram identities and communities, scam type, normalized domain/wallet/pattern indicators, and moderation outcomes. Raw Telegram IDs, aliases, private DM request text, and full URLs stay out of shared DKG triples. Verified Memory publishing is optional and operator-enabled because it spends TRAC/gas; fresh installs keep fraud memory in WM/SWM until the operator funds and registers a publish path.

## Quick Start For Testers

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
cp .env.example .env
npm test
npm run demo
npm run skill -- get_digest '{}'
```

For full human and agent testing paths, see `docs/TESTING.md`. The canonical design brief is `docs/DESIGN_BRIEF.md`.

## Why It Exists

Telegram scam moderation usually stays trapped inside one chat. TRACaBot turns each meaningful scan, report, and moderation action into structured fraud knowledge that can be queried across communities. If a fraudster is banned or reported in one channel, another TRACaBot instance can flag the same Telegram user ID, reused username/display-name alias, wallet, or scam pattern when that actor appears elsewhere.

Existing Telegram moderation tools such as Shieldy, Miss Rose, and similar bots are useful for basic spam filters, captchas, and admin commands, but they were not built for the agent era. They do not keep persistent cross-community memory, do not build reusable evidence, do not reason over scam campaigns across channels, and do not expose agentic workflows for review, correction, or shared intelligence.

TRACaBot is designed for communities that want persistent and verifiable protection instead of isolated bot actions. It is especially relevant for the OriginTrail ecosystem as DKG grows into infrastructure for fighting AI harm: our own community channels, holders, contributors, and newcomers should be protected by the same verifiable memory principles we are building for others.

Telegram is one of the most active social surfaces for many Web3 and AI communities. TRACaBot turns that surface into a practical DKG onboarding point: new participants can see how Working Memory, Shared Working Memory, and evidence-backed trust gradients can secure real communication rather than only reading about DKG in abstract terms.

## Commands

- `/start` opens the inline Tracabot protection menu for stats, reviews, explanations, enforcement history, and settings. In private chat it also exposes **Protection controls**, **Status**, **Recent automatic bans**, and **Appeals** for groups where the caller is a current Telegram admin.
- `/scan` checks a user, Telegram ID, wallet, replied user, or replied SangMata rename alert against local heuristics and DKG Shared Memory, then returns a friendly risk verdict.
- `/appeal` is private-chat only. It lists the caller’s own locally stored ban cases and accepts `/appeal <case code> <reason>`. The bot cannot send the first DM.
- `/appeals` works in private chat for admins of affected groups. Group use only returns private-chat guidance because appeal details are not posted to the group. The `/start` Appeals button opens the same live admin-scoped view.
- `/controls` is the private admin keyboard for groups where you are a current Telegram admin. It pauses/resumes future automatic join removals, shows recent automatic join bans, and supports selection → confirmation → **Override / allow return**. A failed unban exposes **Retry unban**. Pausing future removals is separate from reversing a specific ban; resume cannot enable a policy configured off or bypass missing bot rights or trusted-layer bounds. Only current group admins see a group's controls, bans, or appeals; configured bot owners do not bypass group administration.

Compatibility commands remain available but are not the primary protection path: `/report` queues legacy manual review evidence, `/ban` optionally performs an admin ban with a supplied reason, and `/mute` temporarily restricts a replied or mentioned user. Automatic exact-identity join protection and native Telegram admin-ban logging do not require these commands.

Stats, campaigns, sources, reviews, settings, and recent enforcement actions are available through `/start` menu buttons instead of public slash commands. Admins can also reply naturally to review alerts with explicit verdicts such as “confirm scam” or “reject as not a scam”; non-admin corrections are logged as appeals.

## Community Workflow

Community members can use TRACaBot without needing admin permissions:

- Reply to a suspicious message with `/scan` to get a risk verdict before engaging.
- Reply with `/report` when a message, username, wallet, or link looks like a scam. Reports are queued for admin review before any DKG fraud memory is written.
- Use `/report` with forwarded DM context, a screenshot caption, or a clear description for scam DMs and fake support accounts.
- Open `/start` and use Explain Event when TRACaBot returns an event ID and you want to understand the evidence behind a decision.
- Reply naturally to a bot review alert if you think a report, restriction, or ban was wrong; non-admin corrections are logged as appeals.

## Admin Workflow

Admins keep enforcement guarded and auditable:

- Add TRACaBot to the group as an admin and keep one bot process running. Bans performed by any admin through normal Telegram controls are logged automatically from live `chat_member` updates. No per-ban command is required.
- Use `/ban` only when you want the bot to perform the ban or attach an explicit reason. It is optional and still requires bot ban rights.
- Resolve private appeals from `/appeals` in the bot’s private chat. Only actual admins of the affected group can uphold or overturn. Overturn records a local correction and retries unban; it does not change the creator-curator global record.
- Use `/controls` in the bot’s private chat, or the **Protection controls**, **Status**, and **Recent automatic bans** buttons in private `/start`, for groups where you are a current Telegram admin. The keyboard pauses/resumes future automatic join removals and lists recent automatic join bans; select one, confirm **Override / allow return** to record a local correction and request safe unban without requiring the member to appeal. Failed unbans expose **Retry unban**. Pause state applies only to future removals and is separate from reversing an existing ban. Bot owners and non-admins cannot use these controls for a group.
- Open `/start` and use Reviews to see pending review items and temporary mutes.
- Reply naturally to review alerts with an explicit verdict to resolve appeals or false positives. Review decisions are written to DKG Shared Memory.
- Open `/start` and use Stats/Campaigns to understand recent detections, repeated scam waves, and recommended follow-up.
- Open `/start` and use Settings/Status to verify bot permissions, DKG/OpenClaw adapter versions and memory capabilities, thresholds, learning policy, and conversational mode without exposing secrets.

## Native Admin Ban Logging

Add TRACaBot as a group admin and keep it running. When another admin bans a member through the normal Telegram member controls, Telegram sends a live `chat_member` update. TRACaBot records the target, community scope, observed time, the admin actor when Telegram provides it, and an explicit reason status. This is the default ingestion path; `/ban` is not required.

What the Bot API can and cannot provide:

- **Available:** live membership transitions while the bot is an admin and polling, including a ban (`kicked`), the acting admin as `from`, the target user, and the community.
- **Not available:** Telegram Recent Actions, the admin log, bans that happened before TRACaBot was installed, or a reason the admin did not supply. TRACaBot does not fabricate a reason, infer one from the last message, or silently add a userbot/MTProto credential.
- If no reason is available, the record says `reason not provided`. An explicit `/ban <reason>` reason is recorded when an admin chooses to supply one.

When message context is available, TRACaBot attaches up to 8 recently observed messages from the same stable user ID in the same chat, from the 60 minutes before the live ban. The bot must have seen those messages; it does not fetch chat history, follow later messages, or read media. Each entry keeps bounded text/caption locally, while the record labels the whole set **“recent pre-ban context; causal link unverified”**. It is never presented as the message that caused the ban.

The context is classified with deterministic local signals into `unknown`, `behavior`, `spam`, `suspected_scam`, or `suspected_campaign`, with a triage severity. These are evidence-based suspicions, not a confirmed scam, not a statement of admin intent, and not grounds for new automatic enforcement. Missing messages, media-only messages, or text with no known signal produce partial or `unknown` context instead of invented content. Raw context text stays local; copies inside older ban events are redacted on store startup and on later store activity (throttled to at most once per hour) after the 7-day observed-message retention window. Message-cache text is removed by the same activity-based expiry. Public sharing carries only the category, severity, confidence, message counts, and bounded domains/wallets/patterns. Set `TRACABOT_BAN_CONTEXT=false` to disable content capture.

A live admin ban is `admin_enforcement`, not `confirmed_scam`. With operator graph writes and automatic promotion enabled, eligible provenance-backed enforcement records are shared automatically as enforcement-only claims. Auto-sharing fails closed unless explicit consent, verified action provenance, and a valid target are present; high confidence or corroborating roots cannot bypass that gate. They do not carry scam verdicts and cannot by themselves trigger a cross-community ban. An observed unban records a `review_overturned` correction; the original enforcement record remains as history instead of being silently erased.

Unavoidable setup requirements: the bot must be a group admin with ban/restrict visibility, exactly one process must poll the bot token, `allowed_updates` must include `chat_member` (TRACaBot already requests it), and the operator must enable DKG writes plus automatic evidence promotion for public SWM sharing. Set `TRACABOT_AUTO_PROMOTE_EVIDENCE=false` for local-only enforcement records.

## Campaign Summaries

TRACaBot clusters repeated domains, wallets, scam patterns, and message fingerprints into `fraud_campaign` events. Campaign summaries are only published when they have at least two evidence-backed roots, such as accepted reports, high-confidence findings, restrictions, bans, appeals, or reviews. Weak local detections and prior campaign summaries cannot become campaign evidence roots by themselves.

Published campaign summaries include the campaign key, event count, affected community IDs, evidence root IDs, repeated domains, wallets, and patterns. This lets another TRACaBot instance query the same Context Graph and recognize a repeated scam wave before it spreads further.

## DKG Join Challenge

TRACaBot can replace generic captcha bots with a DKG-native onboarding gate. When `TRACABOT_JOIN_CHALLENGE=true`, low-risk new members are muted until they verify with a Knowledge Asset or configured Knowledge Asset Q&A in DM, then normal chat permissions are restored.

The default-friendly mode is Q&A: publish `docs/TRACABOT_CHALLENGE_ASSET.md` as a DKG Knowledge Asset, set `TRACABOT_JOIN_CHALLENGE_ASSET_URL` to its DKG Explorer link, and configure `TRACABOT_JOIN_CHALLENGE_QA_BANK` with rotating questions whose answers are visible in the asset. The bot posts the asset link in the group, asks one question, and asks the user to DM the answer. Answers are normalized for case, punctuation, and spacing.

If Q&A is not configured, TRACaBot falls back to the Knowledge Asset address challenge: the group prompt asks the user to open `https://dkg.origintrail.io/`, pick any Knowledge Asset address starting with `did:dkg:`, and DM it to the bot. TRACaBot can validate that address against the live DKG before restoring permissions, then explains in DM what Knowledge Assets mean for trusted, shared AI memory.

A Knowledge Asset is a verifiable data item on the Decentralized Knowledge Graph. The challenge gives new members a practical first interaction with DKG while TRACaBot continues checking shared scam memory for high-risk joins, impersonators, and scam patterns.

High-risk joins still bypass the challenge and go directly to the configured risk action. Raw challenge starts, failed attempts, solves, and one-off expirations stay local-only. Repeated challenge failure patterns by stable Telegram ID or normalized alias can be written to DKG Shared Memory as aggregate onboarding-abuse intelligence and surfaced in `/stats campaigns` and `/digest`; evidence-backed scam findings and enforcement outcomes remain the primary events written to DKG Shared Memory.

## DKG v10 Integration

TRACaBot uses the official DKG/OpenClaw adapter setup as its DKG boundary. `DkgDaemonClient` points at the local DKG v10 daemon at `DKG_NODE_URL` and keeps TRACaBot aligned with the same DKG service OpenClaw uses:

- `DkgDaemonClient.createContextGraph` ensures the configured Context Graph exists.
- `DkgDaemonClient.createAssertion`, `writeAssertion`, and `promoteAssertion` stage evidence in DKG Working Memory and promote selected roots to Shared Working Memory when available.
- `DkgDaemonClient.share` remains the compatibility fallback for DKG v10 Shared Memory writes when an older adapter lacks assertion lifecycle methods.
- `DkgDaemonClient.publishSharedMemory` can publish eligible high-confidence or admin-reviewed fraud memory into Verified Memory when `TRACABOT_DKG_PUBLISH_VERIFIED=true` and the graph/wallet are funded.
- `DkgDaemonClient.query` reads shared DKG evidence before scoring a target.

TRACaBot maps Telegram moderation onto the DKG v10 memory model as a trust gradient:

- Working Memory: daily communication artifacts, weak signals, local watch notes, review queues, join-challenge state, and draft conversation artifacts that the agent should remember but not yet share.
- Shared Working Memory: moderate to high-risk evidence that should help related communities, including accepted reports, impersonation patterns, suspicious domains, reused wallets, appeals, admin reviews, and campaign signals.
- Verified Memory readiness: high-confidence or admin-reviewed evidence, such as confirmed impersonation attempts, bans, accepted reports, and false-positive corrections, is shaped so it can later be published or consumed by context oracles without rewriting the data model.

This cross-community loop is the core product behavior: observe locally, write structured evidence to DKG Shared Working Memory, optionally publish high-confidence/admin-reviewed events to Verified Memory, then let every other TRACaBot instance query the same graph before the fraudster can repeat the attack in a different channel.

TRACaBot's event ontology and lifecycle are documented in `docs/TRACABOT_ONTOLOGY.md`. The lifecycle is `observed -> shared_memory -> admin_reviewed -> verified_memory -> campaign_summary`; runtime events include community scope (`communityId`, optional `communityName`, `communityType`) and `policyId` so multiple communities can share one Context Graph without losing policy provenance.

TRACaBot also ships an OpenClaw skill interface in `skills/tracabot/skill.json` and a JSON CLI bridge, `tracabot-skill`, so OpenClaw agents can call the same fraud intelligence without going through Telegram. Skill tools include `scan_target`, `monitor_chat_event`, `explain_event`, `get_watchlist`, `get_digest`, `query_campaigns`, `submit_appeal`, and `review_event`.

OpenClaw can also call `sort_conversation_artifact` to classify scam, spam, phishing, weak-report, warning, benign contrast, or false-positive conversation material. High-quality artifacts are written as `conversation_artifact` events to DKG v10 Shared Memory for LLM-Wiki-style learning, but they do not trigger autonomous enforcement by themselves.

For autonomous LLM-Wiki-style learning, run `node ./bin/openclaw-learning-loop.js` beside the Telegram bot. TRACaBot keeps listening to Telegram and drafting local WM artifacts; the OpenClaw loop drains those drafts through `sort_conversation_artifact`, stamps committed artifacts with `commit_receipt_id`, and writes only committed artifacts to DKG Shared Memory. Use `--once` for a single pass or `--dry-run` to inspect pending draft inputs. Tune with `TRACABOT_LEARNING_LOOP_INTERVAL_MS` and `TRACABOT_LEARNING_LOOP_LIMIT`.

The DKG-native curator runs with `node ./bin/tracabot-curator.js --once` (or without `--once` every 12 hours). Selected suspicious Telegram artefacts are staged as unsealed DKG Working Memory Knowledge Assets. A local script first filters drafts by score and concrete indicators; at most five per run are reviewed by the OpenCode `tracabot-curator` agent (`9router/cx/gpt-6-sol`, `medium`). Only explicit, reasoned fraud/impersonation/harmful-signal approvals are annotated in WM and shared to SWM. Invalid or unavailable LLM reviews never promote. Reviews are persisted in `data/curator-reviews.sqlite` to avoid repeat token use. Expired drafts are discarded after 48 hours. This script does not depend on the OpenClaw gateway. Ordinary low-risk chatter is skipped. With `TRACABOT_HIGH_CONFIDENCE_AUTO_BAN=true`, active Telegram polling script considers concrete wallet-verification lures with a link and pressure/authority cue, then requires exact-actor admin-verified scam history in DKG Shared Working Memory plus explicit OpenCode curator approval before ban. No history, later false-positive clear, DKG read error, curator hold/error, admin target, or missing bot ban rights blocks ban. Run one curator instance per bot identity. Start scheduling only after DKG `working-memory` reads succeed; a retryable authority error blocks curation and expiry.

TRACaBot can also run in conversational safety mode. It keeps its own standalone Telegram bot token and can use `9router`, an OpenClaw-discovered LLM account, a direct OpenAI-compatible API, or a local LLM gateway to draft short scam-safety replies and classify ambiguous natural-language intent. Deterministic routing handles obvious requests such as stats, digest, reviews, watchlist, campaigns, help, and private-info refusals before any LLM call, so tokens are reserved for ambiguous or genuinely conversational turns. Conversation is limited to scam/fraud/wallet-safety questions and TRACaBot capabilities; LLM text never executes Telegram bans, deletes, restrictions, or DKG writes by itself.

Local SQLite WAL state is the bot's operational working memory for weak reports, watchlist state, polling idempotency, digest state, join-challenge state, and ambiguous monitoring-only actions. Existing JSONL state is imported once and retained as a backup. Unsafe chat events with concrete evidence are written to DKG v10 Shared Memory through the OpenClaw adapter as collaborative evidence memory; only admin-verified or very-high-confidence events are published as Verified Memory.

`channel_observation` events increase DKG v10 Shared Memory for spam/scam/fraud pattern analysis without capturing normal discussion. TRACaBot writes bounded raw `message_text` only for high-confidence public messages that look like real channel abuse: new-member scam channel promos, outside coin/token promotions, scam domains/wallets, fake airdrops, investment-profit lures, or admin/support impersonators asking users to DM. General discussion about scam coins or scam prevention stays local and is not shared as raw DKG text.

The bot separates local analysis confidence from DKG confidence. Report-only evidence does not automatically snowball into high-confidence bans; DKG evidence must be credible, and non-admin reports cannot directly trigger a Telegram ban. Plain watchlist monitoring stays local-only; DKG writes are reserved for evidence-backed unsafe chat observations, actions, reports, campaigns, appeals, reviews, restrictions, and bans.

TRACaBot applies graduated autonomous enforcement by default: low-confidence events are logged, medium-confidence events can be deleted and restricted, and high-confidence events can be deleted and banned. It also writes and queries scam domains in DKG Shared Memory, so a phishing or Telegram lure domain seen in one community can be flagged in another. Repeated domains, wallets, scam patterns, or text fingerprints are clustered into local campaign signals and can be written as `fraud_campaign` DKG events when the same wave repeats.

Conversation artifact logging is controlled by `TRACABOT_WM_ARTIFACTS`, `TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE`, `TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS`, `TRACABOT_WM_ARTIFACT_REDACT`, and `TRACABOT_WM_ARTIFACT_SHARE_LOW_CONFIDENCE`. By default, raw identifiers are redacted and low-quality artifacts stay local.

## Public Reader and Bounded Community Writes

TRACaBot ships a dependency-free public reader and a scoped evidence API:

```bash
npm run web
# local by default: http://127.0.0.1:8787
```

The reader is free and unauthenticated. It returns only sanitized evidence already marked for shared/public memory: hashed public IDs, claim level, normalized domains/wallets/patterns, stable HMAC target/actor references, enforcement reason status, counts, timestamps, and provenance. It never returns raw Telegram IDs, usernames, chat titles, private messages, screenshots, or reporter data. Campaign summaries can also be read from DKG Shared Working Memory when `TRACABOT_PUBLIC_READ_DKG=true`.

Writes are closed by default. Configure an operator-issued token per community:

```env
TRACABOT_COMMUNITY_TOKENS=[{"token":"replace-with-a-long-random-value","communityId":"community-one","name":"Community One","instanceId":"instance-one","scopes":["evidence:write"]}]
```

`POST /api/public/evidence` accepts only `observation` or `allegation`, requires consent, an idempotency key, validation, and per-community rate limits. It stages local working memory; it cannot submit `admin_verified`, `confirmed_scam`, confidence, or ban instructions. `POST /api/public/join-requests` records membership interest for manual operator review and grants nothing automatically.

For an independent instance that should contribute to a creator-hosted graph, opt in explicitly:

```env
TRACABOT_INSTANCE_ID=community-one-instance
TRACABOT_SUBMIT_SHARED_EVIDENCE=true
TRACABOT_CREATOR_SUBMIT_URL=https://creator.example/api/public/evidence
TRACABOT_CREATOR_SUBMIT_TOKEN=<community-scoped token>
```

The submitter queues a bounded observation/allegation locally, deduplicates it, and retries with bounded backoff. It never queues test-mode events or raw message text. Opting out stops new sends. `TRACABOT_CREATOR_SUBMIT_TOKEN` is a write credential; do not put it in a browser, public page, or log. Reading the creator graph still requires a DKG node connected to that graph, not a write token.

The evidence policy separates observations, allegations, admin enforcement, high-confidence flags, confirmed scam findings, and retractions. An admin ban is an evidence signal, never proof on its own, but a live provenance-backed admin ban may be shared automatically as an enforcement-only claim without a scam verdict. Model-only suspicion can request review but cannot create a confirmed-scam record. Qualifying corroborated evidence is promoted to DKG Shared Working Memory automatically by `npm run promote`, the Telegram proactive scan, or the running reader; `review_overturned` stops promotion and keeps the correction visible. See [docs/PUBLIC_GRAPH.md](./docs/PUBLIC_GRAPH.md) for endpoints, claim levels, token provisioning, membership approval, and the exact supported DKG/OpenClaw setup commands.

## LLM Backends

TRACaBot uses the LLM for two bounded tasks: natural-language Telegram replies and intent classification for direct bot mentions/replies. It does not use LLM output as direct enforcement authority. Slash commands, obvious natural-language intents, private-info refusals, and most scam scoring are deterministic to avoid wasting tokens.

Start with the zero-LLM path; protection, joins, reports, review, and deterministic replies still work:

```text
TRACABOT_CONVERSATIONAL=false
TRACABOT_LLM_PROVIDER=off
```

Optional hosted setup with 9router:

```text
TRACABOT_CONVERSATIONAL=true
TRACABOT_LLM_PROVIDER=9router
TRACABOT_LLM_BASE_URL=https://api.9router.com
TRACABOT_LLM_API_KEY=your-9router-key
TRACABOT_LLM_MODEL=openai/gpt-4o-mini
```

Recommended model: `openai/gpt-4o-mini`. TRACaBot mostly needs compact JSON intent classification and one-sentence safety replies, so a small fast model is usually a better default than a frontier reasoning model. Use a stronger model only if your chat has many ambiguous admin-review instructions or multilingual scam reports that the small model misses.

The model ID is operator-selected and must exist in your provider's current catalog. TRACaBot does not invent model names and does not translate an unofficial label such as "deepseek 4.1 flask" into a guessed ID. Configure the exact served model ID (for example a local Flask/OpenAI-compatible endpoint's own model string) or leave the LLM off. Provider outages and missing configuration are reported as LLM status only; they never disable deterministic join protection or make the LLM an enforcement authority.

Bound optional LLM usage with:

```text
TRACABOT_LLM_TIMEOUT_MS=30000
TRACABOT_LLM_MAX_TOKENS=220
```

OpenClaw-discovered setup, useful when the host already has OAuth/model config in OpenClaw:

```text
TRACABOT_CONVERSATIONAL=true
TRACABOT_LLM_PROVIDER=auto
OPENCLAW_CONFIG_PATH=/root/.openclaw/openclaw.json
```

Direct OpenAI-compatible or local endpoint:

```text
TRACABOT_CONVERSATIONAL=true
TRACABOT_LLM_PROVIDER=http
TRACABOT_LLM_BASE_URL=http://127.0.0.1:11434
TRACABOT_LLM_API_KEY=
TRACABOT_LLM_MODEL=llama3.1
```

Disable LLM while keeping commands and deterministic templates:

```text
TRACABOT_LLM_PROVIDER=off
```

OpenClaw is still useful when 9router is the LLM backend: TRACaBot keeps using the OpenClaw DKG adapter for Context Graph/Working Memory/Shared Memory/Verified Memory operations, and the OpenClaw skill bridge (`tracabot-skill`) remains the agent-facing API for scan, monitor, curate, digest, review, appeal, and learning-loop workflows.

TRACaBot treats DKG Shared Working Memory as collaborative evidence memory and Verified Memory as an operator-funded permanence layer. Once an event meets the publish policy through admin verification or very high confidence, the bot may ask the OpenClaw DKG adapter to publish that event root if `TRACABOT_DKG_PUBLISH_VERIFIED=true`. If the publish step fails, the SWM write is kept and the error is recorded for audit.

Transient DKG Shared Memory write failures such as temporary network errors, timeouts, 429s, and 5xx responses are retried before the bot gives up. If DKG remains unavailable, Telegram moderation continues and the local event is retained with `dkg_error` so admins can audit the downtime without losing the moderation trail.

## Security Model

- Secrets stay in `.env` or service environment files and are ignored by Git.
- Manual `/ban` requires a configured admin or Telegram chat admin. Native admin bans do not use the command; add TRACaBot as a group admin and keep exactly one process polling.
- Native admin bans are missing: confirm the bot is a group administrator, exactly one process polls the token, and no webhook is active. Telegram does not replay Recent Actions or pre-install bans.
- `/report` includes duplicate checks, reporter rate limits, self-report rejection, and evidence requirements.
- Telegram API calls have request timeouts.
- DKG reads/writes go through the OpenClaw DKG adapter HTTP client, not shell interpolation.
- Accepted DKG evidence is structured and bounded; duplicate, rate-limited, targetless, and no-pattern reports are local-only.
- Reporter reputation is tracked locally from accepted/high-confidence reports so consistently helpful reporters receive more trust without letting them bypass duplicate or rate-limit controls.
- High-confidence or admin-verified eligible fraud memory is published with a targeted OpenClaw adapter `publishSharedMemory` call.
- Appeal and review events are evidence-backed DKG writes so operators can explain or correct decisions without silently mutating history. Plain watchlist state remains local-only.

## Requirements

- Node.js `>=22.20.0`
- Running DKG v10 node with OpenClaw DKG adapter setup
- Telegram bot token from BotFather

## Install

**For AI agents and one-command style self-hosting**, see the dedicated **[AGENT_INSTALL.md](./AGENT_INSTALL.md)** guide. It is written to be followed reliably by coding agents.

---

### Human / Traditional Install

1. Install and set up DKG/OpenClaw on the host:

```bash
npm install -g @origintrail-official/dkg
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

2. Create and configure a Telegram bot:

```text
Open @BotFather
/newbot
Choose a display name and username
Copy the token into TELEGRAM_BOT_TOKEN
/setcommands
```

Paste this command list into BotFather:

```text
start - Open Tracabot protection menu
scan - Check a user, wallet, or replied message for scam risk
report - Report suspicious users, messages, links, wallets, or forwarded DMs
ban - Ban a replied user and publish ban evidence (admin)
mute - Admin: mute a replied or mentioned user for a duration
```

Most other functions (stats, reviews, campaigns, enforcement history, explanations, settings/status, etc.) are available through the `/start` menu buttons or by speaking naturally to the bot when conversational mode is enabled.

Invite the bot to your group and grant administrator rights for **Delete Messages**, **Restrict/Ban Users**, and the ability to see group messages. Telegram bots receive new messages and live `chat_member` updates only while they are in the group with the required visibility; a bot token by itself does not grant message or membership event access. Discord and other platforms are not implemented.

3. Install TRACaBot:

```bash
git clone https://github.com/brxtrac/tracabot.git
cd tracabot
npm install
cp .env.example .env
```

After npm publication, package installs also work with `npm install -g tracabot`; copy `.env.example` from `$(npm root -g)/tracabot/.env.example` into your runtime directory and run `tracabot`.

4. Edit `.env`:

```bash
TELEGRAM_BOT_TOKEN=your-bot-token
TRACABOT_ADMINS=123456789,@your_admin_username
TRACABOT_CONTEXT_GRAPH=tracabot
TRACABOT_DKG_MODE=openclaw-adapter
TRACABOT_DKG_READS=true
TRACABOT_DKG_WRITES=true
TRACABOT_DKG_PUBLISH_VERIFIED=false
TRACABOT_DKG_PSEUDONYM_KEY=replace-with-at-least-32-random-bytes
TRACABOT_CHANNEL_MEMORY=true
TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE=80
TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS=1000
# Bounded local context for live native admin bans. Captures messages the bot
# already observed from the same user/chat before the ban; never a claimed cause.
TRACABOT_BAN_CONTEXT=true
TRACABOT_BAN_CONTEXT_MAX_MESSAGES=8
TRACABOT_BAN_CONTEXT_MAX_AGE_MINUTES=60
TRACABOT_BAN_CONTEXT_MAX_TEXT_CHARS=1000
TRACABOT_AUTO_BAN=false
# Silent exact-identity join protection. Default is observe/log only.
TRACABOT_JOIN_AUTO_REMOVE=false
TRACABOT_JOIN_AUTO_REMOVE_CHATS=
TRACABOT_JOIN_EVIDENCE_MAX_AGE_DAYS=180
TRACABOT_JOIN_MIN_CONFIRMED_ROOTS=1
# Counts independent underlying findings; duplicate reviews/promoted copies count once.
# Add creator-curator only after configuring the pinned creator key and read token.
TRACABOT_JOIN_TRUSTED_LAYERS=local
TRACABOT_JOIN_TRUSTED_SOURCES=
TRACABOT_INSTANCE_ID=
TRACABOT_ACTION_THRESHOLD=85
TRACABOT_AUTO_DELETE=true
TRACABOT_AUTO_RESTRICT=false
TRACABOT_WARN_THRESHOLD=60
TRACABOT_RESTRICT_THRESHOLD=75
TRACABOT_BAN_THRESHOLD=90
TRACABOT_PROACTIVE_SCAN_MINUTES=30
TRACABOT_TELEGRAM_TIMEOUT_MS=30000
TRACABOT_DKG_QUERY_TIMEOUT_MS=4000
TRACABOT_DROP_PENDING_UPDATES_ON_START=true
DKG_NODE_URL=http://127.0.0.1:9200
TRACABOT_DB_PATH=./data/tracabot-events.sqlite
TRACABOT_LEGACY_STORE_PATH=./data/tracabot-events.jsonl
TRACABOT_CONVERSATIONAL=true
TRACABOT_LLM_PROVIDER=off
TRACABOT_LLM_BASE_URL=
TRACABOT_LLM_API_KEY=
TRACABOT_LLM_MODEL=
OPENCLAW_CONFIG_PATH=
TRACABOT_CONVERSATION_MIN_CONFIDENCE=60
TRACABOT_PROACTIVE_REPLY_THRESHOLD=75
TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS=60
TRACABOT_CONVERSATION_MAX_CHARS=700
TRACABOT_JOIN_CHALLENGE=false
TRACABOT_JOIN_CHALLENGE_MODE=qa
TRACABOT_JOIN_CHALLENGE_ASSET_URL=
TRACABOT_JOIN_CHALLENGE_QA_BANK=[]
TRACABOT_JOIN_CHALLENGE_TTL_SECONDS=120
TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS=3
TRACABOT_JOIN_CHALLENGE_ACTION=kick
TRACABOT_JOIN_CHALLENGE_DELETE_ON_PASS=true
TRACABOT_JOIN_CHALLENGE_DELETE_BAD_ATTEMPTS=true
TRACABOT_JOIN_CHALLENGE_DKG_VALIDATE=true
```

Keep `TRACABOT_AUTO_RESTRICT=false` and `TRACABOT_AUTO_BAN=false` until you have tested thresholds in a sandbox group. Enable them only after reviewing local/DKG evidence behavior with your community policy.

5. Start manually:

```bash
npm start
```

6. Optional systemd service: copy `docs/tracabot.service.example` to `/etc/systemd/system/tracabot.service`, update paths/user for your install, then run `sudo systemctl daemon-reload` and `sudo systemctl enable --now tracabot.service`.

```ini
See `docs/tracabot.service.example`.
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tracabot.service
sudo systemctl status tracabot.service
```

Run the DKG write/read demo without Telegram:

```bash
npm run demo
```

Run OpenClaw skill tools directly:

```bash
npm run skill -- scan_target '{"telegramUserId":"8388593201","text":"possible support impersonation"}'
npm run skill -- monitor_chat_event '{"telegramUserId":"8388593201","text":"official support says verify wallet now","adminVerified":false}'
npm run skill -- get_digest '{}'
npm run skill -- get_watchlist '{"filter":"all"}'
```

Run tests:

```bash
npm test
npm audit --omit=dev
npm run test:commands
```

## Troubleshooting

- Bot does not respond: confirm `TELEGRAM_BOT_TOKEN`, service logs, group privacy settings, and that the bot was invited to the correct group.
- Bot cannot delete, restrict, ban, or run join challenge enforcement: confirm Telegram admin permissions for deleting messages, restricting users, and banning users.
- `/ban` says admin required: add your numeric Telegram ID or username to `TRACABOT_ADMINS`, or run the command from a Telegram chat-admin account.
- DKG evidence is missing: confirm `dkg status`, `DKG_NODE_URL`, `TRACABOT_DKG_MODE=openclaw-adapter`, and any `DKG_AUTH_TOKEN` required by your adapter.
- Systemd cannot read DKG auth: set `DKG_AUTH_TOKEN` explicitly in `.env` when running TRACaBot as a different Unix user than the DKG daemon.
- DKG commands hang while `/api/status` works: the local DKG RDF store may be stuck. Stop DKG, move `~/.dkg/store.nq` aside as a backup, restart DKG, then re-subscribe/recreate needed context graphs. Do not delete the backup until you confirm recovery.
- Verified Memory publish is skipped: this is default. Run `dkg wallet`, fund the operational wallet with network gas/TRAC, register/select the publish graph, then set `TRACABOT_DKG_PUBLISH_VERIFIED=true` and `TRACABOT_PUBLISH_CONTEXT_GRAPH_ID` if your network requires a numeric publish id.
- Telegram says `getUpdates` conflict: another bot instance is running with the same `TELEGRAM_BOT_TOKEN`. Stop the duplicate before restarting TRACaBot.
- Skill command returns JSON error: run from the project root, pass valid JSON, and check `OPENCLAW_DKG_ADAPTER_PATH` only if the adapter is installed outside standard OpenClaw paths.
- Conversational replies are template-only: confirm `TRACABOT_CONVERSATIONAL=true`, `TRACABOT_LLM_PROVIDER` is not `off`, and either 9router/direct `TRACABOT_LLM_*` values or OpenClaw discovery are configured. Open `/start` > Settings > Status as an admin to see redacted backend status without exposing credentials.
- Demo refuses to write: set `TRACABOT_TEST_MODE=true` for `npm run demo`; this prevents accidental production test writes.

## OpenClaw Setup

The DKG v10 OpenClaw setup command can be used before running TRACaBot:

```bash
dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund
```

The OpenClaw-facing skill manifest lives at `skills/tracabot/skill.json`. The CLI entrypoint is `node ./bin/tracabot-skill.js <tool> <json-input>` and returns JSON suitable for OpenClaw agent tooling.

Example systemd unit: `docs/tracabot.service.example`.

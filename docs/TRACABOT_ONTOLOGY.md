# TRACaBot Ontology

TRACaBot stores moderation intelligence as evidence-backed RDF in the `tracabot` DKG v10 Context Graph. The ontology is intentionally small and operational: every event should be explainable to a community admin and useful to another TRACaBot instance before it triggers enforcement.

## Event Lifecycle

Events move through this trust path:

1. `observed` - local Telegram or OpenClaw observation, not yet shared.
2. `shared_memory` - evidence-backed event written to DKG Shared Memory.
3. `admin_reviewed` - an admin explicitly upheld, overturned, accepted, or rejected the event.
4. `verified_memory` - event root published into the Context Graph / Verified Memory path.
5. `campaign_summary` - repeated evidence clustered into a reusable campaign entity.

## Core Classes

- `tracabot:UnsafeChatEvent`
- `tracabot:ScamReport`
- `tracabot:DmScamReport`
- `tracabot:ModerationAction`
- `tracabot:Appeal`
- `tracabot:ReviewDecision`
- `tracabot:FraudCampaign`
- `tracabot:ChannelObservation`
- `tracabot:ConversationArtifact`
- `tracabot:ProactiveCrossGroupWarning` (new in Phase 4 — surfaces actors with prior admin actions from other communities)
- `tracabot:EvidenceItem`
- `tracabot:ScamDomain`
- `tracabot:ScamPattern`
- `tracabot:Community`
- `tracabot:CommunityPolicy`

## Required Event Fields

- `tracabot:eventId`
- `tracabot:eventType`
- `dcterms:created`
- `dcterms:creator`
- `tracabot:lifecycleStage`
- `tracabot:publicationStatus`
- `tracabot:confidence`
- `tracabot:localConfidence`
- `tracabot:adminVerified`
- `tracabot:hasEvidence`

## Community Scope

Community-specific policy must stay queryable without leaking unnecessary private data.

- `tracabot:communityId` stores the Telegram chat ID or configured community key.
- `tracabot:communityName` is optional and should only be set for communities that permit disclosure.
- `tracabot:communityType` can be `telegram_group`, `telegram_channel`, `discord`, `forum`, or another integration key.
- `tracabot:policyId` links an event to the policy that scored it.

## Evidence Model

Use structured evidence in addition to the compact JSON summary:

- `tracabot:hasEvidence -> tracabot:EvidenceItem`
- `tracabot:evidenceText`
- `tracabot:evidenceIndex`
- `tracabot:detectionSignal`
- `tracabot:suspiciousUrl`
- `tracabot:observedDomain -> tracabot:ScamDomain`
- `tracabot:observedPattern -> tracabot:ScamPattern`

Verified Memory should be reserved for events with one of these conditions:

- `tracabot:adminVerified = true`
- very high local confidence with concrete indicators
- accepted high-confidence report
- upheld review decision
- repeated campaign summary with multiple evidence-backed roots

## Scaling Guidance

Each new community integration should produce the same event shape. Telegram-specific fields may be empty for non-Telegram sources, but lifecycle, evidence, confidence, community scope, and publication policy should remain consistent.

## Channel Observations

`channel_observation` is DKG v10 Shared Memory only. It captures high-confidence public channel abuse for pattern analysis, not verified fraud by itself. It may include bounded `tracabot:messageText` only when the public message is highly suspicious: scam channel promotion, outside token/coin promotion, fake airdrop, wallet/domain lure, investment-profit spam, or admin/support impersonation with a DM request. Ordinary discussion about scam coins, moderation policy, or scam prevention should not be shared as raw DKG text.

Additional fields:

- `tracabot:observationType`
- `tracabot:messageId`
- `tracabot:replyToMessageId`
- `tracabot:textFingerprint`

`channel_observation` events must use `tracabot:lifecycleStage = "shared_memory"` and `tracabot:publicationStatus = "shared_memory"`; they are not publish-eligible until a later admin-reviewed or high-confidence enforcement event cites them as evidence.

## Conversation Artifacts

`conversation_artifact` captures sorted scam/fraud/phishing learning material from conversations without granting enforcement authority. It is used for safety questions, weak-but-informative reports, tactic candidates, OpenClaw-sorted observations, and false-positive corrections. These artifacts increase DKG working-memory coverage while preserving the existing rule that bans/restrictions require credible findings, accepted reports, admin review, or high-confidence DKG evidence.

Additional fields:

- `tracabot:artifactKind`
- `tracabot:artifactQuality`
- `tracabot:conversationRole`
- `tracabot:redactionLevel`
- `tracabot:normalizedText`
- `tracabot:sourceEventId`
- `tracabot:teachesTactic`
- `tracabot:learningValue`
- `tracabot:operatorNote`
- `tracabot:falsePositiveReason`
- `tracabot:implicitDetection`
- `tracabot:detectionMethod`

Conversation artifacts are DKG v10 Shared Memory only once committed. They can inform replies, warnings, and explanations, but they do not raise `riskScore` for autonomous enforcement by themselves.

## Campaign Summaries

Repeated domains, wallets, scam patterns, and message fingerprints are clustered into `tracabot:FraudCampaign` events. A campaign summary should include:

- `tracabot:campaignKey`
- `tracabot:campaignEventCount`
- `tracabot:campaignCommunityCount`
- `tracabot:evidenceRootId`
- `tracabot:evidenceRoot -> tracabot:event/<event-id>`
- `tracabot:affectedCommunityId`
- repeated `tracabot:observedDomain` / `tracabot:observedPattern`

Campaign summaries are publish-eligible only when they point to at least two evidence-backed roots. Eligible roots are concrete moderation or report events such as `fraud_finding`, accepted `report_submitted`, `dm_scam_report`, `ban_executed`, `restrict_executed`, `appeal_submitted`, and `review_*` events. Weak local-only observations like `scam_detection` and existing `fraud_campaign` summaries must not become roots.

This prevents a single weak report or recursive campaign summary from becoming global intelligence while still letting repeated scam waves become reusable Verified Memory. When a campaign qualifies, the runtime writes it to DKG Shared Memory with `tracabot:lifecycleStage = "campaign_summary"`, `tracabot:publicationStatus = "context_graph_auto_publish_eligible"`, and evidence-root links back to the underlying events before requesting Context Graph publication.

## Interaction Examples

- Member scans a suspicious reply: `/scan`.
- Member reports a phishing link: reply with `/report fake support wallet drain`.
- Member reports an off-platform impersonator: `/dmreport name="Fake Support" role="admin" request="verify wallet" link=https://fake.example`.
- Admin watches a suspicious account without banning: reply with `/watch possible fake support`.
- Admin reviews a contested event: `/review <event-id> overturn user was discussing scam prevention`.
- Admin checks repeated waves: `/stats campaigns` or `/digest`.

## Implicit Action Detection & Rich Provenance (Phase 8 Enhancements)

To support deep LLM-driven implicit actions (watch/appeal/review detected from reply context, tagging, or conversation role without exact slash commands) while maintaining full auditability, the following metadata and patterns are recommended:

**New/Extended Fields on Relevant Events** (report_submitted, dm_scam_report, watch_started, appeal_submitted, review_upheld, review_overturned, risk_review_needed, conversation_artifact, etc.):

- `tracabot:implicitDetection` (boolean) — true when the action was inferred by the LLM from context rather than explicit command.
- `tracabot:detectionMethod` — "llm_context_reply", "llm_admin_reply_after_flag", "llm_tagged_user_context", "explicit_command", etc.
- `tracabot:replyToEventId` or `tracabot:replyToFlagEventId` — links an implicit appeal or review decision back to the original risk_review_needed / alert event.
- `tracabot:adminIntentConfidence` or `tracabot:llmConfidence` — how sure the agent was of the inferred action.
- `tracabot:naturalLanguageSource` — the raw user text that triggered the implicit action.
- `tracabot:originalFlagContext` — bounded excerpt or event id of the message being appealed/reviewed.

**New Recommended Event Types / Roles** (when appropriate):
- Stronger use of existing `tracabot:Appeal` with the new implicit provenance fields.
- `tracabot:ImplicitAdminAction` (or just enrich the concrete events) for watch/review/appeal that came through the conversational brain.

**Banlist / Modlog Support**:
- Enforcement events (ban_executed, restrict_executed, review_upheld) should carry enough summary fields (`tracabot:summaryReason`, `tracabot:shortContext`) so the banlist command (and future LLM memory queries) can produce concise, useful human-readable entries without re-processing raw evidence.

**General Principle**:
Every action that mutates state or adds to the graph — especially those triggered implicitly by the LLM — must carry sufficient structured provenance so that future "why did this happen?" queries (via LLM or direct SPARQL) can give accurate, explainable answers, and so the learning loop / curator can use the signals for better future decisions.

These fields should be populated in the relevant `record()` calls inside telegram.js handlers and in executeAgentAction when implicit paths are taken. The artefact curator and learning loop should preserve and propagate the implicit metadata.

This keeps the memory layer rich, queryable, and trustworthy as the agent becomes more autonomous in interpreting natural language and context.

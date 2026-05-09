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

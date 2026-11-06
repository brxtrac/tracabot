import { createHash } from 'node:crypto';
import {
  EVIDENCE_POLICY_VERSION,
  evaluateEvidence,
  eventTargetKey
} from './evidence-policy.js';

function promotionId(event = {}, evaluation = {}) {
  return `promotion-${createHash('sha256')
    .update(`${event.id}:${evaluation.evidenceFingerprint}`)
    .digest('hex')
    .slice(0, 32)}`;
}

function policyOptions(config = {}) {
  return {
    highConfidenceThreshold: config.evidenceHighConfidenceThreshold,
    localConfidenceThreshold: config.evidenceLocalConfidenceThreshold,
    minIndependentSignals: config.evidenceMinIndependentSignals,
    minIndependentCommunities: config.evidenceMinIndependentCommunities,
    promotionThreshold: config.evidencePromotionThreshold
  };
}

function alreadyPromoted(events = [], event = {}) {
  return events.some((item) => item.event_type === 'evidence_promotion_recorded'
    && item.payload?.source_event_id === event.id);
}

function promotionRecord(event, evaluation, now) {
  const p = event.payload || {};
  return {
    id: promotionId(event, evaluation),
    event_type: 'fraud_finding',
    timestamp: new Date(now).toISOString(),
    agentDid: String(p.agent_did || event.agentDid || ''),
    chat: event.chat || { id: p.community_id || 'community-evidence' },
    user: event.user || p.target || {},
    payload: {
      target: p.target || event.user || {},
      target_key: eventTargetKey(event),
      scam_type: p.scam_type || 'unknown',
      confidence: evaluation.confidence,
      local_confidence: evaluation.localConfidence,
      domains: evaluation.indicators.domains,
      wallets: evaluation.indicators.wallets,
      patterns: evaluation.indicators.patterns,
      claim_level: evaluation.claimLevel,
      source_event_id: event.id,
      source_event_type: event.event_type,
      evidence_root_ids: [event.id, ...evaluation.evidenceRootIds].slice(0, 20),
      source_event_ids: [event.id],
      evidence_fingerprint: evaluation.evidenceFingerprint,
      evidence_policy_version: EVIDENCE_POLICY_VERSION,
      provenance: 'automatic_evidence_policy',
      publication_status: 'shared_memory',
      lifecycle_stage: 'shared_memory',
      community_id: p.community_id || event.chat?.id || '',
      community_name: p.community_name || '',
      community_type: p.community_type || 'telegram_group',
      policy_id: p.policy_id || 'default',
      admin_verified: evaluation.claimLevel === 'confirmed_scam',
      evidence: [
        `Automatic policy promotion from ${event.event_type} ${event.id}`,
        `Claim level ${evaluation.claimLevel}; ${evaluation.independentSignals} independent signal(s); ${evaluation.independentCommunityCount} community reference(s)`,
        ...(p.evidence || []).slice(0, 2).map((item) => String(item).slice(0, 300))
      ]
    }
  };
}

function localAudit(eventType, event, now, extra = {}) {
  return {
    id: `evidence-${eventType}:${event.id}:${createHash('sha256').update(JSON.stringify(extra)).digest('hex').slice(0, 12)}`,
    event_type: eventType,
    timestamp: new Date(now).toISOString(),
    agentDid: event.agentDid || '',
    chat: event.chat,
    user: event.user,
    local_only: true,
    payload: {
      source_event_id: event.id,
      ...extra,
      evidence: [`evidence policy ${eventType} for ${event.id}`]
    }
  };
}

/**
 * Promote qualifying local evidence to DKG Shared Working Memory.
 * Idempotent by source event id plus effect claim. A failure leaves the source
 * event intact and records a retryable local audit entry.
 */
export async function promoteEligibleEvidence({
  store,
  dkg,
  config = {},
  events = null,
  now = Date.now(),
  limit = 50
} = {}) {
  if (!store || !dkg) throw new Error('promoteEligibleEvidence requires store and dkg');
  if (config.dkgWrites === false) return { processed: 0, promoted: [], skipped: [], failed: [], disabled: true };
  const history = (events || store.all()).slice();
  const candidates = history
    .filter((event) => event?.id && event.event_type)
    .filter((event) => event.payload?.provenance !== 'automatic_evidence_policy')
    .filter((event) => {
      const p = event.payload || {};
      return event.event_type === 'evidence_submission'
        || event.local_only === true
        || p.publication_status === 'working_memory'
        || p.lifecycle_stage === 'working_memory'
        || p.lifecycle_stage === 'working_memory_draft';
    })
    .filter((event) => !alreadyPromoted(history, event))
    .slice(-Math.max(1, Number(limit) || 50));
  const promoted = [];
  const skipped = [];
  const failed = [];

  for (const event of candidates) {
    const evaluation = evaluateEvidence(event, { history, policy: policyOptions(config) });
    if (!evaluation.promotion.eligible) {
      skipped.push({ eventId: event.id, eventType: event.event_type, claimLevel: evaluation.claimLevel, reasons: evaluation.promotion.reasons });
      continue;
    }
    const duplicate = history.some((item) => item.payload?.provenance === 'automatic_evidence_policy'
      && item.payload?.evidence_fingerprint === evaluation.evidenceFingerprint);
    if (duplicate) {
      skipped.push({ eventId: event.id, eventType: event.event_type, claimLevel: evaluation.claimLevel, reasons: ['duplicate_evidence_fingerprint'] });
      continue;
    }
    const effectKey = `evidence-promotion:${event.id}`;
    const claim = store.beginEffect?.(effectKey, 'evidence_promotion', { eventId: event.id });
    if (claim?.completed || claim?.inProgress) {
      skipped.push({ eventId: event.id, eventType: event.event_type, claimLevel: evaluation.claimLevel, reasons: ['already_promoted_or_in_progress'] });
      continue;
    }
    const record = promotionRecord(event, evaluation, now);
    try {
      record.dkg = await dkg.writeEvent(record);
      store.append(record);
      store.append(localAudit('evidence_promotion_recorded', event, now, {
        promoted_event_id: record.id,
        claim_level: evaluation.claimLevel,
        evidence_fingerprint: evaluation.evidenceFingerprint
      }));
      store.completeEffect?.(effectKey, { promotedEventId: record.id });
      history.push(record);
      promoted.push({ eventId: event.id, promotedEventId: record.id, claimLevel: evaluation.claimLevel });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      store.append(localAudit('evidence_promotion_failed', event, now, {
        error: message.slice(0, 500),
        claim_level: evaluation.claimLevel,
        evidence_fingerprint: evaluation.evidenceFingerprint
      }));
      store.failEffect?.(effectKey, message);
      failed.push({ eventId: event.id, eventType: event.event_type, claimLevel: evaluation.claimLevel, error: message });
    }
  }
  return { processed: candidates.length, promoted, skipped, failed, disabled: false };
}

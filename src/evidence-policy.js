import { createHash, createHmac } from 'node:crypto';

export const EVIDENCE_POLICY_VERSION = 'tracabot-evidence-v1';

export const CLAIM_LEVELS = Object.freeze([
  'observation',
  'allegation',
  'admin_enforcement',
  'high_confidence_flag',
  'confirmed_scam',
  'retracted'
]);

const PROMOTABLE_EVENT_TYPES = new Set([
  'fraud_finding',
  'fraud_campaign',
  'ban_executed',
  'restrict_executed',
  'review_upheld',
  'unsafe_chat_event',
  'channel_observation',
  'conversation_artifact',
  'evidence_submission'
]);

const PUBLIC_EVENT_TYPES = new Set([
  'fraud_finding',
  'fraud_campaign',
  'ban_executed',
  'restrict_executed',
  'review_upheld',
  'unsafe_chat_event'
]);

const ADMIN_ENFORCEMENT_TYPES = new Set(['ban_executed', 'restrict_executed']);
const ALLEGATION_TYPES = new Set(['report_submitted', 'dm_scam_report', 'report_review_needed', 'risk_review_needed']);

const DEFAULTS = Object.freeze({
  highConfidenceThreshold: 85,
  localConfidenceThreshold: 60,
  minIndependentSignals: 2,
  minIndependentCommunities: 2,
  promotionThreshold: 85
});

function payload(event = {}) {
  return event.payload && typeof event.payload === 'object' ? event.payload : {};
}

function text(value = '') {
  return String(value ?? '').trim();
}

function boundedUnique(values = [], limit = 10, length = 160) {
  return [...new Set(values
    .map((value) => text(value))
    .filter(Boolean)
    .map((value) => value.slice(0, length)))]
    .slice(0, limit);
}

function normalizedDomain(value = '') {
  let raw = text(value).trim().toLowerCase();
  if (!raw) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    try {
      raw = new URL(raw).hostname;
    } catch {
      return '';
    }
  } else {
    raw = raw.split(/[\/?#]/)[0].split('@').pop().split(':')[0];
  }
  const domain = raw.replace(/^www\./, '').replace(/[^a-z0-9.-]/g, '');
  return domain.includes('.') && domain.length <= 253 ? domain : '';
}

function normalizedWallet(value = '') {
  const wallet = text(value);
  if (/^0x[a-f0-9]{40}$/i.test(wallet)) return wallet.toLowerCase();
  if (/^(?:bc1|[13])[a-hj-np-z0-9]{25,62}$/i.test(wallet)) return wallet;
  return '';
}

function normalizedPattern(value = '') {
  const pattern = text(value).toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/^-+|-+$/g, '');
  return pattern.slice(0, 64);
}

function refId(value = '') {
  return text(value).slice(0, 160);
}

function hashRef(value = '') {
  return `ref_${createHash('sha256').update(text(value)).digest('hex').slice(0, 16)}`;
}

export function eventTargetKey(event = {}) {
  const p = payload(event);
  const reviewEvent = ['review_upheld', 'review_overturned'].includes(event.event_type);
  const target = p.target || p.reviewed_target || (reviewEvent ? {} : event.user) || {};
  return text(p.target_key
    || p.reviewed_target_key
    || p.watch_target_key
    || (target.kind === 'wallet' ? `wallet:${target.id || target.label || ''}` : '')
    || (target.id ? `id:${target.id}` : '')
    || (target.username ? `username:${text(target.username).replace(/^@/, '').toLowerCase()}` : '')
    || (p.campaign_key ? `campaign:${p.campaign_key}` : ''));
}

function indicatorSets(event = {}) {
  const p = payload(event);
  return {
    domains: boundedUnique(p.domains || [], 15).map(normalizedDomain).filter(Boolean),
    wallets: boundedUnique(p.wallets || [], 10).map(normalizedWallet).filter(Boolean),
    patterns: boundedUnique(p.patterns || p.teaches_tactics || [], 10).map(normalizedPattern).filter(Boolean)
  };
}

function evidenceRootIds(event = {}) {
  const p = payload(event);
  return boundedUnique([
    ...(p.evidence_root_ids || []),
    ...(p.source_event_ids || []),
    ...(p.related_event_ids || [])
  ], 20).map(refId).filter(Boolean);
}

function communityIds(event = {}) {
  const p = payload(event);
  const ids = new Set();
  if (p.community_id) ids.add(text(p.community_id));
  for (const id of p.affected_community_ids || []) if (id) ids.add(text(id));
  for (const item of [...(p.prior_admin_events || []), ...(p.dkg_campaign_roots || []), ...(p.dkg_evidence || [])]) {
    const id = item?.communityId || item?.community_id || item?.communityToken;
    if (id) ids.add(text(id));
  }
  return [...ids];
}

function enforcementProvenance(event = {}) {
  const p = payload(event);
  return text(p.source || p.enforcement_source || '');
}

function shareableAdminEnforcement(event = {}) {
  const p = payload(event);
  if (!ADMIN_ENFORCEMENT_TYPES.has(event.event_type)) return false;
  if (p.admin_verified !== true && p.enforcement_verified !== true) return false;
  if (!enforcementProvenance(event)) return false;
  if (p.consent_to_share !== true) return false;
  return Boolean(eventTargetKey(event));
}

function modelOnly(event = {}) {
  const p = payload(event);
  const indicators = indicatorSets(event);
  const concrete = indicators.domains.length + indicators.wallets.length + indicators.patterns.length
    + (p.evidence?.length || 0) + evidenceRootIds(event).length;
  const modelMarked = p.ai_generated === true
    || p.llm_only === true
    || p.claim_source === 'model'
    || /^llm/i.test(text(p.detection_method));
  return modelMarked && concrete === 0 && p.admin_verified !== true;
}

function reviewed(event = {}) {
  const p = payload(event);
  return p.admin_verified === true
    || p.review_decision === 'upheld'
    || p.community_verified_flag === 'group_admin_verified'
    || event.event_type === 'review_upheld';
}

function explicitReview(event = {}) {
  return event.event_type === 'review_upheld' || payload(event).review_decision === 'upheld';
}

function retracted(event = {}, history = []) {
  if (event.event_type === 'review_overturned' || payload(event).retracted === true) return true;
  const targetIds = new Set([event.id, ...evidenceRootIds(event)].filter(Boolean));
  return history.some((item) => item?.event_type === 'review_overturned'
    && targetIds.has(text(item.payload?.target_event_id)));
}

function claimLevelFor({ event, highConfidence, corroborated, isRetracted, onlyModel }) {
  if (isRetracted) return 'retracted';
  if (explicitReview(event) && reviewed(event)) return 'confirmed_scam';
  if (ADMIN_ENFORCEMENT_TYPES.has(event.event_type)) return 'admin_enforcement';
  if (onlyModel) return 'observation';
  if (reviewed(event) && highConfidence) return 'high_confidence_flag';
  if (fairlyCorroborated(event) && highConfidence && corroborated) return 'high_confidence_flag';
  if (ALLEGATION_TYPES.has(event.event_type)) return 'allegation';
  if (event.event_type === 'fraud_campaign' && highConfidence && corroborated) return 'high_confidence_flag';
  return 'observation';
}

function fairlyCorroborated(event = {}) {
  const p = payload(event);
  return Boolean(evidenceRootIds(event).length || p.dkg_evidence?.length || p.dkg_campaign_roots?.length || p.prior_admin_events?.length);
}

export function evidenceFingerprint(event = {}) {
  const p = payload(event);
  const indicators = indicatorSets(event);
  const basis = {
    eventType: event.event_type || '',
    target: eventTargetKey(event),
    community: text(p.community_id || event.chat?.id || ''),
    enforcementOccurrence: ADMIN_ENFORCEMENT_TYPES.has(event.event_type) ? text(p.occurred_at || event.timestamp || '') : '',
    domains: indicators.domains.slice().sort(),
    wallets: indicators.wallets.slice().sort(),
    patterns: indicators.patterns.slice().sort(),
    roots: evidenceRootIds(event).slice().sort(),
    evidence: boundedUnique(p.evidence || [], 20, 500).map((item) => item.toLowerCase()).sort()
  };
  return `sha256:${createHash('sha256').update(JSON.stringify(basis)).digest('hex')}`;
}

export function evaluateEvidence(event = {}, { history = [], policy = {} } = {}) {
  const settings = { ...DEFAULTS };
  for (const [key, value] of Object.entries(policy)) {
    if (Number.isFinite(Number(value))) settings[key] = Number(value);
  }
  const p = payload(event);
  const indicators = indicatorSets(event);
  const roots = evidenceRootIds(event);
  const communities = communityIds(event);
  const confidence = Number(p.confidence || 0);
  const localConfidence = Number(p.local_confidence || 0);
  const isRetracted = retracted(event, history);
  const onlyModel = modelOnly(event);
  const independentSignals = [
    indicators.domains.length > 0,
    indicators.wallets.length > 0,
    indicators.patterns.length > 0,
    (p.evidence || []).length > 0,
    roots.length > 0,
    (p.dkg_evidence || []).length > 0
  ].filter(Boolean).length;
  const corroborated = roots.length > 0
    || (p.dkg_evidence || []).length > 0
    || (p.dkg_campaign_roots || []).length > 0
    || (p.prior_admin_events || []).length > 0
    || communities.length >= settings.minIndependentCommunities;
  const highConfidence = confidence >= settings.highConfidenceThreshold
    && (localConfidence >= settings.localConfidenceThreshold || reviewed(event));
  const claimLevel = claimLevelFor({ event, highConfidence, corroborated, isRetracted, onlyModel });
  const adminEnforcementAlone = claimLevel === 'admin_enforcement'
    && !roots.length
    && !(p.evidence || []).length
    && independentSignals < settings.minIndependentSignals;
  const shareableEnforcement = shareableAdminEnforcement(event);
  const enforcementEvent = ADMIN_ENFORCEMENT_TYPES.has(event.event_type);
  const reasons = [];
  if (!PROMOTABLE_EVENT_TYPES.has(event.event_type)) reasons.push('event_type_not_promotable');
  if (p.test_mode === true || p.source === 'test-command-loop') reasons.push('test_event');
  if (isRetracted) reasons.push('retracted');
  if (onlyModel) reasons.push('model_only_suspicion');
  if (['review_upheld', 'review_overturned'].includes(event.event_type) && !eventTargetKey(event)) reasons.push('missing_reviewed_target');
  if (!shareableEnforcement) {
    if (enforcementEvent) {
      // Admin enforcement is only auto-shared as an enforcement claim when
      // consent, verified provenance, and a stable target are all explicit.
      // High confidence or corroborating roots must not bypass this gate.
      reasons.push('admin_enforcement_not_shareable');
      if (!enforcementProvenance(event)) reasons.push('admin_enforcement_missing_provenance');
      if (p.admin_verified !== true && p.enforcement_verified !== true) reasons.push('admin_enforcement_not_verified');
      if (p.consent_to_share !== true) reasons.push('sharing_consent_missing');
      if (!eventTargetKey(event)) reasons.push('admin_enforcement_missing_target');
    } else {
      if (confidence < settings.promotionThreshold) reasons.push('below_promotion_threshold');
      if (localConfidence < settings.localConfidenceThreshold && !reviewed(event)) reasons.push('below_local_threshold');
      if (!independentSignals) reasons.push('no_concrete_evidence');
      if (adminEnforcementAlone) reasons.push('admin_action_without_corroboration');
      if (claimLevel === 'observation' || claimLevel === 'allegation') reasons.push('claim_not_yet_high_confidence');
      if (claimLevel === 'high_confidence_flag' && !corroborated) reasons.push('not_corroborated');
      if (!reviewed(event) && independentSignals < settings.minIndependentSignals && !corroborated) reasons.push('insufficient_independent_signals');
    }
  }

  const promotionEligible = reasons.length === 0;
  return {
    policyVersion: EVIDENCE_POLICY_VERSION,
    eventId: event.id || '',
    eventType: event.event_type || '',
    claimLevel,
    confidence,
    localConfidence,
    highConfidenceFlag: claimLevel === 'high_confidence_flag',
    adminEnforcement: claimLevel === 'admin_enforcement',
    confirmedScam: claimLevel === 'confirmed_scam',
    retracted: isRetracted,
    modelOnly: onlyModel,
    indicators,
    evidenceRootIds: roots,
    communityIds: communities,
    independentSignals,
    independentCommunityCount: communities.length,
    corroborated,
    evidenceFingerprint: evidenceFingerprint(event),
    provenance: {
      agentDid: text(event.agentDid),
      source: text(p.source || 'telegram'),
      detectionMethod: text(p.detection_method || 'deterministic'),
      policyId: text(p.policy_id || 'default')
    },
    promotion: {
      eligible: promotionEligible,
      reasons: promotionEligible ? [] : [...new Set(reasons)],
      threshold: settings.promotionThreshold,
      minIndependentSignals: settings.minIndependentSignals,
      minIndependentCommunities: settings.minIndependentCommunities
    }
  };
}

export function publicCampaignKey(value = '') {
  const key = String(value || '');
  if (!key || /^campaign_sha256:[a-f0-9]{64}$/.test(key)) return key;
  return `campaign_sha256:${createHash('sha256').update('tracabot:public-campaign:v1\0').update(key).digest('hex')}`;
}

export function publicIdFor(event = {}) {
  return `evt_${createHash('sha256').update(text(event.id || evidenceFingerprint(event))).digest('hex').slice(0, 16)}`;
}

export function isPublicEvidence(event = {}) {
  if (!PUBLIC_EVENT_TYPES.has(event.event_type)) return false;
  if (event.dkg_error) return false;
  if (event.dkg) return true;
  return payload(event).public_visibility === 'public' && event.local_only !== true;
}

function publicBanContext(p = {}) {
  const context = p.ban_context;
  if (!context || typeof context !== 'object') return null;
  const indicators = context.indicators || {};
  return {
    category: text(context.category || 'unknown'),
    severity: text(context.severity || 'unknown'),
    confidence: Math.max(0, Math.min(100, Number(context.confidence || 0))),
    confirmedScam: false,
    causalLink: 'unverified',
    provenance: 'recent_pre_ban_context',
    label: 'recent pre-ban context; causal link unverified',
    messageCount: Math.max(0, Number(context.observed_message_count || 0)),
    textMessageCount: Math.max(0, Number(context.text_message_count || 0)),
    mediaOnly: context.media_only === true,
    partial: context.partial === true,
    behaviorFlags: boundedUnique(context.behavior_flags || [], 5).map(text),
    indicators: {
      domains: boundedUnique(indicators.domains || [], 10).map(normalizedDomain).filter(Boolean),
      wallets: boundedUnique(indicators.wallets || [], 10).map(normalizedWallet).filter(Boolean),
      patterns: boundedUnique(indicators.patterns || [], 10).map(normalizedPattern).filter(Boolean)
    }
  };
}

function publicSummary(evaluation, p = {}) {
  const type = evaluation.indicators.patterns[0] || evaluation.eventType.replace(/_/g, ' ');
  const enforcementClaim = p.claim_level === 'admin_enforcement'
    || evaluation.claimLevel === 'admin_enforcement'
    || ADMIN_ENFORCEMENT_TYPES.has(evaluation.eventType)
    || p.enforcement_action === 'ban'
    || p.enforcement_action === 'unban';
  if (evaluation.claimLevel === 'retracted' && enforcementClaim) {
    return 'Observed administrator enforcement was later lifted or corrected; the original record stays visible as history.';
  }
  if (evaluation.claimLevel === 'admin_enforcement') {
    const action = p.enforcement_action === 'restriction' || evaluation.eventType === 'restrict_executed' ? 'restriction' : 'ban';
    const context = publicBanContext(p);
    const contextNote = context && context.category !== 'unknown'
      ? ` Recent observed messages were categorized as ${context.category}; no causal link to the enforcement was established.`
      : '';
    return (p.reason_provided === true
      ? `Observed administrator ${action}; a reason was recorded internally but is not published. Enforcement is an evidence signal, not a confirmed scam.`
      : `Observed administrator ${action}; no reason was provided through the Telegram Bot API. Enforcement is an evidence signal, not a confirmed scam.`) + contextNote;
  }
  if (evaluation.claimLevel === 'confirmed_scam') return `Admin review upheld a ${type} finding.`;
  if (evaluation.claimLevel === 'high_confidence_flag') return `Corroborated high-confidence ${type} signal from shared evidence.`;
  return `Shared ${evaluation.claimLevel} evidence for ${type}.`;
}

export function sanitizePublicEvidence(event = {}, { history = [], policy = {}, pseudonymKey = '' } = {}) {
  if (!isPublicEvidence(event)) return null;
  const evaluation = evaluateEvidence(event, { history, policy });
  const p = payload(event);
  const actorRef = pseudonymKey && eventTargetKey(event)
    ? `hmac:v1:${createHmac('sha256', pseudonymKey).update(`public-actor:${eventTargetKey(event)}`).digest('hex')}`
    : '';
  const communityRef = pseudonymKey && (p.community_id || event.chat?.id)
    ? `hmac:v1:${createHmac('sha256', pseudonymKey).update(`public-community:${p.community_id || event.chat.id}`).digest('hex')}`
    : '';
  const enforcementClaim = p.claim_level === 'admin_enforcement'
    || ADMIN_ENFORCEMENT_TYPES.has(event.event_type)
    || p.enforcement_action === 'ban'
    || p.enforcement_action === 'unban';
  return {
    publicId: publicIdFor(event),
    eventType: event.event_type,
    claimLevel: evaluation.claimLevel,
    confidence: evaluation.confidence,
    scamType: text(p.scam_type || 'unknown'),
    createdAt: text(p.occurred_at || event.timestamp || ''),
    summary: publicSummary(evaluation, p),
    indicators: {
      domains: evaluation.indicators.domains,
      wallets: evaluation.indicators.wallets,
      patterns: evaluation.indicators.patterns
    },
    enforcement: enforcementClaim ? {
      action: p.enforcement_action || (event.event_type === 'restrict_executed' ? 'restriction' : 'ban'),
      reason: p.reason_provided === true ? 'recorded internally; not published' : 'reason not provided',
      reasonProvided: p.reason_provided === true,
      actorRecorded: p.performed_by_recorded === true || Boolean(p.performed_by?.id || p.performed_by?.username),
      source: text(p.enforcement_observed_from || ''),
      claimState: evaluation.claimLevel
    } : null,
    banContext: publicBanContext(p),
    actorRef,
    targetRef: actorRef,
    communityRef,
    evidenceCount: (p.evidence || []).length,
    evidenceRootCount: evaluation.evidenceRootIds.length,
    evidenceFingerprint: evaluation.evidenceFingerprint,
    evidenceRefs: evaluation.evidenceRootIds.map(hashRef),
    provenance: {
      policy: evaluation.policyVersion,
      layer: evaluation.claimLevel === 'confirmed_scam' ? 'verified_memory_candidate' : 'shared_working_memory',
      source: evaluation.provenance.source
    }
  };
}

export function sanitizePublicEvidenceList(events = [], { limit = 20, policy = {}, pseudonymKey = '' } = {}) {
  const history = events;
  const seen = new Set();
  const records = [];
  for (const event of [...events].reverse()) {
    const record = sanitizePublicEvidence(event, { history, policy, pseudonymKey });
    if (!record || seen.has(record.evidenceFingerprint)) continue;
    seen.add(record.evidenceFingerprint);
    records.push(record);
    if (records.length >= Math.min(100, Math.max(1, Number(limit) || 20))) break;
  }
  return records;
}

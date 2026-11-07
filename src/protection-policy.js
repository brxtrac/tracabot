import { createHash } from 'node:crypto';

export const PROTECTION_POLICY_VERSION = 'tracabot-join-protection-v3';
export const DEFAULT_TRUSTED_LAYERS = Object.freeze(['local']);
export const SUPPORTED_TRUSTED_LAYERS = Object.freeze(['verified-memory', 'local', 'shared-working-memory', 'creator-curator']);

const CONFIRMED_TYPES = new Set(['review_upheld']);
const RETRACTION_TYPES = new Set(['review_overturned']);

function text(value = '') {
  return String(value ?? '').trim();
}

function bounded(value = '', max = 200) {
  return text(value).slice(0, max);
}

function numeric(value = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : 0;
}

function timestamp(value = '') {
  const parsed = Date.parse(text(value));
  return Number.isFinite(parsed) ? parsed : 0;
}

function list(value = [], limit = 20, length = 160) {
  return [...new Set((Array.isArray(value) ? value : [])
    .map((item) => bounded(item, length))
    .filter(Boolean))]
    .slice(0, limit);
}

function confirmedEvidence(item = {}) {
  if (RETRACTION_TYPES.has(item.eventType)) return false;
  if (item.claimLevel === 'confirmed_scam') return true;
  return CONFIRMED_TYPES.has(item.eventType) && item.adminVerified === true;
}

function normalizeEvidence(item = {}) {
  return {
    eventId: bounded(item.eventId, 160),
    eventType: bounded(item.eventType, 64),
    claimLevel: bounded(item.claimLevel || 'observation', 32),
    confidence: numeric(item.confidence),
    created: bounded(item.created, 64),
    expiresAt: bounded(item.expiresAt || item.expires_at, 64),
    adminVerified: item.adminVerified === true,
    exactActorMatch: item.exactActorMatch === true,
    trustLayer: bounded(item.trustLayer || 'unknown', 32),
    source: bounded(item.source, 160),
    communityId: bounded(item.communityId, 160),
    targetEventId: bounded(item.targetEventId || item.target_event_id, 160),
    sourceEventId: bounded(item.sourceEventId || item.source_event_id, 160),
    evidenceRootIds: list(item.evidenceRootIds || item.evidence_root_ids, 20),
    publisherApprovalVerified: item.publisherApprovalVerified === true,
    creatorAttestation: item.creatorAttestation === true,
    localApproval: item.localApproval === true,
    retracted: item.retracted === true,
    confirmed: confirmedEvidence(item)
  };
}

function trustedLayersFor(policy = {}) {
  const configured = Array.isArray(policy.trustedLayers) && policy.trustedLayers.length
    ? policy.trustedLayers
    : DEFAULT_TRUSTED_LAYERS;
  return new Set(configured
    .map((layer) => text(layer).toLowerCase().replace(/_/g, '-'))
    .filter((layer) => SUPPORTED_TRUSTED_LAYERS.includes(layer)));
}

function trustedSourcesFor(policy = {}) {
  return new Set((policy.trustedSources || [])
    .map((source) => text(source).toLowerCase())
    .filter(Boolean));
}

function chatAllowed(chatId, policy = {}) {
  const allowed = (policy.allowedChatIds || []).map(String);
  if (!allowed.length) return true;
  return allowed.includes(String(chatId || ''));
}

function evidenceRef(evidence = []) {
  const basis = evidence
    .map((item) => `${item.eventId}:${item.claimLevel}:${item.created}:${item.targetEventId}`)
    .sort()
    .join('|');
  return `sha256:${createHash('sha256').update(basis).digest('hex')}`;
}

function lineageOf(item = {}) {
  return new Set([item.eventId, item.sourceEventId, item.targetEventId, ...(item.evidenceRootIds || [])]
    .map((value) => bounded(value, 160))
    .filter(Boolean));
}

function lineageIntersects(item = {}, values = new Set()) {
  for (const value of lineageOf(item)) if (values.has(value)) return true;
  return false;
}

function intersectLineage(a = new Set(), b = new Set()) {
  for (const value of a) if (b.has(value)) return true;
  return false;
}

/**
 * Count independent underlying evidence roots, not wrapper review or promoted
 * event IDs. Two reviews of the same finding, or a promoted copy of it, share
 * lineage and count once.
 */
function independentRootCount(items = []) {
  const lineages = items.map((item) => lineageOf(item));
  const seen = new Set();
  let count = 0;
  for (let index = 0; index < lineages.length; index += 1) {
    if (seen.has(index)) continue;
    count += 1;
    const stack = [index];
    seen.add(index);
    while (stack.length) {
      const current = stack.pop();
      for (let other = 0; other < lineages.length; other += 1) {
        if (seen.has(other)) continue;
        if (intersectLineage(lineages[current], lineages[other])) {
          seen.add(other);
          stack.push(other);
        }
      }
    }
  }
  return count;
}

/**
 * Deterministic join-enforcement decision. No LLM, display name, alias, or
 * campaign association can authorize removal.
 *
 * Shared-graph evidence is flag-only unless the installed adapter can prove an
 * authenticated operator-trusted publisher approval. The current adapter does
 * not expose that capability, so queryProtectionEvidence marks shared evidence
 * unapproved. Local same-chat admin review carries localApproval=true.
 */
export function evaluateJoinProtection({
  target = {},
  evidence = [],
  policy = {},
  chatId = '',
  now = Date.now()
} = {}) {
  const normalized = evidence.map(normalizeEvidence).filter((item) => item.eventId);
  const trustedLayers = trustedLayersFor(policy);
  const trustedSources = trustedSourcesFor(policy);
  const retractions = normalized
    .filter((item) => RETRACTION_TYPES.has(item.eventType) && item.exactActorMatch && trustedLayers.has(item.trustLayer))
    .sort((a, b) => timestamp(b.created) - timestamp(a.created));
  const maxAgeMs = Math.max(1, Number(policy.maxAgeDays) || 180) * 24 * 60 * 60 * 1000;
  const minRoots = Math.max(1, Math.min(5, Number(policy.minRoots) || 1));
  const creatorMinConfidence = Math.max(0, Math.min(100, Number(policy.creatorMinConfidence) || 90));

  const base = {
    policyVersion: PROTECTION_POLICY_VERSION,
    action: 'allow',
    reason: '',
    autoRemove: policy.autoRemove === true,
    chatOptIn: chatAllowed(chatId, policy),
    evidenceComplete: policy.evidenceComplete !== false,
    trustedLayers: [...trustedLayers],
    trustedSources: [...trustedSources],
    maxAgeDays: Math.round(maxAgeMs / (24 * 60 * 60 * 1000)),
    minRoots,
    creatorMinConfidence,
    exactIdentity: Boolean(text(target.id)),
    evidenceCount: normalized.length,
    confirmedEvidenceCount: normalized.filter((item) => item.confirmed).length,
    retractionCount: retractions.length,
    staleEvidenceCount: 0,
    untrustedEvidenceCount: 0,
    unapprovedEvidenceCount: 0,
    ambiguousRetractionCount: 0,
    evidenceRef: normalized.length ? evidenceRef(normalized) : '',
    evidence: normalized
      .filter((item) => item.confirmed || RETRACTION_TYPES.has(item.eventType))
      .slice(0, 8)
      .map((item) => ({
        eventId: item.eventId,
        eventType: item.eventType,
        claimLevel: item.claimLevel,
        confidence: item.confidence,
        created: item.created,
        trustLayer: item.trustLayer,
        source: item.source,
        sourceEventId: item.sourceEventId,
        targetEventId: item.targetEventId
      }))
  };

  if (!base.exactIdentity) return { ...base, reason: 'missing_stable_identity' };
  if (target.is_bot === true || target.isBot === true) return { ...base, reason: 'protected_bot' };
  if (policy.targetIsAdmin === true) return { ...base, reason: 'protected_admin' };
  if (policy.targetIsOwner === true) return { ...base, reason: 'protected_owner' };

  const hasAnyEvidence = normalized.some((item) => item.confirmed);
  if (!hasAnyEvidence) return { ...base, reason: 'no_confirmed_evidence' };
  if (!normalized.some((item) => item.confirmed && item.exactActorMatch)) {
    return { ...base, action: 'flag', reason: 'no_exact_identity_evidence' };
  }
  if (policy.evidenceComplete === false) {
    return { ...base, action: 'flag', reason: 'incomplete_evidence' };
  }

  const trustedConfirmed = normalized.filter((item) => item.confirmed
    && item.exactActorMatch
    && trustedLayers.has(item.trustLayer)
    && !item.retracted);
  const sourceAllowed = trustedConfirmed.filter((item) => item.trustLayer === 'local'
    || trustedSources.size === 0
    || trustedSources.has(item.source.toLowerCase()));
  const approved = sourceAllowed.filter((item) => {
    if (item.localApproval || item.publisherApprovalVerified) {
      if (item.trustLayer !== 'creator-curator') return true;
      return item.creatorAttestation && item.publisherApprovalVerified && item.confidence >= creatorMinConfidence;
    }
    return false;
  });
  const unapproved = sourceAllowed.filter((item) => !approved.includes(item));
  const untrusted = normalized.filter((item) => item.confirmed
    && (!trustedLayers.has(item.trustLayer)
      || (item.trustLayer !== 'local'
        && trustedSources.size > 0
        && !trustedSources.has(item.source.toLowerCase()))));

  const globalRetraction = retractions.find((item) => !item.targetEventId && !item.evidenceRootIds.length) || null;
  const targetedRetractions = new Set();
  for (const retraction of retractions) {
    if (retraction.targetEventId) targetedRetractions.add(retraction.targetEventId);
    for (const root of retraction.evidenceRootIds || []) targetedRetractions.add(root);
  }
  const confirmedLineage = new Set();
  for (const item of approved) for (const value of lineageOf(item)) confirmedLineage.add(value);
  const retractionRoots = (retraction) => [retraction.targetEventId, ...(retraction.evidenceRootIds || [])].filter(Boolean);
  const ambiguousRetractions = retractions.filter((retraction) => {
    const roots = retractionRoots(retraction);
    return roots.length > 0 && !roots.some((value) => confirmedLineage.has(value));
  });
  const reviewLike = approved.filter((item) => CONFIRMED_TYPES.has(item.eventType) || item.claimLevel === 'confirmed_scam');

  const stale = approved.filter((item) => {
    const created = timestamp(item.created);
    const expiresAt = timestamp(item.expiresAt);
    return !created || now - created > maxAgeMs || (expiresAt && expiresAt <= now);
  });
  const fresh = approved.filter((item) => !stale.includes(item));
  const active = fresh.filter((item) => {
    if (globalRetraction && timestamp(item.created) <= timestamp(globalRetraction.created)) return false;
    return !lineageIntersects(item, targetedRetractions);
  });
  const independentRoots = independentRootCount(active);

  const withCounts = {
    ...base,
    staleEvidenceCount: stale.length,
    untrustedEvidenceCount: untrusted.length,
    unapprovedEvidenceCount: unapproved.length,
    ambiguousRetractionCount: ambiguousRetractions.length,
    freshConfirmedEvidenceCount: fresh.length,
    activeEvidenceItems: active.length,
    activeConfirmedEvidenceCount: independentRoots
  };

  if (ambiguousRetractions.length && reviewLike.length) {
    return { ...withCounts, action: 'flag', reason: 'ambiguous_retraction_lineage' };
  }
  if (!trustedConfirmed.length) {
    const layerMismatch = untrusted.some((item) => !trustedLayers.has(item.trustLayer));
    return { ...withCounts, action: 'flag', reason: layerMismatch ? 'untrusted_evidence_layer' : 'untrusted_evidence_source' };
  }
  if (!sourceAllowed.length) {
    return { ...withCounts, action: 'flag', reason: 'untrusted_evidence_source' };
  }
  if (!approved.length) {
    return { ...withCounts, action: 'flag', reason: 'missing_authenticated_approval' };
  }
  if (!fresh.length) {
    return { ...withCounts, action: 'flag', reason: globalRetraction ? 'retracted_evidence' : 'stale_evidence' };
  }
  if (!active.length) return { ...withCounts, action: 'flag', reason: 'retracted_evidence' };
  if (independentRoots < minRoots) return { ...withCounts, action: 'flag', reason: 'insufficient_confirmed_roots' };
  if (policy.autoRemove !== true) return { ...withCounts, action: 'flag', reason: 'enforcement_disabled' };
  if (!chatAllowed(chatId, policy)) return { ...withCounts, action: 'flag', reason: 'chat_not_opted_in' };

  return {
    ...withCounts,
    action: 'remove',
    reason: 'confirmed_exact_identity_evidence',
    roots: active.slice(0, 5).map((item) => item.eventId)
  };
}

export function protectionSummary(decision = {}) {
  const evidence = decision.activeConfirmedEvidenceCount ?? decision.confirmedEvidenceCount ?? 0;
  if (decision.action === 'remove') {
    return `Exact stable identity matched ${evidence} active confirmed fraud/scam root(s) with authenticated approval.`;
  }
  if (decision.action === 'flag') {
    return `Join observed and flagged locally; no automatic removal (${decision.reason || 'policy'}).`;
  }
  return `Join observed; no confirmed exact-identity evidence (${decision.reason || 'no_confirmed_evidence'}).`;
}

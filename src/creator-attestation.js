import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import { fetchService } from './secure-transport.js';

export const CREATOR_ATTESTATION_VERSION = 'tracabot-creator-attestation-v1';
export const CREATOR_STATUS_VERSION = 'tracabot-creator-status-v1';
export const CREATOR_DEFAULT_ISSUER = 'tracabot-creator-curator';
export const CREATOR_PLATFORM = 'telegram';
export const CREATOR_CLASSIFICATIONS = Object.freeze(['fraud', 'scam']);
export const CREATOR_ROOT_TYPES = Object.freeze(['ban_executed', 'review_upheld', 'fraud_finding']);
const MAX_STATUS_AGE_MS = 15 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const MAX_TTL_DAYS = 3650;

function text(value = '') {
  return String(value ?? '').trim();
}

function bounded(value = '', max = 200) {
  return text(value).slice(0, max);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function timestamp(value = '') {
  const parsed = Date.parse(text(value));
  return Number.isFinite(parsed) ? parsed : 0;
}

function numeric(value = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

export function keyIdFor(publicKey) {
  const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('creator curator key must be ed25519');
  return `sha256:${createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex').slice(0, 32)}`;
}

function signedMessage(payload) {
  return Buffer.from(canonical(payload), 'utf8');
}

export function signPayload(payload = {}, privateKey) {
  const publicKey = createPublicKey(privateKey);
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('creator curator key must be ed25519');
  const signature = sign(null, signedMessage(payload), privateKey).toString('base64url');
  return { payload, signature, key_id: keyIdFor(publicKey), algorithm: 'ed25519' };
}

export function verifySignedPayload(envelope = {}, publicKey) {
  if (!envelope || typeof envelope !== 'object' || !envelope.payload || typeof envelope.payload !== 'object') {
    return { ok: false, reason: 'missing_signed_payload' };
  }
  if (envelope.algorithm !== 'ed25519') return { ok: false, reason: 'unsupported_signature_algorithm' };
  let key;
  try {
    key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  } catch {
    return { ok: false, reason: 'invalid_public_key' };
  }
  if (key.asymmetricKeyType !== 'ed25519') return { ok: false, reason: 'invalid_key_type' };
  const expectedKeyId = keyIdFor(key);
  if (bounded(envelope.key_id, 80) !== expectedKeyId) return { ok: false, reason: 'key_id_mismatch' };
  if (typeof envelope.signature !== 'string' || !envelope.signature) return { ok: false, reason: 'missing_signature' };
  let valid = false;
  try {
    valid = verify(null, signedMessage(envelope.payload), key, Buffer.from(envelope.signature, 'base64url'));
  } catch {
    valid = false;
  }
  return valid ? { ok: true, payload: envelope.payload } : { ok: false, reason: 'invalid_signature' };
}

function normalizeSubject(subject = {}) {
  const platform = text(subject.platform || subject.type).toLowerCase();
  const userId = text(subject.user_id || subject.userId || subject.telegramUserId);
  if (platform !== CREATOR_PLATFORM) throw new Error('subject.platform must be telegram');
  if (!/^\d{4,24}$/.test(userId)) throw new Error('subject.user_id must be a numeric Telegram ID');
  return { platform: CREATOR_PLATFORM, user_id: userId };
}

function normalizeRoots(roots = [], subject = {}) {
  if (!Array.isArray(roots) || !roots.length) throw new Error('roots must be a non-empty array');
  if (roots.length > 20) throw new Error('roots supports at most 20 items');
  const seenIds = new Set();
  const seenLineage = new Set();
  return roots.map((root, index) => {
    if (!root || typeof root !== 'object' || Array.isArray(root)) throw new Error(`roots[${index}] must be an object`);
    const id = bounded(root.id || root.root_id, 160);
    const eventType = bounded(root.event_type || root.eventType, 64);
    const platform = text(root.platform || CREATOR_PLATFORM).toLowerCase();
    const userId = text(root.user_id || root.userId || subject.user_id);
    const communityId = bounded(root.community_id || root.communityId, 128);
    const lineageId = bounded(root.lineage_id || root.lineageId || id, 160);
    if (!id || seenIds.has(id)) throw new Error('root ids must be unique and non-empty');
    if (!CREATOR_ROOT_TYPES.includes(eventType)) throw new Error(`roots[${index}].event_type must be one of ${CREATOR_ROOT_TYPES.join(', ')}`);
    if (platform !== CREATOR_PLATFORM) throw new Error(`roots[${index}].platform must be telegram`);
    if (userId !== subject.user_id) throw new Error(`roots[${index}].user_id must bind the attestation subject`);
    if (!communityId) throw new Error(`roots[${index}].community_id is required`);
    if (seenLineage.has(lineageId)) throw new Error('root lineage must be independent');
    seenIds.add(id);
    seenLineage.add(lineageId);
    return { id, event_type: eventType, platform, user_id: userId, community_id: communityId, lineage_id: lineageId };
  });
}

export function validateAttestationPayload(payload = {}, {
  now = Date.now(),
  expectedUserId = '',
  expectedIssuer = CREATOR_DEFAULT_ISSUER,
  minConfidence = 90,
  minRoots = 1,
  maxAgeDays = 180
} = {}) {
  if (!payload || payload.version !== CREATOR_ATTESTATION_VERSION) return { ok: false, reason: 'unsupported_attestation_version' };
  if (bounded(payload.issuer, 120) !== expectedIssuer) return { ok: false, reason: 'unexpected_issuer' };
  let subject;
  try { subject = normalizeSubject(payload.subject); } catch (error) { return { ok: false, reason: error.message }; }
  if (expectedUserId && subject.user_id !== String(expectedUserId)) return { ok: false, reason: 'subject_mismatch' };
  const classification = text(payload.classification).toLowerCase();
  if (!CREATOR_CLASSIFICATIONS.includes(classification)) return { ok: false, reason: 'classification_not_fraud_or_scam' };
  if (payload.claim_level !== 'confirmed_scam') return { ok: false, reason: 'claim_level_not_confirmed' };
  const confidence = numeric(payload.confidence);
  if (confidence < Math.max(1, numeric(minConfidence)) || confidence > 100) return { ok: false, reason: 'confidence_below_threshold' };
  const issuedAt = timestamp(payload.issued_at);
  const expiresAt = timestamp(payload.expires_at);
  if (!issuedAt || !expiresAt) return { ok: false, reason: 'missing_issue_or_expiry' };
  if (issuedAt > now + MAX_FUTURE_SKEW_MS) return { ok: false, reason: 'issued_in_future' };
  if (now - issuedAt > Math.max(1, numeric(maxAgeDays)) * 24 * 60 * 60 * 1000) return { ok: false, reason: 'attestation_too_old' };
  if (expiresAt <= now) return { ok: false, reason: 'attestation_expired' };
  if (expiresAt <= issuedAt) return { ok: false, reason: 'invalid_expiry' };
  let roots;
  try { roots = normalizeRoots(payload.roots, subject); } catch (error) { return { ok: false, reason: error.message }; }
  const independent = new Set(roots.map((root) => root.lineage_id));
  if (independent.size < Math.max(1, Number(minRoots) || 1)) return { ok: false, reason: 'insufficient_independent_roots' };
  return { ok: true, subject, classification, confidence, roots, issuedAt, expiresAt };
}

export function createAttestation({ subject, classification = 'fraud', confidence = 95, roots = [], ttlDays = 180,
  issuer = CREATOR_DEFAULT_ISSUER, now = Date.now(), privateKey, minConfidence = 90 } = {}) {
  if (!privateKey) throw new Error('creator curator private key is required');
  const normalizedSubject = normalizeSubject(subject);
  const normalizedClassification = text(classification).toLowerCase();
  if (!CREATOR_CLASSIFICATIONS.includes(normalizedClassification)) throw new Error('classification must be fraud or scam');
  const normalizedRoots = normalizeRoots(roots, normalizedSubject);
  const issuedAt = Number(now);
  const ttl = Number(ttlDays);
  if (!Number.isFinite(ttl) || ttl < 1 || ttl > MAX_TTL_DAYS) throw new Error(`ttlDays must be 1-${MAX_TTL_DAYS}`);
  const payload = {
    version: CREATOR_ATTESTATION_VERSION,
    issuer: bounded(issuer, 120),
    subject: normalizedSubject,
    classification: normalizedClassification,
    claim_level: 'confirmed_scam',
    confidence: numeric(confidence),
    roots: normalizedRoots,
    issued_at: new Date(issuedAt).toISOString(),
    expires_at: new Date(issuedAt + ttl * 24 * 60 * 60 * 1000).toISOString()
  };
  const check = validateAttestationPayload(payload, { now: issuedAt, expectedIssuer: issuer, minConfidence, minRoots: 1, maxAgeDays: MAX_TTL_DAYS });
  if (!check.ok) throw new Error(`invalid creator attestation: ${check.reason}`);
  return signPayload(payload, privateKey);
}

export function verifyAttestation(envelope = {}, publicKey, options = {}) {
  const signed = verifySignedPayload(envelope, publicKey);
  if (!signed.ok) return signed;
  const check = validateAttestationPayload(signed.payload, options);
  if (!check.ok) return check;
  return { ...check, ok: true, envelope, payload: signed.payload };
}

export function attestationEvidence(verified = {}) {
  const payload = verified.payload || {};
  const subject = verified.subject || {};
  const roots = verified.roots || [];
  return {
    eventId: `creator:${subject.user_id}:${bounded(payload.issued_at, 64)}`,
    eventType: 'review_upheld',
    claimLevel: 'confirmed_scam',
    confidence: verified.confidence,
    created: payload.issued_at,
    expiresAt: payload.expires_at,
    adminVerified: true,
    exactActorMatch: true,
    trustLayer: 'creator-curator',
    source: 'creator-curator',
    communityId: '',
    targetEventId: roots[0]?.id || '',
    sourceEventId: roots[0]?.id || '',
    evidenceRootIds: roots.map((root) => root.id).slice(0, 20),
    publisherApprovalVerified: true,
    creatorAttestation: true,
    localApproval: false,
    retracted: false
  };
}

export function createStatusEnvelope({ record = null, subject = {}, issuer = CREATOR_DEFAULT_ISSUER, now = Date.now(), privateKey } = {}) {
  if (!privateKey) throw new Error('creator curator private key is required');
  const normalizedSubject = normalizeSubject(subject);
  const base = {
    version: CREATOR_STATUS_VERSION,
    issuer: bounded(issuer, 120),
    subject: normalizedSubject,
    read_at: new Date(now).toISOString(),
    expires_at: new Date(now + MAX_STATUS_AGE_MS).toISOString()
  };
  if (!record) return signPayload({ ...base, status: 'not_found' }, privateKey);
  const attestation = record.attestation;
  const expiresAt = timestamp(attestation?.payload?.expires_at);
  const status = record.status === 'revoked' ? 'revoked' : expiresAt <= now ? 'expired' : 'active';
  return signPayload({
    ...base,
    status,
    attestation,
    revoked_at: record.status === 'revoked' ? bounded(record.revoked_at, 64) : '',
    revocation_reason: record.status === 'revoked' ? bounded(record.revocation_reason, 300) : ''
  }, privateKey);
}

export function verifyStatusEnvelope(envelope = {}, publicKey, {
  now = Date.now(),
  expectedUserId = '',
  expectedIssuer = CREATOR_DEFAULT_ISSUER,
  minConfidence = 90,
  minRoots = 1,
  maxAgeDays = 180,
  maxStatusAgeMs = MAX_STATUS_AGE_MS
} = {}) {
  const signed = verifySignedPayload(envelope, publicKey);
  if (!signed.ok) return signed;
  const payload = signed.payload;
  if (payload.version !== CREATOR_STATUS_VERSION) return { ok: false, reason: 'unsupported_status_version' };
  if (bounded(payload.issuer, 120) !== expectedIssuer) return { ok: false, reason: 'unexpected_issuer' };
  let subject;
  try { subject = normalizeSubject(payload.subject); } catch (error) { return { ok: false, reason: error.message }; }
  if (expectedUserId && subject.user_id !== String(expectedUserId)) return { ok: false, reason: 'subject_mismatch' };
  const readAt = timestamp(payload.read_at);
  const statusExpires = timestamp(payload.expires_at);
  if (!readAt || !statusExpires) return { ok: false, reason: 'missing_status_time' };
  if (readAt > now + MAX_FUTURE_SKEW_MS) return { ok: false, reason: 'status_read_in_future' };
  if (now - readAt > Math.max(1000, numeric(maxStatusAgeMs))) return { ok: false, reason: 'stale_status_read' };
  if (statusExpires <= now) return { ok: false, reason: 'status_read_expired' };
  if (!['active', 'revoked', 'expired', 'not_found'].includes(payload.status)) return { ok: false, reason: 'invalid_status' };
  if (payload.status === 'not_found') return { ok: true, status: 'not_found', subject, payload };
  // A signed revocation or expiry status is authoritative on its own: it can
  // only suppress use, never authorize removal. No evidence is returned.
  if (payload.status === 'revoked') return { ok: true, status: 'revoked', subject, payload };
  if (payload.status === 'expired') return { ok: true, status: 'expired', subject, payload };
  if (!payload.attestation) return { ok: false, reason: 'missing_attestation' };
  const attestation = verifyAttestation(payload.attestation, publicKey, { now, expectedUserId, expectedIssuer, minConfidence, minRoots, maxAgeDays });
  if (!attestation.ok) return { ok: false, reason: `attestation_${attestation.reason}` };
  return { ok: true, status: 'active', subject, payload, attestation, evidence: attestationEvidence(attestation) };
}

export async function fetchCreatorAttestation({
  baseUrl = '',
  userId = '',
  publicKey = '',
  token = '',
  issuer = CREATOR_DEFAULT_ISSUER,
  minConfidence = 90,
  minRoots = 1,
  maxAgeDays = 180,
  statusMaxAgeMs = MAX_STATUS_AGE_MS,
  timeoutMs = 4000,
  now = Date.now(),
  fetchImpl = globalThis.fetch
} = {}) {
  if (!baseUrl) return { ok: true, configured: false, status: 'disabled', evidence: [], complete: true, error: '' };
  if (!publicKey) return { ok: false, configured: true, status: 'invalid_config', evidence: [], complete: false, error: 'creator public key not configured' };
  if (!token) return { ok: false, configured: true, status: 'invalid_config', evidence: [], complete: false, error: 'creator read token not configured' };
  if (typeof fetchImpl !== 'function') return { ok: false, configured: true, status: 'unavailable', evidence: [], complete: false, error: 'fetch_unavailable' };
  const url = new URL(`/api/creator/attestations/telegram/${encodeURIComponent(String(userId))}`, baseUrl);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(500, Number(timeoutMs) || 4000));
  try {
    const response = await fetchService(url, {
      method: 'GET',
      headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
      cache: 'no-store',
      signal: controller.signal
    }, { fetchImpl, label: 'creator status read' });
    if (!response.ok) return { ok: false, configured: true, status: 'unavailable', evidence: [], complete: false, error: `creator status read failed with ${response.status}` };
    let envelope;
    try { envelope = await response.json(); } catch { envelope = null; }
    const verified = verifyStatusEnvelope(envelope, publicKey, { now, expectedUserId: userId, expectedIssuer: issuer, minConfidence, minRoots, maxAgeDays, maxStatusAgeMs: statusMaxAgeMs });
    if (!verified.ok) return { ok: false, configured: true, status: 'invalid_response', evidence: [], complete: false, error: verified.reason };
    return {
      ok: true,
      configured: true,
      status: verified.status,
      evidence: verified.status === 'active' ? [verified.evidence] : [],
      complete: true,
      revoked: verified.status === 'revoked',
      error: ''
    };
  } catch (error) {
    return { ok: false, configured: true, status: 'unavailable', evidence: [], complete: false, error: error instanceof Error ? error.message : String(error) };
  } finally {
    clearTimeout(timer);
  }
}

import { createHash } from 'node:crypto';
import { fetchService } from './secure-transport.js';

export const FEDERATION_QUEUE_TYPE = 'federation_submission_queued';
export const FEDERATION_SENT_TYPE = 'federation_submission_sent';
export const FEDERATION_FAILED_TYPE = 'federation_submission_failed';
const MAX_ATTEMPTS = 8;

function text(value = '') {
  return String(value ?? '').trim();
}

function bounded(value = '', max = 300) {
  return text(value).slice(0, max);
}

function hash(value = '') {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 24);
}

function configured(config = {}) {
  return config.submitSharedEvidence === true && Boolean(config.creatorSubmitUrl) && Boolean(config.creatorSubmitToken);
}

function numericTelegramId(value = '') {
  const id = text(value);
  return /^\d{4,24}$/.test(id) ? id : '';
}

export function federationSubmissionFor({ promotedEvent = {}, sourceEvent = {}, config = {} } = {}) {
  if (!configured(config)) return null;
  const p = promotedEvent.payload || {};
  const target = p.target || sourceEvent.user || {};
  const telegramUserId = numericTelegramId(target.id || target.telegramUserId);
  if (!telegramUserId) return null;
  if (p.test_mode === true || p.source === 'test-command-loop') return null;
  const domains = (p.domains || []).slice(0, 10).map((item) => bounded(item, 160)).filter(Boolean);
  const wallets = (p.wallets || []).slice(0, 10).map((item) => bounded(item, 160)).filter(Boolean);
  const patterns = (p.patterns || []).slice(0, 10).map((item) => bounded(item, 64)).filter(Boolean);
  const claimType = p.claim_level === 'allegation' ? 'allegation' : 'observation';
  const summary = [
    `Instance ${bounded(config.instanceId || 'unnamed', 64)} shared ${claimType} evidence for a stable Telegram identity.`,
    `Claim: ${bounded(p.claim_level || 'observation', 32)}. Type: ${bounded(p.scam_type || 'unknown', 64)}.`,
    domains.length ? `Domains: ${domains.join(', ')}.` : '',
    wallets.length ? `Wallets: ${wallets.join(', ')}.` : '',
    patterns.length ? `Patterns: ${patterns.join(', ')}.` : ''
  ].filter(Boolean).join(' ').slice(0, 1000);
  return {
    claimType,
    consentToShare: true,
    instanceId: bounded(config.instanceId, 64),
    summary,
    subject: { telegramUserId },
    indicators: { domains, wallets, patterns }
  };
}

export function queueFederationSubmission({ store, promotedEvent = {}, sourceEvent = {}, config = {}, now = Date.now() } = {}) {
  if (!store || !configured(config)) return null;
  const submission = federationSubmissionFor({ promotedEvent, sourceEvent, config });
  if (!submission) return null;
  const queueId = hash(`${config.instanceId || 'instance'}:${sourceEvent.id || promotedEvent.id || ''}`);
  const existing = store.all().some((event) => event.event_type === FEDERATION_QUEUE_TYPE && event.payload?.queue_id === queueId);
  if (existing) return { queueId, duplicate: true };
  const event = {
    id: `federation-queue:${queueId}`,
    event_type: FEDERATION_QUEUE_TYPE,
    timestamp: new Date(now).toISOString(),
    local_only: true,
    agentDid: promotedEvent.agentDid || '',
    chat: { id: 'federation-queue' },
    user: { id: 'federation-queue', kind: 'system' },
    payload: {
      queue_id: queueId,
      instance_id: config.instanceId || '',
      source_event_id: sourceEvent.id || '',
      promoted_event_id: promotedEvent.id || '',
      submission,
      attempts: 0,
      evidence: ['Opt-in creator-graph submission queued; contains only bounded indicators and a stable platform ID.']
    }
  };
  store.append(event);
  return { queueId, queued: true };
}

function latestOutcome(events = [], queueId = '') {
  const sent = events.find((event) => event.event_type === FEDERATION_SENT_TYPE && event.payload?.queue_id === queueId);
  if (sent) return { sent: true };
  const failures = events
    .filter((event) => event.event_type === FEDERATION_FAILED_TYPE && event.payload?.queue_id === queueId)
    .sort((a, b) => Date.parse(b.timestamp || '') - Date.parse(a.timestamp || ''));
  return failures[0] ? { failure: failures[0] } : null;
}

async function postOnce({ config, submission, queueId, fetchImpl, timeoutMs }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchService(config.creatorSubmitUrl, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${config.creatorSubmitToken}`,
        'content-type': 'application/json',
        'idempotency-key': queueId
      },
      body: JSON.stringify(submission),
      signal: controller.signal
    }, { fetchImpl, label: 'creator submission' });
    const body = await response.text().catch(() => '');
    if (!response.ok) throw new Error(`creator submission rejected with ${response.status}: ${body.slice(0, 200)}`);
    let parsed = {};
    try { parsed = JSON.parse(body || '{}'); } catch { parsed = {}; }
    return { status: response.status, publicId: parsed.publicId || '', eventId: parsed.eventId || '' };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Retry queued opt-in submissions. Never throws; bot protection keeps running
 * when the creator endpoint is unreachable. Disabling opt-in stops new sends.
 */
export async function flushFederationQueue({ store, config = {}, fetchImpl = globalThis.fetch, now = Date.now(), limit = 10 } = {}) {
  if (!store) throw new Error('flushFederationQueue requires store');
  if (!configured(config)) return { disabled: true, sent: 0, failed: 0, skipped: 0 };
  if (typeof fetchImpl !== 'function') return { disabled: true, sent: 0, failed: 0, skipped: 0, error: 'fetch_unavailable' };
  const events = store.all();
  const queuedAll = events
    .filter((event) => event.event_type === FEDERATION_QUEUE_TYPE)
    .sort((a, b) => Date.parse(a.timestamp || '') - Date.parse(b.timestamp || ''));
  const pending = queuedAll.filter((event) => {
    const queueId = event.payload?.queue_id || '';
    if (!queueId) return false;
    const outcome = latestOutcome(events, queueId);
    if (outcome?.sent) return false;
    const attempts = Number(outcome?.failure?.payload?.attempts || 0);
    if (attempts >= MAX_ATTEMPTS) return false;
    const retryAt = Date.parse(outcome?.failure?.payload?.retry_at || '');
    return !(Number.isFinite(retryAt) && retryAt > now);
  });
  const queued = pending.slice(0, Math.max(1, Number(limit) || 10));
  let sent = 0;
  let failed = 0;
  let skipped = queuedAll.length - queued.length;
  for (const event of queued) {
    const queueId = event.payload?.queue_id || '';
    if (!queueId) continue;
    const outcome = latestOutcome(events, queueId);
    const attempts = Number(outcome?.failure?.payload?.attempts || 0);
    try {
      const response = await postOnce({
        config,
        submission: event.payload.submission,
        queueId,
        fetchImpl,
        timeoutMs: Math.max(1000, Number(config.creatorSubmitTimeoutMs) || 15000)
      });
      store.append({
        id: `federation-sent:${queueId}:${attempts + 1}`,
        event_type: FEDERATION_SENT_TYPE,
        timestamp: new Date(now).toISOString(),
        local_only: true,
        payload: {
          queue_id: queueId,
          status: response.status,
          public_id: bounded(response.publicId, 64),
          remote_event_id: bounded(response.eventId, 120),
          evidence: ['Creator endpoint accepted the sanitized opt-in submission.']
        }
      });
      sent += 1;
    } catch (error) {
      const nextAttempts = attempts + 1;
      const backoffMs = Math.min(60 * 60 * 1000, 30000 * (2 ** Math.min(6, nextAttempts)));
      store.append({
        id: `federation-failed:${queueId}:${nextAttempts}`,
        event_type: FEDERATION_FAILED_TYPE,
        timestamp: new Date(now).toISOString(),
        local_only: true,
        payload: {
          queue_id: queueId,
          attempts: nextAttempts,
          error: bounded(error instanceof Error ? error.message : String(error), 300),
          retry_at: new Date(now + backoffMs).toISOString(),
          evidence: ['Creator endpoint unavailable or rejected the submission; retry is bounded.']
        }
      });
      failed += 1;
    }
  }
  return { disabled: false, sent, failed, skipped, queued: queued.length };
}

export { configured as federationConfigured };

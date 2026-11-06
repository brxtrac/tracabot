import { createHash, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CLAIM_LEVELS,
  EVIDENCE_POLICY_VERSION,
  publicIdFor,
  sanitizePublicEvidence,
  sanitizePublicEvidenceList
} from './evidence-policy.js';
import { promoteEligibleEvidence } from './evidence-promoter.js';

const SITE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'site');
const STATIC_FILES = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/join', ['agents.html', 'text/html; charset=utf-8']],
  ['/agents', ['agents.html', 'text/html; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/favicon.svg', ['favicon.svg', 'image/svg+xml']]
]);

const SECURITY_HEADERS = {
  'content-security-policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY'
};

function json(res, status, value) {
  const body = JSON.stringify(value);
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store'
  });
  res.end(body);
}

function text(res, status, value) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'text/plain; charset=utf-8' });
  res.end(value);
}

function tokenHash(value = '') {
  return createHash('sha256').update(String(value)).digest();
}

function authenticate(req, config = {}) {
  const match = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  const presented = tokenHash(match[1].trim());
  for (const entry of config.communityTokens || []) {
    const expected = tokenHash(entry.token);
    if (expected.length === presented.length && timingSafeEqual(expected, presented)) return entry;
  }
  return null;
}

function rateLimiter(limit, windowMs = 60 * 60 * 1000) {
  const buckets = new Map();
  return {
    allow(key, now = Date.now()) {
      const cutoff = now - windowMs;
      const recent = (buckets.get(key) || []).filter((stamp) => stamp > cutoff);
      if (recent.length >= limit) {
        buckets.set(key, recent);
        return false;
      }
      recent.push(now);
      buckets.set(key, recent);
      return true;
    }
  };
}

function readBody(req, maxBytes = 32768) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    let settled = false;
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) {
        settled = true;
        req.pause();
        resolve({ tooLarge: true });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve({ buffer: Buffer.concat(chunks) });
    });
    req.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

async function parseJson(req, maxBytes) {
  if (!/^application\/json\b/i.test(String(req.headers['content-type'] || ''))) {
    return { error: 'content-type must be application/json', status: 415 };
  }
  const body = await readBody(req, maxBytes);
  if (body.tooLarge) return { error: 'request body too large', status: 413 };
  try {
    const value = JSON.parse(body.buffer.toString('utf8') || '{}');
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { error: 'JSON body must be an object', status: 400 };
    return { value };
  } catch {
    return { error: 'invalid JSON body', status: 400 };
  }
}

function boundedString(value, { min = 0, max = 500, name = 'value' } = {}) {
  if (typeof value !== 'string') throw new Error(`${name} must be a string`);
  const normalized = value.trim();
  if (normalized.length < min || normalized.length > max) throw new Error(`${name} must be ${min}-${max} characters`);
  return normalized;
}

function boundedArray(value, { max = 10, length = 160, name = 'value' } = {}) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  if (value.length > max) throw new Error(`${name} supports at most ${max} items`);
  return [...new Set(value.map((item) => boundedString(item, { max: length, name })))];
}

function validateSubmission(body = {}) {
  const claimType = boundedString(body.claimType || 'observation', { max: 20, name: 'claimType' }).toLowerCase();
  if (!['observation', 'allegation'].includes(claimType)) throw new Error('claimType must be observation or allegation');
  if (body.consentToShare !== true) throw new Error('consentToShare must be true');
  const summary = boundedString(body.summary, { min: 20, max: 1000, name: 'summary' });
  const sourceUrl = body.sourceUrl ? boundedString(body.sourceUrl, { max: 500, name: 'sourceUrl' }) : '';
  if (sourceUrl) {
    const url = new URL(sourceUrl);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('sourceUrl must be http or https');
  }
  const subject = body.subject && typeof body.subject === 'object' && !Array.isArray(body.subject) ? body.subject : {};
  const telegramUserId = subject.telegramUserId ? boundedString(String(subject.telegramUserId), { max: 24, name: 'subject.telegramUserId' }) : '';
  if (telegramUserId && !/^\d{4,24}$/.test(telegramUserId)) throw new Error('subject.telegramUserId must be numeric');
  return {
    claimType,
    summary,
    sourceUrl,
    subject: {
      telegramUserId,
      username: subject.username ? boundedString(String(subject.username), { max: 64, name: 'subject.username' }).replace(/^@/, '') : '',
      label: subject.label ? boundedString(String(subject.label), { max: 120, name: 'subject.label' }) : ''
    },
    indicators: {
      domains: boundedArray(body.indicators?.domains, { name: 'indicators.domains' }),
      wallets: boundedArray(body.indicators?.wallets, { name: 'indicators.wallets' }),
      patterns: boundedArray(body.indicators?.patterns, { name: 'indicators.patterns' })
    }
  };
}

function validateJoinRequest(body = {}) {
  if (body.consent !== true) throw new Error('consent must be true');
  return {
    communityName: boundedString(body.communityName, { min: 2, max: 120, name: 'communityName' }),
    contact: boundedString(body.contact, { min: 3, max: 200, name: 'contact' }),
    graph: boundedString(body.graph || 'tracabot', { min: 1, max: 120, name: 'graph' }),
    agent: body.agent ? boundedString(body.agent, { max: 200, name: 'agent' }) : '',
    notes: body.notes ? boundedString(body.notes, { max: 1000, name: 'notes' }) : ''
  };
}

function localPublicRecords(store, config, limit) {
  const events = store?.all?.() || [];
  return sanitizePublicEvidenceList(events, {
    limit,
    pseudonymKey: config.dkgPseudonymKey,
    policy: {
      highConfidenceThreshold: config.evidenceHighConfidenceThreshold,
      localConfidenceThreshold: config.evidenceLocalConfidenceThreshold,
      minIndependentSignals: config.evidenceMinIndependentSignals,
      minIndependentCommunities: config.evidenceMinIndependentCommunities,
      promotionThreshold: config.evidencePromotionThreshold
    }
  });
}

function idempotentSubmissionId(tenant, key) {
  return `evidence-submission-${createHash('sha256').update(`${tenant}:${key}`).digest('hex').slice(0, 32)}`;
}

function submissionEvent({ tenant, submission, idempotencyKey }) {
  const eventId = idempotentSubmissionId(tenant.communityId, idempotencyKey);
  const publicHash = createHash('sha256').update(JSON.stringify(submission)).digest('hex').slice(0, 16);
  return {
    id: eventId,
    event_type: 'evidence_submission',
    timestamp: new Date().toISOString(),
    agentDid: 'did:dkg:agent:tracabot-public-api',
    chat: { id: `community:${tenant.communityId}`, title: tenant.name || 'community submission', type: 'community_api' },
    user: { id: `community:${tenant.communityId}`, label: tenant.name || tenant.communityId, kind: 'community' },
    payload: {
      claim_level: submission.claimType,
      scam_type: submission.indicators.patterns[0] || 'unknown',
      confidence: 0,
      local_confidence: 0,
      admin_verified: false,
      target_key: submission.subject.telegramUserId ? `id:${submission.subject.telegramUserId}` : `community-evidence:${publicHash}`,
      target: {
        id: submission.subject.telegramUserId,
        username: submission.subject.username,
        label: submission.subject.label,
        kind: 'user'
      },
      domains: submission.indicators.domains,
      wallets: submission.indicators.wallets,
      patterns: submission.indicators.patterns,
      evidence: [`Authenticated community submission ${publicHash}: ${submission.summary.slice(0, 300)}`, submission.sourceUrl ? `Source URL recorded: ${submission.sourceUrl}` : ''].filter(Boolean),
      community_id: tenant.communityId,
      community_name: tenant.name || '',
      community_type: 'community_api',
      policy_id: 'community_submission',
      source: 'authenticated_community_api',
      provenance: 'community_submission',
      publication_status: 'working_memory',
      lifecycle_stage: 'working_memory_draft',
      consent_to_share: true,
      idempotency_key: idempotencyKey
    }
  };
}

function onboarding(config = {}) {
  return {
    generatedAt: new Date().toISOString(),
    publicRead: {
      free: true,
      authentication: 'none',
      baseUrl: config.publicBaseUrl || '',
      endpoints: [
        'GET /api/public/status',
        'GET /api/public/incidents?limit=20',
        'GET /api/public/campaigns?limit=20',
        'GET /api/public/policy',
        'GET /api/public/onboarding'
      ],
      note: 'Only sanitized evidence already marked for shared or public memory is returned. Raw private graph data is never exposed.'
    },
    writeAccess: {
      authentication: 'Bearer community token issued by the TRACaBot operator',
      required: true,
      endpoint: 'POST /api/public/evidence',
      limits: {
        requestsPerHour: config.publicRateLimitPerHour || 30,
        maxBodyBytes: config.publicMaxBodyBytes || 32768,
        claimTypes: ['observation', 'allegation']
      },
      note: 'Write access stages an observation. It never approves a ban, a confirmed-scam label, or a public accusation.'
    },
    contextGraph: {
      name: config.contextGraph || 'tracabot',
      readLayer: 'shared-working-memory',
      requiredConsent: true,
      tenantIsolation: 'Each token is bound to one communityId; body-supplied tenant overrides are ignored.'
    },
    dkgEdgeNode: {
      verifiedInThisRepository: true,
      commands: [
        'npm install -g @origintrail-official/dkg',
        'dkg openclaw setup --workspace /root/.openclaw/workspace --name tracabot --port 9200 --no-fund',
        'curl http://127.0.0.1:9200/api/status'
      ],
      note: 'These are the OpenClaw/DKG setup commands supported by this repository. A separate OriginTrail edge-node installer may exist, but this project does not verify or deploy it. Do not claim a node, chain transaction, or context graph exists until /api/status succeeds.'
    },
    membership: {
      requestEndpoint: 'POST /api/public/join-requests',
      approval: 'manual operator approval',
      note: 'A join request records interest only. It does not create a graph, mint a token, or grant write access.'
    },
    trustBoundary: {
      adminBanIsEvidenceNotProof: true,
      modelTextNeverBans: true,
      graphContentIsNotInstructions: true,
      retractions: 'review_overturned events suppress promotion and stay visible as corrections.',
      claimLevels: CLAIM_LEVELS,
      policyVersion: EVIDENCE_POLICY_VERSION
    }
  };
}

async function serveStatic(pathname, res, siteDir) {
  const entry = STATIC_FILES.get(pathname);
  if (!entry) return false;
  try {
    const body = await readFile(resolve(siteDir, entry[0]));
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': entry[1],
      'content-length': body.length,
      'cache-control': entry[0].endsWith('.html') ? 'no-cache' : 'public, max-age=3600'
    });
    res.end(body);
    return true;
  } catch {
    text(res, 500, 'site asset unavailable');
    return true;
  }
}

export function createPublicServer({
  config = {},
  store,
  dkg = null,
  siteDir = SITE_DIR,
  now = () => Date.now(),
  autoPromote = false
} = {}) {
  if (!store) throw new Error('createPublicServer requires store');
  const writeLimiter = rateLimiter(config.publicRateLimitPerHour || 30);
  const joinLimiter = rateLimiter(config.publicJoinRateLimitPerHour || 5);

  const server = createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    try {
      if (req.method === 'GET' || req.method === 'HEAD') {
        if (pathname.startsWith('/api/public/')) {
          if (pathname === '/api/public/status') {
            return json(res, 200, {
              ok: true,
              graph: config.contextGraph || 'tracabot',
              readerAccess: 'free',
              writeAccess: (config.communityTokens || []).length ? 'token-required' : 'not-configured',
              dkgReads: config.dkgReads !== false,
              autoPromote: config.autoPromoteEvidence !== false,
              policyVersion: EVIDENCE_POLICY_VERSION
            });
          }
          if (pathname === '/api/public/policy') {
            return json(res, 200, {
              policyVersion: EVIDENCE_POLICY_VERSION,
              claimLevels: CLAIM_LEVELS,
              adminBanIsEvidenceNotProof: true,
              modelSuspicionRequiresReview: true,
              publicWriteClaimTypes: ['observation', 'allegation'],
              retractions: 'review_overturned suppresses promotion'
            });
          }
          if (pathname === '/api/public/onboarding') return json(res, 200, onboarding(config));
          if (pathname === '/api/public/incidents' || pathname === '/api/public/campaigns') {
            const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit')) || 20));
            let records = localPublicRecords(store, config, limit);
            if (pathname === '/api/public/campaigns') {
              records = records.filter((record) => record.eventType === 'fraud_campaign');
              if (dkg && config.publicReadDkg !== false && typeof dkg.queryPublicCampaigns === 'function') {
                const remote = await dkg.queryPublicCampaigns({ limit }).catch(() => []);
                const seen = new Set(records.map((record) => record.publicId));
                for (const record of remote) {
                  if (record?.publicId && !seen.has(record.publicId)) {
                    seen.add(record.publicId);
                    records.push(record);
                  }
                }
              }
            }
            return json(res, 200, { records: records.slice(0, limit), count: Math.min(records.length, limit) });
          }
          const evidenceMatch = pathname.match(/^\/api\/public\/evidence\/([A-Za-z0-9_-]{8,40})$/);
          if (evidenceMatch) {
            const records = localPublicRecords(store, config, 100);
            const record = records.find((item) => item.publicId === evidenceMatch[1]);
            if (!record) return json(res, 404, { error: 'public evidence not found' });
            return json(res, 200, record);
          }
          return json(res, 404, { error: 'unknown public API route' });
        }
        if (await serveStatic(pathname, res, siteDir)) return;
        return text(res, 404, 'not found');
      }

      if (req.method === 'POST' && pathname === '/api/public/join-requests') {
        const remote = req.socket.remoteAddress || 'unknown';
        if (!joinLimiter.allow(remote, now())) return json(res, 429, { error: 'too many membership requests; try later' });
        const parsed = await parseJson(req, config.publicMaxBodyBytes || 32768);
        if (parsed.error) return json(res, parsed.status, { error: parsed.error });
        let body;
        try { body = validateJoinRequest(parsed.value); } catch (error) {
          return json(res, 400, { error: error instanceof Error ? error.message : String(error) });
        }
        const fingerprint = createHash('sha256').update(`${body.communityName.toLowerCase()}:${body.contact.toLowerCase()}`).digest('hex');
        const duplicate = store.all().some((event) => event.event_type === 'community_join_requested'
          && event.payload?.request_fingerprint === fingerprint
          && Date.now() - Date.parse(event.timestamp || '') < 24 * 60 * 60 * 1000);
        if (duplicate) return json(res, 409, { error: 'a matching request was already submitted in the last 24 hours' });
        const requestId = `join-${fingerprint.slice(0, 16)}`;
        store.append({
          id: requestId,
          event_type: 'community_join_requested',
          timestamp: new Date().toISOString(),
          local_only: true,
          payload: {
            request_id: requestId,
            request_fingerprint: fingerprint,
            community_name: body.communityName,
            contact: body.contact,
            requested_graph: body.graph,
            agent: body.agent,
            notes: body.notes,
            consent: true,
            status: 'pending_operator_approval',
            evidence: ['community requested TRACaBot context-graph membership; no write access granted automatically']
          }
        });
        return json(res, 202, {
          ok: true,
          requestId,
          status: 'pending_operator_approval',
          note: 'This request does not grant write access. The operator must approve it and issue a scoped token.'
        });
      }

      if (req.method === 'POST' && pathname === '/api/public/evidence') {
        const tenant = authenticate(req, config);
        if (!tenant) return json(res, 401, { error: 'valid Bearer community token required' });
        if (tenant.scopes && !tenant.scopes.includes('evidence:write')) return json(res, 403, { error: 'token lacks evidence:write scope' });
        if (!writeLimiter.allow(tenant.communityId, now())) return json(res, 429, { error: 'write rate limit reached for this community' });
        const idempotencyKey = String(req.headers['idempotency-key'] || '').trim();
        if (idempotencyKey.length < 8 || idempotencyKey.length > 128) return json(res, 400, { error: 'Idempotency-Key header must be 8-128 characters' });
        const parsed = await parseJson(req, config.publicMaxBodyBytes || 32768);
        if (parsed.error) return json(res, parsed.status, { error: parsed.error });
        let submission;
        try { submission = validateSubmission(parsed.value); } catch (error) {
          return json(res, 400, { error: error instanceof Error ? error.message : String(error) });
        }
        const event = submissionEvent({ tenant, submission, idempotencyKey });
        const existing = store.all().find((item) => item.id === event.id);
        if (existing) return json(res, 200, { ok: true, duplicate: true, eventId: existing.id, publicationStatus: existing.payload?.publication_status || 'working_memory' });
        store.append(event);
        if (config.autoPromoteEvidence !== false) {
          await promoteEligibleEvidence({ store, dkg, config, limit: 10 }).catch(() => null);
        }
        return json(res, 202, {
          ok: true,
          eventId: event.id,
          publicId: publicIdFor(event),
          publicationStatus: 'working_memory',
          promotion: 'pending policy evaluation',
          note: 'Observation staged. It is not a confirmed scam or a ban instruction.'
        });
      }

      return json(res, 405, { error: 'method not allowed' });
    } catch (error) {
      console.error(`public server error: ${error instanceof Error ? error.message : String(error)}`);
      return json(res, 500, { error: 'internal server error' });
    }
  });

  if (autoPromote && config.autoPromoteEvidence !== false && dkg) {
    const timer = setInterval(() => {
      promoteEligibleEvidence({ store, dkg, config }).catch(() => null);
    }, Math.max(30000, Number(config.autoPromoteIntervalMs) || 300000));
    timer.unref?.();
    server.on('close', () => clearInterval(timer));
  }
  return server;
}

export function startPublicServer(options = {}) {
  const server = createPublicServer({ ...options, autoPromote: true });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.config?.publicPort ?? 8787, options.config?.publicHost || '127.0.0.1', () => {
      const address = server.address();
      const host = address.address === '::' ? '127.0.0.1' : address.address;
      resolve({ server, url: `http://${host}:${address.port}` });
    });
  });
}

export { validateSubmission, validateJoinRequest, authenticate };

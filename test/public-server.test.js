import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:net';
import { EventStore } from '../src/store.js';
import { createPublicServer } from '../src/public-server.js';
import { DkgClient } from '../src/dkg-client.js';
import { publicCampaignKey } from '../src/evidence-policy.js';

test('malformed Host returns a bounded 400 and the server remains healthy', async () => {
  const { server } = makeServer();
  const base = await listen(server);
  try {
    const response = await new Promise((resolve, reject) => {
      const socket = connect(server.address().port, '127.0.0.1');
      let data = '';
      socket.on('connect', () => socket.end('GET /api/public/status HTTP/1.1\r\nHost: [\r\nConnection: close\r\n\r\n'));
      socket.on('data', (chunk) => { data += chunk; });
      socket.on('end', () => resolve(data));
      socket.on('error', reject);
    });
    assert.match(response, /^HTTP\/1\.1 400/);
    assert.ok(response.length < 1000);
    assert.equal((await fetch(`${base}/api/public/policy`)).status, 200);
  } finally { await close(server); }
});

test('remote DKG campaign API hashes legacy text keys without exposing reporter or private evidence', async () => {
  const { store, config } = makeServer({ publicReadDkg: true });
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  const key = 'text:synthetic_reporter_contact private_evidence_secret';
  dkg.queryBindings = async () => [{
    g: 'did:dkg:context-graph:tracabot/_shared_memory',
    s: 'https://tracabot.org/ontology#event/legacy-campaign',
    confidence: '91', campaignKey: key, campaignEventCount: '2', campaignCommunityCount: '2'
  }];
  const server = createPublicServer({ store, config, dkg, autoPromote: false });
  const base = await listen(server);
  try {
    const response = await fetch(`${base}/api/public/campaigns`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.records.length, 1);
    assert.equal(body.records[0].campaignKey, publicCampaignKey(key));
    assert.equal(publicCampaignKey(publicCampaignKey(key)), publicCampaignKey(key));
    assert.doesNotMatch(JSON.stringify(body), /synthetic_reporter_contact|private_evidence_secret/);
  } finally { await close(server); }
});

function makeServer(overrides = {}) {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-public-')), 'events.sqlite'));
  store.append({
    id: 'shared-finding',
    event_type: 'fraud_finding',
    timestamp: '2026-11-01T10:00:00.000Z',
    chat: { id: -100, title: 'Private Community' },
    user: { id: '8388593201', username: 'fake_support', first_name: 'Fake Support' },
    dkg: { ual: 'did:dkg:context-graph:tracabot/_shared_memory' },
    payload: {
      confidence: 94,
      local_confidence: 88,
      scam_type: 'impersonation',
      domains: ['verify-example.example'],
      patterns: ['fake-support'],
      evidence: ['Fake support sent a private message with a wallet lure.'],
      evidence_root_ids: ['root-a', 'root-b'],
      affected_community_ids: ['community-a', 'community-b'],
      community_id: 'private-chat-id',
      message_text: 'victim private text and seed phrase',
      publication_status: 'shared_memory'
    }
  });
  const config = {
    contextGraph: 'tracabot',
    communityTokens: [
      { token: 'token-community-one-123456', communityId: 'community-one', name: 'One' },
      { token: 'token-community-two-123456', communityId: 'community-two', name: 'Two' }
    ],
    publicRateLimitPerHour: 30,
    publicJoinRateLimitPerHour: 5,
    publicMaxBodyBytes: 4096,
    publicReadDkg: false,
    autoPromoteEvidence: false,
    dkgPseudonymKey: 'test-key-at-least-32-bytes-long',
    dkgReads: true,
    ...overrides
  };
  const server = createPublicServer({ config, store, dkg: null, autoPromote: false });
  return { server, store, config };
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return `http://127.0.0.1:${port}`;
}

async function close(server) {
  await new Promise((resolve) => server.close(resolve));
}

function submission(overrides = {}) {
  return {
    claimType: 'observation',
    consentToShare: true,
    summary: 'A fake support account asked a member to verify a wallet over DM.',
    sourceUrl: 'https://t.me/example/123',
    indicators: {
      domains: ['verify-example.example'],
      patterns: ['impersonation']
    },
    ...overrides
  };
}

test('public reader returns sanitized evidence and no private fields', async () => {
  const { server } = makeServer();
  const base = await listen(server);
  try {
    const status = await fetch(`${base}/api/public/status`).then((response) => response.json());
    assert.equal(status.readerAccess, 'free');
    assert.equal(status.writeAccess, 'token-required');
    const body = await fetch(`${base}/api/public/incidents`).then((response) => response.json());
    assert.equal(body.count, 1);
    const record = body.records[0];
    assert.equal(record.claimLevel, 'high_confidence_flag');
    assert.match(record.publicId, /^evt_/);
    assert.match(record.actorRef, /^hmac:v1:/);
    const serialized = JSON.stringify(record);
    assert.doesNotMatch(serialized, /8388593201|fake_support|Fake Support|Private Community|private-chat-id|victim private text|seed phrase|-100/);
    const detail = await fetch(`${base}/api/public/evidence/${record.publicId}`).then((response) => response.json());
    assert.equal(detail.publicId, record.publicId);
    assert.equal((await fetch(`${base}/api/public/evidence/does-not-exist`)).status, 404);
  } finally {
    await close(server);
  }
});

test('private appeal events are never exposed by the public reader', async () => {
  const { server, store } = makeServer();
  store.append({
    id: 'private-appeal',
    event_type: 'appeal_submitted',
    timestamp: new Date().toISOString(),
    local_only: true,
    chat: { id: 4242, type: 'private' },
    user: { id: '4242' },
    payload: {
      appeal_ref: 'ap-private',
      ban_event_id: 'ban-private',
      target: { id: '4242' },
      target_chat_id: '-100',
      reason: 'private appeal text with medical detail and seed phrase',
      local_only: true,
      consent_to_share: false
    }
  });
  const base = await listen(server);
  try {
    const body = await fetch(`${base}/api/public/incidents`).then((response) => response.json());
    assert.equal(body.records.some((record) => String(record.publicId || '').includes('appeal')), false);
    assert.doesNotMatch(JSON.stringify(body), /private appeal text|seed phrase|4242|ban-private/);
  } finally {
    await close(server);
  }
});

test('write endpoint requires a scoped token, validates claims, and stages only working memory', async () => {
  const { server, store } = makeServer();
  const base = await listen(server);
  try {
    const unauthorized = await fetch(`${base}/api/public/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'idempotency-key': 'submission-0001' },
      body: JSON.stringify(submission())
    });
    assert.equal(unauthorized.status, 401);

    const confirmed = await fetch(`${base}/api/public/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token-community-one-123456', 'idempotency-key': 'submission-0002' },
      body: JSON.stringify(submission({ claimType: 'confirmed_scam' }))
    });
    assert.equal(confirmed.status, 400);

    const response = await fetch(`${base}/api/public/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token-community-one-123456', 'idempotency-key': 'submission-0003' },
      body: JSON.stringify({ ...submission(), communityId: 'community-two' })
    });
    assert.equal(response.status, 202);
    const body = await response.json();
    assert.equal(body.publicationStatus, 'working_memory');
    const stored = store.all().find((event) => event.id === body.eventId);
    assert.equal(stored.payload.community_id, 'community-one');
    assert.equal(stored.payload.admin_verified, false);
    assert.equal(stored.payload.confidence, 0);
    assert.equal(stored.payload.lifecycle_stage, 'working_memory_draft');
    assert.equal(stored.payload.claim_level, 'observation');

    const duplicate = await fetch(`${base}/api/public/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token-community-one-123456', 'idempotency-key': 'submission-0003' },
      body: JSON.stringify(submission())
    });
    assert.equal(duplicate.status, 200);
    assert.equal((await duplicate.json()).duplicate, true);
    assert.equal(store.all().filter((event) => event.event_type === 'evidence_submission').length, 1);
  } finally {
    await close(server);
  }
});

test('tenant tokens cannot write into each other and body limits are enforced', async () => {
  const { server, store } = makeServer({ publicMaxBodyBytes: 512 });
  const base = await listen(server);
  try {
    for (const [token, communityId] of [['token-community-one-123456', 'community-one'], ['token-community-two-123456', 'community-two']]) {
      const result = await fetch(`${base}/api/public/evidence`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'idempotency-key': `tenant-${communityId}` },
        body: JSON.stringify(submission({ summary: `A concrete impersonation observation for ${communityId} with enough detail.`, instanceId: `instance-${communityId}` }))
      });
      assert.equal(result.status, 202);
    }
    const events = store.all().filter((event) => event.event_type === 'evidence_submission');
    assert.deepEqual(events.map((event) => event.payload.community_id).sort(), ['community-one', 'community-two']);
    assert.deepEqual(events.map((event) => event.payload.instance_id).sort(), ['instance-community-one', 'instance-community-two']);
    assert.notEqual(events[0].payload.target_key, undefined);
    const tooLarge = await fetch(`${base}/api/public/evidence`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer token-community-one-123456', 'idempotency-key': 'too-large-0001' },
      body: JSON.stringify(submission({ notes: 'x'.repeat(2000) }))
    });
    assert.equal(tooLarge.status, 413);
  } finally {
    await close(server);
  }
});

test('membership requests require consent, are deduplicated, and never grant access', async () => {
  const { server, store } = makeServer();
  const base = await listen(server);
  try {
    const missingConsent = await fetch(`${base}/api/public/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ communityName: 'Builders', contact: '@builder_admin', graph: 'tracabot' })
    });
    assert.equal(missingConsent.status, 400);

    const first = await fetch(`${base}/api/public/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ communityName: 'Builders', contact: '@builder_admin', graph: 'tracabot', consent: true })
    });
    assert.equal(first.status, 202);
    const payload = await first.json();
    assert.equal(payload.status, 'pending_operator_approval');
    assert.match(payload.note, /does not grant write access/);
    const stored = store.all().find((event) => event.event_type === 'community_join_requested');
    assert.equal(stored.local_only, true);
    assert.equal(stored.payload.consent, true);

    const duplicate = await fetch(`${base}/api/public/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ communityName: 'Builders', contact: '@builder_admin', graph: 'tracabot', consent: true })
    });
    assert.equal(duplicate.status, 409);
  } finally {
    await close(server);
  }
});

test('public policy and onboarding disclose native admin ban limits', async () => {
  const { server } = makeServer();
  const base = await listen(server);
  try {
    const policy = await fetch(`${base}/api/public/policy`).then((response) => response.json());
    assert.match(policy.nativeBanIngestion, /chat_member/);
    assert.match(policy.nativeBanIngestion, /Recent Actions/);
    assert.equal(policy.missingReason, 'reason not provided');
    assert.match(policy.adminEnforcementAutoShare, /admin_enforcement/);
    const onboarding = await fetch(`${base}/api/public/onboarding`).then((response) => response.json());
    assert.match(onboarding.nativeAdminBans.source, /chat_member/);
    assert.equal(onboarding.nativeAdminBans.reasonFallback, 'reason not provided');
    assert.ok(onboarding.nativeAdminBans.unavailable.some((item) => /Recent Actions/.test(item)));
    assert.match(onboarding.silentJoinProtection.automaticCheck, /exact HMAC-scoped platform ID/i);
    assert.equal(onboarding.silentJoinProtection.autoRemove, 'off');
    assert.ok(onboarding.silentJoinProtection.neverAuthorizesRemoval.some((item) => /display name/i.test(item)));
    assert.equal(onboarding.federation.readRequiresWriteToken, false);
    assert.equal(onboarding.federation.outboundSubmissions, 'off');
  } finally {
    await close(server);
  }
});

test('static assets are allowlisted and unknown or traversal paths do not leak files', async () => {
  const { server } = makeServer();
  const base = await listen(server);
  try {
    const home = await fetch(`${base}/`);
    assert.equal(home.status, 200);
    assert.match(await home.text(), /Memory with receipts/);
    const agents = await fetch(`${base}/join`);
    assert.match(await agents.text(), /Bring an agent/);
    for (const path of ['/../.env', '/..%2F.env', '/package.json', '/src/config.js']) {
      const response = await fetch(`${base}${path}`);
      assert.equal(response.status, 404);
    }
  } finally {
    await close(server);
  }
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventStore } from '../src/store.js';
import { createPublicServer } from '../src/public-server.js';

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
        body: JSON.stringify(submission({ summary: `A concrete impersonation observation for ${communityId} with enough detail.` }))
      });
      assert.equal(result.status, 202);
    }
    const events = store.all().filter((event) => event.event_type === 'evidence_submission');
    assert.deepEqual(events.map((event) => event.payload.community_id).sort(), ['community-one', 'community-two']);
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

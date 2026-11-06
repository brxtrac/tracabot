import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventStore } from '../src/store.js';
import { promoteEligibleEvidence } from '../src/evidence-promoter.js';
import { evaluateEvidence } from '../src/evidence-policy.js';

const CONFIG = {
  dkgWrites: true,
  agentDid: 'did:dkg:agent:test',
  evidenceHighConfidenceThreshold: 85,
  evidenceLocalConfidenceThreshold: 60,
  evidenceMinIndependentSignals: 2,
  evidenceMinIndependentCommunities: 2,
  evidencePromotionThreshold: 85
};

function store() {
  return new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-promote-')), 'events.sqlite'));
}

function evidenceEvent(overrides = {}) {
  return {
    id: 'finding-a',
    event_type: 'fraud_finding',
    timestamp: '2026-11-01T10:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: -100, title: 'Community' },
    user: { id: '8388593201', username: 'fake_support' },
    payload: {
      confidence: 92,
      local_confidence: 82,
      scam_type: 'impersonation',
      domains: ['verify-example.example'],
      wallets: ['0x0000000000000000000000000000000000000001'],
      patterns: ['fake-support'],
      evidence: ['Fake support asked a member to verify a wallet.'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      policy_id: 'default',
      publication_status: 'working_memory',
      lifecycle_stage: 'working_memory'
    },
    ...overrides,
    payload: {
      confidence: 92,
      local_confidence: 82,
      scam_type: 'impersonation',
      domains: ['verify-example.example'],
      wallets: ['0x0000000000000000000000000000000000000001'],
      patterns: ['fake-support'],
      evidence: ['Fake support asked a member to verify a wallet.'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      policy_id: 'default',
      publication_status: 'working_memory',
      lifecycle_stage: 'working_memory',
      ...(overrides.payload || {})
    }
  };
}

test('promotion writes one sanitized SWM finding and is idempotent across runs', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent());
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory', eventId: event.id }; } };

  const first = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(first.promoted.length, 1);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].event_type, 'fraud_finding');
  assert.equal(writes[0].payload.claim_level, 'high_confidence_flag');
  assert.equal(writes[0].payload.provenance, 'automatic_evidence_policy');
  assert.equal(writes[0].payload.admin_verified, false);
  assert.equal(writes[0].payload.publication_status, 'shared_memory');
  assert.equal(eventStore.all().filter((event) => event.event_type === 'evidence_promotion_recorded').length, 1);

  const second = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(second.promoted.length, 0);
  assert.equal(writes.length, 1);
  assert.equal(eventStore.all().filter((event) => event.event_type === 'fraud_finding'
    && event.payload?.provenance === 'automatic_evidence_policy').length, 1);
  eventStore.db.close();
});

test('promotion failure is recorded and retryable without losing the source event', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent({ id: 'finding-retry' }));
  let attempts = 0;
  const dkg = {
    async writeEvent(event) {
      attempts += 1;
      if (attempts === 1) throw new Error('DKG timeout');
      return { ual: 'did:dkg:.../_shared_memory', eventId: event.id };
    }
  };
  const first = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(first.failed.length, 1);
  assert.match(first.failed[0].error, /DKG timeout/);
  assert.ok(eventStore.all().some((event) => event.event_type === 'evidence_promotion_failed'
    && event.payload?.source_event_id === 'finding-retry'));
  const second = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(second.promoted.length, 1);
  eventStore.db.close();
});

test('retracted and admin-ban-only evidence is never auto-promoted', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent({ id: 'finding-retracted' }));
  eventStore.append({
    id: 'review-overturn',
    event_type: 'review_overturned',
    timestamp: '2026-11-02T10:00:00.000Z',
    payload: { target_event_id: 'finding-retracted', admin_verified: true }
  });
  eventStore.append({
    id: 'ban-alone',
    event_type: 'ban_executed',
    timestamp: '2026-11-02T11:00:00.000Z',
    payload: {
      confidence: 100,
      local_confidence: 100,
      admin_verified: true,
      evidence: [],
      evidence_root_ids: [],
      affected_community_ids: [],
      domains: [],
      wallets: [],
      patterns: [],
      publication_status: 'working_memory'
    }
  });
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 0);
  assert.equal(writes.length, 0);
  assert.ok(result.skipped.some((item) => item.eventId === 'finding-retracted' && item.reasons.includes('retracted')));
  assert.ok(result.skipped.some((item) => item.eventId === 'ban-alone' && item.reasons.includes('admin_action_without_corroboration')));
  eventStore.db.close();
});

test('promotion stays disabled when DKG writes are disabled', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent({ id: 'finding-disabled' }));
  const result = await promoteEligibleEvidence({ store: eventStore, dkg: { writeEvent: async () => { throw new Error('should not write'); } }, config: { ...CONFIG, dkgWrites: false } });
  assert.equal(result.disabled, true);
  assert.equal(result.promoted.length, 0);
  eventStore.db.close();
});

test('promoted evidence itself is not recursively promoted', async () => {
  const source = evidenceEvent({ id: 'finding-one' });
  const promoted = evidenceEvent({ id: 'promoted-one', payload: {
    ...source.payload,
    provenance: 'automatic_evidence_policy',
    claim_level: 'high_confidence_flag'
  } });
  assert.equal(evaluateEvidence(promoted, { policy: CONFIG }).promotion.eligible, true);
  const eventStore = store();
  eventStore.append(promoted);
  const writes = [];
  const result = await promoteEligibleEvidence({ store: eventStore, dkg: { async writeEvent(event) { writes.push(event); } }, config: CONFIG });
  assert.equal(result.promoted.length, 0);
  assert.equal(writes.length, 0);
  eventStore.db.close();
});

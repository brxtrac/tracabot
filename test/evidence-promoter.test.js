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

test('promotion of a review uses the reviewed subject and keeps underlying lineage', async () => {
  const eventStore = store();
  const source = {
    id: 'review-upheld-source',
    event_type: 'review_upheld',
    timestamp: new Date().toISOString(),
    agentDid: 'did:dkg:agent:test',
    chat: { id: -100, title: 'Community' },
    user: { id: 'moderator-1', username: 'moderator' },
    payload: {
      target_event_id: 'underlying-finding',
      reviewed_target: { id: '8388593201', username: 'subject' },
      reviewed_target_key: 'id:8388593201',
      admin_verified: true,
      confidence: 96,
      local_confidence: 90,
      evidence_root_ids: ['underlying-finding'],
      evidence: ['admin upheld the finding'],
      community_id: '-100',
      publication_status: 'working_memory'
    }
  };
  eventStore.append(source);
  const dkg = { async writeEvent(event) { return { eventId: event.id, ual: 'did:dkg:context-graph:tracabot/_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 1);
  const promoted = eventStore.all().find((event) => event.id === result.promoted[0].promotedEventId);
  assert.equal(promoted.user.id, '8388593201');
  assert.equal(promoted.payload.target.id, '8388593201');
  assert.equal(promoted.payload.target_event_id, 'underlying-finding');
  assert.ok(promoted.payload.evidence_root_ids.includes('underlying-finding'));
  assert.ok(promoted.payload.source_event_ids.includes('underlying-finding'));
  assert.equal(promoted.payload.claim_level, 'confirmed_scam');
});

test('subjectless legacy review cannot promote the reviewer as the fraud subject', async () => {
  const eventStore = store();
  eventStore.append({
    id: 'legacy-subjectless-review',
    event_type: 'review_upheld',
    timestamp: new Date().toISOString(),
    agentDid: 'did:dkg:agent:test',
    chat: { id: -100, title: 'Community' },
    user: { id: 'reviewer-2222', username: 'moderator' },
    payload: {
      target_event_id: 'missing-underlying',
      admin_verified: true,
      confidence: 96,
      local_confidence: 90,
      evidence: ['legacy review without reviewed_target'],
      publication_status: 'working_memory'
    }
  });
  const dkg = { async writeEvent() { throw new Error('must not write'); } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 0);
  assert.ok(result.skipped.some((item) => item.eventId === 'legacy-subjectless-review'
    && item.reasons.includes('missing_reviewed_target')));
});

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

test('retracted evidence is never auto-promoted', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent({ id: 'finding-retracted' }));
  eventStore.append({
    id: 'review-overturn',
    event_type: 'review_overturned',
    timestamp: '2026-11-02T10:00:00.000Z',
    payload: { target_event_id: 'finding-retracted', admin_verified: true }
  });
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 0);
  assert.equal(writes.length, 0);
  assert.ok(result.skipped.some((item) => item.eventId === 'finding-retracted' && item.reasons.includes('retracted')));
  eventStore.db.close();
});

test('provenance-backed native admin ban promotes once as enforcement only', async () => {
  const eventStore = store();
  eventStore.append({
    id: 'native-ban',
    event_type: 'ban_executed',
    timestamp: '2026-11-02T11:00:00.000Z',
    chat: { id: '-100777', type: 'supergroup' },
    user: { id: '8388593201', username: 'banned_user' },
    payload: {
      target: { id: '8388593201', username: 'banned_user' },
      target_key: 'id:8388593201',
      confidence: 0,
      local_confidence: 0,
      admin_verified: true,
      enforcement_verified: true,
      consent_to_share: true,
      enforcement_action: 'ban',
      enforcement_observed_from: 'telegram_chat_member',
      source: 'native_chat_member_admin_ban',
      reason: 'reason not provided',
      reason_provided: false,
      performed_by: { id: 77, username: 'moderator' },
      ban_context: {
        provenance: 'recent_pre_ban_context',
        causal_link: 'unverified',
        category: 'suspected_scam',
        severity: 'high',
        confidence: 88,
        confirmed_scam: false,
        observed_message_count: 2,
        text_message_count: 2,
        media_only: false,
        partial: false,
        indicators: { domains: ['evil.example'], wallets: [], patterns: ['wallet-drain'] },
        messages: [{ message_id: 44, text: 'private raw message text', caption: '' }]
      },
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: [],
      affected_community_ids: [],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement'],
      publication_status: 'working_memory'
    }
  });
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const first = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(first.promoted.length, 1);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].event_type, 'ban_executed');
  assert.equal(writes[0].payload.claim_level, 'admin_enforcement');
  assert.equal(writes[0].payload.admin_verified, false);
  assert.equal(writes[0].payload.enforcement_action, 'ban');
  assert.equal(writes[0].payload.reason_provided, false);
  assert.equal(writes[0].payload.source, 'native_chat_member_admin_ban');
  assert.equal(writes[0].payload.performed_by_recorded, true);
  assert.equal('performed_by' in writes[0].payload, false);
  assert.equal(writes[0].payload.source_event_type, 'ban_executed');
  assert.equal(writes[0].payload.ban_context.category, 'suspected_scam');
  assert.equal(writes[0].payload.ban_context.causal_link, 'unverified');
  assert.equal(writes[0].payload.ban_context.confirmed_scam, false);
  assert.equal(writes[0].payload.ban_context.observed_message_count, 2);
  assert.deepEqual(writes[0].payload.ban_context.indicators.domains, ['evil.example']);
  assert.equal('messages' in writes[0].payload.ban_context, false);
  assert.doesNotMatch(JSON.stringify(writes[0]), /private raw message text|moderator/);
  assert.match(writes[0].payload.evidence.join(' '), /Claim level admin_enforcement/);
  const second = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(second.promoted.length, 0);
  assert.equal(writes.length, 1);
  eventStore.db.close();
});

test('same target banned in two communities promotes once per community scope', async () => {
  const eventStore = store();
  const base = {
    event_type: 'ban_executed',
    user: { id: '8388593201', username: 'banned_user' },
    payload: {
      target: { id: '8388593201', username: 'banned_user' },
      target_key: 'id:8388593201',
      confidence: 0,
      local_confidence: 0,
      admin_verified: true,
      enforcement_verified: true,
      consent_to_share: true,
      enforcement_action: 'ban',
      enforcement_observed_from: 'telegram_chat_member',
      source: 'native_chat_member_admin_ban',
      reason: 'reason not provided',
      reason_provided: false,
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: [],
      affected_community_ids: [],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement'],
      publication_status: 'working_memory'
    }
  };
  eventStore.append({ id: 'ban-community-a', timestamp: '2026-11-02T11:00:00.000Z', occurred_at: '2026-11-02T10:59:00.000Z', chat: { id: '-100111' }, ...base, payload: { ...base.payload, community_id: 'community-a', occurred_at: '2026-11-02T10:59:00.000Z' } });
  eventStore.append({ id: 'ban-community-b', timestamp: '2026-11-02T12:00:00.000Z', chat: { id: '-100222' }, ...base, payload: { ...base.payload, community_id: 'community-b', occurred_at: '2026-11-02T11:59:00.000Z' } });
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 2);
  assert.equal(writes.length, 2);
  assert.deepEqual(writes.map((event) => event.payload.community_id).sort(), ['community-a', 'community-b']);
  assert.notEqual(writes[0].payload.evidence_fingerprint, writes[1].payload.evidence_fingerprint);
  eventStore.db.close();
});

test('high-confidence admin enforcement without consent is not auto-promoted', async () => {
  const eventStore = store();
  eventStore.append({
    id: 'ban-high-signal-no-consent',
    event_type: 'ban_executed',
    timestamp: '2026-11-02T11:00:00.000Z',
    chat: { id: '-100777' },
    user: { id: '8388593201', username: 'banned_user' },
    payload: {
      target: { id: '8388593201', username: 'banned_user' },
      target_key: 'id:8388593201',
      confidence: 100,
      local_confidence: 100,
      admin_verified: true,
      enforcement_verified: true,
      enforcement_action: 'ban',
      source: 'native_chat_member_admin_ban',
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement'],
      publication_status: 'working_memory'
    }
  });
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 0);
  assert.equal(writes.length, 0);
  const skipped = result.skipped.find((item) => item.eventId === 'ban-high-signal-no-consent');
  assert.ok(skipped.reasons.includes('admin_enforcement_not_shareable'));
  assert.ok(skipped.reasons.includes('sharing_consent_missing'));
  eventStore.db.close();
});

test('admin enforcement without provenance is not auto-promoted', async () => {
  const eventStore = store();
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
  assert.ok(result.skipped.some((item) => item.eventId === 'ban-alone' && item.reasons.includes('admin_enforcement_missing_provenance')));
  eventStore.db.close();
});

test('explicit consent denial blocks promotion for private fraud and other event shapes', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent({
    id: 'private-fraud-denied',
    local_only: true,
    payload: { consent_to_share: false }
  }));
  eventStore.append(evidenceEvent({
    id: 'review-denied',
    event_type: 'review_upheld',
    payload: {
      consent_to_share: false,
      target_event_id: 'private-fraud-denied',
      reviewed_target: { id: '8388593201', username: 'fake_support' },
      reviewed_target_key: 'id:8388593201',
      admin_verified: true,
      review_decision: 'upheld'
    }
  }));
  eventStore.append(evidenceEvent({
    id: 'submission-denied',
    event_type: 'evidence_submission',
    payload: { consent_to_share: false }
  }));
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 0);
  assert.equal(writes.length, 0);
  for (const eventId of ['private-fraud-denied', 'review-denied', 'submission-denied']) {
    const skipped = result.skipped.find((item) => item.eventId === eventId);
    assert.ok(skipped, eventId);
    assert.ok(skipped.reasons.includes('sharing_consent_denied'), eventId);
  }
  eventStore.db.close();
});

test('local staging with explicit sharing consent still promotes intentionally shared fraud', async () => {
  const eventStore = store();
  eventStore.append(evidenceEvent({
    id: 'private-fraud-shared',
    local_only: true,
    payload: { consent_to_share: true }
  }));
  const writes = [];
  const dkg = { async writeEvent(event) { writes.push(event); return { ual: 'did:dkg:.../_shared_memory' }; } };
  const result = await promoteEligibleEvidence({ store: eventStore, dkg, config: CONFIG });
  assert.equal(result.promoted.length, 1);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].payload.source_event_id, 'private-fraud-shared');
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

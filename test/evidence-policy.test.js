import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EVIDENCE_POLICY_VERSION,
  evaluateEvidence,
  sanitizePublicEvidence,
  sanitizePublicEvidenceList
} from '../src/evidence-policy.js';

const POLICY = {
  highConfidenceThreshold: 85,
  localConfidenceThreshold: 60,
  minIndependentSignals: 2,
  minIndependentCommunities: 2,
  promotionThreshold: 85
};

function event(overrides = {}) {
  return {
    id: 'event-a',
    event_type: 'fraud_finding',
    timestamp: '2026-11-01T10:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: -100, title: 'Private Community' },
    user: { id: '8388593201', username: 'fake_support', first_name: 'Fake Support' },
    dkg: { ual: 'did:dkg:context-graph:tracabot/_shared_memory', eventId: 'event-a' },
    payload: {
      confidence: 92,
      local_confidence: 80,
      scam_type: 'impersonation',
      domains: ['verify-example.example'],
      wallets: ['0x0000000000000000000000000000000000000001'],
      patterns: ['fake-support'],
      evidence: ['Fake support asked the member to verify a wallet.'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      publication_status: 'shared_memory',
      ...overrides.payload
    },
    ...overrides,
    payload: {
      confidence: 92,
      local_confidence: 80,
      scam_type: 'impersonation',
      domains: ['verify-example.example'],
      wallets: ['0x0000000000000000000000000000000000000001'],
      patterns: ['fake-support'],
      evidence: ['Fake support asked the member to verify a wallet.'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      publication_status: 'shared_memory',
      ...(overrides.payload || {})
    }
  };
}

test('admin ban alone stays enforcement evidence and never becomes a confirmed scam', () => {
  const ban = event({
    event_type: 'ban_executed',
    payload: {
      confidence: 100,
      local_confidence: 100,
      admin_verified: true,
      evidence: [],
      evidence_root_ids: [],
      affected_community_ids: [],
      domains: [],
      wallets: [],
      patterns: []
    }
  });
  const result = evaluateEvidence(ban, { policy: POLICY });
  assert.equal(result.claimLevel, 'admin_enforcement');
  assert.equal(result.confirmedScam, false);
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('admin_action_without_corroboration'));
});

test('admin-reviewed corroborated evidence can be confirmed, while model-only suspicion cannot', () => {
  const reviewed = event({
    event_type: 'review_upheld',
    payload: {
      admin_verified: true,
      review_decision: 'upheld',
      claim_level: 'confirmed_scam'
    }
  });
  assert.equal(evaluateEvidence(reviewed, { policy: POLICY }).claimLevel, 'confirmed_scam');

  const model = event({
    event_type: 'risk_review_needed',
    payload: {
      ai_generated: true,
      detection_method: 'llm_context_reply',
      evidence: [],
      evidence_root_ids: [],
      affected_community_ids: [],
      domains: [],
      wallets: [],
      patterns: []
    }
  });
  const result = evaluateEvidence(model, { policy: POLICY });
  assert.equal(result.confirmedScam, false);
  assert.equal(result.claimLevel, 'observation');
  assert.equal(result.modelOnly, true);
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('model_only_suspicion'));
});

test('corroborated high-confidence evidence is eligible for automatic SWM promotion', () => {
  const result = evaluateEvidence(event(), { policy: POLICY });
  assert.equal(result.claimLevel, 'high_confidence_flag');
  assert.equal(result.confirmedScam, false);
  assert.equal(result.promotion.eligible, true);
  assert.deepEqual(result.promotion.reasons, []);
  assert.match(result.evidenceFingerprint, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.provenance.policyId, 'default');
});

test('retractions suppress promotion and keep the correction as the claim state', () => {
  const source = event();
  const overturned = {
    id: 'review-1',
    event_type: 'review_overturned',
    timestamp: '2026-11-02T10:00:00.000Z',
    payload: { target_event_id: source.id, admin_verified: true }
  };
  const result = evaluateEvidence(source, { history: [source, overturned], policy: POLICY });
  assert.equal(result.claimLevel, 'retracted');
  assert.equal(result.retracted, true);
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('retracted'));
});

test('public sanitization removes identities, private text, and chat metadata', () => {
  const source = event({
    payload: {
      message_text: 'private victim message with seed phrase',
      evidence: ['raw reporter identity 8388593201'],
      preview: 'https://private.example/path'
    }
  });
  const record = sanitizePublicEvidence(source, { history: [source], policy: POLICY, pseudonymKey: 'test-key-32-bytes-long' });
  assert.ok(record);
  assert.equal(record.claimLevel, 'high_confidence_flag');
  assert.match(record.publicId, /^evt_[a-f0-9]{16}$/);
  assert.equal(record.actorRef.startsWith('hmac:v1:'), true);
  assert.deepEqual(record.indicators.domains, ['verify-example.example']);
  const serialized = JSON.stringify(record);
  assert.doesNotMatch(serialized, /8388593201|fake_support|private victim|seed phrase|-100|Private Community|private\.example/);
  assert.doesNotMatch(serialized, /"user"|"chat"|"evidence"/);
  assert.equal(record.provenance.policy, EVIDENCE_POLICY_VERSION);
});

test('local-only or failed evidence never appears in the public reader', () => {
  const local = event({ dkg: undefined, payload: { publication_status: 'working_memory' } });
  assert.equal(sanitizePublicEvidence(local, { history: [local], policy: POLICY }), null);
  const failed = event({ dkg_error: 'write failed' });
  assert.equal(sanitizePublicEvidence(failed, { history: [failed], policy: POLICY }), null);
});

test('public list deduplicates the same evidence fingerprint', () => {
  const first = event({ id: 'event-a' });
  const duplicate = event({ id: 'event-b' });
  const records = sanitizePublicEvidenceList([first, duplicate], { limit: 10, policy: POLICY, pseudonymKey: 'test-key-32-bytes-long' });
  assert.equal(records.length, 1);
});

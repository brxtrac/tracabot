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

test('admin ban without provenance stays enforcement evidence and is not promoted', () => {
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
  assert.ok(result.promotion.reasons.includes('admin_enforcement_missing_provenance'));
});

test('provenance-backed native admin ban is auto-shareable as enforcement only', () => {
  const ban = event({
    event_type: 'ban_executed',
    payload: {
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
      target_key: 'id:8388593201',
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: [],
      affected_community_ids: [],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement']
    }
  });
  const result = evaluateEvidence(ban, { policy: POLICY });
  assert.equal(result.claimLevel, 'admin_enforcement');
  assert.equal(result.confirmedScam, false);
  assert.equal(result.promotion.eligible, true);
  assert.deepEqual(result.promotion.reasons, []);
});

test('high-confidence admin enforcement cannot bypass explicit community opt-out', () => {
  const ban = event({
    event_type: 'ban_executed',
    payload: {
      confidence: 100,
      local_confidence: 100,
      admin_verified: true,
      enforcement_verified: true,
      consent_to_share: false,
      enforcement_action: 'ban',
      source: 'native_chat_member_admin_ban',
      target_key: 'id:8388593201',
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement']
    }
  });
  const result = evaluateEvidence(ban, { policy: POLICY });
  assert.equal(result.claimLevel, 'admin_enforcement');
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('admin_enforcement_not_shareable'));
  assert.ok(result.promotion.reasons.includes('sharing_consent_missing'));
});

test('explicit consent or privacy opt-out blocks every promotable event kind', () => {
  const denied = event({
    local_only: true,
    payload: { consent_to_share: false }
  });
  const deniedResult = evaluateEvidence(denied, { policy: POLICY });
  assert.equal(deniedResult.promotion.eligible, false);
  assert.ok(deniedResult.promotion.reasons.includes('sharing_consent_denied'));

  const optedOut = event({
    payload: { privacy_opt_out: true }
  });
  const optedOutResult = evaluateEvidence(optedOut, { policy: POLICY });
  assert.equal(optedOutResult.promotion.eligible, false);
  assert.ok(optedOutResult.promotion.reasons.includes('sharing_consent_denied'));

  const native = event({
    event_type: 'ban_executed',
    payload: {
      consent_to_share: false,
      admin_verified: true,
      enforcement_verified: true,
      source: 'native_chat_member_admin_ban',
      target_key: 'id:8388593201'
    }
  });
  const nativeResult = evaluateEvidence(native, { policy: POLICY });
  assert.equal(nativeResult.promotion.eligible, false);
  assert.ok(nativeResult.promotion.reasons.includes('sharing_consent_denied'));
});

test('high-confidence admin enforcement cannot bypass missing consent', () => {
  const ban = event({
    event_type: 'ban_executed',
    payload: {
      confidence: 100,
      local_confidence: 100,
      admin_verified: true,
      enforcement_verified: true,
      enforcement_action: 'ban',
      source: 'native_chat_member_admin_ban',
      target_key: 'id:8388593201',
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement']
    }
  });
  const result = evaluateEvidence(ban, { policy: POLICY });
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('sharing_consent_missing'));
});

test('high-confidence admin enforcement cannot bypass missing verified action provenance', () => {
  const ban = event({
    event_type: 'ban_executed',
    payload: {
      confidence: 100,
      local_confidence: 100,
      admin_verified: false,
      enforcement_verified: false,
      consent_to_share: true,
      enforcement_action: 'ban',
      source: 'native_chat_member_admin_ban',
      target_key: 'id:8388593201',
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement']
    }
  });
  const result = evaluateEvidence(ban, { policy: POLICY });
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('admin_enforcement_not_verified'));
});

test('admin enforcement cannot auto-share without a valid target', () => {
  const ban = event({
    event_type: 'ban_executed',
    user: {},
    payload: {
      confidence: 100,
      local_confidence: 100,
      admin_verified: true,
      enforcement_verified: true,
      consent_to_share: true,
      enforcement_action: 'ban',
      source: 'native_chat_member_admin_ban',
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: ['prior-a', 'prior-b'],
      affected_community_ids: ['community-a', 'community-b'],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement']
    }
  });
  const result = evaluateEvidence(ban, { policy: POLICY });
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('admin_enforcement_missing_target'));
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

test('public admin-enforcement record exposes reason status, not identities or private text', () => {
  const ban = event({
    event_type: 'ban_executed',
    payload: {
      claim_level: 'admin_enforcement',
      confidence: 0,
      local_confidence: 0,
      scam_type: 'admin_enforcement',
      enforcement_action: 'ban',
      enforcement_observed_from: 'telegram_chat_member',
      reason: 'reason not provided',
      reason_provided: false,
      performed_by: { id: 77, username: 'moderator' },
      ban_context: {
        provenance: 'recent_pre_ban_context',
        causal_link: 'unverified',
        label: 'recent pre-ban context; causal link unverified',
        category: 'suspected_scam',
        severity: 'high',
        confidence: 88,
        confirmed_scam: false,
        behavior_flags: ['harassment'],
        observed_message_count: 2,
        text_message_count: 2,
        media_only: false,
        partial: false,
        indicators: { domains: ['https://api_token:secret@evil.example/claim?token=abc123'], wallets: [], patterns: ['wallet-drain'] },
        messages: [{ message_id: 44, text: 'raw private message', caption: '' }]
      },
      evidence: ['Telegram chat_member update observed a live ban transition'],
      evidence_root_ids: ['event-ban'],
      affected_community_ids: ['community-a'],
      domains: [],
      wallets: [],
      patterns: ['admin_enforcement']
    }
  });
  const record = sanitizePublicEvidence(ban, { history: [ban], policy: POLICY, pseudonymKey: 'test-key-32-bytes-long' });
  assert.equal(record.claimLevel, 'admin_enforcement');
  assert.equal(record.enforcement.action, 'ban');
  assert.equal(record.enforcement.reason, 'reason not provided');
  assert.equal(record.enforcement.reasonProvided, false);
  assert.equal(record.enforcement.actorRecorded, true);
  assert.equal(record.banContext.category, 'suspected_scam');
  assert.equal(record.banContext.confirmedScam, false);
  assert.equal(record.banContext.causalLink, 'unverified');
  assert.equal(record.banContext.messageCount, 2);
  assert.deepEqual(record.banContext.behaviorFlags, ['harassment']);
  assert.deepEqual(record.banContext.indicators.domains, ['evil.example']);
  assert.equal('messages' in record.banContext, false);
  assert.match(record.summary, /no causal link/i);
  assert.match(record.targetRef, /^hmac:v1:[a-f0-9]{64}$/);
  assert.equal(record.targetRef, record.actorRef);
  assert.match(record.summary, /no reason was provided/i);
  const serialized = JSON.stringify(record);
  assert.doesNotMatch(serialized, /8388593201|moderator|telegram-user|evidenceText|raw private message|api_token|secret|abc123|token=/);
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

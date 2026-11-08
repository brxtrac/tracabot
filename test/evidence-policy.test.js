import test from 'node:test';
import assert from 'node:assert/strict';
import {
  EVIDENCE_POLICY_VERSION,
  evaluateEvidence,
  sanitizePublicEvidence,
  sanitizePublicEvidenceList,
  sharingDeniedInLineage
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

test('retraction of an underlying finding also retracts its review wrapper', () => {
  const review = event({
    id: 'review-up',
    event_type: 'review_upheld',
    payload: {
      target_event_id: 'finding-under-review',
      admin_verified: true,
      review_decision: 'upheld',
      reviewed_target: { id: '8388593201' },
      reviewed_target_key: 'id:8388593201',
      target_chat_id: '-100'
    }
  });
  const overturned = {
    id: 'review-down',
    event_type: 'review_overturned',
    timestamp: '2026-11-02T10:00:00.000Z',
    payload: { target_event_id: 'finding-under-review', admin_verified: true }
  };
  const result = evaluateEvidence(review, { history: [review, overturned], policy: POLICY });
  assert.equal(result.retracted, true);
  assert.equal(result.claimLevel, 'retracted');
  assert.equal(result.promotion.eligible, false);
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

test('public sanitization drops arbitrary graph text from scam types, patterns, and context labels', () => {
  const secret = 'sk-live-SYNTHETIC-DO-NOT-PUBLISH';
  const ban = event({
    event_type: 'ban_executed',
    payload: {
      confidence: 0,
      local_confidence: 0,
      admin_verified: true,
      enforcement_verified: true,
      enforcement_action: 'ban',
      enforcement_observed_from: 'telegram_chat_member',
      consent_to_share: true,
      reason_provided: false,
      scam_type: secret,
      patterns: [secret],
      target: { id: '8388593201' },
      target_key: 'id:8388593201',
      ban_context: {
        category: secret,
        severity: secret,
        confidence: 70,
        behavior_flags: [secret],
        observed_message_count: 1,
        text_message_count: 1,
        indicators: { domains: [], wallets: [], patterns: [secret] }
      }
    }
  });
  const record = sanitizePublicEvidence(ban, { history: [ban], policy: POLICY, pseudonymKey: 'test-key-32-bytes-long' });
  assert.ok(record);
  assert.equal(record.scamType, 'unknown');
  assert.deepEqual(record.indicators.patterns, []);
  assert.equal(record.banContext.category, 'unknown');
  assert.equal(record.banContext.severity, 'unknown');
  assert.deepEqual(record.banContext.behaviorFlags, []);
  assert.deepEqual(record.banContext.indicators.patterns, []);
  assert.doesNotMatch(JSON.stringify(record), new RegExp(secret));
});

test('explicit denial propagates through bounded review lineage for promotion and public reads', () => {
  const root = event({
    id: 'denied-root',
    payload: { consent_to_share: false }
  });
  const wrapper = event({
    id: 'allowed-wrapper',
    event_type: 'review_upheld',
    payload: {
      target_event_id: 'denied-root',
      evidence_root_ids: ['denied-root'],
      reviewed_target: { id: '8388593201' },
      reviewed_target_key: 'id:8388593201',
      review_decision: 'upheld',
      admin_verified: true
    }
  });
  const lineage = [root, wrapper];
  const result = evaluateEvidence(wrapper, { history: lineage, policy: POLICY });
  assert.equal(result.promotion.eligible, false);
  assert.ok(result.promotion.reasons.includes('sharing_consent_denied'));
  assert.equal(sanitizePublicEvidence(wrapper, { history: lineage, policy: POLICY }), null);
  assert.equal(sharingDeniedInLineage(lineage, 'allowed-wrapper'), true);
  assert.equal(sharingDeniedInLineage(lineage, wrapper), true);

  const cycleA = { id: 'cycle-a', payload: { target_event_id: 'cycle-b' } };
  const cycleB = { id: 'cycle-b', payload: { target_event_id: 'cycle-a' } };
  assert.equal(sharingDeniedInLineage([cycleA, cycleB], 'cycle-a'), false);

  const openRoot = event({ id: 'open-root', payload: { consent_to_share: true } });
  const openWrapper = event({
    id: 'open-wrapper',
    event_type: 'review_upheld',
    payload: {
      target_event_id: 'open-root',
      evidence_root_ids: ['open-root'],
      reviewed_target: { id: '8388593201' },
      reviewed_target_key: 'id:8388593201',
      review_decision: 'upheld',
      admin_verified: true
    }
  });
  const openLineage = [openRoot, openWrapper];
  assert.equal(evaluateEvidence(openWrapper, { history: openLineage, policy: POLICY }).promotion.reasons.includes('sharing_consent_denied'), false);
  assert.equal(sharingDeniedInLineage(openLineage, 'open-wrapper'), false);
  assert.ok(sanitizePublicEvidence(openWrapper, { history: openLineage, policy: POLICY }));
});

test('lineage walk fails closed on depth, node, and reference overflow and missing structural links', () => {
  const chain = (length) => Array.from({ length }, (_, index) => ({
    id: `n${index}`,
    payload: { consent_to_share: true, ...(index < length - 1 ? { target_event_id: `n${index + 1}` } : {}) }
  }));
  assert.equal(sharingDeniedInLineage(chain(9), 'n0'), false);
  assert.equal(sharingDeniedInLineage(chain(10), 'n0'), true);

  const refs = Array.from({ length: 41 }, (_, index) => `root-${index}`);
  const refOverflow = [
    { id: 'ref-root', payload: { consent_to_share: true, evidence_root_ids: refs } },
    ...refs.map((id) => ({ id, payload: { consent_to_share: true } }))
  ];
  assert.equal(sharingDeniedInLineage(refOverflow, 'ref-root'), true);

  const children = Array.from({ length: 33 }, (_, index) => `b${index}`);
  const leaves = Array.from({ length: 33 }, (_, index) => ({ id: `c${index}`, payload: { consent_to_share: true } }));
  const nodeOverflow = [
    { id: 'node-root', payload: { consent_to_share: true, target_event_id: 'node-a' } },
    { id: 'node-a', payload: { consent_to_share: true, target_event_id: 'b0', evidence_root_ids: children.slice(1) } },
    ...children.map((id, index) => ({ id, payload: { consent_to_share: true, target_event_id: `c${index}` } })),
    ...leaves
  ];
  assert.equal(sharingDeniedInLineage(nodeOverflow, 'node-root'), true);

  const missingStructural = [{ id: 'missing-root', payload: { consent_to_share: true, target_event_id: 'not-present' } }];
  assert.equal(sharingDeniedInLineage(missingStructural, 'missing-root'), true);
  const missingCorroborating = [{ id: 'external-root', payload: { consent_to_share: true, evidence_root_ids: ['https://dkg.example/root'] } }];
  assert.equal(sharingDeniedInLineage(missingCorroborating, 'external-root'), false);

  // The same missing ID may appear first as a corroborating root and later as
  // a structural review link. Structural resolution must be validated even when
  // the ID was already visited as corroborating.
  const sharedMissing = [
    { id: 'lineage-start', payload: { consent_to_share: true, target_event_id: 'lineage-middle', evidence_root_ids: ['shared-missing'] } },
    { id: 'lineage-middle', payload: { consent_to_share: true, target_event_id: 'shared-missing' } }
  ];
  assert.equal(sharingDeniedInLineage(sharedMissing, 'lineage-start'), true);
  const reversed = [...sharedMissing].reverse();
  assert.equal(sharingDeniedInLineage(reversed, 'lineage-start'), true);
  const sameEvent = [{
    id: 'lineage-same',
    payload: { consent_to_share: true, target_event_id: 'shared-missing', evidence_root_ids: ['shared-missing'] }
  }];
  assert.equal(sharingDeniedInLineage(sameEvent, 'lineage-same'), true);
});

test('public projection allowlists enforcement and provenance labels and validates timestamps', () => {
  const record = sanitizePublicEvidence(event({
    event_type: 'ban_executed',
    payload: {
      consent_to_share: true,
      admin_verified: true,
      enforcement_verified: true,
      confidence: 95,
      local_confidence: 90,
      source: 'token=SECRET',
      enforcement_action: 'password=HUSH',
      enforcement_observed_from: 'api_key=SUPERSECRET',
      occurred_at: 'api_key=SUPERSECRET',
      target_key: 'id:8388593201'
    }
  }), { history: [], policy: POLICY, pseudonymKey: 'k'.repeat(32) });
  assert.ok(record);
  assert.equal(record.enforcement.action, 'unknown');
  assert.equal(record.enforcement.source, '');
  assert.equal(record.provenance.source, 'unknown');
  assert.equal(record.createdAt, '');
  assert.doesNotMatch(JSON.stringify(record), /SECRET|HUSH|SUPERSECRET/);
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

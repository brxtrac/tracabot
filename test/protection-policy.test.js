import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateJoinProtection, PROTECTION_POLICY_VERSION } from '../src/protection-policy.js';

const NOW = Date.parse('2026-11-06T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const fresh = new Date(NOW - DAY).toISOString();
const old = new Date(NOW - 400 * DAY).toISOString();

function confirmed(overrides = {}) {
  return {
    eventId: 'evt-confirmed-1',
    eventType: 'review_upheld',
    claimLevel: 'confirmed_scam',
    confidence: 96,
    created: fresh,
    adminVerified: true,
    exactActorMatch: true,
    trustLayer: 'local',
    source: 'local_admin_review',
    localApproval: true,
    ...overrides
  };
}

function policy(overrides = {}) {
  return {
    autoRemove: true,
    trustedLayers: ['verified-memory', 'local'],
    maxAgeDays: 180,
    minRoots: 1,
    ...overrides
  };
}

test('join protection allows a join with no confirmed evidence', () => {
  const decision = evaluateJoinProtection({ target: { id: 42 }, evidence: [], policy: policy(), now: NOW });
  assert.equal(decision.policyVersion, PROTECTION_POLICY_VERSION);
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'no_confirmed_evidence');
  assert.equal(decision.exactIdentity, true);
});

test('join protection requires a stable platform identity', () => {
  const decision = evaluateJoinProtection({ target: { username: 'only_name' }, evidence: [confirmed()], policy: policy(), now: NOW });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'missing_stable_identity');
});

test('bots, admins and owner identities are never removed', () => {
  assert.equal(evaluateJoinProtection({ target: { id: 42, is_bot: true }, evidence: [confirmed()], policy: policy(), now: NOW }).reason, 'protected_bot');
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: [confirmed()], policy: policy({ targetIsAdmin: true }), now: NOW }).reason, 'protected_admin');
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: [confirmed()], policy: policy({ targetIsOwner: true }), now: NOW }).reason, 'protected_owner');
});

test('confirmed exact identity evidence removes only when the operator opts in', () => {
  const remove = evaluateJoinProtection({ target: { id: 42 }, evidence: [confirmed()], policy: policy(), now: NOW });
  assert.equal(remove.action, 'remove');
  assert.equal(remove.reason, 'confirmed_exact_identity_evidence');
  assert.deepEqual(remove.roots, ['evt-confirmed-1']);

  const observe = evaluateJoinProtection({ target: { id: 42 }, evidence: [confirmed()], policy: policy({ autoRemove: false }), now: NOW });
  assert.equal(observe.action, 'flag');
  assert.equal(observe.reason, 'enforcement_disabled');
});

test('shared-memory community reports are not trusted for automatic removal', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [confirmed({ trustLayer: 'shared-working-memory', source: 'fork-instance', localApproval: false })],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'untrusted_evidence_layer');
  assert.equal(decision.untrustedEvidenceCount, 1);
});

test('display-name-only and alias-only evidence cannot remove', () => {
  for (const exactActorMatch of [false, undefined]) {
    const decision = evaluateJoinProtection({ target: { id: 42, first_name: 'Same Name' }, evidence: [confirmed({ exactActorMatch })], policy: policy(), now: NOW });
    assert.equal(decision.action, 'flag');
    assert.equal(decision.reason, 'no_exact_identity_evidence');
  }
});

test('admin enforcement alone is not confirmed scam evidence', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [confirmed({ eventType: 'ban_executed', claimLevel: 'admin_enforcement', adminVerified: true })],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'no_confirmed_evidence');
});

test('stale confirmed evidence only flags', () => {
  const decision = evaluateJoinProtection({ target: { id: 42 }, evidence: [confirmed({ created: old })], policy: policy(), now: NOW });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'stale_evidence');
});

test('a newer correction or retraction suppresses older confirmed evidence', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [
      confirmed({ eventId: 'evt-confirmed-1', created: new Date(NOW - 10 * DAY).toISOString() }),
      confirmed({
        eventId: 'evt-retraction-1',
        eventType: 'review_overturned',
        claimLevel: 'retracted',
        created: new Date(NOW - DAY).toISOString(),
        source: 'creator-curator'
      })
    ],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'retracted_evidence');
});

test('a targeted retraction suppresses only its own root', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [
      confirmed({ eventId: 'evt-a' }),
      confirmed({ eventId: 'evt-b' }),
      confirmed({
        eventId: 'evt-retraction',
        eventType: 'review_overturned',
        claimLevel: 'retracted',
        targetEventId: 'evt-a',
        created: new Date(NOW - 1000).toISOString()
      })
    ],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'remove');
  assert.deepEqual(decision.roots, ['evt-b']);
});

test('minimum independent confirmed roots and chat opt-in are enforced', () => {
  const twoRoots = [confirmed({ eventId: 'evt-a' }), confirmed({ eventId: 'evt-b' })];
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: [confirmed()], policy: policy({ minRoots: 2 }), now: NOW }).reason, 'insufficient_confirmed_roots');
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: twoRoots, policy: policy({ minRoots: 2 }), now: NOW }).action, 'remove');
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: twoRoots, policy: policy({ allowedChatIds: ['-200'] }), chatId: '-100', now: NOW }).reason, 'chat_not_opted_in');
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: twoRoots, policy: policy({ allowedChatIds: ['-200'] }), chatId: '-200', now: NOW }).action, 'remove');
});

test('an optional trusted source allowlist is enforced for shared evidence', () => {
  const approvedShared = (overrides = {}) => confirmed({
    trustLayer: 'verified-memory',
    localApproval: false,
    publisherApprovalVerified: true,
    source: 'unknown-publisher',
    ...overrides
  });
  const evidence = [approvedShared()];
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence,
    policy: policy({ trustedSources: ['creator-curator'] }),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'untrusted_evidence_source');
  assert.equal(decision.untrustedEvidenceCount, 1);
  assert.equal(evaluateJoinProtection({
    target: { id: 42 },
    evidence: [approvedShared({ source: 'creator-curator' })],
    policy: policy({ trustedSources: ['creator-curator'] }),
    now: NOW
  }).action, 'remove');
});

test('verified-memory membership without authenticated publisher approval is flag-only', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [confirmed({
      trustLayer: 'verified-memory',
      source: 'creator-curator',
      localApproval: false,
      publisherApprovalVerified: false
    })],
    policy: policy({ trustedLayers: ['verified-memory', 'local'] }),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'missing_authenticated_approval');
  assert.equal(decision.unapprovedEvidenceCount, 1);
});

test('a correction suppresses the promoted root that shares the underlying finding lineage', () => {
  const promoted = confirmed({
    eventId: 'promoted-777',
    sourceEventId: 'upheld-1',
    evidenceRootIds: ['finding-1']
  });
  const retraction = confirmed({
    eventId: 'overturn-1',
    eventType: 'review_overturned',
    claimLevel: 'retracted',
    targetEventId: 'finding-1',
    localApproval: false,
    created: new Date(NOW - 1000).toISOString()
  });
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [promoted, retraction],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'retracted_evidence');
});

test('an unmatched retraction target is ambiguous and suppresses removal', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [
      confirmed({ eventId: 'promoted-777', sourceEventId: 'upheld-1', evidenceRootIds: ['finding-1'] }),
      confirmed({
        eventId: 'overturn-other',
        eventType: 'review_overturned',
        claimLevel: 'retracted',
        targetEventId: 'different-finding',
        localApproval: false,
        created: new Date(NOW - 1000).toISOString()
      })
    ],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'ambiguous_retraction_lineage');
});

test('incomplete evidence sets cannot authorize removal', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [confirmed()],
    policy: policy({ evidenceComplete: false }),
    now: NOW
  });
  assert.equal(decision.action, 'flag');
  assert.equal(decision.reason, 'incomplete_evidence');
});

test('minimum roots counts independent underlying evidence, not wrapper IDs', () => {
  const duplicateReviews = [
    confirmed({ eventId: 'review-a', sourceEventId: 'finding-one', targetEventId: 'finding-one' }),
    confirmed({ eventId: 'review-b', sourceEventId: 'finding-one', targetEventId: 'finding-one' })
  ];
  const promotedCopies = [
    confirmed({ eventId: 'promoted-a', sourceEventId: 'review-a', evidenceRootIds: ['review-a', 'finding-one'] }),
    confirmed({ eventId: 'review-b', sourceEventId: 'finding-one', targetEventId: 'finding-one' })
  ];
  const independent = [
    confirmed({ eventId: 'review-a', sourceEventId: 'finding-one', targetEventId: 'finding-one' }),
    confirmed({ eventId: 'review-b', sourceEventId: 'finding-two', targetEventId: 'finding-two' })
  ];
  assert.equal(evaluateJoinProtection({
    target: { id: 42 }, evidence: duplicateReviews, policy: policy({ minRoots: 2 }), now: NOW
  }).reason, 'insufficient_confirmed_roots');
  assert.equal(evaluateJoinProtection({
    target: { id: 42 }, evidence: promotedCopies, policy: policy({ minRoots: 2 }), now: NOW
  }).reason, 'insufficient_confirmed_roots');
  const decision = evaluateJoinProtection({
    target: { id: 42 }, evidence: independent, policy: policy({ minRoots: 2 }), now: NOW
  });
  assert.equal(decision.action, 'remove');
  assert.equal(decision.activeConfirmedEvidenceCount, 2);
});

test('local admin reviews are trusted and do not include raw message text', () => {
  const decision = evaluateJoinProtection({
    target: { id: 42 },
    evidence: [confirmed({ trustLayer: 'local', source: 'local_admin_review' })],
    policy: policy(),
    now: NOW
  });
  assert.equal(decision.action, 'remove');
  assert.equal(decision.evidence[0].trustLayer, 'local');
  assert.doesNotMatch(JSON.stringify(decision), /message_text|private message/i);
});

test('creator-curator layer requires the verified marker and confidence, not a bare source or boolean', () => {
  const bare = confirmed({ trustLayer: 'creator-curator', source: 'creator-curator', publisherApprovalVerified: true, creatorAttestation: false, localApproval: false });
  const forged = confirmed({ trustLayer: 'creator-curator', source: 'arbitrary-fork', publisherApprovalVerified: true, creatorAttestation: false, localApproval: false });
  const lowConfidence = confirmed({ trustLayer: 'creator-curator', source: 'creator-curator', publisherApprovalVerified: true, creatorAttestation: true, localApproval: false, confidence: 70 });
  const verified = confirmed({ trustLayer: 'creator-curator', source: 'creator-curator', publisherApprovalVerified: true, creatorAttestation: true, localApproval: false, confidence: 96 });
  const creatorPolicy = policy({ trustedLayers: ['creator-curator'] });
  assert.notEqual(evaluateJoinProtection({ target: { id: 42 }, evidence: [bare], policy: creatorPolicy, now: NOW }).action, 'remove');
  assert.notEqual(evaluateJoinProtection({ target: { id: 42 }, evidence: [forged], policy: creatorPolicy, now: NOW }).action, 'remove');
  assert.notEqual(evaluateJoinProtection({ target: { id: 42 }, evidence: [lowConfidence], policy: creatorPolicy, now: NOW }).action, 'remove');
  assert.equal(evaluateJoinProtection({ target: { id: 42 }, evidence: [verified], policy: creatorPolicy, now: NOW }).action, 'remove');
});

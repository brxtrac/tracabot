import test from 'node:test';
import assert from 'node:assert/strict';
import { combineRisk, displayName, formatDkgReference, formatRiskAssessment, formatScanReply, formatStatsReply } from '../src/risk-engine.js';

test('combines DKG evidence with local analysis and triggers ban threshold', () => {
  const risk = combineRisk({
    threshold: 85,
    analysis: {
      is_scam: true,
      confidence: 70,
      scam_type: 'phishing',
      evidence: ['Suspicious link'],
      recommended_action: 'warn'
    },
    dkgIntel: {
      riskScore: 90,
      reportsAcrossCommunities: 3,
      wallets: ['0x1111111111111111111111111111111111111111'],
      patterns: ['wallet-drain'],
      evidence: [{ source: 'https://tracabot.org/ontology#event/known-scam', eventId: 'known-scam', ual: 'did:dkg:context-graph:claw-shield-intel/_shared_memory' }]
    }
  });
  assert.equal(risk.confidence, 90);
  assert.equal(risk.recommended_action, 'ban');
  assert.equal(risk.community_verified_flag, 'candidate-high-confidence');
  assert.match(formatRiskAssessment({ target: { username: 'badactor' }, risk }), /HIGH RISK/);
  assert.match(risk.evidence.join('\n'), /DKG evidence: UAL did:dkg:context-graph:claw-shield-intel\/_shared_memory event known-scam/);
  assert.doesNotMatch(risk.evidence.join('\n'), /https:\/\/tracabot\.org\/ontology#event/);
});

test('formats Telegram users by friendly name before numeric ID', () => {
  assert.equal(displayName({ id: 517276940, first_name: 'BRX', last_name: '1947' }), 'BRX 1947');
  assert.equal(displayName({ id: 517276940, username: 'BRX86', first_name: 'BRX' }), '@BRX86');
  const clean = formatScanReply({
    target: { id: 517276940, first_name: 'BRX', last_name: '1947' },
    risk: { confidence: 0 },
    eventId: 'evt'
  });
  assert.match(clean, /BRX 1947 looks clean/);
  assert.doesNotMatch(clean, /517276940 looks clean/);
});

test('formats DKG write references as UAL plus share operation', () => {
  assert.equal(formatDkgReference({
    id: 'evt-1',
    dkg: {
      ual: 'did:dkg:context-graph:claw-shield-intel/_shared_memory',
      shareOperation: 'swm-123'
    }
  }), 'did:dkg:context-graph:claw-shield-intel/_shared_memory event evt-1 share swm-123');
});

test('formats stats like a readable risk summary', () => {
  const text = formatStatsReply({
    total: 54,
    highConfidence: 43,
    byEventType: { fraud_finding: 18, risk_query: 15, ban_executed: 5 },
    byRiskType: { impersonation: 34, other: 20 }
  });
  assert.match(text, /DKG stats for the last 7 days: HIGH ACTIVITY/);
  assert.match(text, /Signals: 43 high-confidence \/ 54 total fraud intel events \(80%\)/);
  assert.match(text, /Events: Fraud Finding: 18, Risk Query: 15, Ban Executed: 5/);
  assert.match(text, /Risk types: Impersonation: 34, Other: 20/);
  assert.doesNotMatch(text, /\{"fraud_finding"/);
});

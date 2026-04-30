import test from 'node:test';
import assert from 'node:assert/strict';
import { combineRisk, displayName, formatRiskAssessment, formatScanReply } from '../src/risk-engine.js';

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
      evidence: [{ source: 'https://tracabot.org/ontology#event/known-scam' }]
    }
  });
  assert.equal(risk.confidence, 90);
  assert.equal(risk.recommended_action, 'ban');
  assert.equal(risk.community_verified_flag, 'candidate-high-confidence');
  assert.match(formatRiskAssessment({ target: { username: 'badactor' }, risk }), /HIGH RISK/);
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

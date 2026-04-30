import test from 'node:test';
import assert from 'node:assert/strict';
import { combineRisk, formatRiskAssessment } from '../src/risk-engine.js';

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

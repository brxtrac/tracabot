import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage } from '../src/scam-analyzer.js';

test('detects high-confidence crypto giveaway impersonation scams', () => {
  const result = analyzeMessage({
    text: 'URGENT free 1000 USDT airdrop, claim now at t.me/fakeclaim and DM support admin',
    user: { username: 'support_admin_bonus' },
    globalIntel: { reportsAcrossCommunities: 3, evidence: [] }
  });
  assert.equal(result.is_scam, true);
  assert.equal(result.recommended_action, 'ban');
  assert.ok(result.confidence >= 90);
  assert.equal(result.scam_type, 'impersonation');
});

test('does not flag normal community messages', () => {
  const result = analyzeMessage({
    text: 'Can someone share the meeting notes from today?',
    user: { username: 'regular_member' }
  });
  assert.equal(result.is_scam, false);
  assert.equal(result.recommended_action, 'ignore');
});

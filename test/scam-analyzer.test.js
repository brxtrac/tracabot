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

test('scores DM help requests as report-worthy impersonation evidence', () => {
  const result = analyzeMessage({
    text: 'DM me for help with your wallet issue',
    user: { username: 'regular_member' }
  });
  assert.equal(result.scam_type, 'impersonation');
  assert.ok(result.confidence >= 40);
  assert.match(result.evidence.join('\n'), /DMs/);
});

test('detects usernames that copy configured admin handles', () => {
  const result = analyzeMessage({
    text: 'I can help, message me',
    user: { username: 'brx86_support', adminUsernames: ['brx86'] }
  });
  assert.equal(result.scam_type, 'impersonation');
  assert.ok(result.confidence >= 80);
  assert.match(result.evidence.join('\n'), /configured admin/);
});

test('detects display names that copy configured admin handles', () => {
  const result = analyzeMessage({
    text: 'message me for support',
    user: { first_name: 'BRX 86', adminUsernames: ['brx86'] }
  });
  assert.equal(result.scam_type, 'impersonation');
  assert.ok(result.confidence >= 60);
});

test('detects investment profit testimonial Telegram scams', () => {
  const result = analyzeMessage({
    text: 'From Zero to $685K profit I joined Alpha Trading (https://t.me/alpha_trading_cricle) 16 months ago and within the past 3 months I earned $685,000 thanks to the coaching and education Mr Theo provides. The strategy and community support made all the difference.',
    user: { username: 'new_member' }
  });
  assert.equal(result.is_scam, true);
  assert.equal(result.recommended_action, 'ban');
  assert.equal(result.scam_type, 'investment_scam');
  assert.ok(result.confidence >= 90);
  assert.match(result.evidence.join('\n'), /Investment-profit testimonial/);
});

test('detects admin-targeted institutional partnership outreach lures', () => {
  const result = analyzeMessage({
    text: 'Gmgm Admin. Who can I discuss Institutional Investment Partnership with? I have serious VC partners interested in exploring investment partnership in your project.',
    user: { username: 'new_partner_outreach' }
  });
  assert.equal(result.is_scam, true);
  assert.equal(result.scam_type, 'investment_scam');
  assert.ok(result.confidence >= 70);
  assert.match(result.evidence.join('\n'), /partnership outreach/);
});

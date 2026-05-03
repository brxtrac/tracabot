import test from 'node:test';
import assert from 'node:assert/strict';
import { combineRisk, displayName, formatDkgReference, formatRiskAssessment, formatScanReply, formatStatsReply, formatStatsSourcesReply } from '../src/risk-engine.js';

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
      domains: ['fake-claim.example'],
      patterns: ['wallet-drain'],
      evidence: [{ source: 'https://tracabot.org/ontology#event/known-scam', eventId: 'known-scam', ual: 'did:dkg:context-graph:tracabot/_shared_memory' }]
    }
  });
  assert.equal(risk.confidence, 90);
  assert.equal(risk.recommended_action, 'ban');
  assert.equal(risk.community_verified_flag, 'auto-publish-high-confidence');
  assert.match(formatRiskAssessment({ target: { username: 'badactor' }, risk }), /HIGH RISK/);
  assert.match(risk.evidence.join('\n'), /DKG evidence: UAL did:dkg:context-graph:tracabot\/_shared_memory event known-scam/);
  assert.match(risk.evidence.join('\n'), /Domains checked: fake-claim\.example/);
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
  assert.match(clean, /BRX 1947 looks low risk/);
  assert.doesNotMatch(clean, /Stay cautious with wallet links or DMs/);
  assert.doesNotMatch(clean, /517276940 looks low risk/);
});

test('scan replies vary low-risk safety closers without exposing internals', () => {
  const first = formatScanReply({ target: { username: 'alice' }, risk: { confidence: 0 }, eventId: 'evt-a' });
  const second = formatScanReply({ target: { username: 'bob' }, risk: { confidence: 0 }, eventId: 'evt-b' });
  assert.match(first, /looks low risk/);
  assert.match(second, /looks low risk/);
  assert.notEqual(first, second);
  assert.doesNotMatch(`${first}\n${second}`, /UAL|Context Graph|Shared Memory|evt-a|evt-b/);
});

test('public risk replies redact internal DKG references', () => {
  const risk = {
    confidence: 91,
    scam_type: 'phishing',
    recommended_action: 'ban',
    evidence: [
      'DKG evidence: UAL did:dkg:context-graph:tracabot/_shared_memory event evt-secret share swm-secret',
      'Active watchlist entry: configured admin watch',
      'wallet-drain phrase detected',
      'Domains checked: fake-claim.example'
    ]
  };
  const scan = formatScanReply({ target: { username: 'badactor' }, risk, eventId: 'evt-secret', findingId: 'finding-secret' });
  const assessment = formatRiskAssessment({ target: { username: 'badactor' }, risk });
  assert.match(scan, /HIGH RISK/);
  assert.match(scan, /wallet-drain phrase detected/);
  assert.doesNotMatch(scan, /UAL|Context Graph|evt-secret|finding-secret|configured admin|swm-secret/);
  assert.match(assessment, /Public signals/);
  assert.doesNotMatch(assessment, /UAL|Context Graph|evt-secret|configured admin|swm-secret/);
});

test('formats DKG write references as UAL plus share operation', () => {
  assert.equal(formatDkgReference({
    id: 'evt-1',
    dkg: {
      ual: 'did:dkg:context-graph:tracabot/_shared_memory',
      shareOperation: 'swm-123'
    }
  }), 'did:dkg:context-graph:tracabot/_shared_memory event evt-1 share swm-123');
});

test('formats stats like a readable risk summary', () => {
  const text = formatStatsReply({
    total: 54,
    highConfidence: 43,
    graph: 'tracabot',
    byEventType: { fraud_finding: 18, risk_query: 15, ban_executed: 5 },
    byRiskType: { impersonation: 34, other: 20 }
  });
  assert.match(text, /TRACaBot report \(7d\): hot week/);
  assert.match(text, /43 high-confidence signals from 54 DKG events \(80%\)/);
  assert.match(text, /Top pattern: Impersonation \(34\)/);
  assert.match(text, /Actions: 5 bans, 0 reports, 15 scans/);
  assert.match(text, /DKG vault has receipts/);
  assert.match(text, /Source: DKG graph tracabot/);
  assert.doesNotMatch(text, /\{"fraud_finding"/);
});

test('formats stats source receipts without dumping raw JSON', () => {
  const text = formatStatsSourcesReply({
    graph: 'tracabot',
    sources: [{
      eventId: 'evt-123',
      eventType: 'report_submitted',
      created: '2026-04-30T21:44:00.000Z',
      confidence: 90
    }]
  });
  assert.match(text, /Stats sources from DKG graph tracabot/);
  assert.match(text, /Report Submitted 90% - evt-123 - 2026-04-30T21:44:00Z/);
  assert.doesNotMatch(text, /\{"eventId"/);
});

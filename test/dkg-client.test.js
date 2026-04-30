import test from 'node:test';
import assert from 'node:assert/strict';
import { DkgClient, extractPatterns, extractWallets } from '../src/dkg-client.js';

test('extracts wallet addresses and scam patterns for DKG lookups', () => {
  const text = 'URGENT official support says verify wallet 0x1111111111111111111111111111111111111111 to claim free USDT airdrop';
  assert.deepEqual(extractWallets(text), ['0x1111111111111111111111111111111111111111']);
  assert.deepEqual(extractPatterns(text), ['fake-airdrop', 'wallet-drain', 'impersonation', 'urgency-pressure']);
});

test('ignores report-only DKG evidence without independent local confidence', async () => {
  const dkg = new DkgClient({ contextGraph: 'test' });
  dkg.queryBindings = async () => [
    {
      g: 'did:dkg:context-graph:claw-shield-intel/_shared_memory',
      s: 'https://tracabot.org/ontology#event/weak',
      eventType: '"report_submitted"',
      confidence: '"100"',
      localConfidence: '"0"'
    },
    {
      g: 'did:dkg:context-graph:claw-shield-intel/_shared_memory',
      s: 'https://tracabot.org/ontology#event/strong',
      eventType: '"fraud_finding"',
      confidence: '"95"',
      localConfidence: '"80"'
    }
  ];
  const intel = await dkg.queryRiskIndicators({ username: 'BRX86' });
  assert.equal(intel.reportsAcrossCommunities, 1);
  assert.equal(intel.riskScore, 25);
  assert.deepEqual(intel.evidence.map((item) => item.eventId), ['strong']);
});

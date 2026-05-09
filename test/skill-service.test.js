import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { TracabotSkillService } from '../src/skill-service.js';
import { EventStore } from '../src/store.js';

const execFileAsync = promisify(execFile);

function makeService() {
  const dkgWrites = [];
  const service = new TracabotSkillService({
    config: { adminIds: new Set(['admin']), actionThreshold: 85, agentDid: 'did:dkg:agent:test' },
    analyzer: ({ text }) => ({ is_scam: /support|wallet/i.test(text), confidence: /support|wallet/i.test(text) ? 75 : 0, scam_type: /support|wallet/i.test(text) ? 'impersonation' : 'other', evidence: /support|wallet/i.test(text) ? ['support wallet lure'] : [], recommended_action: 'warn' }),
    dkg: {
      async queryRiskIndicators() { return { riskScore: 20, reportsAcrossCommunities: 1, wallets: [], domains: [], patterns: ['impersonation'], evidence: [{ eventId: 'prior', ual: 'did:dkg:context-graph:tracabot/_shared_memory' }] }; },
      async writeEvent(event) { dkgWrites.push(event); return { ual: 'did:dkg:context-graph:tracabot/_shared_memory', eventId: event.id }; }
    },
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-skill-')), 'events.jsonl'))
  });
  return { service, dkgWrites };
}

test('skill service scans targets with local and DKG evidence', async () => {
  const { service } = makeService();
  const result = await service.scanTarget({ telegramUserId: '8388593201', text: 'DM support to verify wallet' });
  assert.equal(result.tool, 'scan_target');
  assert.equal(result.target.id, '8388593201');
  assert.equal(result.risk.confidence, 75);
  assert.match(result.risk.evidence.join('\n'), /support wallet lure/);
  assert.equal(result.writesDkg, false);
});

test('skill service watchlist and digest stay local', () => {
  const { service } = makeService();
  service.store.append({ id: 'watch-a', event_type: 'watch_started', timestamp: new Date().toISOString(), user: { id: '1' }, payload: { watch_target_key: 'id:1', target: { id: '1' }, reason: 'admin watch' }, local_only: true });
  const watchlist = service.getWatchlist();
  const digest = service.getDigest();
  assert.equal(watchlist.watches.length, 1);
  assert.equal(digest.totalEvents, 1);
});

test('skill service appeal and review write DKG evidence', async () => {
  const { service, dkgWrites } = makeService();
  const appeal = await service.submitAppeal({ eventId: 'evt-1', reason: 'false positive', actorUsername: 'admin' });
  const review = await service.reviewEvent({ eventId: 'evt-1', decision: 'overturn', reason: 'appeal accepted', actorUsername: 'admin' });
  assert.equal(appeal.tool, 'submit_appeal');
  assert.equal(review.decision, 'overturned');
  assert.ok(dkgWrites.some((event) => event.event_type === 'appeal_submitted'));
  assert.ok(dkgWrites.some((event) => event.event_type === 'review_overturned'));
  assert.equal(dkgWrites.find((event) => event.event_type === 'review_overturned').payload.admin_verified, true);
});

test('skill service monitors unsafe chat events through DKG working memory', async () => {
  const { service, dkgWrites } = makeService();
  const result = await service.monitorChatEvent({ telegramUserId: '8388593201', username: 'fake_support', text: 'official support says verify wallet now', adminVerified: false });
  assert.equal(result.tool, 'monitor_chat_event');
  assert.equal(result.monitored, true);
  assert.equal(result.writesDkg, true);
  assert.equal(dkgWrites[0].event_type, 'unsafe_chat_event');
  assert.equal(dkgWrites[0].payload.publication_status, 'shared_memory');
});

test('skill service query_campaigns returns campaign roots and indicators', () => {
  const { service } = makeService();
  service.store.append({
    id: 'campaign-1',
    event_type: 'fraud_campaign',
    timestamp: new Date().toISOString(),
    payload: {
      campaign_key: 'domain:fake.example',
      related_event_ids: ['evt-a', 'evt-b'],
      evidence_root_ids: ['evt-a', 'evt-b'],
      affected_community_ids: ['-1001', '-1002'],
      campaign_event_count: 2,
      campaign_community_count: 2,
      domains: ['fake.example'],
      wallets: ['0x0000000000000000000000000000000000000001'],
      patterns: ['wallet-drain'],
      evidence: ['Campaign repeated across two communities']
    }
  });
  const result = service.queryCampaigns();
  assert.equal(result.campaigns[0].eventId, 'campaign-1');
  assert.deepEqual(result.campaigns[0].evidenceRootIds, ['evt-a', 'evt-b']);
  assert.deepEqual(result.campaigns[0].affectedCommunityIds, ['-1001', '-1002']);
  assert.equal(result.campaigns[0].eventCount, 2);
  assert.deepEqual(result.campaigns[0].domains, ['fake.example']);
  assert.deepEqual(result.campaigns[0].patterns, ['wallet-drain']);
});

test('tracabot-skill CLI returns JSON and rejects unknown tools', async () => {
  const env = {
    ...process.env,
    TELEGRAM_BOT_TOKEN: 'test',
    TRACABOT_STORE_PATH: join(mkdtempSync(join(tmpdir(), 'tracabot-cli-')), 'events.jsonl'),
    TRACABOT_DKG_MODE: 'openclaw-adapter',
    DKG_NODE_URL: 'http://127.0.0.1:9200'
  };
  const ok = await execFileAsync('node', ['./bin/tracabot-skill.js', 'get_digest', '{}'], { cwd: '/root/tracabot', env });
  const parsed = JSON.parse(ok.stdout);
  assert.equal(parsed.ok, true);
  await assert.rejects(() => execFileAsync('node', ['./bin/tracabot-skill.js', 'missing_tool', '{}'], { cwd: '/root/tracabot', env }), /Command failed/);
});

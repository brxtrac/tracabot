import test from 'node:test';
import assert from 'node:assert/strict';
import { DkgClient, extractDomains, extractPatterns, extractWallets } from '../src/dkg-client.js';

function makeAdapterClient({ publishError = null } = {}) {
  const calls = [];
  return {
    calls,
    async createContextGraph(id, name, description) {
      calls.push(['createContextGraph', id, name, description]);
      return { created: id, uri: `did:dkg:context-graph:${id}` };
    },
    async share(contextGraphId, quads, opts) {
      calls.push(['share', contextGraphId, quads, opts]);
      return {
        shareOperationId: 'swm-test',
        graph: `did:dkg:context-graph:${contextGraphId}/_shared_memory`,
        triplesWritten: quads.length
      };
    },
    async publishSharedMemory(contextGraphId, opts) {
      calls.push(['publishSharedMemory', contextGraphId, opts]);
      if (publishError) throw publishError;
      return { status: 'published', rootEntities: opts.rootEntities };
    },
    async query() {
      return { result: { bindings: [] } };
    }
  };
}

test('extracts wallet addresses and scam patterns for DKG lookups', () => {
  const text = 'URGENT official support says verify wallet 0x1111111111111111111111111111111111111111 to claim free USDT airdrop';
  assert.deepEqual(extractWallets(text), ['0x1111111111111111111111111111111111111111']);
  assert.deepEqual(extractPatterns(text), ['fake-airdrop', 'wallet-drain', 'impersonation', 'urgency-pressure']);
});

test('extracts canonical domains for DKG lookups', () => {
  const text = 'Claim at https://www.fake-claim.example/path or t.me/fakeclaim and fake-claim.example again';
  assert.deepEqual(extractDomains(text), ['fake-claim.example', 't.me']);
});

test('extracts investment partnership lure patterns for DKG lookups', () => {
  const text = 'Who can I discuss Institutional Investment Partnership with? serious VC partners interested in your project';
  assert.deepEqual(extractPatterns(text), ['investment-partnership-lure']);
});

test('ignores report-only DKG evidence without independent local confidence', async () => {
  const dkg = new DkgClient({ contextGraph: 'test' });
  dkg.queryBindings = async () => [
    {
      g: 'did:dkg:context-graph:test/_shared_memory',
      s: 'https://tracabot.org/ontology#event/weak',
      eventType: '"report_submitted"',
      confidence: '"100"',
      localConfidence: '"0"'
    },
    {
      g: 'did:dkg:context-graph:test/_shared_memory',
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

test('risk lookups ignore old graph and test command DKG evidence', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async () => [
    {
      g: 'did:dkg:context-graph:legacy-scam-intel/_shared_memory',
      s: 'https://tracabot.org/ontology#event/old',
      eventType: '"fraud_finding"',
      confidence: '"95"',
      localConfidence: '"90"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/demo',
      eventType: '"fraud_finding"',
      confidence: '"95"',
      localConfidence: '"90"',
      chatId: '"-100777"',
      username: '"scamadmin12345678"',
      testMode: '"true"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/real',
      eventType: '"fraud_finding"',
      confidence: '"95"',
      localConfidence: '"90"'
    }
  ];
  const intel = await dkg.queryRiskIndicators({ username: 'badactor' });
  assert.equal(intel.reportsAcrossCommunities, 1);
  assert.deepEqual(intel.evidence.map((item) => item.eventId), ['real']);
});

test('risk lookups use shared actor aliases and telegram ids across communities', async () => {
  const queries = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql) => {
    queries.push(sparql);
    return [
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        s: 'https://tracabot.org/ontology#event/by-id',
        eventType: 'ban_executed',
        confidence: '100',
        localConfidence: '0'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        s: 'https://tracabot.org/ontology#event/by-id',
        eventType: 'ban_executed',
        confidence: '100',
        localConfidence: '0'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        s: 'https://tracabot.org/ontology#event/by-alias',
        eventType: 'fraud_finding',
        confidence: '90',
        localConfidence: '75'
      }
    ];
  };
  const intel = await dkg.queryRiskIndicators({ username: 'new_handle', userId: 555, aliases: ['Old Fraud Name'] });
  assert.match(queries[0], /telegramUserId/);
  assert.match(queries[0], /actorAlias/);
  assert.equal(intel.reportsAcrossCommunities, 2);
  assert.deepEqual(intel.evidence.map((item) => item.eventId), ['by-id', 'by-alias']);
});

test('risk lookups use shared scam domains across communities', async () => {
  const queries = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql) => {
    queries.push(sparql);
    if (!sparql.includes('scamDomain')) return [];
    return [{
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/domain-hit',
      eventType: 'fraud_finding',
      confidence: '92',
      localConfidence: '80'
    }];
  };
  const intel = await dkg.queryRiskIndicators({ text: 'claim at https://fake-claim.example/path' });
  assert.ok(queries.some((query) => query.includes('scamDomain')));
  assert.equal(intel.riskScore, 20);
  assert.deepEqual(intel.domains, ['fake-claim.example']);
  assert.equal(intel.evidence[0].eventId, 'domain-hit');
});

test('auto-publishes high-confidence fraud findings to the context graph', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, {
    adapterClient
  });
  const result = await dkg.writeEvent({
    id: 'evt-auto',
    event_type: 'fraud_finding',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 92,
      local_confidence: 88,
      scam_type: 'impersonation',
      evidence: ['admin impersonation']
    }
  });
  assert.ok(result.publish);
  assert.ok(adapterClient.calls.some(([method, id, name]) => method === 'createContextGraph' && id === 'tracabot' && /TRACaBot/.test(name)));
  assert.ok(adapterClient.calls.some(([method, contextGraphId, opts]) => method === 'publishSharedMemory' && contextGraphId === 'tracabot' && opts.rootEntities.includes('https://tracabot.org/ontology#event/evt-auto')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#actorAlias') && triple.object === '"badactor"'));
});

test('writes scam domains as DKG indicators', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-domain',
    event_type: 'fraud_finding',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 92,
      local_confidence: 88,
      scam_type: 'phishing',
      domains: ['www.fake-claim.example'],
      evidence: ['scam domain']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#scamDomain') && triple.object === '"fake-claim.example"'));
});

test('writes structured evidence fields for moderation knowledge', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-structured',
    event_type: 'restrict_executed',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: '8388593201', username: 'badactor' },
    payload: {
      confidence: 78,
      local_confidence: 75,
      target_key: 'id:8388593201',
      target: { id: '8388593201', label: 'Kristian Baumgartner', sangmata: { oldName: 'QQQ', newName: 'Kristian Baumgartner' } },
      moderator: { id: '1', username: 'admin' },
      restricted_until: '2026-05-01T00:00:00.000Z',
      action_duration_seconds: 86400,
      evidence: ['SangMata rename alert: QQQ -> Kristian Baumgartner']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#targetTelegramUserId') && triple.object === '"8388593201"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#targetKey') && triple.object === '"id:8388593201"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#moderatorUsername') && triple.object === '"admin"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#restrictedUntil') && triple.object === '"2026-05-01T00:00:00.000Z"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#sangmataOldName') && triple.object === '"QQQ"'));
});

test('auto-publishes accepted high-confidence reports to the context graph', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, {
    adapterClient
  });
  const result = await dkg.writeEvent({
    id: 'evt-report-auto',
    event_type: 'report_submitted',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 80,
      local_confidence: 60,
      report_decision: 'accepted',
      scam_type: 'impersonation',
      evidence: ['replied scam report']
    }
  });
  assert.ok(result.publish);
  assert.ok(adapterClient.calls.some(([method, contextGraphId, opts]) => method === 'publishSharedMemory' && contextGraphId === 'tracabot' && opts.rootEntities.includes('https://tracabot.org/ontology#event/evt-report-auto')));
});

test('keeps shared-memory write result when automatic context graph publish fails', async () => {
  const adapterClient = makeAdapterClient({ publishError: new Error('publish command failed') });
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, {
    adapterClient
  });
  const result = await dkg.writeEvent({
    id: 'evt-pending',
    event_type: 'ban_executed',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 100,
      local_confidence: 0,
      scam_type: 'impersonation',
      evidence: ['manual ban']
    }
  });
  assert.equal(result.ual, 'did:dkg:context-graph:tracabot/_shared_memory');
  assert.match(result.publish_error, /publish command failed/);
});

test('stats count only production events from the configured DKG graph', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async () => [
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/real-ban',
      eventType: '"ban_executed"',
      created: '"2026-04-30T00:00:00.000Z"',
      confidence: '"95"',
      scamType: '"impersonation"',
      chatId: '"-100123"',
      username: '"badactor"'
    },
    {
      g: 'did:dkg:context-graph:legacy-scam-intel/_shared_memory',
      s: 'https://tracabot.org/ontology#event/old-ban',
      eventType: '"ban_executed"',
      created: '"2026-04-30T00:00:00.000Z"',
      confidence: '"95"',
      scamType: '"impersonation"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/demo-ban',
      eventType: '"ban_executed"',
      created: '"2026-04-30T00:00:00.000Z"',
      confidence: '"95"',
      scamType: '"impersonation"',
      chatId: '"-100777"',
      username: '"scamadmin12345678"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/test-report',
      eventType: '"report_submitted"',
      created: '"2026-04-30T00:00:00.000Z"',
      confidence: '"90"',
      scamType: '"impersonation"',
      eventSource: '"test-command-loop"',
      testMode: '"true"'
    }
  ];
  const stats = await dkg.getStats(7);
  assert.equal(stats.total, 1);
  assert.equal(stats.highConfidence, 1);
  assert.deepEqual(stats.byEventType, { ban_executed: 1 });
  assert.equal(stats.sources[0].eventId, 'real-ban');
});

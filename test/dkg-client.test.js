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
    async post(path, body) {
      calls.push(['post', path, body]);
      if (publishError) throw publishError;
      return { status: 'published', rootEntities: body.selection, publishContextGraphId: body.publishContextGraphId };
    },
    async query() {
      return { result: { bindings: [] } };
    },
    getAuthToken: null
  };
}

test('validates DKG UALs through adapter resolve or query', async () => {
  const resolving = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: { async resolve(ual) { return ual.includes('valid') ? { id: ual } : null; } } });
  assert.equal((await resolving.validateUal('did:dkg:valid-knowledge-asset')).ok, true);
  assert.equal((await resolving.validateUal('not-a-ual')).ok, false);
  const querying = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: { async query() { return { result: { bindings: [{ s: 'asset' }] } }; } } });
  assert.equal((await querying.validateUal('did:dkg:another-valid-asset')).ok, true);
});

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

test('writes structured DM impersonation report fields', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-dm-report',
    event_type: 'dm_scam_report',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'reporter', username: 'brx' },
    payload: {
      confidence: 90,
      local_confidence: 90,
      scam_type: 'dm_impersonation',
      reported_alias: 'Branimir Rakic',
      claimed_role: 'cto',
      claimed_organization: 'OriginTrail',
      dm_platform: 'telegram_dm',
      scam_request: 'connect wallet',
      screenshot_file_ids: ['tg-photo-id'],
      screenshot_caption: 'fake CTO DM asks to connect wallet',
      evidence: ['reported alias: Branimir Rakic']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#reportedAlias') && triple.object === '"Branimir Rakic"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#claimedRole') && triple.object === '"cto"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#scamRequest') && triple.object === '"connect wallet"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#screenshotFileId') && triple.object === '"tg-photo-id"'));
  assert.ok(result.triples.some((triple) => triple.predicate === 'rdf:type' && triple.object === 'http://dkg.io/ontology#KnowledgeAsset'));
});

test('writes unsafe chat event publication and review metadata', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-unsafe-meta',
    event_type: 'unsafe_chat_event',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 96,
      local_confidence: 90,
      scam_type: 'phishing',
      community_id: '-100123',
      community_name: 'Example DAO',
      community_type: 'telegram_group',
      policy_id: 'strict-v1',
      message_text: 'official support says verify wallet now',
      admin_verified: true,
      publication_status: 'context_graph_auto_publish_eligible',
      evidence: ['wallet verification lure'],
      domains: ['fake-claim.example'],
      patterns: ['wallet-drain'],
      urls: ['https://fake-claim.example/claim'],
      signals: ['admin verified screenshot']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#adminVerified') && triple.object === '"true"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#lifecycleStage') && triple.object === '"verified_memory"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#communityId') && triple.object === '"-100123"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#communityName') && triple.object === '"Example DAO"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#policyId') && triple.object === '"strict-v1"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#publicationStatus') && triple.object === '"context_graph_auto_publish_eligible"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#messageText') && /verify wallet/.test(triple.object)));
  assert.ok(result.triples.some((triple) => triple.predicate === 'rdf:type' && triple.object === 'http://dkg.io/ontology#KnowledgeAsset'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#hasEvidence')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#evidenceText') && /wallet verification/.test(triple.object)));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#observedDomain')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#observedPattern')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#suspiciousUrl') && /fake-claim/.test(triple.object)));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#detectionSignal') && /screenshot/.test(triple.object)));
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

test('publishes unsafe chat events only when admin verified or very high confidence', async () => {
  const sharedOnly = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: sharedOnly });
  await dkg.writeEvent({
    id: 'evt-unsafe-shared',
    event_type: 'unsafe_chat_event',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user' },
    payload: { confidence: 75, local_confidence: 70, scam_type: 'phishing', evidence: ['phishing lure'] }
  });
  assert.equal(sharedOnly.calls.some(([method]) => method === 'publishSharedMemory'), false);

  const verified = makeAdapterClient();
  const verifiedDkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: verified });
  await verifiedDkg.writeEvent({
    id: 'evt-unsafe-verified',
    event_type: 'unsafe_chat_event',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user' },
    payload: { confidence: 75, local_confidence: 70, admin_verified: true, scam_type: 'phishing', evidence: ['admin verified phishing lure'] }
  });
  assert.equal(verified.calls.some(([method]) => method === 'publishSharedMemory'), true);
});

test('uses configured on-chain context graph id for verified publish', async () => {
  const adapterClient = makeAdapterClient();
  adapterClient.getAuthToken = () => 'test-token';
  const dkg = new DkgClient({ contextGraph: 'tracabot', publishContextGraphId: '13' }, { adapterClient });
  await dkg.writeEvent({
    id: 'evt-on-chain-cg',
    event_type: 'unsafe_chat_event',
    targetUserId: '44',
    text: 'urgent wallet verification airdrop https://fake.example',
    confidence: 96,
    adminVerified: true,
    source: 'openclaw_monitor_chat_event',
    payload: { confidence: 96, local_confidence: 96, admin_verified: true },
    risk: { confidence: 96, local_confidence: 96, dkg_confidence: 0, scam_type: 'wallet-drain', evidence: [] }
  });
  const publishCall = adapterClient.calls.find(([method]) => method === 'post');
  assert.equal(publishCall[1], '/api/shared-memory/publish');
  assert.equal(publishCall[2].contextGraphId, 'tracabot');
  assert.equal(publishCall[2].publishContextGraphId, '13');
});

test('publishes campaign summaries with evidence roots', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'campaign-1',
    event_type: 'fraud_campaign',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: '-100123' },
    user: { id: 'system', username: 'tracabot' },
    payload: {
      confidence: 90,
      local_confidence: 85,
      scam_type: 'wallet-drain',
      campaign_key: 'domain:fake-claim.example',
      campaign_event_count: 2,
      campaign_community_count: 2,
      evidence_root_ids: ['evt-a', 'evt-b'],
      related_event_ids: ['evt-a', 'evt-b'],
      affected_community_ids: ['-1001', '-1002'],
      domains: ['fake-claim.example'],
      patterns: ['wallet-drain'],
      lifecycle_stage: 'campaign_summary',
      publication_status: 'context_graph_auto_publish_eligible',
      evidence: ['Campaign repeated across two communities']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate === 'rdf:type' && triple.object.endsWith('#FraudCampaign')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#lifecycleStage') && triple.object === '"campaign_summary"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#evidenceRootId') && triple.object === '"evt-a"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#evidenceRoot') && triple.object.endsWith('#event/evt-a')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#affectedCommunityId') && triple.object === '"-1002"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#campaignEventCount') && triple.object === '"2"'));
  assert.equal(adapterClient.calls.some(([method]) => method === 'publishSharedMemory'), true);
  const publishCall = adapterClient.calls.find(([method]) => method === 'publishSharedMemory');
  assert.equal(publishCall[1], 'tracabot');
  assert.deepEqual(publishCall[2].sharedMemoryResult, result.share);
  assert.equal(result.publish.status, 'published');
  assert.deepEqual(result.publish.rootEntities, ['https://tracabot.org/ontology#event/campaign-1']);
});

test('does not publish campaign summaries without two evidence roots', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'campaign-single-root',
    event_type: 'fraud_campaign',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: '-100123' },
    user: { id: 'system', username: 'tracabot' },
    payload: {
      confidence: 95,
      local_confidence: 90,
      campaign_key: 'domain:fake-claim.example',
      evidence_root_ids: ['evt-a'],
      related_event_ids: ['evt-a'],
      domains: ['fake-claim.example'],
      lifecycle_stage: 'campaign_summary',
      evidence: ['Only one evidence root']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#publicationStatus') && triple.object === '"shared_memory"'));
  assert.equal(adapterClient.calls.some(([method]) => method === 'publishSharedMemory'), false);
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
      created: new Date().toISOString(),
      confidence: '"95"',
      scamType: '"impersonation"',
      chatId: '"-100123"',
      username: '"badactor"'
    },
    {
      g: 'did:dkg:context-graph:legacy-scam-intel/_shared_memory',
      s: 'https://tracabot.org/ontology#event/old-ban',
      eventType: '"ban_executed"',
      created: new Date().toISOString(),
      confidence: '"95"',
      scamType: '"impersonation"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/demo-ban',
      eventType: '"ban_executed"',
      created: new Date().toISOString(),
      confidence: '"95"',
      scamType: '"impersonation"',
      chatId: '"-100777"',
      username: '"scamadmin12345678"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/test-report',
      eventType: '"report_submitted"',
      created: new Date().toISOString(),
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

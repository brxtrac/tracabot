import test from 'node:test';
import assert from 'node:assert/strict';
import { DkgClient as BaseDkgClient, extractDomains, extractPatterns, extractWallets } from '../src/dkg-client.js';

const TEST_PSEUDONYM_KEY = 'test-pseudonym-key-at-least-32-bytes';

class DkgClient extends BaseDkgClient {
  constructor(config, dependencies) {
    super({ dkgPseudonymKey: TEST_PSEUDONYM_KEY, ...config }, dependencies);
  }
}

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
    async createKnowledgeAsset(contextGraphId, name, opts) {
      calls.push(['createKnowledgeAsset', contextGraphId, name, opts]);
      return { assertionUri: `did:dkg:context-graph:${contextGraphId}/_wm/${name}`, shareOperationId: 'swm-test', graph: `did:dkg:context-graph:${contextGraphId}/_shared_memory`, triplesWritten: opts.quads.length };
    },
    async knowledgeAssetPublish(contextGraphId, name) {
      calls.push(['knowledgeAssetPublish', contextGraphId, name]);
      if (publishError) throw publishError;
      return { status: 'published', assertionName: name };
    },
    async query() {
      return { result: { bindings: [] } };
    },
    getAuthToken: null
  };
}

function makeFlakyShareAdapterClient({ failures = [], success = {} } = {}) {
  const calls = [];
  return {
    calls,
    async createContextGraph(id, name, description) {
      calls.push(['createContextGraph', id, name, description]);
      return { created: id, uri: `did:dkg:context-graph:${id}` };
    },
    async share(contextGraphId, quads, opts) {
      calls.push(['share', contextGraphId, quads, opts]);
      const failure = failures.shift();
      if (failure) throw failure;
      return {
        shareOperationId: 'swm-retry-test',
        graph: `did:dkg:context-graph:${contextGraphId}/_shared_memory`,
        triplesWritten: quads.length,
        ...success
      };
    },
    async createKnowledgeAsset(contextGraphId, name, opts) {
      calls.push(['createKnowledgeAsset', contextGraphId, name, opts]);
      const failure = failures.shift();
      if (failure) throw failure;
      return { assertionUri: `did:dkg:context-graph:${contextGraphId}/_wm/${name}`, shareOperationId: 'swm-retry-test', graph: `did:dkg:context-graph:${contextGraphId}/_shared_memory`, triplesWritten: opts.quads.length };
    },
    async knowledgeAssetPublish(contextGraphId, name) {
      calls.push(['knowledgeAssetPublish', contextGraphId, name]);
      return { status: 'published', assertionName: name };
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

test('DKG read and write kill switches fail closed', async () => {
  const disabledReads = new DkgClient({ contextGraph: 'tracabot', dkgReads: false }, { adapterClient: { async query() { throw new Error('query should not run'); } } });
  assert.deepEqual(await disabledReads.queryBindings('SELECT * WHERE { ?s ?p ?o }'), []);
  assert.deepEqual(await disabledReads.validateUal('did:dkg:valid-knowledge-asset'), { ok: false, reason: 'dkg_reads_disabled' });

  const disabledWrites = new DkgClient({ contextGraph: 'tracabot', dkgWrites: false }, { adapterClient: makeAdapterClient() });
  const result = await disabledWrites.writeEvent({ id: 'disabled', event_type: 'fraud_finding', timestamp: '2026-04-30T00:00:00.000Z', agentDid: 'did:dkg:agent:test', payload: { confidence: 90, local_confidence: 90 } });
  assert.equal(result.mode, 'dkg-disabled');
  assert.equal(result.eventId, 'disabled');
});

test('direct DKG writes require a strong pseudonym key', async () => {
  const dkg = new BaseDkgClient({ contextGraph: 'tracabot' }, { adapterClient: makeAdapterClient() });
  await assert.rejects(
    () => dkg.writeEvent({ id: 'missing-key', event_type: 'fraud_finding', payload: {} }),
    /TRACABOT_DKG_PSEUDONYM_KEY must be at least 32 bytes/
  );
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

test('extracts gambling promotion patterns from emoji-obfuscated offers', () => {
  const text = '🔤🔤 GAME is dropping 💲1️⃣0️⃣0️⃣ for all new players! Claim the bonus and bet now. Funds hit your wallet instantly.';
  assert.deepEqual(extractPatterns(text), ['gambling-promotion']);
});

test('extracts gambling promotion patterns from fullwidth campaign text', () => {
  const text = 'ＢＣ ＧＡＭＥ bonus for new players. Claim the bonus and get in now.';
  assert.deepEqual(extractPatterns(text), ['gambling-promotion']);
});

test('does not extract gambling promotion patterns from ordinary discussion', () => {
  const text = 'The group discussed casino regulation and betting odds during the community call.';
  assert.deepEqual(extractPatterns(text), []);
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
      localConfidence: '"80"',
      chatId: '"-1001"'
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
      localConfidence: '"90"',
      chatId: '"-1001"'
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
      localConfidence: '"90"',
      chatId: '"-1002"'
    }
  ];
  const intel = await dkg.queryRiskIndicators({ username: 'badactor' });
  assert.equal(intel.reportsAcrossCommunities, 1);
  assert.deepEqual(intel.evidence.map((item) => item.eventId), ['real']);
});

test('risk lookups prefer exact telegram identity over colliding aliases', async () => {
  const queries = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql) => {
    queries.push(sparql);
    if (sparql.includes('#actorIdentity')) return [
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        s: 'https://tracabot.org/ontology#event/by-id',
        eventType: 'ban_executed',
        confidence: '100',
        localConfidence: '0',
        chatId: '-1001'
      },
    ];
    return [{
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/by-colliding-alias',
      eventType: 'fraud_finding',
      confidence: '90',
      localConfidence: '75',
      chatId: '-1002'
    }];
  };
  const intel = await dkg.queryRiskIndicators({ username: 'new_handle', userId: 555, aliases: ['Old Fraud Name'] });
  assert.match(queries[0], /telegramUserId/);
  assert.match(queries[0], /actorIdentity/);
  assert.match(queries[0], /<http:\/\/purl\.org\/dc\/terms\/created>/);
  assert.doesNotMatch(queries[0], /dcterms:created/);
  assert.doesNotMatch(queries[0], /actorAlias/);
  assert.equal(queries.length, 1);
  assert.equal(intel.reportsAcrossCommunities, 1);
  assert.deepEqual(intel.evidence.map((item) => item.eventId), ['by-id']);
});

test('risk lookups fall back to HMAC aliases and legacy raw predicates', async () => {
  const queries = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot', dkgPseudonymKey: 'test-secret' });
  dkg.queryBindings = async (sparql) => {
    queries.push(sparql);
    return [{ g: 'did:dkg:context-graph:tracabot/_verifiable_memory', s: 'https://tracabot.org/ontology#event/legacy', eventType: 'fraud_finding', confidence: '90', localConfidence: '75', communityToken: 'community-one' }];
  };
  const intel = await dkg.queryActor({ username: 'Old Fraud Name' });
  assert.match(queries[0], /actorAliasToken/);
  assert.match(queries[0], /actorAlias/);
  assert.match(queries[0], /username/);
  assert.doesNotMatch(queries[0], /Old Fraud Name/);
  assert.equal(intel.reportsAcrossCommunities, 1);
  assert.equal(intel.evidence[0].eventId, 'legacy');
});

test('admin history escapes identifiers and ignores false-positive or non-production bindings', async () => {
  const queries = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql) => {
    queries.push(sparql);
    return [
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        s: 'https://tracabot.org/ontology#event/false-positive-safe',
        eventType: 'review_overturned',
        confidence: '100',
        adminVerified: 'true',
        tracBackedGlobalAuthority: 'true'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        s: 'https://tracabot.org/ontology#event/fake-admin-clear',
        eventType: 'review_overturned',
        confidence: '100',
        adminVerified: ''
      },
      {
        g: 'did:dkg:context-graph:legacy/_shared_memory',
        eventType: 'ban_executed',
        confidence: '100'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        eventType: 'ban_executed',
        confidence: '100',
        testMode: 'true'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory',
        eventType: 'review_upheld',
        confidence: '90'
      }
    ];
  };
  const history = await dkg.queryAdminHistoryForActor({ username: 'bad" } UNION { ?x ?y ?z } #' });
  assert.equal(history.hasPriorAdminAction, true);
  assert.equal(history.hasPriorFalsePositive, true);
  assert.deepEqual(history.events.map((event) => event.eventType), ['review_upheld']);
  assert.deepEqual(history.falsePositiveEvents.map((event) => event.eventId), ['false-positive-safe']);
  assert.match(queries[0], /"badunionxyz"/);
  assert.match(queries[0], /targetAliasToken/);
  assert.match(queries[0], /targetUsername/);
  assert.match(queries[0], /targetKey/);
  assert.doesNotMatch(queries[0], /UNION \{ \?x \?y \?z \}/);
});

test('campaign moderation roots accept VM and admin-verified SWM hard decisions only', async () => {
  const calls = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql, options = {}) => {
    calls.push({ sparql, options });
    if (options.view === 'verifiable-memory') return [
      {
        g: 'did:dkg:context-graph:tracabot/_verifiable_memory/1',
        s: 'https://tracabot.org/ontology#event/vm-ban',
        eventType: 'ban_executed',
        confidence: '91',
        campaignLabel: 'alias:bcgame'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_verifiable_memory/2',
        s: 'https://tracabot.org/ontology#event/test-ban',
        eventType: 'ban_executed',
        confidence: '99',
        campaignLabel: 'BC GAME',
        testMode: 'true'
      }
    ];
    return [
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory/3',
        s: 'https://tracabot.org/ontology#event/swm-upheld',
        eventType: 'review_upheld',
        confidence: '85',
        campaignLabel: 'Bc Game',
        adminVerified: 'true'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory/4',
        s: 'https://tracabot.org/ontology#event/swm-unverified',
        eventType: 'ban_executed',
        confidence: '95',
        campaignLabel: 'bcgame'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory/5',
        s: 'https://tracabot.org/ontology#event/report-only',
        eventType: 'report_submitted',
        confidence: '100',
        campaignLabel: 'bcgame',
        adminVerified: 'true'
      },
      {
        g: 'did:dkg:context-graph:tracabot/_shared_memory/6',
        s: 'https://tracabot.org/ontology#event/other-campaign',
        eventType: 'ban_executed',
        confidence: '95',
        campaignLabel: 'othergame',
        adminVerified: 'true'
      }
    ];
  };

  const result = await dkg.queryCampaignModerationRoots({ fingerprints: ['ＢＣ ＧＡＭＥ'] });

  assert.deepEqual(result.events.map((event) => event.eventId), ['vm-ban', 'swm-upheld']);
  assert.deepEqual(result.events.map((event) => event.trustLayer), ['verifiable_memory', 'admin_reviewed_shared_memory']);
  assert.deepEqual(calls.map((call) => call.options.view), ['verifiable-memory', 'shared-working-memory']);
  assert.ok(calls.every((call) => call.options.includeSharedMemory === false));
  assert.match(calls[0].sparql, /actorAlias/);
  assert.match(calls[0].sparql, /targetLabel/);
  assert.match(calls[0].sparql, /campaignKey/);
  assert.match(calls[0].sparql, /VALUES \?campaignFingerprint \{ "bcgame" \}/);
  assert.match(calls[0].sparql, /FILTER\(REPLACE\(REPLACE\(LCASE\(STR\(\?campaignLabel\)\)/);
  assert.doesNotMatch(calls[0].sparql, /<https:\/\/tracabot\.org\/ontology#evidence>/);
});

test('campaign moderation roots deduplicate event IDs across memory tiers', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (_sparql, options = {}) => [{
    g: `did:dkg:context-graph:tracabot/${options.view === 'verifiable-memory' ? '_verifiable_memory' : '_shared_memory'}/7`,
    s: 'https://tracabot.org/ontology#event/same-root',
    eventType: 'ban_executed',
    confidence: '90',
    campaignLabel: 'alias:bcgame',
    adminVerified: 'true'
  }];

  const result = await dkg.queryCampaignModerationRoots({ fingerprints: ['bcgame'] });

  assert.equal(result.events.length, 1);
  assert.equal(result.events[0].trustLayer, 'verifiable_memory');
});

test('context oracle prefers verified clear over older risk evidence', async () => {
  const calls = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql, options = {}) => {
    calls.push({ sparql, options });
    if (options.view === 'verifiable-memory') {
      return [{
        g: 'did:dkg:context-graph:tracabot/_verifiable_memory',
        s: 'https://tracabot.org/ontology#event/clear',
        eventType: 'review_overturned',
        confidence: '100',
        trustedGlobalClear: 'true',
        tracBackedGlobalAuthority: 'true'
      }];
    }
    return [{
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/risk',
      eventType: 'ban_executed',
      confidence: '95'
    }];
  };
  const result = await dkg.queryContextOracle({ username: 'safe_user' });
  assert.equal(result.verdict, 'verified_clear');
  assert.equal(result.trustLayer, 'verifiable_memory');
  assert.equal(result.evidence[0].eventId, 'clear');
  assert.deepEqual(calls.map((call) => call.options.view), ['verifiable-memory', 'shared-working-memory']);
});

test('context oracle returns shared warning for unverified SWM risk', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (_sparql, options = {}) => options.view === 'verifiable-memory' ? [] : [{
    g: 'did:dkg:context-graph:tracabot/_shared_memory',
    s: 'https://tracabot.org/ontology#event/swm-risk',
    eventType: 'dm_scam_report',
    confidence: '88',
    localConfidence: '82'
  }];
  const result = await dkg.queryContextOracle({ aliases: ['fake_helper'] });
  assert.equal(result.verdict, 'shared_warning');
  assert.equal(result.trustLayer, 'shared_memory');
  assert.equal(result.evidence[0].eventId, 'swm-risk');
});

test('risk lookups query verifiable memory and score one event only once across indicators', async () => {
  const calls = [];
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (sparql, options = {}) => {
    calls.push(options);
    return [{
      g: 'did:dkg:context-graph:tracabot/_verifiable_memory',
      s: 'https://tracabot.org/ontology#event/same-root',
      eventType: 'fraud_finding',
      confidence: '95',
      localConfidence: '90',
      chatId: '-1001'
    }];
  };
  const intel = await dkg.queryRiskIndicators({
    username: 'badactor',
    text: 'urgent wallet verify at fake.example 0x1111111111111111111111111111111111111111'
  });
  assert.equal(intel.riskScore, 25);
  assert.equal(intel.evidence.length, 1);
  assert.ok(calls.every((options) => options.view === 'verifiable-memory' && options.includeSharedMemory === false));
});

test('actor report count uses distinct communities rather than event count', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async () => [
    { g: 'did:dkg:context-graph:tracabot/_verifiable_memory', s: 'https://tracabot.org/ontology#event/one', eventType: 'ban_executed', confidence: '100', chatId: '-1001' },
    { g: 'did:dkg:context-graph:tracabot/_verifiable_memory', s: 'https://tracabot.org/ontology#event/two', eventType: 'ban_executed', confidence: '100', chatId: '-1001' },
    { g: 'did:dkg:context-graph:tracabot/_verifiable_memory', s: 'https://tracabot.org/ontology#event/three', eventType: 'ban_executed', confidence: '100', chatId: '-1002' }
  ];
  const intel = await dkg.queryActor({ userId: 42 });
  assert.equal(intel.reportsAcrossCommunities, 2);
  assert.equal(intel.evidence.length, 3);
});

test('context oracle uses newest verifiable decision for an actor', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async (_sparql, options = {}) => options.view === 'verifiable-memory' ? [
    {
      g: 'did:dkg:context-graph:tracabot/_verifiable_memory',
      s: 'https://tracabot.org/ontology#event/new-risk',
      eventType: 'review_upheld',
      confidence: '95',
      created: '2026-07-10T10:00:00.000Z'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_verifiable_memory',
      s: 'https://tracabot.org/ontology#event/old-clear',
      eventType: 'review_overturned',
      confidence: '100',
      tracBackedGlobalAuthority: 'true',
      created: '2026-07-09T10:00:00.000Z'
    }
  ] : [];
  const result = await dkg.queryContextOracle({ userId: 42 });
  assert.equal(result.verdict, 'verified_risk');
  assert.equal(result.evidence[0].eventId, 'new-risk');
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

test('DKG query timeouts fail fast and enter cooldown', async () => {
  let calls = 0;
  const dkg = new DkgClient({ contextGraph: 'tracabot', dkgQueryTimeoutMs: 10 }, {
    adapterClient: {
      async query() {
        calls += 1;
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { result: { bindings: [{ s: 'late' }] } };
      }
    }
  });
  const started = Date.now();
  assert.deepEqual(await dkg.queryBindings('SELECT * WHERE { ?s ?p ?o }'), []);
  assert.ok(Date.now() - started < 45);
  assert.deepEqual(await dkg.queryBindings('SELECT * WHERE { ?s ?p ?o }'), []);
  assert.equal(calls, 1);
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
  assert.ok(adapterClient.calls.some(([method, contextGraphId, name]) => method === 'knowledgeAssetPublish' && contextGraphId === 'tracabot' && name === 'tracabot-event-evt-auto'));
  assert.ok(adapterClient.calls.some(([method, contextGraphId, name, opts]) => method === 'createKnowledgeAsset' && contextGraphId === 'tracabot' && name === 'tracabot-event-evt-auto' && opts.alsoShareSwm === true));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#actorAliasToken') && triple.object.startsWith('"hmac:v1:')));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#actorAlias')), false);
});

test('verified-memory publish stays off unless explicitly enabled', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot', dkgPublishVerified: false }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-no-vm-by-default',
    event_type: 'fraud_finding',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    payload: { confidence: 99, local_confidence: 99, evidence: ['strong scam evidence'] }
  });
  assert.equal(result.publish, undefined);
  assert.equal(adapterClient.calls.some(([method]) => method === 'knowledgeAssetPublish'), false);
});

test('falls back to sealed working memory when SWM prerequisite is unavailable', async () => {
  const swmError = new Error('500: A promote prerequisite is temporarily unavailable');
  const adapterClient = makeFlakyShareAdapterClient({ failures: [swmError, swmError, swmError] });
  const dkg = new DkgClient({ contextGraph: 'tracabot', dkgPublishVerified: false }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-swm-down',
    event_type: 'fraud_finding',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    payload: { confidence: 99, local_confidence: 99, evidence: ['strong scam evidence'] }
  });

  const createCalls = adapterClient.calls.filter(([method]) => method === 'createKnowledgeAsset');
  assert.equal(createCalls.length, 4);
  assert.equal(createCalls.at(-1)[3].alsoShareSwm, false);
  assert.equal(result.swmDegraded, true);
  assert.match(result.output, /promote prerequisite/);
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
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#targetIdentity') && triple.object.startsWith('"hmac:v1:')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#moderatorIdentity') && triple.object.startsWith('"hmac:v1:')));
  assert.equal(result.triples.some((triple) => /#(?:targetTelegramUserId|targetKey|moderatorUsername)$/.test(triple.predicate)), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#restrictedUntil') && triple.object === '"2026-05-01T00:00:00.000Z"'));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#sangmataOldName')), false);
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
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#actorAliasToken') && triple.object.startsWith('"hmac:v1:')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#claimedRole') && triple.object === '"cto"'));
  assert.equal(result.triples.some((triple) => /#(?:reportedAlias|scamRequest|screenshotFileId)$/.test(triple.predicate)), false);
  assert.ok(result.triples.some((triple) => triple.predicate === 'rdf:type' && triple.object === 'http://dkg.io/ontology#KnowledgeAsset'));
});

test('writes structured appeal receipts and evidence references', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-appeal',
    event_type: 'appeal_submitted',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: '-100123' },
    user: { id: '42', username: 'appellant' },
    payload: {
      appeal_receipt_id: 'appeal-receipt-1',
      target_event_id: 'evt-flag',
      source_message_id: '77',
      provenance: 'telegram_appeal',
      screenshot_file_ids: ['photo-1'],
      evidence_urls: ['https://example.test/evidence'],
      reason: 'false positive',
      evidence: ['appeal evidence supplied']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#appealReceiptId') && triple.object === '"appeal-receipt-1"'));
  assert.equal(result.triples.some((triple) => /#(?:sourceMessageId|screenshotFileId|appealEvidenceUrl)$/.test(triple.predicate)), false);
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
      target_chat_id: '-100123',
      target_chat_title: 'Example DAO',
      target_chat_type: 'supergroup',
      source_message_id: 42,
      source_message_text_excerpt: 'official support says verify wallet now',
      detected_at: '2026-04-30T00:00:00.000Z',
      evidence_basis: 'prior_admin_action',
      prior_admin_action_id: 'evt-prior-ban',
      similarity_basis: 'same username and lure',
      urgent_admin_alert: true,
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
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#lifecycleStage') && triple.object === '"verified_memory_candidate"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#communityToken') && triple.object.startsWith('"hmac:v1:')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#policyId') && triple.object === '"strict-v1"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#publicationStatus') && triple.object === '"context_graph_auto_publish_eligible"'));
  assert.equal(result.triples.some((triple) => /#(?:communityId|communityName|messageText|targetChatId|targetChatTitle|sourceMessageId)$/.test(triple.predicate)), false);
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#sourceMessageTextExcerpt')), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#evidenceBasis') && triple.object === '"prior_admin_action"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#priorAdminActionId') && triple.object === '"evt-prior-ban"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#similarityBasis') && triple.object === '"same username and lure"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#urgentAdminAlert') && triple.object === '"true"'));
  assert.ok(result.triples.some((triple) => triple.predicate === 'rdf:type' && triple.object === 'http://dkg.io/ontology#KnowledgeAsset'));
  assert.equal(result.triples.some((triple) => /#(?:hasEvidence|evidenceText|evidenceIndex)$/.test(triple.predicate)), false);
  assert.equal(result.triples.some((triple) => triple.subject.includes('/evidence/')), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#observedDomain')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#observedPattern')));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#suspiciousUrl')), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#scamDomain') && /fake-claim/.test(triple.object)));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#detectionSignal') && /screenshot/.test(triple.object)));
});

test('writes channel observations to shared memory without verified publish', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-channel-observation',
    event_type: 'channel_observation',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: '-100123' },
    user: { id: 'user', username: 'promoter' },
    payload: {
      confidence: 92,
      local_confidence: 92,
      scam_type: 'investment_scam',
      observation_type: 'high_confidence_channel_message',
      message_id: 99,
      message_text: 'join alpha signals at https://t.me/fake_alpha',
      text_fingerprint: 'join alpha signals',
      domains: ['t.me'],
      patterns: ['investment-partnership-lure'],
      lifecycle_stage: 'shared_memory',
      publication_status: 'shared_memory',
      evidence: ['Investment-profit testimonial lure']
    }
  });
  assert.equal(adapterClient.calls.some(([method]) => method === 'knowledgeAssetPublish'), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#lifecycleStage') && triple.object === '"shared_memory"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#observationType') && triple.object === '"high_confidence_channel_message"'));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#messageText')), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#textFingerprint') && triple.object === '"join alpha signals"'));
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
  assert.ok(adapterClient.calls.some(([method, contextGraphId, name]) => method === 'knowledgeAssetPublish' && contextGraphId === 'tracabot' && name === 'tracabot-event-evt-report-auto'));
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
  assert.equal(sharedOnly.calls.some(([method]) => method === 'knowledgeAssetPublish'), false);

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
  assert.equal(verified.calls.some(([method]) => method === 'knowledgeAssetPublish'), true);
});

test('review decisions require explicit admin verification before verified publish', async () => {
  const unverifiedUpheld = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: unverifiedUpheld });
  await dkg.writeEvent({
    id: 'evt-review-unverified',
    event_type: 'review_upheld',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user' },
    payload: { review_decision: 'confirm', confidence: 90, evidence: ['admin text without explicit verification flag'] }
  });
  assert.equal(unverifiedUpheld.calls.some(([method]) => method === 'knowledgeAssetPublish'), false);

  const verifiedUpheld = makeAdapterClient();
  const verifiedDkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: verifiedUpheld });
  await verifiedDkg.writeEvent({
    id: 'evt-review-verified',
    event_type: 'review_upheld',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user' },
    payload: { review_decision: 'confirm', admin_verified: true, confidence: 90, evidence: ['explicit admin verification'] }
  });
  assert.equal(verifiedUpheld.calls.some(([method]) => method === 'knowledgeAssetPublish'), true);

  const falsePositive = makeAdapterClient();
  const falsePositiveDkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient: falsePositive });
  await falsePositiveDkg.writeEvent({
    id: 'evt-review-false-positive',
    event_type: 'review_overturned',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'user' },
    payload: { review_decision: 'reject', admin_verified: true, publish_false_positive: true, trac_backed_global_authority: true, confidence: 90, evidence: ['false positive correction'] }
  });
  assert.equal(falsePositive.calls.some(([method]) => method === 'knowledgeAssetPublish'), true);
});

test('review-overturned events write reviewed target identity for global admin clears', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-reviewed-target-clear',
    event_type: 'review_overturned',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: '1', username: 'trustedadmin' },
    payload: {
      review_decision: 'reject',
      admin_verified: true,
      trac_backed_global_authority: true,
      verified_memory_authority: true,
      decision_scope: 'global_verified_memory',
      target_chat_id: '-100123',
      target_chat_title: 'Example DAO',
      target_chat_type: 'supergroup',
      review_chat_id: '-100123',
      review_chat_title: 'Example DAO',
      review_scope: 'same_channel',
      review_jurisdiction: 'local_channel',
      review_weight: 1,
      decision_threshold: 1,
      resolves_target_pending_reviews: true,
      trust_basis: 'bot_owner_verified_memory_trac',
      confidence: 100,
      reviewed_target: { id: '4242', username: 'safeuser', first_name: 'Safe' },
      reviewed_target_key: 'id:4242',
      evidence: ['trusted admin cleared false positive']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#actorIdentity') && triple.object.startsWith('"hmac:v1:')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#targetIdentity') && triple.object.startsWith('"hmac:v1:')));
  assert.equal(result.triples.some((triple) => /#(?:telegramUserId|targetTelegramUserId|targetUsername|targetKey)$/.test(triple.predicate)), false);
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#trustedGlobalClear') && triple.object === '"true"'), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#decisionScope') && triple.object === '"global_verified_memory_candidate"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#trustBasis') && triple.object === '"bot_owner_verified_memory_candidate"'));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#reviewChatId')), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#reviewScope') && triple.object === '"same_channel"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#reviewJurisdiction') && triple.object === '"local_channel"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#reviewWeight') && triple.object === '"1"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#decisionThreshold') && triple.object === '"1"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#resolvesTargetPendingReviews') && triple.object === '"true"'));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#tracBackedGlobalAuthority') && triple.object === '"true"'), false);
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#verifiedMemoryAuthority') && triple.object === '"true"'), false);
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#adminVerified') && triple.object === '"true"'), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#verifiedMemoryCandidate') && triple.object === '"true"'));
});

test('local admin false-positive reviews are not global clears without TRAC-backed authority', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-local-clear',
    event_type: 'review_overturned',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: '2', username: 'localadmin' },
    payload: {
      review_decision: 'reject',
      local_admin_verified: true,
      admin_verified: false,
      decision_scope: 'local_community',
      trust_basis: 'telegram_local_admin',
      reviewed_target: { id: '4242', username: 'safeuser' },
      reviewed_target_key: 'id:4242',
      evidence: ['local admin cleared in one community']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#localAdminVerified') && triple.object === '"true"'));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#decisionScope') && triple.object === '"local_community"'));
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#trustedGlobalClear') && triple.object === '"true"'), false);
});

test('publishes verified events through their named Knowledge Asset', async () => {
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
  const publishCall = adapterClient.calls.find(([method]) => method === 'knowledgeAssetPublish');
  assert.equal(publishCall[1], 'tracabot');
  assert.equal(publishCall[2], 'tracabot-event-evt-on-chain-cg');
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
  assert.equal(result.triples.some((triple) => triple.predicate.endsWith('#affectedCommunityId')), false);
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#affectedCommunityToken') && triple.object.startsWith('"hmac:v1:')));
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#campaignEventCount') && triple.object === '"2"'));
  assert.equal(adapterClient.calls.some(([method]) => method === 'knowledgeAssetPublish'), true);
  const publishCall = adapterClient.calls.find(([method]) => method === 'knowledgeAssetPublish');
  assert.equal(publishCall[1], 'tracabot');
  assert.equal(publishCall[2], 'tracabot-event-campaign-1');
  assert.equal(result.publish.status, 'published');
  assert.equal(result.publish.assertionName, 'tracabot-event-campaign-1');
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
  assert.equal(adapterClient.calls.some(([method]) => method === 'knowledgeAssetPublish'), false);
});

test('retries transient DKG assertion lifecycle failures', async () => {
  const adapterClient = makeFlakyShareAdapterClient({ failures: [new Error('fetch failed')] });
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-retry',
    event_type: 'fraud_finding',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: '-100123' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 70,
      local_confidence: 65,
      scam_type: 'phishing',
      evidence: ['transient DKG failure should be retried']
    }
  });
  assert.equal(result.shareOperation, 'swm-retry-test');
  assert.equal(adapterClient.calls.filter(([method]) => method === 'createKnowledgeAsset').length, 2);
});

test('does not retry non-transient DKG assertion lifecycle failures', async () => {
  const adapterClient = makeFlakyShareAdapterClient({ failures: [new Error('invalid RDF payload')] });
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  await assert.rejects(() => dkg.writeEvent({
    id: 'evt-no-retry',
    event_type: 'fraud_finding',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: '-100123' },
    user: { id: 'user', username: 'badactor' },
    payload: {
      confidence: 70,
      local_confidence: 65,
      scam_type: 'phishing',
      evidence: ['non-transient error should not retry']
    }
  }), /invalid RDF payload/);
  assert.equal(adapterClient.calls.filter(([method]) => method === 'createKnowledgeAsset').length, 1);
});

test('retries transient verified-memory publish failures', async () => {
  const adapterClient = makeAdapterClient();
  let attempts = 0;
  adapterClient.knowledgeAssetPublish = async (contextGraphId, name) => {
    adapterClient.calls.push(['knowledgeAssetPublish', contextGraphId, name]);
    attempts += 1;
    if (attempts === 1) throw new Error('503 temporarily unavailable');
    return { status: 'published', assertionName: name };
  };
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.publishEvent('tracabot-event-retry', 'urn:event:retry');
  assert.equal(attempts, 2);
  assert.equal(result.status, 'published');
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

test('DM scam reports publish reported aliases as reusable HMAC tokens', async () => {
  const adapterClient = makeAdapterClient();
  const dkg = new DkgClient({ contextGraph: 'tracabot' }, { adapterClient });
  const result = await dkg.writeEvent({
    id: 'evt-dm-alias',
    event_type: 'dm_scam_report',
    timestamp: '2026-04-30T00:00:00.000Z',
    agentDid: 'did:dkg:agent:test',
    chat: { id: 'chat' },
    user: { id: 'reporter', username: 'reporter' },
    payload: {
      confidence: 86,
      local_confidence: 82,
      reported_alias: 'fake_helper',
      scam_type: 'dm_impersonation',
      report_decision: 'accepted',
      evidence: ['fake_helper asked for wallet validation in DM']
    }
  });
  assert.ok(result.triples.some((triple) => triple.predicate.endsWith('#actorAliasToken') && triple.object.startsWith('"hmac:v1:')));
  assert.equal(result.triples.some((triple) => /#(?:actorAlias|reportedAlias)$/.test(triple.predicate)), false);
});

test('risk lookups reuse credible DM scam reports by reported alias', async () => {
  const dkg = new DkgClient({ contextGraph: 'tracabot' });
  dkg.queryBindings = async () => [
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/dm-credible',
      eventType: '"dm_scam_report"',
      confidence: '"88"',
      localConfidence: '"82"',
      chatId: '"-1001"',
      evidence: '"accepted DM impersonation report"'
    },
    {
      g: 'did:dkg:context-graph:tracabot/_shared_memory',
      s: 'https://tracabot.org/ontology#event/dm-weak',
      eventType: '"dm_scam_report"',
      confidence: '"70"',
      localConfidence: '"65"',
      evidence: '"weak DM report"'
    }
  ];
  const intel = await dkg.queryRiskIndicators({ aliases: ['fake_helper'] });
  assert.equal(intel.reportsAcrossCommunities, 1);
  assert.equal(intel.riskScore, 25);
  assert.equal(intel.evidence[0].eventId, 'dm-credible');
  assert.equal(intel.evidence[0].eventType, 'dm_scam_report');
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

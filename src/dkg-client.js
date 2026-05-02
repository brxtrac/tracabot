import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const NS = 'https://tracabot.org/ontology#';
const MAX_EVIDENCE_ITEMS = 12;
const MAX_EVIDENCE_LENGTH = 500;
const MAX_INDICATORS = 20;
const ADAPTER_PACKAGE = '@origintrail-official/dkg-adapter-openclaw';
const ADAPTER_PATHS = [
  '/usr/lib/node_modules/@origintrail-official/dkg/node_modules/@origintrail-official/dkg-adapter-openclaw/dist/index.js',
  '/usr/lib/node_modules/@origintrail-official/dkg-adapter-openclaw/dist/index.js'
];

function literal(value) {
  return JSON.stringify(String(value));
}

function cleanValue(value = '') {
  return String(value).replace(/^"/, '').replace(/"$/, '');
}

function numeric(value = '') {
  const match = cleanValue(value).match(/\d+/);
  return match ? Number(match[0]) : 0;
}

function eventIdFromSource(source = '') {
  return cleanValue(source).split('/').pop() || '';
}

function actorAliases(user = {}) {
  return [
    user.username,
    user.first_name,
    [user.first_name, user.last_name].filter(Boolean).join(' ')
  ]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase().replace(/^@/, '').replace(/[^\p{L}\p{N}_-]/gu, ''))
    .filter(Boolean);
}

function normalizeDomain(value = '') {
  const domain = String(value).toLowerCase().replace(/^www\./, '').replace(/[^a-z0-9.-]/g, '');
  if (!domain.includes('.') || domain.length > 253) return '';
  return domain;
}

function boundedList(values = [], limit = MAX_INDICATORS, itemLength = 160) {
  return values
    .filter((value) => value !== null && value !== undefined)
    .slice(0, limit)
    .map((value) => String(value).slice(0, itemLength));
}

function parseWriteOutput(output = '') {
  const shareOperation = output.match(/Share operation:\s*(\S+)/)?.[1] || output.match(/"shareOperationId":\s*"([^"]+)"/)?.[1] || '';
  const graph = output.match(/Graph:\s*(\S+)/)?.[1] || output.match(/"graph":\s*"([^"]+)"/)?.[1] || '';
  return {
    shareOperation,
    graph,
    ual: graph || ''
  };
}

function isCredibleRiskBinding(binding = {}) {
  const eventType = cleanValue(binding.eventType || '');
  const confidence = numeric(binding.confidence || '0');
  const localConfidence = numeric(binding.localConfidence || '0');
  if (eventType === 'ban_executed') return confidence >= 80;
  if (['fraud_finding', 'report_submitted'].includes(eventType)) return confidence >= 80 && localConfidence >= 60;
  return false;
}

function graphBelongsToContext(binding = {}, contextGraph = '') {
  const graph = cleanValue(binding.g || '');
  const expected = `did:dkg:context-graph:${contextGraph}`;
  return graph === expected || graph === `${expected}/_shared_memory`;
}

function isTestStatsBinding(binding = {}) {
  const chatId = cleanValue(binding.chatId || '');
  const username = cleanValue(binding.username || '');
  const source = cleanValue(binding.eventSource || '');
  const testMode = cleanValue(binding.testMode || '');
  return testMode === 'true' || source === 'test-command-loop' || chatId === '-100777' || /^scamadmin\d+/i.test(username);
}

function isProductionBindingForContext(binding = {}, contextGraph = '') {
  return graphBelongsToContext(binding, contextGraph) && !isTestStatsBinding(binding);
}

function shouldAutoPublishEvent(event = {}) {
  const confidence = Number(event.payload?.confidence || 0);
  const localConfidence = Number(event.payload?.local_confidence || 0);
  if (event.event_type === 'ban_executed') return confidence >= 80;
  if (event.event_type === 'fraud_finding') return confidence >= 80 && localConfidence >= 60;
  if (event.event_type === 'report_submitted') return confidence >= 80 && localConfidence >= 60 && event.payload?.report_decision === 'accepted';
  return false;
}

async function loadOpenClawAdapter(config = {}) {
  const candidates = [
    config.openClawDkgAdapterPath,
    ADAPTER_PACKAGE,
    ...ADAPTER_PATHS
  ].filter(Boolean);
  const errors = [];
  for (const candidate of candidates) {
    try {
      if (candidate.startsWith('/') && !existsSync(candidate)) continue;
      const specifier = candidate.startsWith('/') ? pathToFileURL(candidate).href : candidate;
      return await import(specifier);
    } catch (error) {
      errors.push(`${candidate}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(`OpenClaw DKG adapter is not available. Install ${ADAPTER_PACKAGE} or set OPENCLAW_DKG_ADAPTER_PATH. ${errors.join(' | ')}`);
}

function eventTriples(event) {
  const subject = `${NS}event/${event.id}`;
  const evidence = boundedList(event.payload?.evidence || [], MAX_EVIDENCE_ITEMS, MAX_EVIDENCE_LENGTH);
  const status = shouldAutoPublishEvent(event) ? 'context_graph_auto_publish_eligible' : 'shared_memory';
  const triples = [
    { subject, predicate: 'rdf:type', object: `${NS}${event.event_type}` },
    { subject, predicate: `${NS}eventId`, object: literal(event.id) },
    { subject, predicate: `${NS}eventType`, object: literal(event.event_type) },
    { subject, predicate: 'dcterms:created', object: literal(event.timestamp) },
    { subject, predicate: 'dcterms:creator', object: literal(event.agentDid) },
    { subject, predicate: `${NS}telegramChatId`, object: literal(event.chat?.id || '') },
    { subject, predicate: `${NS}telegramUserId`, object: literal(event.user?.id || '') },
    { subject, predicate: `${NS}username`, object: literal(event.user?.username || '') },
    { subject, predicate: `${NS}reporterTelegramUserId`, object: literal(event.payload?.reporter?.id || '') },
    { subject, predicate: `${NS}reporterUsername`, object: literal(event.payload?.reporter?.username || '') },
    { subject, predicate: `${NS}reportDecision`, object: literal(event.payload?.report_decision || '') },
    { subject, predicate: `${NS}targetTelegramUserId`, object: literal(event.payload?.target?.id || event.payload?.target_user_id || event.user?.id || '') },
    { subject, predicate: `${NS}targetUsername`, object: literal(event.payload?.target?.username || event.user?.username || '') },
    { subject, predicate: `${NS}targetLabel`, object: literal(event.payload?.target?.label || event.payload?.target?.first_name || '') },
    { subject, predicate: `${NS}targetKey`, object: literal(event.payload?.target_key || event.payload?.watch_target_key || '') },
    { subject, predicate: `${NS}moderatorTelegramUserId`, object: literal(event.payload?.moderator?.id || event.payload?.reviewer?.id || '') },
    { subject, predicate: `${NS}moderatorUsername`, object: literal(event.payload?.moderator?.username || event.payload?.reviewer?.username || '') },
    { subject, predicate: `${NS}reviewDecision`, object: literal(event.payload?.review_decision || '') },
    { subject, predicate: `${NS}targetEventId`, object: literal(event.payload?.target_event_id || '') },
    { subject, predicate: `${NS}restrictedUntil`, object: literal(event.payload?.restricted_until || '') },
    { subject, predicate: `${NS}actionDurationSeconds`, object: literal(event.payload?.action_duration_seconds || '') },
    { subject, predicate: `${NS}campaignKey`, object: literal(event.payload?.campaign_key || '') },
    { subject, predicate: `${NS}sangmataOldName`, object: literal(event.payload?.target?.sangmata?.oldName || '') },
    { subject, predicate: `${NS}sangmataNewName`, object: literal(event.payload?.target?.sangmata?.newName || '') },
    { subject, predicate: `${NS}source`, object: literal(event.payload?.source || '') },
    { subject, predicate: `${NS}testMode`, object: literal(event.payload?.test_mode ? 'true' : '') },
    { subject, predicate: `${NS}confidence`, object: literal(event.payload?.confidence ?? '') },
    { subject, predicate: `${NS}localConfidence`, object: literal(event.payload?.local_confidence ?? '') },
    { subject, predicate: `${NS}dkgConfidence`, object: literal(event.payload?.dkg_confidence ?? '') },
    { subject, predicate: `${NS}scamType`, object: literal(event.payload?.scam_type || '') },
    { subject, predicate: `${NS}evidence`, object: literal(JSON.stringify(evidence)) },
    { subject, predicate: `${NS}status`, object: literal(event.payload?.publication_status || status) }
  ];
  if (['fraud_finding', 'ban_executed', 'report_submitted'].includes(event.event_type)) {
    triples.push({ subject, predicate: 'rdf:type', object: 'http://dkg.io/ontology#KnowledgeAsset' });
  }
  for (const alias of boundedList(actorAliases(event.user))) {
    triples.push({ subject, predicate: `${NS}actorAlias`, object: literal(alias) });
  }
  for (const wallet of boundedList(event.payload?.wallets || [])) {
    triples.push({ subject, predicate: `${NS}wallet`, object: literal(wallet) });
  }
  for (const domain of boundedList(event.payload?.domains || [])) {
    triples.push({ subject, predicate: `${NS}scamDomain`, object: literal(normalizeDomain(domain)) });
  }
  for (const pattern of boundedList(event.payload?.patterns || [])) {
    triples.push({ subject, predicate: `${NS}scamPattern`, object: literal(pattern) });
  }
  for (const relatedEventId of boundedList(event.payload?.related_event_ids || [])) {
    triples.push({ subject, predicate: `${NS}relatedEventId`, object: literal(relatedEventId) });
  }
  if (event.payload?.community_verified_flag) {
    triples.push({ subject, predicate: `${NS}communityVerifiedFlag`, object: literal(event.payload.community_verified_flag) });
  }
  return triples;
}

export class DkgClient {
  constructor(config, { adapterClient = null, adapterLoader = loadOpenClawAdapter } = {}) {
    this.config = config;
    this.contextReady = false;
    this.adapterClient = adapterClient;
    this.adapterLoader = adapterLoader;
  }

  async client() {
    if (this.adapterClient) return this.adapterClient;
    const { DkgDaemonClient } = await this.adapterLoader(this.config);
    this.adapterClient = new DkgDaemonClient({
      baseUrl: this.config.dkgNodeUrl,
      apiToken: this.config.dkgAuthToken,
      timeoutMs: this.config.telegramTimeoutMs || 30000
    });
    return this.adapterClient;
  }

  async ensureContextGraph() {
    if (this.contextReady) return;
    try {
      const client = await this.client();
      await client.createContextGraph(
        this.config.contextGraph,
        'TRACaBot Fraud Intelligence',
        'DKG v10 Shared Memory Context Graph for evidence-backed Telegram scam reports, findings, reviews, and moderation actions.'
      );
    } catch (error) {
      const output = error instanceof Error ? error.message : String(error);
      if (!/exists|already|duplicate/i.test(output)) throw error;
    }
    this.contextReady = true;
  }

  async writeEvent(event) {
    await this.ensureContextGraph();
    const triples = eventTriples(event);
    const client = await this.client();
    const write = await client.share(this.config.contextGraph, triples, { localOnly: false });
    const output = JSON.stringify(write);
    const subject = `${NS}event/${event.id}`;
    const result = {
      mode: 'openclaw-dkg-adapter',
      output,
      ...parseWriteOutput(output),
      shareOperation: write.shareOperationId || write.workspaceOperationId || '',
      graph: write.graph || `did:dkg:context-graph:${this.config.contextGraph}/_shared_memory`,
      ual: write.graph || `did:dkg:context-graph:${this.config.contextGraph}/_shared_memory`,
      subject,
      eventId: event.id,
      triples
    };
    if (!shouldAutoPublishEvent(event)) return result;
    try {
      result.publish = await this.publishEvent(subject);
    } catch (error) {
      result.publish_error = error instanceof Error ? error.message : String(error);
    }
    return result;
  }

  async publishEvent(subject) {
    const client = await this.client();
    const publish = await client.publishSharedMemory(this.config.contextGraph, {
      rootEntities: [subject],
      clearAfter: false
    });
    return { mode: 'openclaw-dkg-adapter-context-graph', output: JSON.stringify(publish), subject, ...publish };
  }

  async queryBindings(sparql) {
    try {
      const client = await this.client();
      const response = await client.query(sparql, {
        contextGraphId: this.config.contextGraph,
        includeSharedMemory: true
      });
      return response?.result?.bindings || response?.bindings || [];
    } catch (error) {
      console.error(`DKG query failed: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
  }

  async queryActor({ username = '', userId = '', aliases = [] } = {}) {
    const identifiers = [username, ...aliases]
      .filter(Boolean)
      .map((value) => String(value).toLowerCase().replace(/^@/, '').replace(/[^\p{L}\p{N}_-]/gu, ''));
    const clauses = [];
    for (const identifier of [...new Set(identifiers)]) {
      clauses.push(`{ ?s <${NS}username> ${literal(identifier)} . }`);
      clauses.push(`{ ?s <${NS}actorAlias> ${literal(identifier)} . }`);
    }
    if (userId) clauses.push(`{ ?s <${NS}telegramUserId> ${literal(userId)} . }`);
    if (!clauses.length) return { reportsAcrossCommunities: 0, evidence: [] };
    const sparql = `SELECT ?g ?s ?eventType ?type ?confidence ?localConfidence ?evidence ?chatId ?eventSource ?testMode WHERE { GRAPH ?g { ${clauses.join(' UNION ')} OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}scamType> ?type . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } OPTIONAL { ?s <${NS}telegramChatId> ?chatId . } OPTIONAL { ?s <${NS}source> ?eventSource . } OPTIONAL { ?s <${NS}testMode> ?testMode . } } } LIMIT 50`;
    const bindings = await this.queryBindings(sparql);
    const seen = new Set();
    const credible = bindings.filter((binding) => {
      const eventId = eventIdFromSource(binding.s);
      if (seen.has(eventId)) return false;
      if (!isProductionBindingForContext(binding, this.config.contextGraph) || !isCredibleRiskBinding(binding)) return false;
      seen.add(eventId);
      return true;
    });
    return {
      reportsAcrossCommunities: credible.length,
      evidence: credible.map((binding) => ({
        source: binding.s,
        eventId: eventIdFromSource(binding.s),
        ual: cleanValue(binding.g || ''),
        eventType: cleanValue(binding.eventType || ''),
        type: binding.type,
        confidence: binding.confidence,
        evidence: binding.evidence
      }))
    };
  }

  async queryRiskIndicators({ username = '', userId = '', aliases = [], text = '' } = {}) {
    const wallets = extractWallets(text);
    const domains = extractDomains(text);
    const patterns = extractPatterns(text);
    const actorIntel = await this.queryActor({ username, userId, aliases });
    const walletEvidence = [];
    for (const wallet of wallets) {
      const sparql = `SELECT ?g ?s ?eventType ?confidence ?localConfidence ?evidence ?chatId ?username ?eventSource ?testMode WHERE { GRAPH ?g { ?s <${NS}wallet> ${literal(wallet)} . OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } OPTIONAL { ?s <${NS}telegramChatId> ?chatId . } OPTIONAL { ?s <${NS}username> ?username . } OPTIONAL { ?s <${NS}source> ?eventSource . } OPTIONAL { ?s <${NS}testMode> ?testMode . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) walletEvidence.push({ wallet, ...binding, eventId: eventIdFromSource(binding.s), ual: cleanValue(binding.g || '') });
    }
    const patternEvidence = [];
    for (const pattern of patterns) {
      const sparql = `SELECT ?g ?s ?eventType ?confidence ?localConfidence ?evidence ?chatId ?username ?eventSource ?testMode WHERE { GRAPH ?g { ?s <${NS}scamPattern> ${literal(pattern)} . OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } OPTIONAL { ?s <${NS}telegramChatId> ?chatId . } OPTIONAL { ?s <${NS}username> ?username . } OPTIONAL { ?s <${NS}source> ?eventSource . } OPTIONAL { ?s <${NS}testMode> ?testMode . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) patternEvidence.push({ pattern, ...binding, eventId: eventIdFromSource(binding.s), ual: cleanValue(binding.g || '') });
    }
    const domainEvidence = [];
    for (const domain of domains) {
      const sparql = `SELECT ?g ?s ?eventType ?confidence ?localConfidence ?evidence ?chatId ?username ?eventSource ?testMode WHERE { GRAPH ?g { ?s <${NS}scamDomain> ${literal(domain)} . OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } OPTIONAL { ?s <${NS}telegramChatId> ?chatId . } OPTIONAL { ?s <${NS}username> ?username . } OPTIONAL { ?s <${NS}source> ?eventSource . } OPTIONAL { ?s <${NS}testMode> ?testMode . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) domainEvidence.push({ domain, ...binding, eventId: eventIdFromSource(binding.s), ual: cleanValue(binding.g || '') });
    }
    const credibleWalletEvidence = walletEvidence.filter((binding) => isProductionBindingForContext(binding, this.config.contextGraph) && isCredibleRiskBinding(binding));
    const crediblePatternEvidence = patternEvidence.filter((binding) => isProductionBindingForContext(binding, this.config.contextGraph) && isCredibleRiskBinding(binding));
    const credibleDomainEvidence = domainEvidence.filter((binding) => isProductionBindingForContext(binding, this.config.contextGraph) && isCredibleRiskBinding(binding));
    const riskScore = Math.min(100, actorIntel.reportsAcrossCommunities * 25 + credibleWalletEvidence.length * 25 + credibleDomainEvidence.length * 20 + crediblePatternEvidence.length * 10);
    return {
      riskScore,
      reportsAcrossCommunities: actorIntel.reportsAcrossCommunities,
      wallets,
      domains,
      patterns,
      evidence: [...actorIntel.evidence, ...credibleWalletEvidence, ...credibleDomainEvidence, ...crediblePatternEvidence]
    };
  }

  async getStats(days = 7, { includeSources = true } = {}) {
    const sparql = `SELECT ?g ?s ?eventType ?created ?confidence ?scamType ?chatId ?username ?eventSource ?testMode WHERE { GRAPH ?g { ?s <${NS}eventType> ?eventType . OPTIONAL { ?s <dcterms:created> ?created . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}scamType> ?scamType . } OPTIONAL { ?s <${NS}telegramChatId> ?chatId . } OPTIONAL { ?s <${NS}username> ?username . } OPTIONAL { ?s <${NS}source> ?eventSource . } OPTIONAL { ?s <${NS}testMode> ?testMode . } } } LIMIT 1000`;
    const bindings = await this.queryBindings(sparql);
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const production = bindings.filter((binding) => isProductionBindingForContext(binding, this.config.contextGraph));
    const recent = production.filter((binding) => {
      if (!binding.created) return true;
      const createdAt = Date.parse(cleanValue(binding.created));
      return Number.isNaN(createdAt) || createdAt >= cutoff;
    });
    const byEventType = {};
    const byRiskType = {};
    let highConfidence = 0;
    for (const binding of recent) {
      const eventType = cleanValue(binding.eventType || 'unknown');
      const scamType = cleanValue(binding.scamType || 'unknown');
      const confidence = numeric(binding.confidence || '0');
      byEventType[eventType] = (byEventType[eventType] || 0) + 1;
      byRiskType[scamType] = (byRiskType[scamType] || 0) + 1;
      if (confidence >= 80) highConfidence += 1;
    }
    return {
      source: 'dkg',
      graph: this.config.contextGraph,
      total: recent.length,
      highConfidence,
      byEventType,
      byRiskType,
      excluded: bindings.length - recent.length,
      sources: includeSources ? recent
        .slice()
        .sort((a, b) => Date.parse(cleanValue(b.created || '')) - Date.parse(cleanValue(a.created || '')))
        .slice(0, 8)
        .map((binding) => ({
          graph: cleanValue(binding.g || ''),
          eventId: eventIdFromSource(binding.s),
          eventType: cleanValue(binding.eventType || 'unknown'),
          created: cleanValue(binding.created || ''),
          confidence: numeric(binding.confidence || '0'),
          scamType: cleanValue(binding.scamType || 'unknown')
        })) : []
    };
  }
}

export function extractWallets(text = '') {
  const evm = text.match(/0x[a-fA-F0-9]{40}/g) || [];
  const btc = text.match(/\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g) || [];
  return [...new Set([...evm, ...btc])];
}

export function extractDomains(text = '') {
  const domains = [];
  const urlMatches = String(text).matchAll(/https?:\/\/([^\s/)]+)/gi);
  for (const match of urlMatches) {
    const domain = normalizeDomain(match[1].split(':')[0]);
    if (domain) domains.push(domain);
  }
  const telegramMatches = String(text).matchAll(/\bt\.me\/([A-Za-z0-9_+.-]+)/gi);
  for (const match of telegramMatches) {
    if (match[1]) domains.push('t.me');
  }
  const bareMatches = String(text).matchAll(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/\S*)?/gi);
  for (const match of bareMatches) {
    const domain = normalizeDomain(match[1]);
    if (domain && !domain.endsWith('.js')) domains.push(domain);
  }
  return [...new Set(domains)];
}

export function extractPatterns(text = '') {
  const lower = text.toLowerCase();
  const patterns = [];
  if (/airdrop|free\s+(usdt|eth|btc)|giveaway/.test(lower)) patterns.push('fake-airdrop');
  if (/seed phrase|private key|verify wallet|connect wallet/.test(lower)) patterns.push('wallet-drain');
  if (/admin|support|moderator|official/.test(lower)) patterns.push('impersonation');
  if (/institutional investment|investment partnership|\bvc\b|venture capital|serious investors?|serious partners?|collab(?:oration)?|partnership proposal/.test(lower)) patterns.push('investment-partnership-lure');
  if (/urgent|hurry|claim now|limited/.test(lower)) patterns.push('urgency-pressure');
  return [...new Set(patterns)];
}

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const NS = 'https://tracabot.org/ontology#';
const MAX_EVIDENCE_ITEMS = 12;
const MAX_EVIDENCE_LENGTH = 500;
const MAX_INDICATORS = 20;

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

function boundedList(values = [], limit = MAX_INDICATORS, itemLength = 160) {
  return values
    .filter((value) => value !== null && value !== undefined)
    .slice(0, limit)
    .map((value) => String(value).slice(0, itemLength));
}

function parseWriteOutput(output = '') {
  const shareOperation = output.match(/Share operation:\s*(\S+)/)?.[1] || '';
  const graph = output.match(/Graph:\s*(\S+)/)?.[1] || '';
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

function eventTriples(event) {
  const subject = `${NS}event/${event.id}`;
  const evidence = boundedList(event.payload?.evidence || [], MAX_EVIDENCE_ITEMS, MAX_EVIDENCE_LENGTH);
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
    { subject, predicate: `${NS}confidence`, object: literal(event.payload?.confidence ?? '') },
    { subject, predicate: `${NS}localConfidence`, object: literal(event.payload?.local_confidence ?? '') },
    { subject, predicate: `${NS}dkgConfidence`, object: literal(event.payload?.dkg_confidence ?? '') },
    { subject, predicate: `${NS}scamType`, object: literal(event.payload?.scam_type || '') },
    { subject, predicate: `${NS}evidence`, object: literal(JSON.stringify(evidence)) },
    { subject, predicate: `${NS}status`, object: literal('shared_memory') }
  ];
  if (['fraud_finding', 'ban_executed', 'report_submitted'].includes(event.event_type)) {
    triples.push({ subject, predicate: 'rdf:type', object: 'http://dkg.io/ontology#KnowledgeAsset' });
  }
  for (const wallet of boundedList(event.payload?.wallets || [])) {
    triples.push({ subject, predicate: `${NS}wallet`, object: literal(wallet) });
  }
  for (const pattern of boundedList(event.payload?.patterns || [])) {
    triples.push({ subject, predicate: `${NS}scamPattern`, object: literal(pattern) });
  }
  if (event.payload?.community_verified_flag) {
    triples.push({ subject, predicate: `${NS}communityVerifiedFlag`, object: literal(event.payload.community_verified_flag) });
  }
  return triples;
}

export class DkgClient {
  constructor(config) {
    this.config = config;
    this.contextReady = false;
  }

  async ensureContextGraph() {
    if (this.contextReady) return;
    try {
      await execFileAsync('dkg', [
        'context-graph',
        'create',
        this.config.contextGraph,
        '--name',
        'tracabot Shieldy Intelligence',
        '--description',
        'Working and Shared Memory Context Graph for Telegram scam reports.'
      ], { timeout: 30000 });
    } catch (error) {
      const output = `${error.stdout || ''}${error.stderr || ''}`;
      if (!/exists|already|duplicate/i.test(output)) throw error;
    }
    this.contextReady = true;
  }

  async writeEvent(event) {
    await this.ensureContextGraph();
    const triples = JSON.stringify(eventTriples(event));
    const { stdout } = await execFileAsync('dkg', [
      'shared-memory',
      'write',
      this.config.contextGraph,
      '--triples',
      triples
    ], { timeout: 30000, maxBuffer: 1024 * 1024 });
    const output = stdout.trim();
    return { mode: 'shared-memory', output, ...parseWriteOutput(output), subject: `${NS}event/${event.id}`, eventId: event.id, triples: eventTriples(event) };
  }

  async queryBindings(sparql) {
    try {
      const { stdout } = await execFileAsync('dkg', [
        'query',
        this.config.contextGraph,
        '--include-shared-memory',
        '-q',
        sparql
      ], { timeout: 20000, maxBuffer: 1024 * 1024 });
      const parsed = JSON.parse(stdout);
      return parsed.bindings || [];
    } catch (error) {
      console.error(`DKG query failed: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
  }

  async queryActor(username) {
    if (!username) return { reportsAcrossCommunities: 0, evidence: [] };
    const sparql = `SELECT ?g ?s ?eventType ?type ?confidence ?localConfidence ?evidence WHERE { GRAPH ?g { ?s <${NS}username> ${literal(username)} . OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}scamType> ?type . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } } } LIMIT 25`;
    const bindings = await this.queryBindings(sparql);
    const credible = bindings.filter(isCredibleRiskBinding);
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

  async queryRiskIndicators({ username = '', text = '' } = {}) {
    const wallets = extractWallets(text);
    const patterns = extractPatterns(text);
    const actorIntel = await this.queryActor(username);
    const walletEvidence = [];
    for (const wallet of wallets) {
      const sparql = `SELECT ?g ?s ?eventType ?confidence ?localConfidence ?evidence WHERE { GRAPH ?g { ?s <${NS}wallet> ${literal(wallet)} . OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) walletEvidence.push({ wallet, ...binding, eventId: eventIdFromSource(binding.s), ual: cleanValue(binding.g || '') });
    }
    const patternEvidence = [];
    for (const pattern of patterns) {
      const sparql = `SELECT ?g ?s ?eventType ?confidence ?localConfidence ?evidence WHERE { GRAPH ?g { ?s <${NS}scamPattern> ${literal(pattern)} . OPTIONAL { ?s <${NS}eventType> ?eventType . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}localConfidence> ?localConfidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) patternEvidence.push({ pattern, ...binding, eventId: eventIdFromSource(binding.s), ual: cleanValue(binding.g || '') });
    }
    const credibleWalletEvidence = walletEvidence.filter(isCredibleRiskBinding);
    const crediblePatternEvidence = patternEvidence.filter(isCredibleRiskBinding);
    const riskScore = Math.min(100, actorIntel.reportsAcrossCommunities * 25 + credibleWalletEvidence.length * 25 + crediblePatternEvidence.length * 10);
    return {
      riskScore,
      reportsAcrossCommunities: actorIntel.reportsAcrossCommunities,
      wallets,
      patterns,
      evidence: [...actorIntel.evidence, ...credibleWalletEvidence, ...crediblePatternEvidence]
    };
  }

  async getStats(days = 7) {
    const sparql = `SELECT ?s ?eventType ?created ?confidence ?scamType WHERE { GRAPH ?g { ?s <${NS}eventType> ?eventType . OPTIONAL { ?s <dcterms:created> ?created . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}scamType> ?scamType . } } } LIMIT 1000`;
    const bindings = await this.queryBindings(sparql);
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const recent = bindings.filter((binding) => {
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
      total: recent.length,
      highConfidence,
      byEventType,
      byRiskType
    };
  }
}

export function extractWallets(text = '') {
  const evm = text.match(/0x[a-fA-F0-9]{40}/g) || [];
  const btc = text.match(/\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g) || [];
  return [...new Set([...evm, ...btc])];
}

export function extractPatterns(text = '') {
  const lower = text.toLowerCase();
  const patterns = [];
  if (/airdrop|free\s+(usdt|eth|btc)|giveaway/.test(lower)) patterns.push('fake-airdrop');
  if (/seed phrase|private key|verify wallet|connect wallet/.test(lower)) patterns.push('wallet-drain');
  if (/admin|support|moderator|official/.test(lower)) patterns.push('impersonation');
  if (/urgent|hurry|claim now|limited/.test(lower)) patterns.push('urgency-pressure');
  return [...new Set(patterns)];
}

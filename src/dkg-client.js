import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const NS = 'https://tracabot.org/ontology#';

function literal(value) {
  return JSON.stringify(String(value));
}

function eventTriples(event) {
  const subject = `${NS}event/${event.id}`;
  const triples = [
    { subject, predicate: 'rdf:type', object: `${NS}${event.event_type}` },
    { subject, predicate: 'dcterms:created', object: literal(event.timestamp) },
    { subject, predicate: 'dcterms:creator', object: literal(event.agentDid) },
    { subject, predicate: `${NS}telegramChatId`, object: literal(event.chat?.id || '') },
    { subject, predicate: `${NS}telegramUserId`, object: literal(event.user?.id || '') },
    { subject, predicate: `${NS}username`, object: literal(event.user?.username || '') },
    { subject, predicate: `${NS}confidence`, object: literal(event.payload?.confidence ?? '') },
    { subject, predicate: `${NS}scamType`, object: literal(event.payload?.scam_type || '') },
    { subject, predicate: `${NS}evidence`, object: literal(JSON.stringify(event.payload?.evidence || [])) },
    { subject, predicate: `${NS}status`, object: literal('shared_memory') }
  ];
  if (['fraud_finding', 'ban_executed'].includes(event.event_type)) {
    triples.push({ subject, predicate: 'rdf:type', object: 'http://dkg.io/ontology#KnowledgeAsset' });
  }
  for (const wallet of event.payload?.wallets || []) {
    triples.push({ subject, predicate: `${NS}wallet`, object: literal(wallet) });
  }
  for (const pattern of event.payload?.patterns || []) {
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
    return { mode: 'shared-memory', output: stdout.trim(), triples: eventTriples(event) };
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
    } catch {
      return [];
    }
  }

  async queryActor(username) {
    if (!username) return { reportsAcrossCommunities: 0, evidence: [] };
    const sparql = `SELECT ?s ?type ?confidence ?evidence WHERE { GRAPH ?g { ?s <${NS}username> ${literal(username)} . OPTIONAL { ?s <${NS}scamType> ?type . } OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } } } LIMIT 10`;
    const bindings = await this.queryBindings(sparql);
    return {
      reportsAcrossCommunities: bindings.length,
      evidence: bindings.map((binding) => ({
        source: binding.s,
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
      const sparql = `SELECT ?s ?confidence ?evidence WHERE { GRAPH ?g { ?s <${NS}wallet> ${literal(wallet)} . OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) walletEvidence.push({ wallet, ...binding });
    }
    const patternEvidence = [];
    for (const pattern of patterns) {
      const sparql = `SELECT ?s ?confidence ?evidence WHERE { GRAPH ?g { ?s <${NS}scamPattern> ${literal(pattern)} . OPTIONAL { ?s <${NS}confidence> ?confidence . } OPTIONAL { ?s <${NS}evidence> ?evidence . } } } LIMIT 10`;
      const bindings = await this.queryBindings(sparql);
      for (const binding of bindings) patternEvidence.push({ pattern, ...binding });
    }
    const riskScore = Math.min(100, actorIntel.reportsAcrossCommunities * 20 + walletEvidence.length * 25 + patternEvidence.length * 10);
    return {
      riskScore,
      reportsAcrossCommunities: actorIntel.reportsAcrossCommunities,
      wallets,
      patterns,
      evidence: [...actorIntel.evidence, ...walletEvidence, ...patternEvidence]
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

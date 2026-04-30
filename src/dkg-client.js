import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const NS = 'https://tracabot.org/ontology#';

function literal(value) {
  return JSON.stringify(String(value));
}

function eventTriples(event) {
  const subject = `${NS}event/${event.id}`;
  return [
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

  async queryActor(username) {
    if (!username) return { reportsAcrossCommunities: 0 };
    const sparql = `SELECT (COUNT(?s) AS ?count) WHERE { GRAPH ?g { ?s <${NS}username> ${literal(username)} . } }`;
    try {
      const { stdout } = await execFileAsync('dkg', [
        'query',
        this.config.contextGraph,
        '--include-shared-memory',
        '-q',
        sparql
      ], { timeout: 20000, maxBuffer: 1024 * 1024 });
      const match = stdout.match(/"(\d+)"|\b(\d+)\b/);
      return { reportsAcrossCommunities: match ? Number(match[1] || match[2]) : 0 };
    } catch {
      return { reportsAcrossCommunities: 0 };
    }
  }
}

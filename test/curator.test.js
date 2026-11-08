import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { curateWorkingMemory, parseReview, reviewDraft, screenDraft } from '../src/curator.js';
import { DkgClient } from '../src/dkg-client.js';
import { artifactFromUpdate } from '../src/telegram-artifacts.js';
import { loadConfig } from '../src/config.js';
import { evaluateConfirmedCampaignBan } from '../src/risk-engine.js';

const text = 'Urgent: verify your wallet at https://fraud.example/claim to avoid account suspension';
const base = { quality: 85, confidence: 90, text, expires: '2099-01-01T00:00:00Z' };
const approval = { action: 'promote', category: 'fraud', reason: 'Message pressures target to connect wallet at suspicious verification site.', evidence: 'verify your wallet at https://fraud.example/claim' };

function successfulChild() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
  process.nextTick(() => {
    child.stdout.emit('data', Buffer.from(JSON.stringify({ type: 'text', part: { text: JSON.stringify(approval) } }) + '\n'));
    child.emit('close', 0);
  });
  return child;
}

test('default curator cleanup runs without an injected finishSession', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-cleanup-'));
  const path = process.env.PATH;
  const log = join(dir, 'cleanup.log');
  writeFileSync(join(dir, 'opencode'), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\n`, { mode: 0o755 });
  process.env.PATH = `${dir}:${path}`;
  try {
    const answer = await reviewDraft(base, { createSession: () => 'ses_test', runner: successfulChild });
    assert.equal(answer.action, 'promote');
    const calls = readFileSync(log, 'utf8');
    assert.match(calls, /api post \/api\/session\/ses_test\/interrupt/);
    assert.match(calls, /api patch \/api\/session\/ses_test/);
  } finally { process.env.PATH = path; rmSync(dir, { recursive: true, force: true }); }
});

test('cleanup exceptions reject reviews and release review reservations', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-cleanup-'));
  let cleanups = 0;
  const reviewer = (draft) => reviewDraft(draft, {
    createSession: () => 'ses_test', runner: successfulChild,
    finishSession: () => { cleanups++; throw new Error('cleanup unavailable'); }
  });
  try {
    await assert.rejects(reviewer(base), /cleanup unavailable/);
    const options = { dkg: { async pendingConversationArtifacts() { return [{ id: 'one', ...base }]; } },
      ledgerPath: join(dir, 'reviews.sqlite'), reviewer };
    const first = await curateWorkingMemory(options);
    assert.equal(first[0].action, 'error');
    assert.match(first[0].error, /cleanup unavailable/);
    const second = await curateWorkingMemory(options);
    assert.equal(second[0].action, 'retry_deferred');
    assert.equal(cleanups, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('child error followed by close rejects once and cleans up once', async () => {
  let cleanups = 0;
  await assert.rejects(reviewDraft(base, {
    createSession: () => 'ses_test', finishSession: () => { cleanups++; },
    runner: () => {
      const child = new EventEmitter();
      child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
      process.nextTick(() => { child.emit('error', new Error('spawn unavailable')); child.emit('close', -1); });
      return child;
    }
  }), /spawn unavailable/);
  assert.equal(cleanups, 1);
});

test('curator only promotes screened evidence after reasoned LLM approval; reuses cached review', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-curator-'));
  const calls = [];
  let reviews = 0;
  const dkg = {
    async pendingConversationArtifacts() { return [
      { id: 'strong', ...base }, { id: 'weak', ...base, quality: 40 },
      { id: 'old', ...base, expires: '2020-01-01T00:00:00Z' }
    ]; },
    async annotateConversationArtifact(id, review) { calls.push(['annotate', id, review.reason]); },
    async resolveConversationArtifact(id, options) { calls.push(['resolve', id, Boolean(options?.share)]); }
  };
  try {
    const opts = { dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'), now: Date.parse('2026-01-01'),
      reviewer: async () => { reviews++; return approval; } };
    const results = await curateWorkingMemory(opts);
    assert.deepEqual(results.map((item) => item.action), ['promote', 'discard_filtered', 'discard_expired']);
    assert.equal(reviews, 1);
    assert.deepEqual(calls.map((call) => call.slice(0, 2)), [['annotate', 'strong'], ['resolve', 'strong'], ['resolve', 'weak'], ['resolve', 'old']]);
    await curateWorkingMemory(opts);
    assert.equal(reviews, 1);
    assert.equal(calls.filter((call) => call[0] === 'annotate').length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('invalid or inconclusive response never shares; bounded LLM requests use medium reasoning', async () => {
  assert.equal(screenDraft({ ...base, text: 'hello' }), 'weak');
  assert.throws(() => parseReview('{"action":"promote"}'), /missing valid/);
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-curator-'));
  const calls = [];
  const dkg = {
    async pendingConversationArtifacts() { return [{ id: 'one', ...base }, { id: 'two', ...base }]; },
    async resolveConversationArtifact(...args) { calls.push(args); }
  };
  try {
    const result = await curateWorkingMemory({ dkg, ledgerPath: join(dir, 'reviews.sqlite'), maxReviews: 1,
      reviewer: async () => ({ ...approval, action: 'hold', category: 'insufficient' }) });
    assert.deepEqual(result.map((item) => item.action), ['hold', 'budget_deferred']);
    assert.deepEqual(calls, []);
    let invocation;
    const answer = await reviewDraft(base, { cwd: '/synthetic/tracabot', createSession: () => 'ses_synthetic', finishSession: () => {}, runner: (command, args, options) => {
      invocation = { command, args, options };
      const child = new EventEmitter();
      child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
      process.nextTick(() => {
        child.stdout.emit('data', Buffer.from(JSON.stringify({ type: 'text', part: { text: JSON.stringify(approval) } }) + '\n'));
        child.emit('close', 0);
      });
      return child;
    } });
    assert.equal(answer.action, 'promote');
    assert.equal(invocation.command, 'opencode');
    assert.equal(invocation.options.cwd, '/synthetic/tracabot');
    assert.deepEqual(invocation.args.slice(0, 9), ['run', '--session', 'ses_synthetic', '--agent', 'tracabot-curator', '--model', '9router/cx/gpt-6-sol#medium', '--format', 'json']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('LLM failure and fabricated evidence never promote; reviewed decisions do not spend tokens twice', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-curator-'));
  const actions = [];
  let reviews = 0;
  const dkg = {
    async pendingConversationArtifacts() { return [{ id: 'first', ...base }, { id: 'second', ...base }]; },
    async annotateConversationArtifact(id) { actions.push(`annotate:${id}`); },
    async resolveConversationArtifact(id) { actions.push(`share:${id}`); }
  };
  try {
    const opts = { dkg, ledgerPath: join(dir, 'reviews.sqlite'), reviewer: async (draft) => {
      reviews++;
      if (draft.id === 'first') throw new Error('unavailable');
      return { ...approval, evidence: 'evidence nowhere in source' };
    } };
    const first = await curateWorkingMemory(opts);
    assert.deepEqual(first.map((result) => result.action), ['error', 'error']);
    assert.deepEqual(actions, []);
    await curateWorkingMemory(opts);
    assert.equal(reviews, 2);
    assert.deepEqual(actions, []);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('transient DKG list failure retries then curates; persistent failure still throws', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-curator-'));
  let attempts = 0;
  const dkg = {
    async pendingConversationArtifacts() {
      attempts += 1;
      if (attempts === 1) throw new TypeError('fetch failed');
      return [];
    }
  };
  try {
    const results = await curateWorkingMemory({ dkg, ledgerPath: join(dir, 'reviews.sqlite') });
    assert.deepEqual(results, []);
    assert.equal(attempts, 2);
    const down = { pendingConversationArtifacts: async () => { throw new Error('DKG auth rejected'); } };
    await assert.rejects(curateWorkingMemory({ dkg: down, ledgerPath: join(dir, 'reviews.sqlite') }), /auth rejected/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('curator shares a sanitized projection instead of the raw Working Memory artifact', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-curator-sanitized-'));
  const rawText = 'support@example.com +1 555 123 4567 urgent verify wallet at https://evil.example/private/path?token=secret now';
  const evidence = 'verify wallet at https://evil.example/private/path?token=secret';
  let rawQuads = [];
  let sharedQuads = [];
  let discarded = false;
  const adapter = {
    async createContextGraph() { return { created: 'tracabot' }; },
    async createKnowledgeAsset(contextGraphId, name, options) {
      if (options.alsoShareSwm === true) sharedQuads = options.quads;
      else rawQuads = options.quads;
      return { graph: `did:dkg:context-graph:${contextGraphId}/_shared_memory`, shareOperationId: 'shared-1' };
    },
    async knowledgeAssetWrite() { return { ok: true }; },
    async knowledgeAssetDiscard() { discarded = true; return { ok: true }; },
    async query() {
      const stored = (predicate) => {
        const quad = rawQuads.find((item) => item.predicate.endsWith(predicate));
        return quad ? JSON.parse(quad.object) : '';
      };
      return { result: { bindings: [{
        s: 'https://tracabot.org/ontology#event/artifact-1',
        id: 'artifact-1', text: rawText, confidence: '90', quality: '85',
        consent: stored('#consentToShare'), privacy: stored('#privacyOptOut'),
        expires: '2099-01-01T00:00:00Z', scamType: 'impersonation', created: '2026-01-01T00:00:00.000Z'
      }] } };
    }
  };
  const dkg = new DkgClient({
    contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
    dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
  }, { adapterClient: adapter });
  try {
    await dkg.stageConversationArtifact({
      id: 'artifact-1', timestamp: '2026-01-01T00:00:00.000Z',
      chat: { id: -100 }, user: { id: 4242 },
      payload: {
        message_text: rawText, source_message_id: 'raw-message-id', community_id: '-100',
        confidence: 90, scam_type: 'impersonation', artifact_quality: 85,
        consent_to_share: true, expires_at: '2099-01-01T00:00:00Z'
      }
    });
    const results = await curateWorkingMemory({
      dkg,
      ledgerPath: join(dir, 'reviews.sqlite'),
      policyPath: join(dir, 'missing-policy.md'),
      reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence })
    });
    assert.deepEqual(results.map((item) => item.action), ['promote']);
    const rawPredicates = rawQuads.map((quad) => quad.predicate);
    assert.ok(rawPredicates.some((predicate) => predicate.endsWith('#messageText')));
    const sharedPredicates = sharedQuads.map((quad) => quad.predicate);
    assert.ok(sharedPredicates.some((predicate) => predicate.endsWith('#scamDomain')));
    assert.ok(sharedPredicates.some((predicate) => predicate.endsWith('#scamPattern')));
    assert.ok(sharedPredicates.some((predicate) => predicate.endsWith('#claimLevel')));
    assert.ok(sharedPredicates.some((predicate) => predicate.endsWith('#curatorDecision')));
    for (const forbidden of ['#messageText', '#sourceMessageId', '#telegramChatId', '#actorIdentity', '#communityId', '#curatorReason', '#curatorEvidence']) {
      assert.equal(sharedPredicates.some((predicate) => predicate.endsWith(forbidden)), false, forbidden);
    }
    const shared = JSON.stringify(sharedQuads);
    assert.doesNotMatch(shared, /support@example\.com|\+1 555|raw-message-id|private\/path|token=secret/);
    assert.match(shared, /evil\.example/);
    assert.match(shared, /wallet-drain/);
    assert.match(shared, /impersonation/);
    assert.doesNotMatch(shared, /example\.com/);
    assert.equal(discarded, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('staged WM denial or missing consent blocks sharing after a real stage/query roundtrip', async () => {
  for (const payload of [{ consent_to_share: false }, { privacy_opt_out: true }, {}]) {
    const dir = mkdtempSync(join(tmpdir(), 'tracabot-curator-denied-'));
    const rawText = 'urgent verify wallet at https://evil.example/private/path?token=secret now';
    const evidence = 'verify wallet at https://evil.example/private/path?token=secret';
    let rawQuads = [];
    let sharedWrites = 0;
    const adapter = {
      async createContextGraph() { return { created: 'tracabot' }; },
      async createKnowledgeAsset(contextGraphId, name, options) {
        if (options.alsoShareSwm === true) { sharedWrites += 1; return { graph: 'did:dkg:context-graph:tracabot/_shared_memory' }; }
        rawQuads = options.quads;
        return { graph: `did:dkg:context-graph:${contextGraphId}/_working_memory` };
      },
      async knowledgeAssetWrite() { return { ok: true }; },
      async knowledgeAssetDiscard() { return { ok: true }; },
      async query() {
        const stored = (predicate) => {
          const quad = rawQuads.find((item) => item.predicate.endsWith(predicate));
          return quad ? JSON.parse(quad.object) : '';
        };
        return { result: { bindings: [{
          s: 'https://tracabot.org/ontology#event/artifact-1',
          id: 'artifact-1', text: rawText, confidence: '90', quality: '85',
          consent: stored('#consentToShare'), privacy: stored('#privacyOptOut'),
          expires: '2099-01-01T00:00:00Z', scamType: 'impersonation', created: '2026-01-01T00:00:00.000Z'
        }] } };
      }
    };
    const dkg = new DkgClient({
      contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
      dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
    }, { adapterClient: adapter });
    try {
      await dkg.stageConversationArtifact({
        id: 'artifact-1', timestamp: '2026-01-01T00:00:00.000Z',
        chat: { id: -100 }, user: { id: 4242 },
        payload: { message_text: rawText, confidence: 90, scam_type: 'impersonation', artifact_quality: 85, ...payload }
      });
      const results = await curateWorkingMemory({
        dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'),
        reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence })
      });
      assert.equal(results[0].action, 'error');
      assert.match(results[0].error, payload.consent_to_share === false || payload.privacy_opt_out === true
        ? /privacy denial/
        : /no explicit sharing consent/);
      assert.equal(sharedWrites, 0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test('conflicting artifact binding rows are aggregated before review and denial dominates', async () => {
  const run = async (rows) => {
    const dir = mkdtempSync(join(tmpdir(), 'tracabot-aggregate-'));
    let sharedWrites = 0;
    const adapter = {
      async createKnowledgeAsset(contextGraphId, name, options) {
        if (options.alsoShareSwm === true) { sharedWrites += 1; return { graph: 'did:dkg:context-graph:tracabot/_shared_memory' }; }
        return { graph: `did:dkg:context-graph:${contextGraphId}/_working_memory` };
      },
      async knowledgeAssetWrite() { return { ok: true }; },
      async knowledgeAssetDiscard() { return { ok: true }; },
      async query() { return { result: { bindings: rows } }; }
    };
    const dkg = new DkgClient({
      contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
      dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
    }, { adapterClient: adapter });
    try {
      const results = await curateWorkingMemory({
        dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'),
        reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence: 'verify your wallet at https://evil.example/claim' })
      });
      return { results, sharedWrites };
    } finally { rmSync(dir, { recursive: true, force: true }); }
  };
  const row = (overrides = {}) => ({
    s: 'https://tracabot.org/ontology#event/artifact-agg',
    id: 'artifact-agg',
    text: 'urgent verify your wallet at https://evil.example/claim now',
    confidence: '90', quality: '85', expires: '2099-01-01T00:00:00Z',
    chat: 'hmac:chat', user: 'hmac:user', scamType: 'impersonation', created: '2026-01-01T00:00:00.000Z',
    consent: 'true', privacy: 'false',
    ...overrides
  });

  for (const rows of [
    [row(), row({ consent: 'false' })],
    [row({ consent: 'false' }), row()],
    [row(), row({ privacy: 'true' })],
    [row({ privacy: 'true' }), row()]
  ]) {
    const { results, sharedWrites } = await run(rows);
    assert.equal(sharedWrites, 0);
    assert.equal(results[0].action, 'error');
  }

  const conflicting = await run([row(), row({ text: 'different message text' })]);
  assert.equal(conflicting.sharedWrites, 0);
  assert.deepEqual(conflicting.results, []);

  const allowed = await run([row(), row()]);
  assert.equal(allowed.sharedWrites, 1);
  assert.equal(allowed.results[0].action, 'promote');
});

test('curator selects candidate IDs then fetches complete per-artifact authorization outside the old row page', async () => {
  const text = 'urgent verify your wallet at https://evil.example/claim now';
  const baseRow = (overrides = {}) => ({
    s: 'https://tracabot.org/ontology#event/artifact-page',
    id: 'artifact-page', text, confidence: '90', quality: '85',
    expires: '2099-01-01T00:00:00Z', chat: 'hmac:chat', user: 'hmac:user',
    username: 'user', scamType: 'impersonation', created: '2026-01-01T00:00:00.000Z',
    consent: 'true', privacy: 'false', ...overrides
  });
  const allowed = baseRow();
  const denied = baseRow({ consent: 'false' });
  const prior = Array.from({ length: 100 }, (_, index) => baseRow({
    s: `https://tracabot.org/ontology#event/prior-${index}`,
    id: `prior-${index}`,
    expires: `2098-01-${String((index % 28) + 1).padStart(2, '0')}T00:00:00Z`
  }));
  const query = async (sparql) => {
    const limit = Number(sparql.match(/LIMIT\s+(\d+)/)?.[1] || 100);
    if (/SELECT DISTINCT \?id/.test(sparql)) return { result: { bindings: [{ id: 'artifact-page' }].slice(0, limit) } };
    if (sparql.includes('artifact-page')) return { result: { bindings: [allowed, denied].slice(0, limit) } };
    // The old single joined query would stop at 100 allowed rows and never see
    // the denial on the 101st row.
    return { result: { bindings: [...prior, allowed, denied].slice(0, limit) } };
  };
  const run = async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tracabot-page-'));
    let sharedWrites = 0;
    const dkg = new DkgClient({
      contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
      dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
    }, { adapterClient: {
      async createKnowledgeAsset(contextGraphId, name, options) {
        if (options.alsoShareSwm === true) { sharedWrites += 1; return { graph: 'did:dkg:context-graph:tracabot/_shared_memory' }; }
        return { graph: `did:dkg:context-graph:${contextGraphId}/_working_memory` };
      },
      async knowledgeAssetWrite() { return { ok: true }; },
      async knowledgeAssetDiscard() { return { ok: true }; },
      query
    } });
    try {
      const results = await curateWorkingMemory({
        dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'), limit: 100,
        reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence: 'verify your wallet at https://evil.example/claim' })
      });
      return { results, sharedWrites };
    } finally { rmSync(dir, { recursive: true, force: true }); }
  };

  const deniedResult = await run();
  assert.equal(deniedResult.sharedWrites, 0);
  assert.equal(deniedResult.results[0].action, 'error');

  const saturated = async () => {
    const dir = mkdtempSync(join(tmpdir(), 'tracabot-saturated-'));
    let sharedWrites = 0;
    const dkg = new DkgClient({
      contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
      dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
    }, { adapterClient: {
      async createKnowledgeAsset(contextGraphId, name, options) {
        if (options.alsoShareSwm === true) { sharedWrites += 1; return { graph: 'did:dkg:context-graph:tracabot/_shared_memory' }; }
        return { graph: `did:dkg:context-graph:${contextGraphId}/_working_memory` };
      },
      async knowledgeAssetWrite() { return { ok: true }; },
      async knowledgeAssetDiscard() { return { ok: true }; },
      async query(sparql) {
        const limit = Number(sparql.match(/LIMIT\s+(\d+)/)?.[1] || 100);
        if (/SELECT DISTINCT \?id/.test(sparql)) return { result: { bindings: [{ id: 'artifact-page' }].slice(0, limit) } };
        return { result: { bindings: Array.from({ length: 17 }, () => allowed).slice(0, limit) } };
      }
    } });
    try {
      const results = await curateWorkingMemory({
        dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'),
        reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence: 'verify your wallet at https://evil.example/claim' })
      });
      return { results, sharedWrites };
    } finally { rmSync(dir, { recursive: true, force: true }); }
  };
  const saturatedResult = await saturated();
  assert.equal(saturatedResult.sharedWrites, 0);
  assert.deepEqual(saturatedResult.results, []);
});

test('detail query binds ?id and promotes a real RDF-term-shaped allowed candidate', async () => {
  const text = 'urgent verify your wallet at https://evil.example/claim now';
  const evidence = 'verify your wallet at https://evil.example/claim';
  const queries = [];
  const term = (value) => ({ type: 'literal', value: String(value) });
  const row = {
    s: term('https://tracabot.org/ontology#event/artifact-rdf'),
    id: term('artifact-rdf'),
    text: term(text),
    confidence: term('90'),
    quality: term('85'),
    expires: term('2099-01-01T00:00:00Z'),
    chat: term('hmac:chat'),
    user: term('hmac:user'),
    username: term('user'),
    scamType: term('impersonation'),
    created: term('2026-01-01T00:00:00.000Z'),
    consent: term('true'),
    privacy: term('false')
  };
  let sharedWrites = 0;
  const adapter = {
    async createKnowledgeAsset(contextGraphId, name, options) {
      if (options.alsoShareSwm === true) { sharedWrites += 1; return { graph: 'did:dkg:context-graph:tracabot/_shared_memory' }; }
      return { graph: `did:dkg:context-graph:${contextGraphId}/_working_memory` };
    },
    async knowledgeAssetWrite() { return { ok: true }; },
    async knowledgeAssetDiscard() { return { ok: true }; },
    async query(sparql) {
      queries.push(sparql);
      if (/SELECT DISTINCT \?id/.test(sparql)) return { result: { bindings: [{ id: term('artifact-rdf') }] } };
      return { result: { bindings: [row] } };
    }
  };
  const dkg = new DkgClient({
    contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
    dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
  }, { adapterClient: adapter });
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-rdf-'));
  try {
    const results = await curateWorkingMemory({
      dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'),
      reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence })
    });
    assert.equal(results[0].action, 'promote');
    assert.equal(sharedWrites, 1);
    assert.ok(queries.some((sparql) => /VALUES \?id \{ "artifact-rdf" \}/.test(sparql) && /eventId> \?id/.test(sparql)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('producer authorization flows through actual stage/query/curation for enabled and disabled policies', async () => {
  const text = 'urgent verify your wallet at https://evil.example/claim now';
  const evidence = 'verify your wallet at https://evil.example/claim';
  const loadArtifactConfig = (overrides = {}) => loadConfig({
    TRACABOT_DKG_WRITES: 'true',
    TRACABOT_DKG_PSEUDONYM_KEY: 'x'.repeat(32),
    TRACABOT_AUTO_PROMOTE_EVIDENCE: 'true',
    TRACABOT_WM_ARTIFACTS: 'true',
    TRACABOT_CHANNEL_MEMORY: 'true',
    ...overrides
  });
  const baseConfig = loadArtifactConfig();
  const groupUpdate = { update_id: 1, message: { message_id: 9, date: 1780000000, chat: { id: -1001, type: 'supergroup' }, from: { id: 47 }, text } };
  const cases = [
    { name: 'enabled', config: baseConfig, update: groupUpdate, shared: 1 },
    { name: 'auto-promote disabled', config: loadArtifactConfig({ TRACABOT_AUTO_PROMOTE_EVIDENCE: 'false' }), update: groupUpdate, shared: 0 },
    { name: 'per-chat opt-out', config: loadArtifactConfig({ TRACABOT_ARTIFACT_OPT_OUT_CHATS: '-1001' }), update: groupUpdate, shared: 0 },
    { name: 'channel memory disabled', config: loadArtifactConfig({ TRACABOT_CHANNEL_MEMORY: 'false' }), update: { update_id: 2, channel_post: { ...groupUpdate.message, chat: { id: -2002, type: 'channel' } } }, shared: 0 }
  ];
  for (const testCase of cases) {
    const dir = mkdtempSync(join(tmpdir(), 'tracabot-producer-'));
    const event = artifactFromUpdate(testCase.update, testCase.config);
    assert.ok(event, testCase.name);
    let rawQuads = [];
    let sharedWrites = 0;
    const adapter = {
      async createContextGraph() { return { created: 'tracabot' }; },
      async createKnowledgeAsset(contextGraphId, name, options) {
        if (options.alsoShareSwm === true) { sharedWrites += 1; return { graph: 'did:dkg:context-graph:tracabot/_shared_memory' }; }
        rawQuads = options.quads;
        return { graph: `did:dkg:context-graph:${contextGraphId}/_working_memory` };
      },
      async knowledgeAssetWrite() { return { ok: true }; },
      async knowledgeAssetDiscard() { return { ok: true }; },
      async query() {
        const stored = (predicate) => {
          const quad = rawQuads.find((item) => item.predicate.endsWith(predicate));
          return quad ? JSON.parse(quad.object) : '';
        };
        return { result: { bindings: [{
          s: `https://tracabot.org/ontology#event/${event.id}`,
          id: event.id, text, confidence: '90', quality: '85',
          consent: stored('#consentToShare'), privacy: stored('#privacyOptOut'),
          expires: '2099-01-01T00:00:00Z', scamType: 'impersonation', created: '2026-01-01T00:00:00.000Z'
        }] } };
      }
    };
    const dkg = new DkgClient({
      contextGraph: 'tracabot', dkgWrites: true, dkgReads: true,
      dkgPseudonymKey: 'x'.repeat(32), dkgPublishVerified: false
    }, { adapterClient: adapter });
    try {
      await dkg.stageConversationArtifact(event);
      const results = await curateWorkingMemory({
        dkg, ledgerPath: join(dir, 'reviews.sqlite'), policyPath: join(dir, 'missing-policy.md'),
        reviewer: async () => ({ action: 'promote', category: 'fraud', reason: 'Concrete wallet verification lure with a suspicious link.', evidence })
      });
      assert.equal(sharedWrites, testCase.shared, testCase.name);
      assert.equal(results[0].action, testCase.shared ? 'promote' : 'error', testCase.name);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  assert.equal(artifactFromUpdate(groupUpdate, loadArtifactConfig({ TRACABOT_WM_ARTIFACTS: 'false' })), null);
});

test('confirmed ban requires exact actor confirmed evidence and rejects campaign association', () => {
  const root = (eventId, communityId, indicators = [], eventType = 'review_upheld') => ({ eventId, communityId, indicators, eventType, adminVerified: true, localApproval: true });
  assert.equal(evaluateConfirmedCampaignBan({ exactActorRoots: [root('a', 'one')] }).eligible, true);
  assert.equal(evaluateConfirmedCampaignBan({ exactActorRoots: [root('a', 'one')], overturned: true }).eligible, false);
  assert.equal(evaluateConfirmedCampaignBan({ exactActorRoots: [{ eventId: 'old', eventType: 'ban_executed', adminVerified: true }] }).eligible, false);
  assert.equal(evaluateConfirmedCampaignBan({ campaignRoots: [root('a', 'one', ['bc.game']), root('b', 'one', ['bc.game'])], currentIndicators: ['bc.game'] }).eligible, false);
  assert.equal(evaluateConfirmedCampaignBan({ campaignRoots: [root('a', 'one', ['bc.game']), root('b', 'two')], currentIndicators: ['bc.game'] }).eligible, false);
});

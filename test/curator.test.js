import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { EventEmitter } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { curateWorkingMemory, parseReview, reviewDraft, screenDraft } from '../src/curator.js';
import { evaluateConfirmedCampaignBan } from '../src/risk-engine.js';

const text = 'Urgent: verify your wallet at https://fraud.example/claim to avoid account suspension';
const base = { quality: 85, confidence: 90, text, expires: '2099-01-01T00:00:00Z' };
const approval = { action: 'promote', category: 'fraud', reason: 'Message pressures target to connect wallet at suspicious verification site.', evidence: 'verify your wallet at https://fraud.example/claim' };

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
    const opts = { dkg, ledgerPath: join(dir, 'reviews.sqlite'), now: Date.parse('2026-01-01'),
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
    const answer = await reviewDraft(base, { runner: (command, args, options) => {
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
    assert.deepEqual(invocation.args.slice(0, 9), ['run', '--agent', 'tracabot-curator', '--model', '9router/cx/gpt-6-sol', '--variant', 'medium', '--format', 'json']);
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
    assert.equal(reviews, 3);
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

test('confirmed ban uses exact actor or independent campaign bans with extra indicator', () => {
  const root = (eventId, communityId, indicators = []) => ({ eventId, communityId, indicators, eventType: 'ban_executed', adminVerified: true });
  assert.equal(evaluateConfirmedCampaignBan({ exactActorRoots: [root('a', 'one')] }).eligible, true);
  assert.equal(evaluateConfirmedCampaignBan({ exactActorRoots: [root('a', 'one')], overturned: true }).eligible, false);
  assert.equal(evaluateConfirmedCampaignBan({ campaignRoots: [root('a', 'one', ['bc.game']), root('b', 'one', ['bc.game'])], currentIndicators: ['bc.game'] }).eligible, false);
  assert.equal(evaluateConfirmedCampaignBan({ campaignRoots: [root('a', 'one', ['bc.game']), root('b', 'two')], currentIndicators: [] }).eligible, false);
  assert.equal(evaluateConfirmedCampaignBan({ campaignRoots: [root('a', 'one', ['bc.game']), root('b', 'two')], currentIndicators: ['bc.game'] }).eligible, true);
});

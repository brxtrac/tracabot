import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactFromUpdate, enforceHighConfidenceAutoBan, highConfidenceAutoBan, pollArtifacts } from '../src/telegram-artifacts.js';
import { DkgClient } from '../src/dkg-client.js';
import { EventStore } from '../src/store.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const config = { telegramToken: 'test', dkgWrites: true, dkgPseudonymKey: 'x'.repeat(32) };
const update = { update_id: 12, message: { message_id: 9, date: 1780000000, chat: { id: -1001 }, from: { id: 47 }, text: 'Urgent: verify your wallet at https://scam.example now' } };

test('captures relevant message with stable ID and pseudonymous identities', () => {
  const event = artifactFromUpdate(update, config);
  assert.equal(event.event_type, 'conversation_artifact');
  assert.match(event.chat.id, /^hmac:v1:/);
  assert.match(event.user.id, /^hmac:v1:/);
  assert.equal(artifactFromUpdate(update, config).id, event.id);
  assert.equal(artifactFromUpdate({ message: { ...update.message, text: 'hello' } }, config), null);
});

test('transient getUpdates reset stays in poll loop; fatal and once-mode still throw', async () => {
  const sleeps = [];
  let calls = 0;
  const controller = new AbortController();
  const fetcher = async () => {
    calls += 1;
    if (calls === 1) throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } });
    controller.abort();
    return { ok: true, json: async () => ({ ok: true, result: [] }) };
  };
  await pollArtifacts({
    config, store: { pollingOffset: () => 0 }, dkg: {}, fetcher, signal: controller.signal,
    sleep: async (ms) => { sleeps.push(ms); }
  });
  assert.equal(calls, 2);
  assert.equal(sleeps.length, 1);
  assert.ok(sleeps[0] >= 750 && sleeps[0] <= 1500);
  await assert.rejects(pollArtifacts({
    config, store: { pollingOffset: () => 0 }, dkg: {}, once: true,
    fetcher: async () => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNRESET' } }); }
  }), /fetch failed/);
  await assert.rejects(pollArtifacts({
    config, store: { pollingOffset: () => 0 }, dkg: {}, once: true,
    fetcher: async () => ({ ok: false, status: 401, json: async () => ({}) })
  }), /Telegram HTTP 401/);
});

test('failed DKG write leaves update unacknowledged for retry', async () => {
  const calls = [];
  const store = {
    pollingOffset: () => 12, claimUpdate: () => 'claimed',
    completeUpdate: () => calls.push('complete'), failUpdate: () => calls.push('fail')
  };
  await assert.rejects(pollArtifacts({ config, store,
    dkg: { stageConversationArtifact: async () => { throw new Error('DKG down'); } },
    fetcher: async () => ({ ok: true, json: async () => ({ ok: true, result: [update] }) }), once: true
  }), /DKG down/);
  assert.deepEqual(calls, ['fail']);
});

test('auto-ban requires concrete wallet lure, link, pressure, and group sender', () => {
  const message = { ...update.message, chat: { id: -1001, type: 'supergroup' } };
  assert.equal(highConfidenceAutoBan(message), true);
  assert.equal(highConfidenceAutoBan({ ...message, text: 'Warning: never verify your wallet at https://scam.example now' }), false);
  assert.equal(highConfidenceAutoBan({ ...message, text: 'Urgent: verify your wallet now' }), false);
  assert.equal(highConfidenceAutoBan({ ...message, sender_chat: { id: 4 } }), false);
});

test('protected admin and bot without ban rights are never banned; eligible user banned once', async () => {
  const message = { ...update.message, chat: { id: -1001, type: 'supergroup' } };
  const calls = [];
  let targetStatus = 'member';
  let botCanBan = true;
  const fetcher = async (url, init) => {
    const method = url.split('/').at(-1);
    calls.push(method);
    const params = JSON.parse(init.body);
    const result = method === 'getMe' ? { id: 99 } : method === 'getChatMember'
      ? params.user_id === 99 ? { status: 'administrator', can_restrict_members: botCanBan } : { status: targetStatus }
      : true;
    return { ok: true, json: async () => ({ ok: true, result }) };
  };
  const store = {
    beginEffect: () => ({ completed: false }), completeEffect: () => calls.push('completed'),
    markEffectUncertain: () => calls.push('uncertain')
  };
  const dkg = { confirmedSwmScamHistory: async () => [{ eventId: 'prior-ban', eventType: 'ban_executed' }] };
  const reviewer = async () => ({ action: 'ban', historyEventId: 'prior-ban', evidence: 'verify your wallet' });
  targetStatus = 'administrator';
  assert.equal(await enforceHighConfidenceAutoBan(message, { config, store, dkg, reviewer, fetcher }), false);
  targetStatus = 'member'; botCanBan = false;
  assert.equal(await enforceHighConfidenceAutoBan(message, { config, store, dkg, reviewer, fetcher }), false);
  botCanBan = true;
  assert.equal(await enforceHighConfidenceAutoBan(message, { config, store, dkg, reviewer, fetcher }), true);
  assert.equal(calls.filter((name) => name === 'banChatMember').length, 1);
});

test('ban blocked without exact SWM history, on curator hold, and on mismatched evidence', async () => {
  const message = { ...update.message, chat: { id: -1001, type: 'supergroup' } };
  let calls = 0;
  const fetcher = async () => { calls++; throw new Error('Telegram must not be called'); };
  const store = { beginEffect: () => { throw new Error('ban must not be claimed'); } };
  const dkg = { confirmedSwmScamHistory: async () => [] };
  assert.equal(await enforceHighConfidenceAutoBan(message, { config, store, dkg, fetcher }), false);
  dkg.confirmedSwmScamHistory = async () => [{ eventId: 'prior', eventType: 'ban_executed' }];
  for (const response of [{ action: 'hold' }, { action: 'ban', historyEventId: 'wrong', evidence: 'verify your wallet' }, { action: 'ban', historyEventId: 'prior', evidence: 'invented quote' }]) {
    assert.equal(await enforceHighConfidenceAutoBan(message, { config, store, dkg, fetcher, reviewer: async () => response }), false);
  }
  assert.equal(calls, 0);
});

test('SWM history requires exact actor, verified scam decision, and no later clear', async () => {
  let query;
  const graph = 'owner/tracabot';
  const uri = `did:dkg:context-graph:${graph}/_shared_memory/example`;
  const row = (id, type, date) => ({ g: uri, s: `https://tracabot.org/ontology#event/${id}`, type, verified: 'true', created: date });
  let bindings = [row('ban-1', 'ban_executed', '2026-01-01T00:00:00Z')];
  const dkg = new DkgClient({ contextGraph: graph, dkgPseudonymKey: 'x'.repeat(32) }, { adapterClient: {
    async query(sparql, options) { query = { sparql, options }; return { result: { bindings } }; }
  } });
  assert.equal((await dkg.confirmedSwmScamHistory('47')).length, 1);
  assert.equal(query.options.view, 'shared-working-memory');
  assert.match(query.sparql, /actorIdentity/);
  bindings = [row('ban-1', 'ban_executed', '2026-01-01T00:00:00Z'), row('clear-2', 'review_overturned', '2026-01-02T00:00:00Z')];
  assert.deepEqual(await dkg.confirmedSwmScamHistory('47'), []);
  bindings = [row('ban-1', 'ban_executed', '2026-01-01T00:00:00Z'), { ...row('ban-2', 'ban_executed', '2026-01-03T00:00:00Z'), verified: 'false' }];
  assert.deepEqual((await dkg.confirmedSwmScamHistory('47')).map((entry) => entry.eventId), ['ban-1']);
});

test('polling queues ban candidates without calling reviewer and acknowledges update', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-ban-'));
  try {
    const store = new EventStore(join(dir, 'events.sqlite'));
    const message = { ...update.message, date: Math.floor(Date.now() / 1000), chat: { id: -1001, type: 'supergroup' } };
    let calls = 0;
    await pollArtifacts({ config: { ...config, highConfidenceAutoBan: true }, store,
      dkg: { stageConversationArtifact: async () => { calls++; } }, once: true,
      fetcher: async () => ({ ok: true, json: async () => ({ ok: true, result: [{ update_id: 12, message }] }) }) });
    assert.equal(calls, 1);
    assert.equal(store.nextBanCandidate().message.from.id, 47);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

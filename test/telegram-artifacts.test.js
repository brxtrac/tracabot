import test from 'node:test';
import assert from 'node:assert/strict';
import { artifactFromUpdate, enforceHighConfidenceAutoBan, highConfidenceAutoBan, pollArtifacts, processBanCandidates } from '../src/telegram-artifacts.js';
import { EventStore } from '../src/store.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const config = { telegramToken: 'test', dkgWrites: true, dkgPseudonymKey: 'x'.repeat(32), autoPromoteEvidence: true };
const update = { update_id: 12, message: { message_id: 9, date: 1780000000, chat: { id: -1001 }, from: { id: 47 }, text: 'Urgent: verify your wallet at https://scam.example now' } };

test('captures relevant message with stable ID and pseudonymous identities', () => {
  const event = artifactFromUpdate(update, config);
  assert.equal(event.event_type, 'conversation_artifact');
  assert.match(event.chat.id, /^hmac:v1:/);
  assert.match(event.user.id, /^hmac:v1:/);
  assert.equal(artifactFromUpdate(update, config).id, event.id);
  assert.equal(artifactFromUpdate({ message: { ...update.message, text: 'hello' } }, config), null);
});

test('artifact producer derives sharing authorization from settings and opt-outs', () => {
  const enabled = { ...config, autoPromoteEvidence: true, wmArtifacts: true, channelMemory: true };
  const group = artifactFromUpdate(update, enabled);
  assert.equal(group.payload.consent_to_share, true);
  assert.equal(group.payload.privacy_opt_out, undefined);

  for (const [overrides, expected] of [
    [{ autoPromoteEvidence: false }, false],
    [{ artifactOptOutChats: ['-1001'] }, false]
  ]) {
    const event = artifactFromUpdate(update, { ...enabled, ...overrides });
    assert.equal(event.payload.consent_to_share, expected);
    assert.equal(event.payload.privacy_opt_out, true);
  }
  const messageOptOut = artifactFromUpdate({
    ...update,
    message: { ...update.message, consent_to_share: false }
  }, enabled);
  assert.equal(messageOptOut.payload.consent_to_share, false);

  const privacyOptOut = artifactFromUpdate({
    ...update,
    message: { ...update.message, privacy_opt_out: true }
  }, enabled);
  assert.equal(privacyOptOut.payload.consent_to_share, false);

  assert.equal(artifactFromUpdate(update, { ...enabled, wmArtifacts: false }), null);

  const channel = { update_id: 13, channel_post: { ...update.message, chat: { id: -2002, type: 'channel' } } };
  assert.equal(artifactFromUpdate(channel, { ...enabled, channelMemory: false }).payload.consent_to_share, false);
  assert.equal(artifactFromUpdate(channel, { ...enabled, channelMemory: true }).payload.consent_to_share, true);
  assert.equal(artifactFromUpdate(update, { ...enabled, channelMemory: false }).payload.consent_to_share, true);
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

test('polling does not stage an artifact denied by sharing policy', async () => {
  const calls = [];
  const store = {
    pollingOffset: () => 12, claimUpdate: () => 'claimed',
    completeUpdate: () => calls.push('complete'), failUpdate: () => calls.push('fail')
  };
  let stages = 0;
  await pollArtifacts({ config: { ...config, autoPromoteEvidence: false }, store,
    dkg: { stageConversationArtifact: async () => { stages += 1; } },
    fetcher: async () => ({ ok: true, json: async () => ({ ok: true, result: [update] }) }), once: true
  });
  assert.equal(stages, 0);
  assert.deepEqual(calls, ['complete']);
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

test('legacy high-confidence ban worker never sanctions on forged, stale, retracted, or model-approved history', async () => {
  const message = { ...update.message, chat: { id: -1001, type: 'supergroup' } };
  let fetchCalls = 0;
  let effectClaims = 0;
  const fetcher = async () => { fetchCalls++; throw new Error('Telegram must not be called'); };
  const store = {
    beginEffect: () => { effectClaims++; throw new Error('ban must not be claimed'); },
    completeEffect: () => { throw new Error('ban must not complete'); }
  };
  const histories = [
    [],
    [{ eventId: 'ordinary-ban', eventType: 'ban_executed', created: '2026-01-01T00:00:00Z' }],
    [{ eventId: 'stale-ban', eventType: 'ban_executed', created: '2020-01-01T00:00:00Z' }],
    [{ eventId: 'retracted-ban', eventType: 'review_overturned', created: '2026-01-02T00:00:00Z' }]
  ];
  for (const history of histories) {
    const dkg = { confirmedSwmScamHistory: async () => history };
    const reviewer = async () => ({ action: 'ban', historyEventId: history[0]?.eventId || 'none', evidence: 'verify your wallet' });
    assert.equal(await enforceHighConfidenceAutoBan(message, { config: { ...config, highConfidenceAutoBan: true }, store, dkg, reviewer, fetcher }), false);
  }
  const rejected = { confirmedSwmScamHistory: async () => { throw new Error('graph rejected'); } };
  assert.equal(await enforceHighConfidenceAutoBan(message, { config, store, dkg: rejected, fetcher }), false);
  assert.equal(fetchCalls, 0);
  assert.equal(effectClaims, 0);
});

test('retired ban worker drains queued candidates without Telegram, DKG, or reviewer action', async () => {
  const controller = new AbortController();
  let candidateRead = false;
  let fetchCalls = 0;
  const store = {
    nextBanCandidate() {
      if (candidateRead) return null;
      candidateRead = true;
      return { key: 'legacy-candidate', message: { text: 'urgent verify wallet https://scam.example', from: { id: 47 }, chat: { id: -1001 } } };
    },
    finishBanCandidate(key, error) {
      assert.equal(key, 'legacy-candidate');
      assert.equal(error, 'legacy_destructive_worker_retired');
      controller.abort();
    }
  };
  await processBanCandidates({
    config: { ...config, highConfidenceAutoBan: true },
    store,
    dkg: { confirmedSwmScamHistory: async () => { throw new Error('must not read history'); } },
    fetcher: async () => { fetchCalls++; throw new Error('must not call Telegram'); },
    reviewer: async () => { throw new Error('must not call reviewer'); },
    signal: controller.signal
  });
  assert.equal(candidateRead, true);
  assert.equal(fetchCalls, 0);
});

test('polling stages artifacts but never queues retired ban candidates', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-ban-'));
  try {
    const store = new EventStore(join(dir, 'events.sqlite'));
    const message = { ...update.message, date: Math.floor(Date.now() / 1000), chat: { id: -1001, type: 'supergroup' } };
    let calls = 0;
    await pollArtifacts({ config: { ...config, highConfidenceAutoBan: true }, store,
      dkg: { stageConversationArtifact: async () => { calls++; } }, once: true,
      fetcher: async () => ({ ok: true, json: async () => ({ ok: true, result: [{ update_id: 12, message }] }) }) });
    assert.equal(calls, 1);
    assert.equal(store.nextBanCandidate(), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

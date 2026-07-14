import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { EventStore } from '../src/store.js';

test('persists events and returns seven-day stats', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-'));
  const store = new EventStore(join(dir, 'events.jsonl'));
  store.append({ timestamp: new Date().toISOString(), event_type: 'scam_detection', payload: { scam_type: 'giveaway' } });
  store.append({ timestamp: new Date().toISOString(), event_type: 'ban_executed', payload: { scam_type: 'impersonation' } });
  const stats = store.stats();
  assert.equal(stats.total, 2);
  assert.equal(stats.byType.giveaway, 1);
  assert.equal(stats.byType.impersonation, 1);
});

test('ignores malformed jsonl lines', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-'));
  const legacyPath = join(dir, 'events.jsonl');
  appendFileSync(legacyPath, `${JSON.stringify({ id: 'ok', timestamp: new Date().toISOString(), payload: {} })}\nnot-json\n`);
  assert.deepEqual(new EventStore(join(dir, 'events.sqlite'), { legacyPath }).all().map((event) => event.id), ['ok']);
});

test('requires event store path to be a file path', () => {
  assert.throws(() => new EventStore('.'), /file path/);
});

test('shares committed events between SQLite connections', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-'));
  const path = join(dir, 'events.sqlite');
  const first = new EventStore(path);
  const second = new EventStore(path);
  first.append({ id: 'first', timestamp: new Date().toISOString(), payload: {} });
  second.append({ id: 'external', timestamp: new Date().toISOString(), payload: {} });
  assert.deepEqual(first.all().map((event) => event.id), ['first', 'external']);
});

test('imports legacy JSONL exactly once and deduplicates events', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-'));
  const legacyPath = join(dir, 'events.jsonl');
  const path = join(dir, 'events.sqlite');
  appendFileSync(legacyPath, `${JSON.stringify({ id: 'legacy', timestamp: new Date().toISOString(), payload: {} })}\n`);
  const first = new EventStore(path, { legacyPath });
  const second = new EventStore(path, { legacyPath });
  first.append({ id: 'legacy', timestamp: new Date().toISOString(), payload: {} });
  assert.deepEqual(second.all().map((event) => event.id), ['legacy']);
});

test('persists polling offsets and completed update claims', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  const update = { update_id: 10, message: { text: '/start' } };
  assert.equal(store.pollingOffset('bot'), null);
  assert.equal(store.claimUpdate('bot', update), 'claimed');
  store.completeUpdate('bot', 10, 11);
  assert.equal(store.pollingOffset('bot'), 11);
  assert.equal(store.claimUpdate('bot', update), 'completed');
});

test('deduplicates completed operational effects', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  assert.deepEqual(store.beginEffect('ban:1', 'ban', { userId: 1 }), { completed: false, inProgress: false });
  store.completeEffect('ban:1', { ok: true });
  assert.deepEqual(store.beginEffect('ban:1', 'ban', { userId: 1 }), { completed: true, response: { ok: true } });
});

test('rejects effect key reuse with a different kind or request', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  store.beginEffect('stable-key', 'sendMessage', { chat_id: 1, text: 'first' });
  assert.throws(() => store.beginEffect('stable-key', 'deleteMessage', { chat_id: 1, text: 'first' }), /different request/);
  assert.throws(() => store.beginEffect('stable-key', 'sendMessage', { chat_id: 1, text: 'second' }), /different request/);
});

test('persists uncertain effects and refuses automatic reclaim', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite');
  const first = new EventStore(path);
  first.beginEffect('send:unknown', 'sendMessage', { text: 'maybe sent' });
  first.markEffectUncertain('send:unknown', 'response lost');
  const second = new EventStore(path);
  assert.deepEqual(second.beginEffect('send:unknown', 'sendMessage', { text: 'maybe sent' }), { completed: false, inProgress: false, uncertain: true });
});

test('turns abandoned non-replayable effects into explicit uncertainty', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  store.beginEffect('send:abandoned', 'sendMessage', { text: 'maybe sent' });
  store.db.prepare('UPDATE effects SET updated_at = ? WHERE effect_key = ?')
    .run(new Date(Date.now() - 6 * 60 * 1000).toISOString(), 'send:abandoned');
  assert.deepEqual(
    store.beginEffect('send:abandoned', 'sendMessage', { text: 'maybe sent' }, { staleAction: 'uncertain' }),
    { completed: false, inProgress: false, uncertain: true }
  );
  assert.equal(store.db.prepare('SELECT status FROM effects WHERE effect_key = ?').get('send:abandoned').status, 'uncertain');
});

test('rejects unknown stale effect actions', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  assert.throws(() => store.beginEffect('bad', 'sendMessage', {}, { staleAction: 'replay-maybe' }), /Invalid stale effect action/);
});

test('persists cooldown completion and releases definitive failures', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite');
  const first = new EventStore(path);
  assert.equal(first.claimCooldown('notice:-100', 3600000), true);
  first.completeCooldown('notice:-100');
  const second = new EventStore(path);
  assert.equal(second.claimCooldown('notice:-100', 3600000), false);
  assert.equal(second.claimCooldown('notice:-200', 3600000), true);
  second.releaseCooldown('notice:-200');
  assert.equal(first.claimCooldown('notice:-200', 3600000), true);
});

test('migrates pre-dedupe SQLite event schema', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite');
  const legacy = new DatabaseSync(path);
  legacy.exec(`CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, event_type TEXT, timestamp TEXT, body TEXT NOT NULL);`);
  legacy.close();
  const store = new EventStore(path);
  assert.equal(store.db.prepare('PRAGMA user_version').get().user_version, 2);
  assert.ok(store.db.prepare('PRAGMA table_info(events)').all().some((column) => column.name === 'dedupe_key'));
  assert.equal(store.append({ id: 'migrated', timestamp: new Date().toISOString() }, { dedupeKey: 'once' }).inserted, true);
});

test('fresh update and effect claims are exclusive across connections', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite');
  const first = new EventStore(path);
  const second = new EventStore(path);
  const update = { update_id: 12, message: { text: '/start' } };
  assert.equal(first.claimUpdate('bot', update), 'claimed');
  assert.equal(second.claimUpdate('bot', update), 'processing');
  assert.deepEqual(first.beginEffect('delete:1', 'delete', { messageId: 1 }), { completed: false, inProgress: false });
  assert.deepEqual(second.beginEffect('delete:1', 'delete', { messageId: 1 }), { completed: false, inProgress: true });
});

test('rejects invalid update transitions and preserves completed effects', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  assert.throws(() => store.completeUpdate('bot', 99, 100), /not processing/);
  const update = { update_id: 13, message: { text: '/start' } };
  store.claimUpdate('bot', update);
  store.completeUpdate('bot', 13, 14);
  store.failUpdate('bot', 13, 'late failure');
  assert.equal(store.claimUpdate('bot', update), 'completed');
  store.beginEffect('send:1', 'sendMessage', { text: 'ok' });
  store.completeEffect('send:1', { ok: true });
  store.failEffect('send:1', 'late failure');
  assert.deepEqual(store.beginEffect('send:1', 'sendMessage', { text: 'ok' }), { completed: true, response: { ok: true } });
});

test('persists known user message IDs for later moderation cleanup', () => {
  const path = join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite');
  const first = new EventStore(path);
  first.rememberMessage('-100', '77', 41);
  const second = new EventStore(path);
  assert.deepEqual(second.knownMessageIds('-100', '77'), [41]);
  second.forgetMessage('-100', '77', 41);
  assert.deepEqual(first.knownMessageIds('-100', '77'), []);
});

test('bounds persisted observed messages by age and per-user count', () => {
  const store = new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-')), 'events.sqlite'));
  store.db.prepare('INSERT INTO observed_messages (chat_id, user_id, message_id, observed_at) VALUES (?, ?, ?, ?)')
    .run('-old', '1', 1, new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString());
  for (let messageId = 1; messageId <= 101; messageId += 1) store.rememberMessage('-100', '77', messageId);
  assert.equal(store.knownMessageIds('-old', '1').length, 0);
  assert.deepEqual(store.knownMessageIds('-100', '77'), Array.from({ length: 100 }, (_, index) => index + 2));
});

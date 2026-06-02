import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  const store = new EventStore(join(dir, 'events.jsonl'));
  store.append({ id: 'ok', timestamp: new Date().toISOString(), payload: {} });
  appendFileSync(store.path, 'not-json\n');
  assert.deepEqual(new EventStore(store.path).all().map((event) => event.id), ['ok']);
});

test('requires event store path to be a file path', () => {
  assert.throws(() => new EventStore('.'), /file path/);
});

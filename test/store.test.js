import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
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

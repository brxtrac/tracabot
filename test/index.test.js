import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBot } from '../src/index.js';

test('createBot runs without an LLM key or model', () => {
  const bot = createBot({
    TELEGRAM_BOT_TOKEN: 'live-token',
    TRACABOT_DKG_PSEUDONYM_KEY: '0123456789abcdef0123456789abcdef',
    TRACABOT_LLM_PROVIDER: 'off',
    TRACABOT_DB_PATH: join(mkdtempSync(join(tmpdir(), 'tracabot-index-')), 'events.sqlite')
  });
  assert.equal(bot.llm.status().enabled, false);
  assert.equal(bot.config.llmProvider, 'off');
  bot.store.db.close();
});

test('createBot requires strong pseudonym key for live DKG writers', () => {
  assert.throws(
    () => createBot({ TELEGRAM_BOT_TOKEN: 'live-token', TRACABOT_DKG_PSEUDONYM_KEY: 'short' }),
    /TRACABOT_DKG_PSEUDONYM_KEY must be at least 32 bytes/
  );
  assert.doesNotThrow(() => createBot({ TELEGRAM_BOT_TOKEN: 'live-token', TRACABOT_DKG_WRITES: 'false' }));
  assert.doesNotThrow(() => createBot({ TELEGRAM_BOT_TOKEN: 'live-token', TRACABOT_DKG_PSEUDONYM_KEY: '0123456789abcdef0123456789abcdef' }));
});

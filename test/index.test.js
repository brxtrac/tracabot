import test from 'node:test';
import assert from 'node:assert/strict';
import { createBot } from '../src/index.js';

test('createBot requires strong pseudonym key for live DKG writers', () => {
  assert.throws(
    () => createBot({ TELEGRAM_BOT_TOKEN: 'live-token', TRACABOT_DKG_PSEUDONYM_KEY: 'short' }),
    /TRACABOT_DKG_PSEUDONYM_KEY must be at least 32 bytes/
  );
  assert.doesNotThrow(() => createBot({ TELEGRAM_BOT_TOKEN: 'live-token', TRACABOT_DKG_WRITES: 'false' }));
  assert.doesNotThrow(() => createBot({ TELEGRAM_BOT_TOKEN: 'live-token', TRACABOT_DKG_PSEUDONYM_KEY: '0123456789abcdef0123456789abcdef' }));
});

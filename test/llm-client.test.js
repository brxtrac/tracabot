import test from 'node:test';
import assert from 'node:assert/strict';
import { LlmClient } from '../src/llm-client.js';

test('9router provider uses OpenAI-compatible chat endpoint and default model', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    calls.push({ url: String(url), body: JSON.parse(options.body), headers: options.headers });
    return { ok: true, async json() { return { choices: [{ message: { content: 'ok' } }] }; } };
  };
  try {
    const llm = new LlmClient({ llmProvider: '9router', llmApiKey: 'test-key', telegramTimeoutMs: 5000 });
    const result = await llm.complete({ system: 'sys', user: 'user' });
    assert.equal(result.ok, true);
    assert.equal(result.provider, '9router');
    assert.equal(calls[0].url, 'https://api.9router.com/v1/chat/completions');
    assert.equal(calls[0].body.model, 'openai/gpt-4o-mini');
    assert.equal(calls[0].headers.authorization, 'Bearer test-key');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('off provider does not call fetch', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('fetch should not be called'); };
  try {
    const result = await new LlmClient({ llmProvider: 'off' }).complete({ system: 'sys', user: 'user' });
    assert.equal(result.ok, false);
    assert.equal(result.provider, 'off');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('LLM provider errors are returned without throwing', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: false, status: 401, statusText: 'Unauthorized', async json() { return {}; } });
  try {
    const result = await new LlmClient({ llmProvider: '9router', llmApiKey: 'bad', telegramTimeoutMs: 5000 }).complete({ system: 'sys', user: 'user' });
    assert.equal(result.ok, false);
    assert.match(result.error, /401/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

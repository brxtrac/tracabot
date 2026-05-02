import { discoverOpenClawLlm } from './openclaw-config.js';

const OPENCLAW_CHAT_PATHS = [
  '/api/chat/completions',
  '/v1/chat/completions',
  '/chat/completions',
  '/api/agent/chat'
];

function withTimeout(ms = 30000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ms);
  return { controller, done: () => clearTimeout(timeout) };
}

async function postJson(url, body, token, timeoutMs) {
  const { controller, done } = withTimeout(timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return await response.json();
  } finally {
    done();
  }
}

function textFromChatResponse(response) {
  return response?.choices?.[0]?.message?.content || response?.message?.content || response?.content || response?.text || response?.reply || '';
}

export class LlmClient {
  constructor(config = {}) {
    this.config = config;
  }

  async complete({ system, user }) {
    if (this.config.llmProvider === 'off') return { ok: false, provider: 'off', text: '' };
    if (this.config.llmBaseUrl) return this.completeHttp({ system, user });
    if (['auto', 'openclaw', 'openclaw-auto'].includes(this.config.llmProvider || 'auto')) return this.completeOpenClaw({ system, user });
    return { ok: false, provider: this.config.llmProvider || 'auto', text: '' };
  }

  async completeHttp({ system, user }) {
    const model = this.config.llmModel || 'default';
    try {
      const response = await postJson(`${this.config.llmBaseUrl.replace(/\/$/, '')}/v1/chat/completions`, {
        model,
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
        temperature: 0.2,
        max_tokens: 220
      }, this.config.llmApiKey, this.config.telegramTimeoutMs || 30000);
      return { ok: true, provider: 'http-chat', text: textFromChatResponse(response), raw: response };
    } catch (error) {
      return { ok: false, provider: 'http-chat', error: error instanceof Error ? error.message : String(error), text: '' };
    }
  }

  async completeOpenClaw({ system, user }) {
    const discovered = discoverOpenClawLlm(this.config);
    if (!discovered) return { ok: false, provider: 'openclaw-auto', text: '' };
    const base = discovered.baseUrl.replace(/\/$/, '');
    const body = {
      model: discovered.model || 'default',
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
      temperature: 0.2,
      max_tokens: 220
    };
    for (const path of OPENCLAW_CHAT_PATHS) {
      try {
        const response = await postJson(`${base}${path}`, body, discovered.token, this.config.telegramTimeoutMs || 30000);
        const text = textFromChatResponse(response);
        if (text) return { ok: true, provider: 'openclaw-auto', endpoint: path, text, raw: response };
      } catch {
        // OpenClaw gateway route names vary; try the next known chat shape.
      }
    }
    return { ok: false, provider: 'openclaw-auto', text: '' };
  }
}

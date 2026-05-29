import { discoverOpenClawLlm } from './openclaw-config.js';

const OPENCLAW_CHAT_PATHS = [
  '/api/chat/completions',
  '/v1/chat/completions',
  '/chat/completions',
  '/api/agent/chat'
];

const PROVIDER_BASE_URLS = {
  '9router': 'https://api.9router.com',
  ninerouter: 'https://api.9router.com',
  http: '',
  direct: '',
  openai: 'https://api.openai.com',
  openrouter: 'https://openrouter.ai/api',
  local: 'http://127.0.0.1:11434'
};

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

  provider() {
    return String(this.config.llmProvider || 'auto').trim().toLowerCase();
  }

  httpBaseUrl() {
    const configured = String(this.config.llmBaseUrl || '').trim();
    if (configured) return configured;
    return PROVIDER_BASE_URLS[this.provider()] || '';
  }

  modelForProvider() {
    const provider = this.provider();
    if (this.config.llmModel) return this.config.llmModel;
    if (provider === '9router' || provider === 'ninerouter') return 'openai/gpt-4o-mini';
    if (provider === 'openai') return 'gpt-4o-mini';
    if (provider === 'local') return 'llama3.1';
    return 'default';
  }

  async complete({ system, user }) {
    const provider = this.provider();
    if (provider === 'off') return { ok: false, provider: 'off', text: '' };
    if (this.httpBaseUrl()) return this.completeHttp({ system, user });
    if (['auto', 'openclaw', 'openclaw-auto'].includes(provider)) return this.completeOpenClaw({ system, user });
    return { ok: false, provider, text: '' };
  }

  async completeHttp({ system, user }) {
    const provider = this.provider();
    const baseUrl = this.httpBaseUrl().replace(/\/$/, '');
    const model = this.modelForProvider();
    try {
      const response = await postJson(`${baseUrl}/v1/chat/completions`, {
        model,
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
        temperature: 0.2,
        max_tokens: 220
      }, this.config.llmApiKey, this.config.telegramTimeoutMs || 30000);
      return { ok: true, provider: provider === 'auto' ? 'http-chat' : provider, endpoint: '/v1/chat/completions', model, text: textFromChatResponse(response), raw: response };
    } catch (error) {
      return { ok: false, provider: provider === 'auto' ? 'http-chat' : provider, error: error instanceof Error ? error.message : String(error), text: '' };
    }
  }

  async completeOpenClaw({ system, user }) {
    const discovered = discoverOpenClawLlm(this.config);
    if (!discovered) return { ok: false, provider: 'openclaw-auto', text: '' };
    const base = discovered.baseUrl.replace(/\/$/, '');
    if (discovered.provider === 'openclaw-model-provider') {
      try {
        const model = String(discovered.model || 'default').replace(/^[^/]+\//, '');
        const response = await postJson(`${base}/chat/completions`, {
          model,
          messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
          temperature: 0.2,
          max_tokens: 220
        }, discovered.token, this.config.telegramTimeoutMs || 30000);
        return { ok: true, provider: discovered.provider, endpoint: '/chat/completions', text: textFromChatResponse(response), raw: response };
      } catch (error) {
        return { ok: false, provider: discovered.provider, error: error instanceof Error ? error.message : String(error), text: '' };
      }
    }
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

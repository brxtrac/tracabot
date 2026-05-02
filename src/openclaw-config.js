import { readFileSync, existsSync } from 'node:fs';

export function readOpenClawConfig(config = {}) {
  const path = config.openClawConfigPath || '';
  if (!path || !existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

export function discoverOpenClawLlm(config = {}) {
  const openclaw = readOpenClawConfig(config);
  if (!openclaw) return null;
  const gateway = openclaw.gateway || {};
  const model = config.llmModel || openclaw.agents?.defaults?.model?.primary || '';
  const port = gateway.port || 18789;
  const baseUrl = config.llmBaseUrl || `http://127.0.0.1:${port}`;
  const token = config.llmApiKey || gateway.auth?.token || '';
  return {
    provider: 'openclaw-auto',
    baseUrl,
    token,
    model,
    hasToken: Boolean(token),
    authMode: gateway.auth?.mode || '',
    source: config.openClawConfigPath || 'openclaw config'
  };
}

export function redactedOpenClawStatus(config = {}) {
  const discovered = discoverOpenClawLlm(config);
  if (!discovered) return { available: false, provider: config.llmProvider || 'auto' };
  return {
    available: true,
    provider: discovered.provider,
    baseUrl: discovered.baseUrl,
    model: discovered.model,
    auth: discovered.hasToken ? 'configured' : 'none'
  };
}

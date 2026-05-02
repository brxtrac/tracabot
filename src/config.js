import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

const CONTEXT_GRAPH_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  if (/^(true|1|yes)$/i.test(value)) return true;
  if (/^(false|0|no)$/i.test(value)) return false;
  throw new Error(`Invalid boolean value: ${value}`);
}

function readLocalDkgToken() {
  const tokenPath = resolve(homedir(), '.dkg', 'auth.token');
  if (!existsSync(tokenPath)) return '';
  return readFileSync(tokenPath, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line && !line.startsWith('#')) || '';
}

export function loadConfig(env = process.env) {
  const contextGraph = env.TRACABOT_CONTEXT_GRAPH || 'tracabot';
  const warnThreshold = Number(env.TRACABOT_WARN_THRESHOLD || 60);
  const restrictThreshold = Number(env.TRACABOT_RESTRICT_THRESHOLD || 75);
  const actionThreshold = Number(env.TRACABOT_ACTION_THRESHOLD || 85);
  const banThreshold = Number(env.TRACABOT_BAN_THRESHOLD || actionThreshold);
  const proactiveScanMinutes = Number(env.TRACABOT_PROACTIVE_SCAN_MINUTES || 30);
  const telegramTimeoutMs = Number(env.TRACABOT_TELEGRAM_TIMEOUT_MS || 30000);
  const adminIds = new Set((env.TRACABOT_ADMINS || '')
    .split(',')
    .map((id) => id.trim().replace(/^@/, '').toLowerCase())
    .filter(Boolean));
  if (!Number.isFinite(actionThreshold) || actionThreshold < 50 || actionThreshold > 100) {
    throw new Error('TRACABOT_ACTION_THRESHOLD must be a number from 50 to 100');
  }
  if (!Number.isFinite(warnThreshold) || warnThreshold < 1 || warnThreshold > 100) {
    throw new Error('TRACABOT_WARN_THRESHOLD must be a number from 1 to 100');
  }
  if (!Number.isFinite(restrictThreshold) || restrictThreshold < warnThreshold || restrictThreshold > 100) {
    throw new Error('TRACABOT_RESTRICT_THRESHOLD must be a number from warn threshold to 100');
  }
  if (!Number.isFinite(banThreshold) || banThreshold < restrictThreshold || banThreshold > 100) {
    throw new Error('TRACABOT_BAN_THRESHOLD must be a number from restrict threshold to 100');
  }
  if (!CONTEXT_GRAPH_RE.test(contextGraph)) {
    throw new Error('TRACABOT_CONTEXT_GRAPH must be 1-64 characters using letters, numbers, underscores, or hyphens');
  }
  if (!Number.isFinite(proactiveScanMinutes) || proactiveScanMinutes < 5) {
    throw new Error('TRACABOT_PROACTIVE_SCAN_MINUTES must be at least 5');
  }
  if (!Number.isFinite(telegramTimeoutMs) || telegramTimeoutMs < 5000) {
    throw new Error('TRACABOT_TELEGRAM_TIMEOUT_MS must be at least 5000');
  }
  const conversationMinConfidence = Number(env.TRACABOT_CONVERSATION_MIN_CONFIDENCE || 60);
  const proactiveReplyThreshold = Number(env.TRACABOT_PROACTIVE_REPLY_THRESHOLD || 75);
  const conversationRateLimitSeconds = Number(env.TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS || 60);
  const conversationMaxChars = Number(env.TRACABOT_CONVERSATION_MAX_CHARS || 700);
  if (!Number.isFinite(conversationMinConfidence) || conversationMinConfidence < 0 || conversationMinConfidence > 100) {
    throw new Error('TRACABOT_CONVERSATION_MIN_CONFIDENCE must be a number from 0 to 100');
  }
  if (!Number.isFinite(proactiveReplyThreshold) || proactiveReplyThreshold < conversationMinConfidence || proactiveReplyThreshold > 100) {
    throw new Error('TRACABOT_PROACTIVE_REPLY_THRESHOLD must be a number from conversation minimum to 100');
  }
  if (!Number.isFinite(conversationRateLimitSeconds) || conversationRateLimitSeconds < 0) {
    throw new Error('TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS must be a non-negative number');
  }
  if (!Number.isFinite(conversationMaxChars) || conversationMaxChars < 160 || conversationMaxChars > 2000) {
    throw new Error('TRACABOT_CONVERSATION_MAX_CHARS must be a number from 160 to 2000');
  }
  return {
    telegramToken: env.TELEGRAM_BOT_TOKEN || '',
    adminIds,
    autoDelete: parseBoolean(env.TRACABOT_AUTO_DELETE, true),
    autoRestrict: parseBoolean(env.TRACABOT_AUTO_RESTRICT, true),
    autoBan: parseBoolean(env.TRACABOT_AUTO_BAN, true),
    warnThreshold,
    restrictThreshold,
    banThreshold,
    actionThreshold,
    proactiveScanMinutes,
    telegramTimeoutMs,
    contextGraph,
    dkgMode: env.TRACABOT_DKG_MODE || 'openclaw-adapter',
    dkgNodeUrl: env.DKG_NODE_URL || 'http://127.0.0.1:9200',
    dkgAuthToken: env.DKG_AUTH_TOKEN || readLocalDkgToken(),
    openClawDkgAdapterPath: env.OPENCLAW_DKG_ADAPTER_PATH || '',
    storePath: env.TRACABOT_STORE_PATH || './data/tracabot-events.jsonl',
    agentDid: env.TRACABOT_AGENT_DID || 'did:dkg:agent:tracabot',
    testMode: parseBoolean(env.TRACABOT_TEST_MODE, false),
    openClawWorkspace: env.OPENCLAW_WORKSPACE || resolve(homedir(), '.openclaw', 'workspace'),
    conversational: parseBoolean(env.TRACABOT_CONVERSATIONAL, true),
    llmProvider: env.TRACABOT_LLM_PROVIDER || 'auto',
    llmBaseUrl: env.TRACABOT_LLM_BASE_URL || '',
    llmApiKey: env.TRACABOT_LLM_API_KEY || '',
    llmModel: env.TRACABOT_LLM_MODEL || '',
    openClawConfigPath: env.OPENCLAW_CONFIG_PATH || resolve(homedir(), '.openclaw', 'openclaw.json'),
    conversationMinConfidence,
    proactiveReplyThreshold,
    conversationRateLimitSeconds,
    conversationMaxChars
  };
}

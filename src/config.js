import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

function readLocalDkgToken() {
  const tokenPath = resolve(homedir(), '.dkg', 'auth.token');
  if (!existsSync(tokenPath)) return '';
  return readFileSync(tokenPath, 'utf8').trim();
}

export function loadConfig(env = process.env) {
  const contextGraph = env.TRACABOT_CONTEXT_GRAPH || 'claw-shield-intel';
  const actionThreshold = Number(env.TRACABOT_ACTION_THRESHOLD || 85);
  const proactiveScanMinutes = Number(env.TRACABOT_PROACTIVE_SCAN_MINUTES || 30);
  const telegramTimeoutMs = Number(env.TRACABOT_TELEGRAM_TIMEOUT_MS || 30000);
  const adminIds = new Set((env.TRACABOT_ADMINS || '')
    .split(',')
    .map((id) => id.trim().replace(/^@/, '').toLowerCase())
    .filter(Boolean));
  if (!Number.isFinite(actionThreshold) || actionThreshold < 50 || actionThreshold > 100) {
    throw new Error('TRACABOT_ACTION_THRESHOLD must be a number from 50 to 100');
  }
  if (!Number.isFinite(proactiveScanMinutes) || proactiveScanMinutes < 5) {
    throw new Error('TRACABOT_PROACTIVE_SCAN_MINUTES must be at least 5');
  }
  if (!Number.isFinite(telegramTimeoutMs) || telegramTimeoutMs < 5000) {
    throw new Error('TRACABOT_TELEGRAM_TIMEOUT_MS must be at least 5000');
  }
  return {
    telegramToken: env.TELEGRAM_BOT_TOKEN || '',
    adminIds,
    autoBan: env.TRACABOT_AUTO_BAN !== 'false',
    actionThreshold,
    proactiveScanMinutes,
    telegramTimeoutMs,
    contextGraph,
    dkgMode: env.TRACABOT_DKG_MODE || 'cli',
    dkgNodeUrl: env.DKG_NODE_URL || 'http://127.0.0.1:9200',
    dkgAuthToken: env.DKG_AUTH_TOKEN || readLocalDkgToken(),
    storePath: env.TRACABOT_STORE_PATH || './data/tracabot-events.jsonl',
    agentDid: env.TRACABOT_AGENT_DID || 'did:dkg:agent:tracabot',
    openClawWorkspace: env.OPENCLAW_WORKSPACE || resolve(homedir(), '.openclaw', 'workspace')
  };
}

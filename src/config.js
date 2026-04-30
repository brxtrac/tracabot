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
  return {
    telegramToken: env.TELEGRAM_BOT_TOKEN || '',
    adminIds: new Set((env.TRACABOT_ADMINS || '').split(',').map((id) => id.trim()).filter(Boolean)),
    autoBan: env.TRACABOT_AUTO_BAN === 'true',
    contextGraph,
    dkgMode: env.TRACABOT_DKG_MODE || 'cli',
    dkgNodeUrl: env.DKG_NODE_URL || 'http://127.0.0.1:9200',
    dkgAuthToken: env.DKG_AUTH_TOKEN || readLocalDkgToken(),
    storePath: env.TRACABOT_STORE_PATH || './data/tracabot-events.jsonl',
    agentDid: env.TRACABOT_AGENT_DID || 'did:dkg:agent:tracabot',
    openClawWorkspace: env.OPENCLAW_WORKSPACE || resolve(homedir(), '.openclaw', 'workspace')
  };
}

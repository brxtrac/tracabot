import { loadConfig, validateDkgPseudonymKey } from './config.js';
import { analyzeMessage } from './scam-analyzer.js';
import { DkgClient } from './dkg-client.js';
import { EventStore } from './store.js';
import { TelegramShieldBot } from './telegram.js';
import { LlmClient } from './llm-client.js';

export function createBot(env = process.env) {
  const config = loadConfig(env);
  validateDkgPseudonymKey(config);
  const store = new EventStore(config.databasePath || config.storePath, { legacyPath: config.legacyStorePath });
  const dkg = new DkgClient(config);
  const llm = new LlmClient(config);
  return new TelegramShieldBot({ config, analyzer: analyzeMessage, dkg, store, llm });
}

export async function main() {
  const bot = createBot();
  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    await bot.run({ signal: controller.signal });
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}

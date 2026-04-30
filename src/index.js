import { loadConfig } from './config.js';
import { analyzeMessage } from './scam-analyzer.js';
import { DkgClient } from './dkg-client.js';
import { EventStore } from './store.js';
import { TelegramShieldBot } from './telegram.js';

export function createBot(env = process.env) {
  const config = loadConfig(env);
  const store = new EventStore(config.storePath);
  const dkg = new DkgClient(config);
  return new TelegramShieldBot({ config, analyzer: analyzeMessage, dkg, store });
}

export async function main() {
  const bot = createBot();
  await bot.run();
}

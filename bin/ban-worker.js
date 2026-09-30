#!/usr/bin/env node
import { loadConfig } from '../src/config.js';
import { DkgClient } from '../src/dkg-client.js';
import { EventStore } from '../src/store.js';
import { processBanCandidates } from '../src/telegram-artifacts.js';

const config = loadConfig();
const controller = new AbortController();
process.once('SIGTERM', () => controller.abort());
process.once('SIGINT', () => controller.abort());
processBanCandidates({ config, store: new EventStore(config.databasePath), dkg: new DkgClient(config), signal: controller.signal })
  .catch((error) => { console.error(error); process.exitCode = 1; });

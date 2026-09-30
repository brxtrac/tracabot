#!/usr/bin/env node
import { loadConfig } from '../src/config.js';
import { DkgClient } from '../src/dkg-client.js';
import { EventStore } from '../src/store.js';
import { pollArtifacts } from '../src/telegram-artifacts.js';

const config = loadConfig();
const store = new EventStore(config.databasePath, { legacyPath: config.legacyStorePath });
const controller = new AbortController();
process.once('SIGTERM', () => controller.abort());
process.once('SIGINT', () => controller.abort());
pollArtifacts({ config, store, dkg: new DkgClient(config), signal: controller.signal, once: process.argv.includes('--once') })
  .catch((error) => { if (!controller.signal.aborted) { console.error(error); process.exitCode = 1; } });

#!/usr/bin/env node
import { loadConfig, validateDkgPseudonymKey } from '../src/config.js';
import { DkgClient } from '../src/dkg-client.js';
import { EventStore } from '../src/store.js';
import { startPublicServer } from '../src/public-server.js';

const config = loadConfig();
validateDkgPseudonymKey(config);
const store = new EventStore(config.databasePath || config.storePath, { legacyPath: config.legacyStorePath });
const dkg = new DkgClient(config);
const { server, url } = await startPublicServer({ config, store, dkg });
process.stdout.write(`TRACaBot public reader: ${url}\n`);
process.stdout.write('Reader access is free; writes require an operator-issued community token.\n');

const stop = () => server.close(() => {
  store.db?.close?.();
  process.exit(0);
});
process.once('SIGINT', stop);
process.once('SIGTERM', stop);

#!/usr/bin/env node
import { loadConfig, validateDkgPseudonymKey } from '../src/config.js';
import { DkgClient } from '../src/dkg-client.js';
import { EventStore } from '../src/store.js';
import { promoteEligibleEvidence } from '../src/evidence-promoter.js';

const once = process.argv.includes('--once');
const config = loadConfig();
validateDkgPseudonymKey(config);
const store = new EventStore(config.databasePath || config.storePath, { legacyPath: config.legacyStorePath });
const dkg = new DkgClient(config);

async function run() {
  const result = await promoteEligibleEvidence({ store, dkg, config });
  process.stdout.write(`${JSON.stringify({ ok: result.failed.length === 0, ...result }, null, 2)}\n`);
  if (result.failed.length) process.exitCode = 1;
}

try {
  await run();
} catch (error) {
  process.stderr.write(`evidence promotion unavailable: ${error instanceof Error ? error.message : String(error)}\n`);
  if (once) process.exitCode = 1;
}
if (!once) {
  setInterval(() => run().catch((error) => {
    process.stderr.write(`evidence promotion unavailable: ${error instanceof Error ? error.message : String(error)}\n`);
  }), Math.max(30000, config.autoPromoteIntervalMs || 300000));
}

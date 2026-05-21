#!/usr/bin/env node
import { processLearningDrafts } from '../src/learning-loop.js';

const args = new Set(process.argv.slice(2));
const once = args.has('--once');
const dryRun = args.has('--dry-run');
const intervalMs = Number(process.env.TRACABOT_LEARNING_LOOP_INTERVAL_MS || 300000);
const limit = Number(process.env.TRACABOT_LEARNING_LOOP_LIMIT || 25);

async function runOnce() {
  const result = await processLearningDrafts({ limit, dryRun });
  process.stdout.write(`${JSON.stringify({ ok: true, ...result }, null, 2)}\n`);
}

if (once || dryRun) {
  await runOnce();
} else {
  await runOnce();
  setInterval(() => {
    runOnce().catch((error) => {
      process.stderr.write(`openclaw learning loop failed: ${error instanceof Error ? error.message : String(error)}\n`);
    });
  }, Math.max(30000, intervalMs));
}

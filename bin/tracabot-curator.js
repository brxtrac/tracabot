#!/usr/bin/env node
import { curateWorkingMemory } from '../src/curator.js';

const once = process.argv.includes('--once');
const run = async () => {
  const results = await curateWorkingMemory();
  process.stdout.write(`${JSON.stringify({ processed: results.length, results })}\n`);
  if (results.some((item) => item.action === 'error')) process.exitCode = 1;
};
try {
  await run();
} catch (error) {
  process.stderr.write(`tracabot curator unavailable: ${error.message}\n`);
  if (once) process.exitCode = 1;
}
if (!once) setInterval(() => run().catch((error) => process.stderr.write(`tracabot curator unavailable: ${error.message}\n`)), 12 * 60 * 60 * 1000);

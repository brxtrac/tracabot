#!/usr/bin/env node
import { curateWorkingMemory } from '../src/curator.js';
import { loadConfig } from '../src/config.js';
import { createCreatorAttestation, creatorStatus, revokeCreatorAttestation } from '../src/creator-curator.js';

const once = process.argv.includes('--once');
const args = process.argv.slice(2);

function flag(name, fallback = '') {
  const index = args.findIndex((arg) => arg === `--${name}`);
  return index >= 0 ? String(args[index + 1] || '') : fallback;
}

function flags(name) {
  return args.reduce((values, arg, index) => {
    if (arg === `--${name}` && args[index + 1]) values.push(String(args[index + 1]));
    return values;
  }, []);
}

function parseRoot(value = '', subjectId = '') {
  const raw = String(value || '').trim();
  if (!raw) throw new Error('root value is empty');
  let root;
  if (raw.startsWith('{')) {
    root = JSON.parse(raw);
  } else {
    root = Object.fromEntries(raw.split(',').map((part) => {
      const [key, ...rest] = part.split('=');
      return [key.trim(), rest.join('=').trim()];
    }).filter(([key]) => key));
  }
  return {
    id: root.id || root.root_id || root.event_id,
    event_type: root.event_type || root.eventType || 'ban_executed',
    community_id: root.community_id || root.communityId || root.chat_id,
    lineage_id: root.lineage_id || root.lineageId || root.id || root.root_id || root.event_id,
    user_id: root.user_id || root.userId || subjectId,
    platform: root.platform || 'telegram'
  };
}

async function curatorCommand() {
  const config = loadConfig();
  const subjectId = flag('subject') || flag('user-id') || flag('user');
  if (!subjectId || !/^\d{4,24}$/.test(subjectId)) throw new Error('--subject must be a numeric Telegram user ID');
  if (!config.creatorCuratorPrivateKey) throw new Error('TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH is required');
  const options = {
    storePath: config.creatorCuratorStorePath,
    privateKey: config.creatorCuratorPrivateKey,
    subject: { platform: 'telegram', user_id: subjectId },
    issuer: config.creatorCuratorIssuer
  };
  if (args.includes('--status')) {
    return { status: 'status', envelope: creatorStatus(options) };
  }
  if (args.includes('--revoke')) {
    return { status: 'revoked', envelope: revokeCreatorAttestation({ ...options, reason: flag('reason', 'curator revocation') }) };
  }
  const roots = flags('root').map((value) => parseRoot(value, subjectId));
  if (!roots.length) throw new Error('at least one --root is required; use id=...,community_id=...,event_type=ban_executed');
  const attestation = createCreatorAttestation({
    ...options,
    classification: flag('classification', 'fraud'),
    confidence: Number(flag('confidence', '95')),
    roots,
    ttlDays: Number(flag('ttl-days', '180')),
    minConfidence: config.creatorCuratorMinConfidence || 90
  });
  return { status: 'active', attestation };
}

const run = async () => {
  if (args.some((arg) => ['--attest', '--revoke', '--status'].includes(arg))) {
    const result = await curatorCommand();
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }
  const results = await curateWorkingMemory();
  process.stdout.write(`${JSON.stringify({ processed: results.length, results })}\n`);
  if (results.some((item) => item.action === 'error')) process.exitCode = 1;
};

try {
  await run();
} catch (error) {
  process.stderr.write(`tracabot curator unavailable: ${error.message}\n`);
  if (once || args.some((arg) => ['--attest', '--revoke', '--status'].includes(arg))) process.exitCode = 1;
}
if (!once && !args.some((arg) => ['--attest', '--revoke', '--status'].includes(arg))) {
  setInterval(() => {
    curateWorkingMemory()
      .then((results) => process.stdout.write(`${JSON.stringify({ processed: results.length, results })}\n`))
      .catch((error) => process.stderr.write(`tracabot curator unavailable: ${error.message}\n`));
  }, 12 * 60 * 60 * 1000);
}

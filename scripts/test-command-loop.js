#!/usr/bin/env node
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.js';
import { DkgClient } from '../src/dkg-client.js';
import { analyzeMessage } from '../src/scam-analyzer.js';
import { EventStore } from '../src/store.js';
import { TelegramShieldBot } from '../src/telegram.js';

const config = {
  ...loadConfig(),
  telegramToken: 'stub-token',
  adminIds: new Set(),
  autoBan: true,
  testMode: true,
  actionThreshold: 80,
  proactiveScanMinutes: 30,
  storePath: join(mkdtempSync(join(tmpdir(), 'tracabot-live-loop-')), 'events.jsonl')
};
const dkg = new DkgClient(config);
const store = new EventStore(config.storePath);
const bot = new TelegramShieldBot({ config, analyzer: analyzeMessage, dkg, store });
const calls = [];
bot.call = async (method, payload) => {
  calls.push({ method, payload });
  if (method === 'getMe') return { id: 999, username: 'tracethembot' };
  if (method === 'getChatMember') return { status: 'administrator', can_restrict_members: true, can_delete_messages: true };
  return true;
};

const chat = { id: -100777, title: 'tracabot command loop' };
const admin = { id: 1, username: 'admin' };
const suspect = { id: 8080, username: `scamadmin${String(Date.now()).slice(-8)}`, is_bot: false };
const scamText = 'URGENT official support admin says verify wallet 0x1111111111111111111111111111111111111111 to claim free USDT airdrop now';

await dkg.ensureContextGraph();

await bot.handleCommand({ chat, from: admin, message_id: 1, text: '/stats' });
await bot.handleCommand({ chat, from: admin, message_id: 2, text: `/scan @${suspect.username} ${scamText}` });
await bot.handleCommand({ chat, from: admin, message_id: 3, text: `/report @${suspect.username} ${scamText}` });
await bot.handleCommand({
  chat,
  from: admin,
  message_id: 4,
  text: '/ban fake support impersonation',
  reply_to_message: { text: scamText, from: suspect }
});
await bot.handleCommand({ chat, from: admin, message_id: 5, text: '/stats' });
await bot.handleCommand({ chat, from: admin, message_id: 6, text: `/scan @${suspect.username}` });

const messages = calls.filter((call) => call.method === 'sendMessage').map((call) => call.payload.text);
const bans = calls.filter((call) => call.method === 'banChatMember');
const events = store.all().map((event) => ({
  id: event.id,
  type: event.event_type,
  dkg: event.dkg?.shareOperation || event.dkg?.eventId || event.dkg_error || 'no dkg result'
}));
const stats = await dkg.getStats(7);
const intel = await dkg.queryRiskIndicators({ username: suspect.username, userId: suspect.id, aliases: [suspect.username], text: scamText });

console.log(JSON.stringify({
  suspect: suspect.username,
  messages,
  bans,
  events,
  dkgStats: stats,
  retrievedIntel: {
    riskScore: intel.riskScore,
    reportsAcrossCommunities: intel.reportsAcrossCommunities,
    evidenceCount: intel.evidence.length,
    note: 'test-mode command-loop evidence is intentionally excluded from production risk queries'
  }
}, null, 2));

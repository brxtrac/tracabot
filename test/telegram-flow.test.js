import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TELEGRAM_COMMANDS, TelegramShieldBot } from '../src/telegram.js';
import { EventStore } from '../src/store.js';

function makeBot({ canBan }) {
  const calls = [];
  const dkg = {
    async queryRiskIndicators() {
      return {
        riskScore: 90,
        reportsAcrossCommunities: 2,
        wallets: [],
        patterns: ['impersonation'],
        evidence: [{ source: 'https://tracabot.org/ontology#event/prior' }]
      };
    },
    async writeEvent(event) {
      return { output: 'written', eventId: event.id };
    },
    async getStats() {
      return {
        source: 'dkg',
        total: 3,
        highConfidence: 2,
        byEventType: { fraud_finding: 1, ban_executed: 1, risk_query: 1 },
        byRiskType: { impersonation: 2, unknown: 1 }
      };
    },
    async ensureContextGraph() {}
  };
  const analyzer = () => ({
    is_scam: true,
    confidence: 88,
    scam_type: 'impersonation',
    evidence: ['test evidence'],
    recommended_action: 'ban'
  });
  const bot = new TelegramShieldBot({
    config: {
      telegramToken: 'test',
      adminIds: new Set(['1234']),
      autoBan: true,
      actionThreshold: 85,
      proactiveScanMinutes: 30,
      agentDid: 'did:dkg:agent:test'
    },
    analyzer,
    dkg,
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-flow-')), 'events.jsonl'))
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') return { status: canBan ? 'administrator' : 'member', can_restrict_members: canBan };
    return { ok: true };
  };
  return { bot, calls };
}

test('new high-risk join is banned when bot has admin rights', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 42, username: 'fake_support', is_bot: false }]
  });
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 42));
  assert.ok(bot.store.all().some((event) => event.event_type === 'ban_executed'));
});

test('new high-risk join alerts admins when bot lacks ban rights', async () => {
  const { bot, calls } = makeBot({ canBan: false });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 43, username: 'fake_support2', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Admin heads-up')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'fraud_finding'));
});

test('telegram command descriptions match the public bot command list', () => {
  assert.deepEqual(TELEGRAM_COMMANDS, [
    { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
    { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
    { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
    { command: 'stats', description: 'Show recent fraud checks and detections' }
  ]);
});

test('/scan checks a wallet without banning', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 10,
    text: '/scan 0x1111111111111111111111111111111111111111'
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('HIGH RISK')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_query'));
  assert.ok(bot.store.all().some((event) => event.event_type === 'fraud_finding'));
});

test('/report publishes wallet findings without attempting a Telegram ban', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 11,
    text: '/report 0x1111111111111111111111111111111111111111 fake airdrop wallet'
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'report_submitted'));
  assert.ok(bot.store.all().some((event) => event.event_type === 'fraud_finding'));
});

test('/ban bans replied user and publishes ban evidence', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 12,
    text: '/ban fake support impersonation',
    reply_to_message: {
      text: 'DM support admin to verify wallet',
      from: { id: 55, username: 'fake_support', is_bot: false }
    }
  });
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 55));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed');
  assert.ok(ban);
  assert.match(JSON.stringify(ban.payload.evidence), /manual \/ban command/);
});

test('/stats pulls DKG aggregate data', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 13,
    text: '/stats'
  });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Last 7 days from DKG')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('2 high-confidence busts')));
});

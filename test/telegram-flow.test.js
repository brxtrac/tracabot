import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TelegramShieldBot } from '../src/telegram.js';
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
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('admin alert')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'fraud_finding'));
});

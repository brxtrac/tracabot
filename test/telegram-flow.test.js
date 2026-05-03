import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TELEGRAM_COMMANDS, TelegramShieldBot } from '../src/telegram.js';
import { analyzeMessage } from '../src/scam-analyzer.js';
import { EventStore } from '../src/store.js';

function makeBot({ canBan, trustedUserIds = [1], analyzer: analyzerOverride = null, dkgIntel = null, adminIds = ['1234'], llm = null, conversational = false, chatAdmins = [], configOverrides = {}, validateUal = null }) {
  const calls = [];
  const dkgWrites = [];
  const dkg = {
    async queryRiskIndicators() {
      return dkgIntel || {
        riskScore: 90,
        reportsAcrossCommunities: 2,
        wallets: [],
        patterns: ['impersonation'],
        evidence: [{ source: 'https://tracabot.org/ontology#event/prior' }]
      };
    },
    async writeEvent(event) {
      dkgWrites.push(event);
      return {
        output: 'written',
        eventId: event.id,
        ual: 'did:dkg:context-graph:tracabot/_shared_memory',
        shareOperation: `swm-${event.id}`
      };
    },
    async getStats() {
      return {
        source: 'dkg',
        total: 3,
        highConfidence: 2,
        graph: 'tracabot',
        byEventType: { fraud_finding: 1, ban_executed: 1, risk_query: 1 },
        byRiskType: { impersonation: 2, unknown: 1 },
        sources: [{ eventId: 'evt-stats', eventType: 'fraud_finding', created: '2026-04-30T00:00:00.000Z', confidence: 92 }]
      };
    },
    async validateUal(ual) {
      return validateUal ? validateUal(ual) : { ok: true, reason: 'test' };
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
        adminIds: new Set(adminIds),
        autoDelete: true,
        autoRestrict: true,
        autoBan: true,
        warnThreshold: 60,
        restrictThreshold: 75,
        banThreshold: 85,
        actionThreshold: 85,
        conversational,
        llmProvider: 'auto',
        conversationMinConfidence: 60,
        proactiveReplyThreshold: 75,
        conversationRateLimitSeconds: 60,
        conversationMaxChars: 700,
        contextGraph: 'tracabot',
      proactiveScanMinutes: 30,
      agentDid: 'did:dkg:agent:test',
      joinChallenge: false,
      joinChallengeTtlSeconds: 60,
      joinChallengeAction: 'kick',
      joinChallengeDeleteOnPass: true,
      joinChallengeDeleteBadAttempts: true,
      joinChallengeDkgValidate: true,
      ...configOverrides
    },
    analyzer: analyzerOverride || analyzer,
    dkg,
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-flow-')), 'events.jsonl')),
    llm
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getUpdates') return [];
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') {
      if (payload.user_id === 999) return { status: canBan ? 'administrator' : 'member', can_restrict_members: canBan, can_delete_messages: canBan };
      return { status: trustedUserIds.includes(payload.user_id) ? 'administrator' : 'member', can_restrict_members: false };
    }
    if (method === 'getChatAdministrators') {
      return chatAdmins.map((user) => ({ status: 'administrator', user }));
    }
    if (method === 'unbanChatMember') return { ok: true };
    return { ok: true };
  };
  return { bot, calls, dkgWrites };
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

test('high-risk first post is deleted and banned when bot has rights', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 66, username: 'profit_coach', is_bot: false },
    message_id: 27,
    text: 'From Zero to $685K profit I joined Alpha Trading (https://t.me/alpha_trading_cricle) 16 months ago and within the past 3 months I earned $685,000 thanks to the coaching Mr Theo provides.'
  });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 27));
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 66));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed');
  assert.match(JSON.stringify(ban.payload.evidence), /triggering message removed/);
});

test('recent joiner renamed to admin-like identity is banned before DM bait', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    adminIds: ['brx86']
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({
    chat,
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 67, username: 'random_guest', first_name: 'Random', is_bot: false }]
  });
  await bot.handleMessage({
    chat,
    from: { id: 67, username: 'brx86_support', first_name: 'BRX 86', is_bot: false },
    message_id: 28,
    text: 'DM me if you need help'
  });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 28));
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 67));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed' && event.user.id === 67);
  assert.match(JSON.stringify(ban.payload.evidence), /changed identity to resemble admin/);
});

test('auto-discovered admin usernames are used for impersonation detection', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    adminIds: [],
    chatAdmins: [{ id: 500, username: 'BRX86', first_name: 'BRX', is_bot: false }],
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 88, username: 'brx86_support', first_name: 'BRX 86 Support', is_bot: false },
    message_id: 40,
    text: 'message me for support'
  });
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 88));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed' && event.user.id === 88);
  assert.match(JSON.stringify(ban.payload.evidence), /Username resembles configured admin/);
});

test('auto-discovered admin display names are used for rename copycat detection', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    adminIds: [],
    chatAdmins: [{ id: 500, first_name: 'BRX', last_name: '1947', is_bot: false }],
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'owner' }, new_chat_members: [{ id: 89, username: 'random_guest', first_name: 'Random', is_bot: false }] });
  await bot.handleMessage({ chat, from: { id: 89, username: 'brx1947_help', first_name: 'BRX 1947', is_bot: false }, message_id: 41, text: 'DM me if you need help' });
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 89));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed' && event.user.id === 89);
  assert.match(JSON.stringify(ban.payload.evidence), /changed identity to resemble admin/);
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
  const alert = calls.find((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Admin heads-up'))?.payload.text || '';
  assert.match(alert, /internal DKG receipts are not posted/);
  assert.doesNotMatch(alert, /DKG UAL|DKG event|did:dkg:context-graph|event ID/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_review_needed' && event.local_only));
});

test('auto-actions are suppressed for Telegram chat admins', async () => {
  const { bot, calls } = makeBot({ canBan: true, trustedUserIds: [77] });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 77, username: 'chat_admin', is_bot: false },
    message_id: 29,
    text: 'URGENT official support admin says verify wallet now'
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 77), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_action_suppressed' && event.local_only));
});

test('new bot members are ignored by proactive join moderation', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 12345, username: 'helper_bot', is_bot: true }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(bot.store.all().length, 0);
});

test('low-risk new members receive DKG UAL join challenge', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeTtlSeconds: 60 }
  });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 44, username: 'newhuman', first_name: 'New', is_bot: false }]
  });
  const restriction = calls.find((call) => call.method === 'restrictChatMember' && call.payload.user_id === 44);
  assert.equal(restriction.payload.permissions.can_send_messages, true);
  assert.equal(restriction.payload.permissions.can_send_audios, false);
  assert.equal(restriction.payload.permissions.can_send_documents, false);
  assert.equal(restriction.payload.permissions.can_send_photos, false);
  assert.equal(restriction.payload.permissions.can_send_videos, false);
  assert.equal(restriction.payload.permissions.can_send_video_notes, false);
  assert.equal(restriction.payload.permissions.can_send_voice_notes, false);
  assert.equal(restriction.payload.permissions.can_send_polls, false);
  assert.equal(restriction.payload.permissions.can_send_other_messages, false);
  assert.equal(restriction.payload.permissions.can_add_web_page_previews, false);
  assert.equal(restriction.payload.permissions.can_invite_users, false);
  const challenge = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(challenge, /quick DKG check/);
  assert.match(challenge, /Pick any Knowledge Asset/);
  assert.match(challenge, /A Knowledge Asset is a verifiable data item/);
  assert.match(challenge, /DM the UAL to me: https:\/\/t\.me\/tracethembot\?start=verify_m100_44/);
  assert.match(challenge, /You are restricted here until verified/);
  assert.match(challenge, /starting with did:dkg/);
  assert.doesNotMatch(challenge, /prove that you’re human and ready to join/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_started' && event.local_only));
});

test('chat_member joins receive DKG UAL join challenge', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true }
  });
  await bot.handleChatMemberUpdate({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    old_chat_member: { status: 'left', user: { id: 48, username: 'member48', is_bot: false } },
    new_chat_member: { status: 'member', user: { id: 48, username: 'member48', first_name: 'Member', is_bot: false } }
  });
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 48 && call.payload.permissions.can_send_messages === true));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('quick DKG check')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_started' && event.user.id === 48));
});

test('polling requests chat member updates for joins', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.pollOnce();
  const poll = calls.find((call) => call.method === 'getUpdates');
  assert.deepEqual(poll.payload.allowed_updates, ['message', 'chat_member', 'my_chat_member']);
});

test('valid DKG UAL solves join challenge and restores permissions', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: true, reason: 'resolved' })
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 45, username: 'learner', first_name: 'Learner', is_bot: false }] });
  await bot.handleMessage({ chat, from: { id: 45, username: 'learner', first_name: 'Learner', is_bot: false }, message_id: 45, text: 'did:dkg:knowledge-asset-valid-123456' });
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 45 && call.payload.permissions.can_send_photos === true));
  const success = calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '';
  assert.match(success, /DKG-verified/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_solved' && event.local_only));
});

test('DM DKG UAL solves join challenge and restores group permissions', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: true, reason: 'resolved' })
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  await bot.handleNewMembers({ chat: group, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 145, username: 'dmlearner', first_name: 'Dm', is_bot: false }] });
  await bot.handleMessage({ chat: { id: 145, type: 'private' }, from: { id: 145, username: 'dmlearner', is_bot: false }, message_id: 1, text: '/start verify_m100_145' });
  await bot.handleMessage({ chat: { id: 145, type: 'private' }, from: { id: 145, username: 'dmlearner', is_bot: false }, message_id: 2, text: 'did:dkg:knowledge-asset-valid-123456' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('Paste the full Knowledge Asset UAL')));
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 145 && call.payload.permissions.can_send_photos === true));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('unlocked in the group')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('DKG-verified')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_solved' && event.payload.verification_channel === 'dm'));
});

test('wrong user cannot use someone else DM verification link', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true }
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  await bot.handleNewMembers({ chat: group, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 245, username: 'target', first_name: 'Target', is_bot: false }] });
  await bot.handleMessage({ chat: { id: 9999, type: 'private' }, from: { id: 9999, username: 'wrong', is_bot: false }, message_id: 1, text: '/start verify_m100_245' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 9999 && String(call.payload.text).includes('could not match')));
  assert.ok(!calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 245 && call.payload.permissions.can_send_photos === true));
  assert.ok(bot.joinChallenges.has('-100:245'));
});

test('invalid challenge first message is deleted and reminded', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 46, username: 'badstart', first_name: 'Bad', is_bot: false }] });
  await bot.handleMessage({ chat, from: { id: 46, username: 'badstart', first_name: 'Bad', is_bot: false }, message_id: 46, text: 'hello everyone' });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 46));
  const reminder = calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '';
  assert.match(reminder, /starts with did:dkg/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.local_only));
});

test('invalid DKG UAL challenge attempt is deleted and not accepted', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: false, reason: 'not_found' })
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 146, username: 'badual', first_name: 'Badual', is_bot: false }] });
  await bot.handleMessage({ chat, from: { id: 146, username: 'badual', first_name: 'Badual', is_bot: false }, message_id: 146, text: 'did:dkg:knowledge-asset-missing-123456' });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 146));
  assert.ok(!calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 146 && call.payload.permissions.can_send_photos === true));
  const reminder = calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '';
  assert.match(reminder, /could not validate/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.payload.validation_reason === 'not_found'));
});

test('expired DKG join challenge kicks unresolved user', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeAction: 'kick' }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 47, username: 'timeout', first_name: 'Timeout', is_bot: false }] });
  const challenge = bot.joinChallenges.get('-100:47');
  challenge.expiresAt = Date.now() - 1;
  await bot.expireJoinChallenges();
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 47));
  assert.ok(calls.some((call) => call.method === 'unbanChatMember' && call.payload.user_id === 47));
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_expired' && event.local_only));
});

test('telegram command descriptions match the public bot command list', () => {
  assert.deepEqual(TELEGRAM_COMMANDS, [
    { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
    { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
    { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
    { command: 'stats', description: 'Show recent fraud checks and detections' },
    { command: 'why', description: 'Explain a tracabot event decision' },
    { command: 'watch', description: 'Admin: watch a suspicious actor' },
    { command: 'unwatch', description: 'Admin: remove a watched actor' },
    { command: 'watchlist', description: 'Admin: show watches, mutes, and review items' },
    { command: 'appeal', description: 'Submit an appeal or correction for an event' },
    { command: 'review', description: 'Admin: uphold or overturn an event' },
    { command: 'digest', description: 'Show recent moderation digest' },
    { command: 'status', description: 'Admin: show bot, DKG, and conversation status' },
    { command: 'help', description: 'Show tracabot commands and autonomous policy' }
  ]);
});

test('/help explains commands, thresholds, and DKG memory', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 30,
    text: '/help'
  });
  const help = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(help, /tracabot commands/);
  assert.match(help, /delete\/restrict at 75%/);
  assert.match(help, /\/why <event-id>/);
  assert.match(help, /\/watchlist/);
  assert.match(help, /shared fraud evidence/);
  assert.doesNotMatch(help, /Context Graph tracabot/);
});

test('/status reports permissions without exposing secrets', async () => {
  const { bot, calls } = makeBot({ canBan: true, trustedUserIds: [1], adminIds: ['1'] });
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 1, username: 'admin' }, message_id: 31, text: '/status' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /TRACaBot status/);
  assert.match(reply, /DKG: reachable/);
  assert.match(reply, /delete=yes/);
  assert.match(reply, /Join challenge: off/);
  assert.match(reply, /Secrets and internal endpoints are not displayed/);
  assert.doesNotMatch(reply, /token/i);
  assert.doesNotMatch(reply, /127\.0\.0\.1|openai|codex|Context Graph tracabot/);
});

test('explicit scam questions use bounded conversational LLM reply', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'This looks like a scam risk based on the supplied evidence. Do not click links or share wallet secrets. Ask an admin to review.' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  const chat = { id: -100, title: 'demo' };
  await bot.handleMessage({ chat, from: { id: 2, username: 'member' }, message_id: 32, text: '@tracabot is this a scam?', reply_to_message: { chat, from: { id: 90, username: 'fake_support' }, text: 'URGENT verify your wallet with support admin now at t.me/fakeclaim' } });
  assert.equal(llmCalls.length, 1);
  assert.match(llmCalls[0].system, /Vary the final safety note/);
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /scam risk/);
  assert.doesNotMatch(reply, /definitely/);
});

test('repeated bot mentions still trigger bounded safety replies', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'This looks risky. Do not click links or share wallet secrets. Ask an admin to review.' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 2, username: 'member' }, message_id: 35, text: '@tracethembot is this a scam?@tracethembot is this a scam?' });
  assert.equal(llmCalls.length, 1);
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /risky/);
});

test('common legitimacy questions trigger bounded safety replies', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'It may be fake. Do not click links or share wallet secrets until an admin reviews it.' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  const chat = { id: -100, title: 'demo' };
  await bot.handleMessage({ chat, from: { id: 2, username: 'member' }, message_id: 36, text: '@tracethembot is this legit?', reply_to_message: { chat, from: { id: 90, username: 'fake_support' }, text: 'claim airdrop now' } });
  assert.equal(llmCalls.length, 1);
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /fake|wallet secrets/);
});

test('legitimacy questions target mentioned user instead of bot or asker', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 5150, username: 'a_51_50' }, message_id: 37, text: '@tracethembot is @BRX86 legit?' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /@BRX86/);
  assert.doesNotMatch(reply, /Still avoid sharing seed phrases, private keys, or connecting wallets from chat links/);
  assert.doesNotMatch(reply, /@a_51_50/);
});

test('legitimacy questions target named user instead of asker', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  const chat = { id: -100, title: 'demo' };
  bot.rememberUser(chat, { id: 777, first_name: 'Dmitry' }, 'recent chat context');
  await bot.handleMessage({ chat, from: { id: 1947, username: 'BRX86' }, message_id: 38, text: '@tracethembot is Dmitry legit?' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /Dmitry/);
  assert.doesNotMatch(reply, /@BRX86/);
});

test('unknown plain named targets ask for reply or username instead of scanning asker', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], evidence: [] } });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 1947, username: 'BRX86' }, message_id: 39, text: '@tracethembot is Dmitry a scammer?' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /cannot identify that user from a display name alone/);
  assert.match(reply, /Reply to one of their messages/);
  assert.doesNotMatch(reply, /@BRX86 looks/);
});

test('conversation falls back when LLM is unavailable and ignores unrelated chat', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  bot.config.restrictThreshold = 90;
  bot.config.banThreshold = 95;
  const chat = { id: -100, title: 'demo' };
  await bot.handleMessage({ chat, from: { id: 3, username: 'member' }, message_id: 33, text: 'nice weather today' });
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
  await bot.handleMessage({ chat, from: { id: 4, username: 'fake_support' }, message_id: 34, text: 'URGENT free USDT airdrop claim now and verify wallet with support admin' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /TRACaBot warning|TRACaBot caution/);
});

test('/why explains local event decisions', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  bot.store.append({
    id: 'evt-why',
    event_type: 'ban_executed',
    timestamp: new Date().toISOString(),
    user: { id: 55, username: 'badactor' },
    payload: { confidence: 91, local_confidence: 80, dkg_confidence: 20, scam_type: 'phishing', recommended_action: 'ban', evidence: ['scam domain'], dkg_evidence: [{ ual: 'did:dkg:context-graph:tracabot/_shared_memory', eventId: 'prior' }] }
  });
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 1, username: 'admin' }, message_id: 32, text: '/why evt-why' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /Why evt-why/);
  assert.match(reply, /Confidence: 91%/);
  assert.match(reply, /scam domain/);
});

test('/appeal records correction request and /review records admin decision', async () => {
  const { bot, dkgWrites, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 86, username: 'BRX86' }, message_id: 33, text: '/appeal evt-ban false positive' });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 34, text: '/review evt-ban overturn agreed false positive' });
  assert.ok(dkgWrites.some((event) => event.event_type === 'appeal_submitted' && event.payload.target_event_id === 'evt-ban'));
  assert.ok(dkgWrites.some((event) => event.event_type === 'review_overturned' && event.payload.review_decision === 'overturned'));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Review overturned')));
});

test('/watch boosts scrutiny until /unwatch closes it', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: () => ({ is_scam: false, confidence: 50, scam_type: 'other', evidence: ['thin signal'], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 35, text: '/watch suspicious outreach', reply_to_message: { chat, from: { id: 77, username: 'maybe_scam' }, text: 'dm me for support' } });
  const risk = await bot.assess({ chat, from: { id: 77, username: 'maybe_scam' }, text: 'hello' }, { id: 77, username: 'maybe_scam' }, 'hello');
  assert.equal(risk.confidence, 65);
  assert.match(risk.evidence.join('\n'), /Active watchlist/);
  const watchReply = calls.find((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Watching'));
  assert.match(watchReply.payload.text, /tg:\/\/user\?id=77/);
  assert.equal(watchReply.payload.parse_mode, 'HTML');
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 36, text: '/unwatch resolved', reply_to_message: { chat, from: { id: 77, username: 'maybe_scam' }, text: 'dm me for support' } });
  const riskAfter = await bot.assess({ chat, from: { id: 77, username: 'maybe_scam' }, text: 'hello' }, { id: 77, username: 'maybe_scam' }, 'hello');
  assert.equal(riskAfter.confidence, 50);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Removed watch')));
});

test('/watch falls back to clickable username text when only @username is known', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 39, text: '/watch @maybe_scam suspicious outreach' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload || {};
  assert.match(reply.text || '', /Watching @maybe_scam/);
  assert.equal(reply.parse_mode, 'HTML');
});

test('/watch and /unwatch accept numeric Telegram IDs without a reason', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: () => ({ is_scam: false, confidence: 50, scam_type: 'other', evidence: ['thin signal'], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 40, text: '/watch 8388593201' });
  const watchEvent = bot.store.all().find((event) => event.event_type === 'watch_started');
  assert.equal(watchEvent.payload.watch_target_key, 'id:8388593201');
  assert.equal(watchEvent.payload.reason, 'admin watch');
  assert.equal(watchEvent.local_only, true);
  const risk = await bot.assess({ chat, from: { id: 8388593201 }, text: 'hello' }, { id: 8388593201 }, 'hello');
  assert.equal(risk.confidence, 65);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('tg://user?id=8388593201')));
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 41, text: '/unwatch 8388593201' });
  const riskAfter = await bot.assess({ chat, from: { id: 8388593201 }, text: 'hello' }, { id: 8388593201 }, 'hello');
  assert.equal(riskAfter.confidence, 50);
});

test('/watch replying to SangMata rename watches the renamed user ID', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  const sangmata = { chat, from: { id: 461843263, username: 'SangMataInfo_bot', is_bot: true }, text: 'User 8388593201 changed name from QQQ to Kristian Baumgartner.' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 42, text: '/watch', reply_to_message: sangmata });
  const event = bot.store.all().find((item) => item.event_type === 'watch_started');
  assert.equal(event.payload.watch_target_key, 'id:8388593201');
  assert.match(event.payload.reason, /QQQ -> Kristian Baumgartner/);
  assert.match(JSON.stringify(event.payload.evidence), /SangMata rename alert/);
  assert.equal(event.local_only, true);
  const reply = calls.find((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Watching'))?.payload || {};
  assert.match(reply.text || '', /tg:\/\/user\?id=8388593201/);
  assert.match(reply.text || '', /Kristian Baumgartner/);
});

test('/watchlist shows active watches, mutes, and review items', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  const now = new Date().toISOString();
  bot.store.append({ id: 'watch-a', event_type: 'watch_started', timestamp: now, chat, user: { id: '8388593201', first_name: 'Kristian Baumgartner' }, payload: { watch_target_key: 'id:8388593201', target: { id: '8388593201', first_name: 'Kristian Baumgartner' }, reason: 'admin watch', evidence: ['admin watch started'] }, local_only: true });
  bot.store.append({ id: 'mute-a', event_type: 'restrict_executed', timestamp: now, chat, user: { id: 77, username: 'muted_user' }, payload: { confidence: 78, restricted_until: new Date(Date.now() + 60 * 60 * 1000).toISOString(), evidence: ['medium-risk phishing domain'] } });
  bot.store.append({ id: 'review-a', event_type: 'risk_review_needed', timestamp: now, chat, user: { id: 88, username: 'review_user' }, payload: { confidence: 70, evidence: ['thin DKG match'] } });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 45, text: '/watchlist all' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload || {};
  assert.match(reply.text || '', /Watchlist manager/);
  assert.match(reply.text || '', /Active watches/);
  assert.match(reply.text || '', /Temp mutes/);
  assert.match(reply.text || '', /Needs review/);
  assert.match(reply.text || '', /tg:\/\/user\?id=8388593201/);
  assert.equal(reply.parse_mode, 'HTML');
});

test('/watchlist rejects non-admin requesters', async () => {
  const { bot, calls } = makeBot({ canBan: true, trustedUserIds: [] });
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 2, username: 'member' }, message_id: 46, text: '/watchlist' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('restricted')));
});

test('/scan replying to SangMata rename scans the renamed user ID', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  const sangmata = { chat, from: { id: 461843263, username: 'SangMataInfo_bot', is_bot: true }, text: 'User 8388593201 changed name from QQQ to Kristian Baumgartner.' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 43, text: '/scan', reply_to_message: sangmata });
  const event = bot.store.all().find((item) => item.event_type === 'risk_query');
  assert.equal(event.user.id, '8388593201');
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Kristian Baumgartner')));
});

test('/ban replying to SangMata rename bans the renamed user ID', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  const sangmata = { chat, from: { id: 461843263, username: 'SangMataInfo_bot', is_bot: true }, text: 'User 8388593201 changed name from QQQ to Kristian Baumgartner.' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 44, text: '/ban', reply_to_message: sangmata });
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === '8388593201'));
  const event = bot.store.all().find((item) => item.event_type === 'ban_executed');
  assert.equal(event.user.id, '8388593201');
  assert.match(JSON.stringify(event.payload.evidence), /SangMata rename alert/);
});

test('/stats campaigns and /digest summarize local memory', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const timestamp = new Date().toISOString();
  bot.store.append({ id: 'evt-c1', event_type: 'scam_detection', timestamp, payload: { domains: ['fake.example'], confidence: 80, evidence: ['fake.example'] } });
  bot.store.append({ id: 'evt-c2', event_type: 'report_submitted', timestamp, payload: { domains: ['fake.example'], confidence: 90, evidence: ['fake.example'] } });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 37, text: '/stats campaigns' });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 38, text: '/digest' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('domain:fake.example')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('tracabot digest')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Recommended follow-up')));
});

test('medium-risk message is deleted and restricted instead of banned', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: () => ({
      is_scam: true,
      confidence: 78,
      scam_type: 'phishing',
      evidence: ['medium risk domain lure'],
      recommended_action: 'warn'
    }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: ['fake-claim.example'], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 68, username: 'medium_risk', is_bot: false },
    message_id: 31,
    text: 'Check fake-claim.example'
  });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 31));
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 68));
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 68), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'restrict_executed'));
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

test('/scan with a plain name scans that name, not the command sender', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 14,
    text: '/scan Dmitry'
  });
  const riskEvent = bot.store.all().find((event) => event.event_type === 'risk_query');
  assert.equal(riskEvent.user.username, 'Dmitry');
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('@Dmitry')));
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('@BRX86 looks clean')), false);
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
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /saved the evidence to DKG fraud memory/);
  assert.doesNotMatch(reply, /UAL|did:dkg:context-graph|event ID/);
});

test('/report publishes suspicious DM support reports from non-admins without DKG history', async () => {
  const { bot, calls, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 21,
    text: '/report @fake_helper DM me for help with your wallet issue'
  });
  assert.ok(bot.store.all().some((event) => event.event_type === 'report_submitted'));
  assert.ok(dkgWrites.some((event) => event.event_type === 'report_submitted'));
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /saved the evidence to DKG fraud memory/);
  assert.doesNotMatch(reply, /UAL|did:dkg:context-graph|event ID/);
});

test('/report as a reply uses the replied fraudulent message without extra reporter text', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 23,
    text: '/report',
    reply_to_message: {
      text: 'DM me for help with your wallet issue',
      from: { id: 55, username: 'fake_helper', is_bot: false }
    }
  });
  const report = dkgWrites.find((event) => event.event_type === 'report_submitted');
  assert.ok(report);
  assert.equal(report.user.username, 'fake_helper');
  assert.equal(report.payload.report_decision, 'accepted');
  assert.equal(report.payload.confidence >= 80, true);
  assert.equal(report.payload.local_confidence >= 60, true);
  assert.ok(bot.store.all().some((event) => event.event_type === 'reporter_reputation_update' && event.local_only));
});

test('/report mention uses recently observed target context without extra reporter text', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleMessage({
    chat,
    from: { id: 55, username: 'fake_helper', is_bot: false },
    message_id: 24,
    text: 'DM me for help with your wallet issue'
  });
  await bot.handleCommand({
    chat,
    from: { id: 86, username: 'BRX86' },
    message_id: 25,
    text: '/report @fake_helper'
  });
  const report = dkgWrites.find((event) => event.event_type === 'report_submitted');
  assert.ok(report);
  assert.match(report.payload.evidence.join('\n'), /recent observed message/);
  assert.equal(report.payload.confidence >= 80, true);
  assert.equal(report.payload.local_confidence >= 60, true);
});

test('successful reporters can submit a bare target report for DKG review', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] }
  });
  const reporter = { id: 86, username: 'BRX86' };
  const timestamp = new Date().toISOString();
  bot.store.append({ event_type: 'report_submitted', timestamp, payload: { reporter, target_key: 'username:one', report_decision: 'accepted', report_outcome: 'high_confidence_dkg_report', confidence: 90 } });
  bot.store.append({ event_type: 'report_submitted', timestamp, payload: { reporter, target_key: 'username:two', report_decision: 'accepted', report_outcome: 'high_confidence_dkg_report', confidence: 90 } });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: reporter,
    message_id: 26,
    text: '/report @new_suspect'
  });
  const report = dkgWrites.find((event) => event.event_type === 'report_submitted');
  assert.ok(report);
  assert.equal(report.payload.reporter_trusted, true);
  assert.equal(report.payload.confidence >= 80, true);
  assert.equal(report.payload.local_confidence >= 60, true);
});

test('/report publishes configured-admin impersonation reports from non-admins', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    adminIds: ['brx86']
  });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 77, username: 'reporter' },
    message_id: 22,
    text: '/report @brx86_support message me for private support'
  });
  assert.ok(bot.store.all().some((event) => event.event_type === 'report_submitted'));
  assert.ok(dkgWrites.some((event) => event.event_type === 'report_submitted'));
});

test('/report without target evidence is local-only and does not pollute DKG', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 16,
    text: '/report'
  });
  const rejected = bot.store.all().find((event) => event.event_type === 'report_rejected');
  assert.ok(rejected);
  assert.equal(rejected.local_only, true);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('need stronger evidence')));
});

test('/report duplicate from non-admin is rejected before DKG write', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const message = {
    chat: { id: -100, title: 'demo' },
    from: { id: 77, username: 'reporter' },
    message_id: 17,
    text: '/report @fake_support urgent official support admin says verify wallet now'
  };
  await bot.handleCommand(message);
  await bot.handleCommand({ ...message, message_id: 18 });
  const reports = bot.store.all();
  assert.ok(reports.some((event) => event.event_type === 'report_submitted'));
  assert.ok(reports.some((event) => event.event_type === 'report_rejected' && event.local_only));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('need stronger evidence')));
});

test('/ban bans replied user and publishes ban evidence', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 12,
    text: '/ban fake support impersonation',
    reply_to_message: {
      message_id: 99,
      text: 'DM support admin to verify wallet',
      from: { id: 55, username: 'fake_support', is_bot: false }
    }
  });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 99));
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 55));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed');
  assert.ok(ban);
  assert.equal(ban.payload.replied_message_deleted, true);
  assert.match(JSON.stringify(ban.payload.evidence), /manual \/ban command/);
  assert.match(JSON.stringify(ban.payload.evidence), /replied scam message deleted/);
});

test('/ban continues if replied message deletion fails', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') {
      if (payload.user_id === 999) return { status: 'administrator', can_restrict_members: true, can_delete_messages: true };
      return { status: payload.user_id === 1 ? 'administrator' : 'member', can_restrict_members: false };
    }
    if (method === 'deleteMessage') throw new Error('message too old');
    return { ok: true };
  };
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 47,
    text: '/ban fake support impersonation',
    reply_to_message: { message_id: 100, text: 'DM support admin to verify wallet', from: { id: 55, username: 'fake_support', is_bot: false } }
  });
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 55));
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed');
  assert.equal(ban.payload.replied_message_deleted, false);
  assert.match(ban.payload.replied_message_delete_error, /message too old/);
});

test('/ban with a plain name does not ban the sender without a replied user', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 15,
    text: '/ban Dmitry'
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'ban_requested_no_reply' && event.user.username === 'Dmitry'));
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /reply to the exact user's message/);
  assert.doesNotMatch(reply, /DKG event|event ID|UAL/);
});

test('/ban rejects non-admin requesters even when the bot can ban', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 19,
    text: '/ban fake support impersonation',
    reply_to_message: {
      text: 'DM support admin to verify wallet',
      from: { id: 55, username: 'fake_support', is_bot: false }
    }
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'ban_rejected_unauthorized' && event.local_only));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('/ban is restricted')));
});

test('configured admin usernames match with or without @ and case differences', async () => {
  const { bot } = makeBot({ canBan: true, trustedUserIds: [] });
  bot.config.adminIds = new Set(['brx86']);
  assert.equal(bot.isConfiguredAdmin({ id: 86, username: 'BRX86' }), true);
  assert.equal(bot.isConfiguredAdmin({ id: 87, username: 'not_admin' }), false);
});

test('telegram command evidence is bounded before analysis', async () => {
  const { bot } = makeBot({ canBan: true });
  let analyzedText = '';
  bot.analyzer = ({ text }) => {
    analyzedText = text;
    return {
      is_scam: false,
      confidence: 0,
      scam_type: 'other',
      evidence: [],
      recommended_action: 'ignore'
    };
  };
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 20,
    text: `/scan ${'x'.repeat(6000)}`
  });
  assert.equal(analyzedText.length <= 4096, true);
});

test('normal messages are not logged with chat text', async () => {
  const { bot } = makeBot({ canBan: true });
  const originalLog = console.log;
  const logs = [];
  console.log = (line) => logs.push(String(line));
  try {
    await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 3, username: 'member' }, message_id: 71, text: 'normal private-looking chat text' });
  } finally {
    console.log = originalLog;
  }
  assert.equal(logs.some((line) => line.includes('normal private-looking chat text')), false);
});

test('/stats pulls DKG aggregate data', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 13,
    text: '/stats'
  });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('TRACaBot report (7d)')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('2 high-confidence signals from 3 DKG events')));
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('{"fraud_finding"')), false);
});

test('/stats sources returns DKG event receipts', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 14,
    text: '/stats sources'
  });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Stats sources from DKG graph tracabot')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('evt-stats')));
});

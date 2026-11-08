import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TelegramShieldBot } from '../src/telegram.js';
import { EventStore } from '../src/store.js';

const LOW_ANALYZER = () => ({ is_scam: false, confidence: 0, local_confidence: 0, scam_type: 'unknown', evidence: [], recommended_action: 'ignore' });
const LOW_INTEL = { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] };

function makeBot({ store = null, config = {}, adminChats = ['-100'], ownerIds = [], unban = 'ok' } = {}) {
  const calls = [];
  const writes = [];
  const dkg = {
    async queryRiskIndicators() { return LOW_INTEL; },
    async queryAdminHistoryForActor() { return { hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] }; },
    async queryCampaignModerationRoots() { return { events: [] }; },
    async queryProtectionEvidence() { return { ok: true, evidence: [], complete: true, error: '' }; },
    async writeEvent(event) { writes.push(event); return { eventId: event.id, ual: 'did:dkg:test' }; },
    async runtimeStatus() { return { capabilities: {} }; },
    async getStats() { return { total: 0, source: 'local' }; },
    async validateUal() { return { ok: true }; }
  };
  const eventStore = store || new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-controls-')), 'events.sqlite'));
  const bot = new TelegramShieldBot({
    config: {
      telegramToken: 'test',
      adminIds: new Set(['1']),
      botOwnerIds: new Set(ownerIds.map(String)),
      autoDelete: false,
      autoRestrict: false,
      autoBan: false,
      knownCampaignAutoBan: false,
      knownCampaignPatterns: [],
      warnThreshold: 60,
      restrictThreshold: 75,
      banThreshold: 85,
      actionThreshold: 85,
      conversational: false,
      llmProvider: 'off',
      contextGraph: 'tracabot',
      agentDid: 'did:dkg:agent:test',
      joinChallenge: false,
      joinAutoRemove: true,
      joinAutoRemoveChats: [],
      joinEvidenceMaxAgeDays: 180,
      joinMinConfirmedRoots: 1,
      joinTrustedLayers: ['local'],
      appealMaxPerHour: 3,
      appealDedupHours: 24,
      appealMaxReasonChars: 500,
      ...config
    },
    analyzer: LOW_ANALYZER,
    dkg,
    store: eventStore,
    llm: null
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') {
      if (String(payload.user_id) === '999') return { status: 'administrator', can_restrict_members: true, can_delete_messages: true };
      return adminChats.map(String).includes(String(payload.chat_id)) && String(payload.user_id) === '1'
        ? { status: 'administrator', user: { id: 1 } }
        : { status: 'member', user: { id: payload.user_id } };
    }
    if (method === 'getChatAdministrators') {
      return adminChats.map(String).includes(String(payload.chat_id)) ? [{ status: 'administrator', user: { id: 1 } }] : [];
    }
    if (method === 'unbanChatMember') {
      if (unban === 'fail') throw new Error('telegram unban failed');
      return { ok: true };
    }
    if (method === 'sendMessage') return { message_id: calls.length, ...payload };
    return { ok: true };
  };
  return { bot, calls, writes, store: eventStore };
}

function privateMessage(userId = 1, text = '/controls', messageId = 1) {
  return { chat: { id: userId, type: 'private' }, from: { id: userId, username: `user${userId}` }, message_id: messageId, text };
}

function seedAutoBan(bot, { id = 'auto-ban-1', userId = 4242, chatId = -100, roots = [`root-${id}`], timestamp = new Date().toISOString() } = {}) {
  bot.store.append({
    id,
    event_type: 'ban_executed',
    timestamp,
    chat: { id: chatId, type: 'supergroup', title: 'Demo Group' },
    user: { id: userId, username: 'accused' },
    payload: {
      target: { id: userId, username: 'accused', first_name: 'Accused' },
      target_key: `id:${userId}`,
      source: 'silent_join_protection',
      enforcement_observed_from: 'tracabot_join_protection',
      enforcement_action: 'ban',
      confidence: 100,
      evidence_root_ids: roots,
      evidence: ['Join exact-identity evidence']
    }
  });
}

function seedLocalReview(bot, userId, findingId, chatId = -100) {
  bot.store.append({
    id: findingId,
    event_type: 'risk_review_needed',
    timestamp: new Date().toISOString(),
    chat: { id: chatId, type: 'supergroup', title: 'Demo Group' },
    user: { id: userId, username: 'accused' },
    payload: { target: { id: userId }, target_key: `id:${userId}`, confidence: 90, recommended_action: 'admin_review' }
  });
  bot.store.append({
    id: `review-${findingId}`,
    event_type: 'review_upheld',
    timestamp: new Date().toISOString(),
    chat: { id: chatId, type: 'supergroup', title: 'Demo Group' },
    user: { id: 1, username: 'admin' },
    payload: {
      target_event_id: findingId,
      reviewed_target: { id: userId, username: 'accused' },
      reviewed_target_key: `id:${userId}`,
      target_chat_id: String(chatId),
      local_approval: true,
      approval_source: 'telegram_admin_review',
      admin_verified: true,
      confidence: 96,
      community_id: String(chatId)
    }
  });
}

async function joinUser(bot, userId, messageId, date) {
  await bot.handleNewMembers({
    chat: { id: -100, type: 'supergroup', title: 'Demo Group' },
    from: { id: 1, username: 'admin' },
    message_id: messageId,
    date,
    new_chat_members: [{ id: userId, username: 'accused', first_name: 'Accused', is_bot: false }]
  });
}

function keyboardButtons(calls, method = 'sendMessage') {
  const payload = calls.filter((call) => call.method === method).at(-1)?.payload || {};
  return (payload.reply_markup?.inline_keyboard || []).flat();
}
test('/controls routes to a private current-admin keyboard and redirects group/unauthorized users', async () => {
  const { bot, calls } = makeBot();
  seedAutoBan(bot, { id: 'auto-route', userId: 4242 });
  await bot.handleCommand(privateMessage(1, '/controls', 1));
  const buttons = keyboardButtons(calls);
  assert.ok(buttons.some((item) => String(item.callback_data).includes('controls-join-toggle')));
  assert.ok(buttons.some((item) => String(item.callback_data).includes('controls-ban-open')));
  assert.match(String(calls.at(-1).payload.text), /Only current Telegram admins/);
  assert.match(String(calls.at(-1).payload.text), /Pausing stops future automatic join removals only/);

  await bot.handleCommand({ chat: { id: -100, type: 'supergroup' }, from: { id: 1, username: 'admin' }, message_id: 2, text: '/controls' });
  const groupText = String(calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload?.text || '');
  assert.match(groupText, /private/i);
  assert.equal(groupText.includes('Demo Group'), false);

  const outsider = makeBot({ ownerIds: ['777'] });
  seedAutoBan(outsider.bot, { id: 'auto-route-owner', userId: 5555 });
  await outsider.bot.handleCommand(privateMessage(777, '/controls', 1));
  const outsiderText = String(outsider.calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload?.text || '');
  assert.match(outsiderText, /No groups were found/);
  assert.equal(outsiderText.includes('Demo Group'), false);
  assert.equal(keyboardButtons(outsider.calls).some((item) => String(item.callback_data).includes('controls-join-toggle')), false);
});

test('pause persists across restart, resume works, and resume cannot enable a configured-off policy', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-controls-persist-'));
  const storePath = join(dir, 'events.sqlite');
  const first = makeBot({ store: new EventStore(storePath) });
  await first.bot.setJoinAutoRemovalPaused({ id: -100, type: 'supergroup', title: 'Demo Group' }, true, { id: 1 }, 'test');
  assert.equal(first.bot.joinAutoRemovalPaused(-100), true);
  const audit = first.bot.store.all().find((event) => event.event_type === 'join_auto_removal_setting_changed');
  assert.equal(audit.payload.moderator.id, 1);
  assert.equal(audit.payload.source, 'test');
  assert.equal(audit.chat.id, '-100');

  const restarted = makeBot({ store: new EventStore(storePath) });
  assert.equal(restarted.bot.joinAutoRemovalPaused(-100), true);
  seedLocalReview(restarted.bot, 4242, 'finding-paused');
  await joinUser(restarted.bot, 4242, 7001, 700);
  assert.equal(restarted.calls.some((call) => call.method === 'banChatMember'), false);
  const pausedCheck = restarted.bot.store.all().find((event) => event.event_type === 'join_protection_check');
  assert.equal(pausedCheck.payload.reason, 'join_auto_removal_paused');
  assert.equal(pausedCheck.payload.auto_remove, true);
  assert.ok(pausedCheck.payload.evidence.length > 0);
  assert.ok(pausedCheck.payload.evidence_roots.length > 0);
  assert.notEqual(restarted.bot.config.autoPromoteEvidence, false);

  await restarted.bot.setJoinAutoRemovalPaused({ id: -100, type: 'supergroup', title: 'Demo Group' }, false, { id: 1 }, 'test');
  seedLocalReview(restarted.bot, 4343, 'finding-resumed');
  await joinUser(restarted.bot, 4343, 7002, 701);
  assert.equal(restarted.calls.filter((call) => call.method === 'banChatMember').length, 1);

  const disabled = makeBot({ store: new EventStore(storePath), config: { joinAutoRemove: false } });
  await disabled.bot.setJoinAutoRemovalPaused({ id: -100, type: 'supergroup', title: 'Demo Group' }, false, { id: 1 }, 'test');
  seedLocalReview(disabled.bot, 4444, 'finding-disabled');
  await joinUser(disabled.bot, 4444, 7003, 702);
  assert.equal(disabled.calls.some((call) => call.method === 'banChatMember'), false);
  const decision = disabled.bot.store.all().filter((event) => event.event_type === 'join_protection_check').at(-1).payload;
  assert.equal(decision.reason, 'enforcement_disabled');
});

test('pause is checked again after admin lookup and blocks the destructive race', async () => {
  const { bot, calls } = makeBot();
  seedLocalReview(bot, 4242, 'finding-race');
  const originalCall = bot.call;
  let targetLookups = 0;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.chat_id) === '-100' && String(payload.user_id) === '4242') {
      targetLookups += 1;
      if (targetLookups === 2) await bot.setJoinAutoRemovalPaused({ id: -100, type: 'supergroup', title: 'Demo Group' }, true, { id: 1 }, 'race');
      return { status: 'member', user: { id: 4242 } };
    }
    return originalCall(method, payload);
  };
  await joinUser(bot, 4242, 7101, 710);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const suppressed = bot.store.all().find((event) => event.event_type === 'join_protection_suppressed');
  assert.equal(suppressed.payload.reason, 'join_auto_removal_paused');
  assert.equal(bot.joinAutoRemovalPaused(-100), true);
});

test('recent auto-ban selection and confirmation override without a member appeal and unban safely', async () => {
  const { bot, calls } = makeBot();
  seedAutoBan(bot, { id: 'auto-override', userId: 4242 });
  const originalCall = bot.call;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.chat_id) === '-100' && String(payload.user_id) === '4242') return { status: 'kicked', user: { id: 4242 } };
    return originalCall(method, payload);
  };
  await bot.handleCommand(privateMessage(1, '/controls', 1));
  const open = keyboardButtons(calls).find((item) => String(item.callback_data).includes('controls-ban-open'));
  assert.ok(open);
  await bot.handleCallbackQuery({ id: 'open', from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 55 }, data: open.callback_data });
  const confirm = keyboardButtons(calls, 'editMessageText').find((item) => item.text === 'Override / allow return');
  assert.ok(confirm);
  assert.match(String(calls.find((call) => call.method === 'editMessageText' && call.payload.text.includes('Automatic join ban')).payload.text), /does not revoke a creator-curator global record/);
  await bot.handleCallbackQuery({ id: 'confirm', from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 55 }, data: confirm.callback_data });
  assert.equal(bot.store.all().filter((event) => event.event_type === 'appeal_submitted').length, 0);
  const correction = bot.store.all().find((event) => event.event_type === 'review_overturned');
  assert.equal(correction.payload.correction_source, 'telegram_admin_auto_ban_override');
  assert.equal(correction.payload.creator_global_record_unchanged, true);
  const resolution = bot.store.all().find((event) => event.event_type === 'auto_ban_override');
  assert.equal(resolution.payload.status, 'unban_completed');
  assert.equal(calls.some((call) => call.method === 'unbanChatMember'), true);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.chat_id) === '-100'), false);
  assert.ok(bot.localProtectionOverride({ id: 4242 }, -100));
  assert.match(String(calls.filter((call) => call.method === 'editMessageText').at(-1).payload.text), /unban completed/i);

  await joinUser(bot, 4242, 7201, 720);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('controls reject cross-chat callbacks and owners without live admin status', async () => {
  const { bot, calls } = makeBot({ adminChats: ['-100'] });
  seedAutoBan(bot, { id: 'auto-cross', userId: 4242 });
  await bot.handleCommand(privateMessage(1, '/controls', 1));
  await bot.handleCallbackQuery({
    id: 'cross',
    from: { id: 1 },
    message: { chat: { id: 1, type: 'private' }, message_id: 60 },
    data: 'tc:v1:controls-join-toggle:1:-200:on'
  });
  assert.equal(bot.joinAutoRemovalPaused(-200), false);
  assert.match(String(calls.filter((call) => call.method === 'answerCallbackQuery').at(-1).payload.text), /Only a current admin/);

  const owner = makeBot({ adminChats: ['-100'], ownerIds: ['777'] });
  seedAutoBan(owner.bot, { id: 'auto-owner', userId: 5252 });
  await owner.bot.handleCommand(privateMessage(777, '/controls', 1));
  assert.equal(owner.calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Demo Group')), false);
  const result = await owner.bot.overrideAutomaticBan({ ban: owner.bot.store.all().find((event) => event.id === 'auto-owner'), admin: { id: 777 }, sourceChat: { id: 777, type: 'private' } });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'not_chat_admin');
  assert.equal(owner.calls.some((call) => call.method === 'unbanChatMember'), false);
});

test('private /start exposes reachable protection controls, status, recent auto bans, and appeals without cross-chat leaks', async () => {
  const { bot, calls } = makeBot();
  seedAutoBan(bot, { id: 'auto-menu', userId: 4242 });
  await bot.handleCommand(privateMessage(1, '/start', 1));
  const labels = keyboardButtons(calls).map((item) => String(item.text));
  for (const expected of ['Protection controls', 'Status', 'Recent automatic bans', 'Appeals']) {
    assert.ok(labels.some((label) => label.includes(expected)), `missing ${expected}`);
  }

  const menuButtons = keyboardButtons(calls);
  const click = async (text, id) => {
    const item = menuButtons.find((button) => String(button.text).includes(text));
    assert.ok(item, `missing ${text}`);
    await bot.handleCallbackQuery({ id, from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 80 }, data: item.callback_data });
    return calls.filter((call) => call.method === 'editMessageText').at(-1)?.payload;
  };
  const status = await click('Status', 'menu-status');
  assert.match(String(status?.text), /Protection status/);
  assert.match(String(status?.text), /Demo Group/);
  assert.match(String(status?.text), /Bot rights:/);
  const recent = await click('Recent automatic bans', 'menu-recent');
  assert.match(String(recent?.text), /Demo Group/);
  assert.ok(keyboardButtons(calls, 'editMessageText').some((item) => String(item.text).includes('Review auto-ban')));
  const appeals = await click('Appeals', 'menu-appeals');
  assert.match(String(appeals?.text), /No pending appeals/);

  const outsider = makeBot({ ownerIds: ['777'] });
  seedAutoBan(outsider.bot, { id: 'auto-menu-owner', userId: 5555 });
  await outsider.bot.handleCommand(privateMessage(777, '/start', 1));
  for (const [text, id] of [['Status', 'owner-status'], ['Recent automatic bans', 'owner-recent'], ['Appeals', 'owner-appeals']]) {
    const item = keyboardButtons(outsider.calls).find((button) => String(button.text).includes(text));
    await outsider.bot.handleCallbackQuery({ id, from: { id: 777 }, message: { chat: { id: 777, type: 'private' }, message_id: 81 }, data: item.callback_data });
    const panel = String(outsider.calls.filter((call) => call.method === 'editMessageText').at(-1)?.payload?.text || '');
    assert.doesNotMatch(panel, /Demo Group|4242/);
  }
});

test('stale protection callbacks are denied after live admin demotion', async () => {
  const { bot, calls } = makeBot();
  seedAutoBan(bot, { id: 'auto-stale', userId: 4242 });
  await bot.handleCommand(privateMessage(1, '/controls', 1));
  let liveAdmin = true;
  const original = bot.call;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.chat_id) === '-100' && String(payload.user_id) === '1') {
      return liveAdmin ? { status: 'administrator', user: { id: 1 } } : { status: 'member', user: { id: 1 } };
    }
    return original(method, payload);
  };
  const toggle = keyboardButtons(calls).find((item) => String(item.callback_data).includes('controls-join-toggle'));
  liveAdmin = false;
  await bot.handleCallbackQuery({ id: 'stale-toggle', from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 82 }, data: toggle.callback_data });
  assert.equal(bot.joinAutoRemovalPaused(-100), false);
  assert.match(String(calls.filter((call) => call.method === 'answerCallbackQuery').at(-1).payload.text), /Only a current admin/);
});

test('auto-ban override failure is retryable without an appeal and same-evidence rejoin stays suppressed', async () => {
  const { bot, calls } = makeBot();
  seedLocalReview(bot, 4242, 'finding-auto-retry');
  seedAutoBan(bot, { id: 'auto-retry', userId: 4242, roots: ['review-finding-auto-retry'] });
  let failUnban = true;
  let memberStatus = 'kicked';
  const original = bot.call;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.chat_id) === '-100' && String(payload.user_id) === '4242') {
      return { status: memberStatus, user: { id: 4242 } };
    }
    if (method === 'unbanChatMember') {
      calls.push({ method, payload });
      if (failUnban) throw new Error('telegram 503 unavailable');
      return { ok: true };
    }
    return original(method, payload);
  };
  await bot.handleCommand(privateMessage(1, '/controls', 1));
  const open = keyboardButtons(calls).find((item) => String(item.callback_data).includes('controls-ban-open'));
  await bot.handleCallbackQuery({ id: 'retry-open', from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 83 }, data: open.callback_data });
  const confirm = keyboardButtons(calls, 'editMessageText').find((item) => item.text === 'Override / allow return');
  await bot.handleCallbackQuery({ id: 'retry-confirm', from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 83 }, data: confirm.callback_data });
  assert.equal(bot.store.all().filter((event) => event.event_type === 'review_overturned').length, 1);
  assert.equal(bot.autoBanOverrideRecord('auto-retry').payload.status, 'unban_pending');
  const retry = keyboardButtons(calls, 'editMessageText').find((item) => String(item.text).includes('Retry unban'));
  assert.ok(retry, 'failed override should expose retry');

  failUnban = false;
  await bot.handleCallbackQuery({ id: 'retry-unban', from: { id: 1 }, message: { chat: { id: 1, type: 'private' }, message_id: 83 }, data: retry.callback_data });
  assert.equal(bot.store.all().filter((event) => event.event_type === 'review_overturned').length, 1);
  assert.equal(bot.autoBanOverrideRecord('auto-retry').payload.status, 'unban_completed');
  assert.match(String(calls.filter((call) => call.method === 'editMessageText').at(-1)?.payload?.text), /unban retry completed/i);

  await joinUser(bot, 4242, 7301, 730);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(calls.some((call) => call.method === 'unbanChatMember' && String(call.payload.chat_id) === '-200'), false);
});

test('stale auto-ban retry is rejected after a newer independent ban', async () => {
  const { bot, calls } = makeBot();
  seedLocalReview(bot, 4242, 'finding-superseded');
  seedAutoBan(bot, {
    id: 'auto-superseded',
    userId: 4242,
    roots: ['review-finding-superseded'],
    timestamp: '2026-11-07T10:00:00.000Z'
  });
  const original = bot.call;
  let failUnban = true;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.chat_id) === '-100' && String(payload.user_id) === '4242') {
      return { status: 'kicked', user: { id: 4242 } };
    }
    if (method === 'unbanChatMember') {
      calls.push({ method, payload });
      if (failUnban) throw new Error('telegram 503 unavailable');
      return { ok: true };
    }
    return original(method, payload);
  };
  const ban = bot.store.all().find((event) => event.id === 'auto-superseded');
  const override = await bot.overrideAutomaticBan({ ban, admin: { id: 1 }, sourceChat: { id: 1, type: 'private' } });
  assert.equal(override.ok, true);
  assert.equal(bot.autoBanOverrideRecord('auto-superseded').payload.status, 'unban_pending');

  seedAutoBan(bot, {
    id: 'auto-newer',
    userId: 4242,
    roots: ['newer-root'],
    timestamp: '2026-11-07T11:00:00.000Z'
  });
  failUnban = false;
  const before = calls.filter((call) => call.method === 'unbanChatMember').length;
  const retry = await bot.retryAutomaticBanOverride({
    ban,
    admin: { id: 1 },
    sourceChat: { id: 1, type: 'private' },
    requestId: 'stale-retry'
  });
  assert.equal(retry.ok, false);
  assert.equal(retry.error, 'ban_superseded');
  assert.equal(retry.newer_ban_event_id, 'auto-newer');
  assert.equal(calls.filter((call) => call.method === 'unbanChatMember').length, before);
});

test('first automatic-ban override is rejected after a newer independent ban', async () => {
  const { bot, calls } = makeBot();
  seedAutoBan(bot, {
    id: 'auto-first-override-old',
    userId: 4343,
    timestamp: '2026-11-07T10:00:00.000Z'
  });
  seedAutoBan(bot, {
    id: 'auto-first-override-newer',
    userId: 4343,
    timestamp: '2026-11-07T11:00:00.000Z'
  });
  const before = calls.filter((call) => call.method === 'unbanChatMember').length;
  const result = await bot.overrideAutomaticBan({
    ban: bot.store.all().find((event) => event.id === 'auto-first-override-old'),
    admin: { id: 1 },
    sourceChat: { id: 1, type: 'private' }
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'ban_superseded');
  assert.equal(result.newer_ban_event_id, 'auto-first-override-newer');
  assert.equal(calls.filter((call) => call.method === 'unbanChatMember').length, before);
  assert.equal(bot.store.all().some((event) => event.event_type === 'review_overturned'), false);
  assert.equal(bot.store.all().some((event) => event.event_type === 'auto_ban_override'), false);
});

test('equal-time independent ban fails closed before a first automatic-ban override', async () => {
  const { bot, calls } = makeBot();
  seedAutoBan(bot, {
    id: 'auto-equal-old',
    userId: 4344,
    timestamp: '2026-11-07T10:00:00.000Z'
  });
  seedAutoBan(bot, {
    id: 'auto-equal-distinct',
    userId: 4344,
    timestamp: '2026-11-07T10:00:00.000Z'
  });
  const before = calls.filter((call) => call.method === 'unbanChatMember').length;
  const result = await bot.overrideAutomaticBan({
    ban: bot.store.all().find((event) => event.id === 'auto-equal-old'),
    admin: { id: 1 },
    sourceChat: { id: 1, type: 'private' }
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'ban_superseded');
  assert.equal(result.newer_ban_event_id, 'auto-equal-distinct');
  assert.equal(calls.filter((call) => call.method === 'unbanChatMember').length, before);
  assert.equal(bot.store.all().some((event) => event.event_type === 'review_overturned'), false);
});


test('native admin ban idempotency keeps distinct same-second transitions and dedupes redelivery after restart', async () => {
  const { bot } = makeBot({ config: { autoPromoteEvidence: false } });
  const chat = { id: -100, title: 'Demo Group', type: 'supergroup' };
  const member = { id: 4545, username: 'target' };
  const update = (date = 1000) => ({
    chat,
    from: { id: 1, username: 'admin' },
    date,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });
  const count = () => bot.store.all().filter((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4545').length;

  bot.currentUpdateId = 100;
  await bot.handleNativeAdminBan(update(1000), member, 'member', 'kicked');
  bot.currentUpdateId = 101;
  await bot.handleNativeAdminBan(update(1000), member, 'member', 'kicked');
  assert.equal(count(), 2);

  bot.currentUpdateId = 101;
  await bot.handleNativeAdminBan(update(1000), member, 'member', 'kicked');
  assert.equal(count(), 2);

  const restarted = new TelegramShieldBot({
    config: bot.config,
    analyzer: LOW_ANALYZER,
    dkg: bot.dkg,
    store: bot.store
  });
  restarted.currentUpdateId = 101;
  await restarted.handleNativeAdminBan(update(1000), member, 'member', 'kicked');
  assert.equal(count(), 2);
});

test('resume stays bounded by configured chat allowlist and missing bot rights', async () => {
  const bounded = makeBot({ config: { joinAutoRemoveChats: ['-200'] } });
  seedLocalReview(bounded.bot, 4242, 'finding-bounded');
  await bounded.bot.setJoinAutoRemovalPaused({ id: -100, type: 'supergroup', title: 'Demo Group' }, false, { id: 1 }, 'test');
  await joinUser(bounded.bot, 4242, 7401, 740);
  assert.equal(bounded.calls.some((call) => call.method === 'banChatMember'), false);

  const noRights = makeBot();
  seedLocalReview(noRights.bot, 4343, 'finding-rights');
  const original = noRights.bot.call;
  noRights.bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.user_id) === '999') return { status: 'member', user: { id: 999 } };
    return original(method, payload);
  };
  await noRights.bot.setJoinAutoRemovalPaused({ id: -100, type: 'supergroup', title: 'Demo Group' }, false, { id: 1 }, 'test');
  await joinUser(noRights.bot, 4343, 7402, 741);
  assert.equal(noRights.calls.some((call) => call.method === 'banChatMember'), false);
  const suppressed = noRights.bot.store.all().filter((event) => event.event_type === 'join_protection_suppressed').at(-1);
  assert.equal(suppressed.payload.reason, 'missing_ban_rights');
});

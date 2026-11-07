import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TelegramShieldBot } from '../src/telegram.js';
import { EventStore } from '../src/store.js';

const LOW_ANALYZER = () => ({ is_scam: false, confidence: 0, local_confidence: 0, scam_type: 'unknown', evidence: [], recommended_action: 'ignore' });
const LOW_INTEL = { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] };

function makeBot({ config = {}, chatAdmins = [{ id: 1, username: 'admin' }], unban = 'ok' } = {}) {
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
  const bot = new TelegramShieldBot({
    config: {
      telegramToken: 'test',
      adminIds: new Set(['1']),
      botOwnerIds: new Set(),
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
      joinAutoRemove: false,
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
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-appeals-')), 'events.sqlite')),
    llm: null
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') {
      if (payload.user_id === 999) return { status: 'administrator', can_restrict_members: true, can_delete_messages: true };
      return chatAdmins.some((user) => String(user.id) === String(payload.user_id))
        ? { status: 'administrator', user: { id: payload.user_id } }
        : { status: 'member', user: { id: payload.user_id } };
    }
    if (method === 'getChatAdministrators') return chatAdmins.map((user) => ({ status: 'administrator', user }));
    if (method === 'unbanChatMember') {
      if (unban === 'fail') throw new Error('telegram unban failed');
      return { ok: true };
    }
    if (method === 'sendMessage') return { message_id: calls.length, ...payload };
    return { ok: true };
  };
  return { bot, calls, writes };
}

function seedBan(bot, { id = 'ban-1', userId = 4242, chatId = -100, roots = [`root-${id}`] } = {}) {
  bot.store.append({
    id,
    event_type: 'ban_executed',
    timestamp: new Date().toISOString(),
    chat: { id: chatId, type: 'supergroup', title: 'Demo Group' },
    user: { id: userId, username: 'accused' },
    payload: {
      target: { id: userId, username: 'accused' },
      target_key: `id:${userId}`,
      confidence: 100,
      admin_verified: true,
      source: 'native_chat_member_admin_ban',
      evidence_root_ids: roots,
      evidence: ['native admin ban']
    }
  });
}

function privateMessage(userId = 4242, text = '/appeal', messageId = 1) {
  return { chat: { id: userId, type: 'private' }, from: { id: userId, username: `user${userId}` }, message_id: messageId, text };
}

test('private /start and /appeal reveal only the caller own locally stored cases', async () => {
  const { bot, calls } = makeBot();
  seedBan(bot, { id: 'ban-owner', userId: 4242 });
  seedBan(bot, { id: 'ban-other', userId: 5555 });
  await bot.handleCommand(privateMessage(4242, '/start', 1));
  assert.match(String(calls.at(-1).payload.text), /\/appeal/);
  assert.match(String(calls.at(-1).payload.text), /Telegram only lets the bot message you/);

  await bot.handleCommand(privateMessage(4242, '/appeal', 2));
  const listText = String(calls.at(-1).payload.text);
  assert.match(listText, /case-[a-f0-9]{10}/);
  assert.doesNotMatch(listText, /5555|accused|Demo Group|-100/);

  await bot.handleCommand(privateMessage(5555, '/appeal', 3));
  assert.match(String(calls.at(-1).payload.text), /case-[a-f0-9]{10}/);
  assert.doesNotMatch(String(calls.at(-1).payload.text), /4242|accused|Demo Group|-100/);
  await bot.handleCommand(privateMessage(7777, '/appeal', 4));
  assert.match(String(calls.at(-1).payload.text), /No locally stored ban case/);
});

test('private appeals are bounded, deduplicated, rate limited, and local-only', async () => {
  const { bot, calls, writes } = makeBot({ config: { appealMaxPerHour: 1 } });
  seedBan(bot, { id: 'ban-a', userId: 4242, chatId: -100 });
  seedBan(bot, { id: 'ban-b', userId: 4242, chatId: -200 });
  await bot.handleCommand(privateMessage(4242, '/appeal', 1));
  const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} I believe this was a false positive`, 2));
  assert.equal(bot.store.all().filter((event) => event.event_type === 'appeal_submitted').length, 1);
  const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');
  assert.equal(appeal.local_only, true);
  assert.equal(appeal.payload.consent_to_share, false);
  assert.equal(appeal.payload.appealant_id, '4242');
  assert.equal(writes.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.chat_id) === '-100'), false);

  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} duplicate reason text`, 3));
  assert.equal(bot.store.all().filter((event) => event.event_type === 'appeal_submitted').length, 1);

  await bot.handleCommand(privateMessage(4242, '/appeal', 4));
  const secondRef = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/g).find((value) => value !== ref);
  await bot.handleCommand(privateMessage(4242, `/appeal ${secondRef} a different case reason`, 5));
  assert.match(String(calls.at(-1).payload.text), /Too many appeals/);
  assert.equal(bot.store.all().filter((event) => event.event_type === 'appeal_submitted').length, 1);
});

test('only an actual admin of the affected group can uphold or overturn an appeal', async () => {
  const { bot, calls } = makeBot({ chatAdmins: [{ id: 1, username: 'admin' }] });
  seedBan(bot, { id: 'ban-scope', userId: 4242 });
  await bot.handleCommand(privateMessage(4242, '/appeal', 1));
  const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} please review this ban`, 2));
  const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');
  const appealRef = appeal.payload.appeal_ref;

  const outsider = await bot.resolveAppeal({ appealRef, admin: { id: 777 }, decision: 'uphold', sourceChat: { id: 777, type: 'private' } });
  assert.equal(outsider.ok, false);
  assert.equal(outsider.error, 'not_chat_admin');
  assert.equal(bot.store.all().some((event) => event.event_type === 'appeal_resolved'), false);

  await bot.handleCallbackQuery({
    id: 'appeal-callback',
    from: { id: 1, username: 'admin' },
    message: { chat: { id: 1, type: 'private' }, message_id: 99 },
    data: `tc:v1:appeal-uphold:admin:${appealRef}`
  });
  const resolved = bot.store.all().find((event) => event.event_type === 'appeal_resolved');
  assert.equal(resolved.payload.decision, 'uphold');
  assert.equal(resolved.payload.status, 'upheld');
});

test('bot owners without current group admin status cannot view, resolve, or receive unrelated appeal details', async () => {
  const { bot, calls } = makeBot({ config: { botOwnerIds: new Set(['777']) }, chatAdmins: [{ id: 1, username: 'admin' }] });
  seedBan(bot, { id: 'ban-owner-scope', userId: 4242 });
  await bot.handleCommand(privateMessage(4242, '/appeal', 1));
  const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} owner scope test`, 2));
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.chat_id) === '777'), false);
  const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');

  await bot.handleCommand(privateMessage(777, '/appeals', 3));
  assert.match(String(calls.at(-1).payload.text), /No pending appeals/);
  assert.doesNotMatch(String(calls.at(-1).payload.text), /owner scope test/);

  const ownerResult = await bot.resolveAppeal({ appealRef: appeal.payload.appeal_ref, admin: { id: 777 }, decision: 'overturn', sourceChat: { id: 777, type: 'private' } });
  assert.equal(ownerResult.ok, false);
  assert.equal(ownerResult.error, 'not_chat_admin');
  assert.equal(calls.some((call) => call.method === 'unbanChatMember'), false);
  assert.equal(bot.store.all().some((event) => event.event_type === 'appeal_resolved'), false);

  const originalCall = bot.call;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.chat_id) === '-100' && String(payload.user_id) === '1') throw new Error('telegram admin lookup failed');
    return originalCall(method, payload);
  };
  const failedLookup = await bot.resolveAppeal({ appealRef: appeal.payload.appeal_ref, admin: { id: 1 }, decision: 'overturn', sourceChat: { id: 1, type: 'private' } });
  assert.equal(failedLookup.ok, false);
  assert.equal(failedLookup.error, 'not_chat_admin');
  assert.equal(calls.some((call) => call.method === 'unbanChatMember'), false);
});

test('local appeal override persists through same-lineage wrappers without a creator URL', async () => {
  const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
  const chat = { id: -100, type: 'supergroup', title: 'Demo Group' };
  const now = Date.now();
  const finding = (id) => ({
    id,
    event_type: 'risk_review_needed',
    timestamp: new Date(now - 5000).toISOString(),
    chat,
    user: { id: 4242, username: 'accused' },
    payload: { target: { id: 4242 }, target_key: 'id:4242', confidence: 90, recommended_action: 'admin_review' }
  });
  const review = (id, targetEventId, stamp) => ({
    id,
    event_type: 'review_upheld',
    timestamp: new Date(stamp).toISOString(),
    chat,
    user: { id: 1, username: 'admin' },
    payload: {
      target_event_id: targetEventId,
      reviewed_target: { id: 4242, username: 'accused' },
      reviewed_target_key: 'id:4242',
      target_chat_id: '-100',
      local_approval: true,
      approval_source: 'telegram_admin_review',
      admin_verified: true,
      confidence: 96,
      community_id: '-100'
    }
  });
  bot.store.append(finding('finding-lineage'));
  bot.store.append(review('review-wrapper-1', 'finding-lineage', now - 4000));
  seedBan(bot, { id: 'ban-lineage', userId: 4242, roots: ['review-wrapper-1'] });
  bot.store.append({
    id: 'appeal-lineage',
    event_type: 'appeal_submitted',
    timestamp: new Date(now - 3000).toISOString(),
    chat: { id: 4242, type: 'private' },
    user: { id: 4242 },
    payload: {
      appeal_ref: 'ap-lineage',
      ban_event_id: 'ban-lineage',
      case_ref: 'case-lineage',
      appealant_id: '4242',
      target: { id: 4242 },
      target_chat_id: '-100',
      reason: 'please review this local ban',
      local_only: true
    }
  });
  const resolved = await bot.resolveAppeal({ appealRef: 'ap-lineage', admin: { id: 1 }, decision: 'overturn', sourceChat: { id: 1, type: 'private' } });
  assert.equal(resolved.ok, true);
  assert.equal(bot.localProtectionOverride({ id: 4242 }, -100)?.event_type, 'appeal_resolved');

  bot.store.append(review('review-wrapper-2', 'finding-lineage', now + 1000));
  assert.ok(bot.localProtectionOverride({ id: 4242 }, -100));
  assert.notEqual(bot.localProtectionDecision({ id: 4242 }, -100).action, 'remove');
  await bot.handleNewMembers({
    chat,
    from: { id: 1, username: 'admin' },
    message_id: 8101,
    date: 8101,
    new_chat_members: [{ id: 4242, username: 'accused', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);

  bot.store.append(finding('finding-independent'));
  bot.store.append(review('review-wrapper-3', 'finding-independent', now + 2000));
  assert.equal(bot.localProtectionOverride({ id: 4242 }, -100), null);
  assert.equal(bot.localProtectionDecision({ id: 4242 }, -100).action, 'remove');
  bot.closeMembershipEpisode(-100, 4242, { eventDate: 8101, updateId: 8101, messageId: 8101 });
  await bot.handleNewMembers({
    chat,
    from: { id: 1, username: 'admin' },
    message_id: 8102,
    date: 8102,
    new_chat_members: [{ id: 4242, username: 'accused', is_bot: false }]
  });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
});

test('a final upheld appeal is not accepted again as a dead pending case', async () => {
  const { bot, calls } = makeBot({ chatAdmins: [{ id: 1, username: 'admin' }] });
  seedBan(bot, { id: 'ban-upheld-final', userId: 4242 });
  await bot.handleCommand(privateMessage(4242, '/appeal', 1));
  const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} first appeal reason`, 2));
  const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');
  const resolved = await bot.resolveAppeal({ appealRef: appeal.payload.appeal_ref, admin: { id: 1 }, decision: 'uphold', sourceChat: { id: 1, type: 'private' } });
  assert.equal(resolved.ok, true);
  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} second appeal with new words`, 3));
  assert.match(String(calls.at(-1).payload.text), /finally upheld/);
  assert.equal(bot.store.all().filter((event) => event.event_type === 'appeal_submitted').length, 1);
  assert.equal(bot.pendingAppeals().length, 0);
});

test('overturn records a local correction, idempotent unban, and creator reconsideration without touching the global record', async () => {
  const { bot, calls, writes } = makeBot({ config: { creatorCuratorUrl: 'http://127.0.0.1:1' } });
  seedBan(bot, { id: 'ban-overturn', userId: 4242 });
  await bot.handleCommand(privateMessage(4242, '/appeal', 1));
  const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
  await bot.handleCommand(privateMessage(4242, `/appeal ${ref} an admin told me this was a mistake`, 2));
  const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');

  const result = await bot.resolveAppeal({ appealRef: appeal.payload.appeal_ref, admin: { id: 1 }, decision: 'overturn', reason: 'admin verified the account was misidentified', sourceChat: { id: 1, type: 'private' } });
  assert.equal(result.ok, true);
  assert.equal(result.unban.ok, true);
  const correction = bot.store.all().find((event) => event.event_type === 'review_overturned');
  assert.equal(correction.chat.id, -100);
  assert.equal(correction.payload.correction_source, 'telegram_private_appeal_overturn');
  assert.equal(correction.payload.creator_global_record_unchanged, true);
  const resolved = bot.store.all().find((event) => event.event_type === 'appeal_resolved');
  assert.equal(resolved.payload.status, 'overturned');
  assert.equal(bot.store.all().some((event) => event.event_type === 'appeal_unban_completed'), true);
  assert.equal(bot.store.all().some((event) => event.event_type === 'creator_reconsideration_requested'), true);
  assert.equal(writes.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.chat_id) === '-100'), false);

  await bot.handleNewMembers({
    chat: { id: -100, type: 'supergroup', title: 'Demo Group' },
    from: { id: 1, username: 'admin' },
    message_id: 9001,
    date: 9001,
    new_chat_members: [{ id: 4242, username: 'accused', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const check = bot.store.all().find((event) => event.event_type === 'join_protection_check');
  assert.equal(check.payload.reason, 'local_overturn');
  assert.equal(check.payload.decision, 'allow');
});

test('timeout and 5xx unban failures remain retryable with new idempotent attempt keys', async () => {
  for (const errorMode of ['timeout', '5xx']) {
    const { bot, calls } = makeBot();
    seedBan(bot, { id: `ban-retry-${errorMode}`, userId: 4343 });
    await bot.handleCommand(privateMessage(4343, '/appeal', 1));
    const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
    await bot.handleCommand(privateMessage(4343, `/appeal ${ref} please check the evidence again`, 2));
    const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');
    const originalCall = bot.call;
    let restored = false;
    let unbanCalls = 0;
    bot.call = async (method, payload) => {
      if (method === 'unbanChatMember') {
        unbanCalls += 1;
        calls.push({ method, payload });
        if (!restored) {
          const error = new Error(errorMode === 'timeout' ? 'telegram timeout' : 'telegram 500 server error');
          if (errorMode === 'timeout') error.telegramOutcomeUnknown = true;
          throw error;
        }
        return { ok: true };
      }
      if (method === 'getChatMember' && String(payload.user_id) === '4343') return { status: 'kicked', user: { id: 4343 } };
      return originalCall(method, payload);
    };
    const result = await bot.resolveAppeal({ appealRef: appeal.payload.appeal_ref, admin: { id: 1 }, decision: 'overturn', sourceChat: { id: 1, type: 'private' } });
    assert.equal(result.ok, true);
    assert.equal(result.unban.ok, false, errorMode);
    assert.equal(bot.store.all().filter((event) => event.event_type === 'appeal_unban_failed').length, 3, errorMode);
    assert.equal(unbanCalls, 3, errorMode);
    const resolved = bot.store.all().find((event) => event.event_type === 'appeal_resolved');
    assert.equal(resolved.payload.status, 'overturned_unban_pending');
    assert.match(resolved.payload.unban_error, /telegram (timeout|500)/);

    restored = true;
    const retry = await bot.retryAppealUnban(appeal.payload.appeal_ref, { id: 1 }, { id: 1, type: 'private' });
    assert.equal(retry.ok, true, errorMode);
    assert.equal(unbanCalls, 4, errorMode);
    assert.equal(bot.store.all().some((event) => event.event_type === 'appeal_unban_completed'), true);
  }
});

test('retry reconciles an already-unbanned member without a duplicate unban call', async () => {
  const { bot, calls } = makeBot();
  seedBan(bot, { id: 'ban-reconcile', userId: 4545 });
  await bot.handleCommand(privateMessage(4545, '/appeal', 1));
  const ref = String(calls.at(-1).payload.text).match(/case-[a-f0-9]{10}/)[0];
  await bot.handleCommand(privateMessage(4545, `/appeal ${ref} please reconcile this ban`, 2));
  const appeal = bot.store.all().find((event) => event.event_type === 'appeal_submitted');
  const originalCall = bot.call;
  let memberStatus = 'kicked';
  let unbanCalls = 0;
  bot.call = async (method, payload) => {
    if (method === 'getChatMember' && String(payload.user_id) === '4545') return { status: memberStatus, user: { id: 4545 } };
    if (method === 'unbanChatMember') {
      unbanCalls += 1;
      throw new Error('telegram 503 unavailable');
    }
    return originalCall(method, payload);
  };
  const resolved = await bot.resolveAppeal({ appealRef: appeal.payload.appeal_ref, admin: { id: 1 }, decision: 'overturn', sourceChat: { id: 1, type: 'private' } });
  assert.equal(resolved.ok, true);
  assert.equal(resolved.unban.ok, false);
  assert.equal(unbanCalls, 3);
  memberStatus = 'member';
  const retry = await bot.retryAppealUnban(appeal.payload.appeal_ref, { id: 1 }, { id: 1, type: 'private' });
  assert.equal(retry.ok, true);
  assert.equal(retry.unban.reconciled, true);
  assert.equal(unbanCalls, 3);
  assert.equal(bot.store.all().some((event) => event.event_type === 'appeal_unban_completed' && event.payload?.reconciled === true), true);
});

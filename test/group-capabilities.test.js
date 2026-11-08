import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TelegramShieldBot } from '../src/telegram.js';
import { EventStore } from '../src/store.js';
import { GROUP_MODE_ADMIN, GROUP_MODE_OBSERVER, resolveGroupCapabilities } from '../src/group-capabilities.js';

const LOW_INTEL = { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] };
const HIGH_ANALYZER = () => ({ is_scam: true, confidence: 90, local_confidence: 90, scam_type: 'impersonation', evidence: ['observed risk signal'], recommended_action: 'admin_review' });
const LOW_ANALYZER = () => ({ is_scam: false, confidence: 0, local_confidence: 0, scam_type: 'unknown', evidence: [], recommended_action: 'ignore' });

function groupState(overrides = {}) {
  return {
    status: 'member',
    canRestrict: false,
    canDelete: false,
    adminUsers: [],
    failBotLookup: false,
    sendFails: false,
    ...overrides
  };
}

function makeBot({ groups = {}, privacy = false, analyzer = LOW_ANALYZER, protection = { ok: true, evidence: [], error: '' }, config = {} } = {}) {
  const calls = [];
  const dkg = {
    async queryRiskIndicators() { return LOW_INTEL; },
    async queryAdminHistoryForActor() { return { hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] }; },
    async queryCampaignModerationRoots() { return { events: [] }; },
    async queryProtectionEvidence() { return protection; },
    async writeEvent(event) { return { eventId: event.id, ual: 'did:dkg:context-graph:tracabot/_shared_memory' }; },
    async runtimeStatus() { return { capabilities: {} }; },
    async getStats() { return { total: 0, source: 'local' }; },
    async validateUal() { return { ok: true }; },
    async ensureContextGraph() {}
  };
  const bot = new TelegramShieldBot({
    config: {
      telegramToken: 'test',
      adminIds: new Set(['1']),
      botOwnerIds: new Set(),
      autoDelete: false,
      autoRestrict: false,
      autoBan: false,
      knownCampaignAutoBan: true,
      knownCampaignMinBanRoots: 2,
      knownCampaignPatterns: [],
      warnThreshold: 60,
      restrictThreshold: 75,
      banThreshold: 85,
      actionThreshold: 85,
      conversational: false,
      llmProvider: 'off',
      conversationMinConfidence: 60,
      proactiveReplyThreshold: 75,
      conversationRateLimitSeconds: 60,
      conversationMaxChars: 700,
      contextGraph: 'tracabot',
      proactiveScanMinutes: 30,
      agentDid: 'did:dkg:agent:test',
      autoDeleteBotMessages: true,
      botMessageTtlSeconds: 60,
      challengeMessageTtlSeconds: 120,
      successMessageTtlSeconds: 45,
      joinChallenge: false,
      joinChallengeMode: 'memory-card',
      joinChallengeAssetUrl: '',
      joinChallengeQaBank: [],
      joinChallengeTtlSeconds: 60,
      joinChallengeMaxAttempts: 3,
      joinChallengeRepeatFailureThreshold: 2,
      joinChallengeRepeatBadAttemptThreshold: 3,
      joinChallengeAction: 'kick',
      joinChallengeDeleteOnPass: true,
      joinChallengeDeleteBadAttempts: true,
      joinChallengeDkgValidate: true,
      joinAutoRemove: false,
      joinAutoRemoveChats: [],
      joinEvidenceMaxAgeDays: 180,
      joinMinConfirmedRoots: 1,
      joinTrustedLayers: ['local'],
      submitSharedEvidence: false,
      channelMemory: false,
      wmArtifacts: false,
      pendingReviewNotifications: true,
      proactiveAlertCrossGroup: true,
      observerAdvisories: false,
      ...config
    },
    analyzer,
    dkg,
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-modes-')), 'events.jsonl')),
    llm: null
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getUpdates') return [];
    if (method === 'getMe') return { id: 999, username: 'tracethembot', can_read_all_group_messages: privacy === true };
    const group = groups[String(payload?.chat_id)] || null;
    if (method === 'getChatMember') {
      if (String(payload.user_id) === '999') {
        if (!group || group.failBotLookup) throw new Error('permission lookup unavailable');
        return {
          status: group.status,
          can_restrict_members: group.canRestrict === true,
          can_delete_messages: group.canDelete === true
        };
      }
      return (group?.adminUsers || []).map(String).includes(String(payload.user_id))
        ? { status: 'administrator', user: { id: payload.user_id } }
        : { status: 'member', user: { id: payload.user_id } };
    }
    if (method === 'getChatAdministrators') {
      return (group?.adminUsers || []).map((id) => ({ status: 'administrator', user: { id } }));
    }
    if (method === 'sendMessage' && group?.sendFails) throw new Error('send denied');
    if (method === 'sendMessage') return { message_id: calls.length, ...payload };
    return { ok: true };
  };
  return { bot, calls, groups };
}

const BOT = { id: 999, username: 'tracethembot', is_bot: true };
const GROUP_A = { id: -100, type: 'supergroup', title: 'Admin Group' };
const GROUP_B = { id: -200, type: 'supergroup', title: 'Observer Group' };

async function waitFor(condition) {
  for (let index = 0; index < 200; index += 1) {
    if (condition()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error('condition was not reached');
}

function delayNextBotLookup(bot, calls, member) {
  let release = null;
  let delayed = true;
  const baseCall = bot.call;
  bot.call = async (method, payload) => {
    if (delayed && method === 'getChatMember' && String(payload.user_id) === '999') {
      calls.push({ method, payload });
      return new Promise((resolve) => {
        release = () => resolve(member);
      });
    }
    return baseCall(method, payload);
  };
  return {
    release: () => { delayed = false; release(); },
    pending: () => Boolean(release)
  };
}

function delayRecordOnce(bot, eventType) {
  const baseRecord = bot.record.bind(bot);
  let release = null;
  let delayed = false;
  bot.record = async (type, message, payload, options) => {
    const result = await baseRecord(type, message, payload, options);
    if (type === eventType && !delayed) {
      delayed = true;
      await new Promise((resolve) => { release = resolve; });
    }
    return result;
  };
  return {
    pending: () => delayed && Boolean(release),
    release: () => release()
  };
}

async function startActiveChallenge(bot, user) {
  await bot.handleNewMembers({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    message_id: 900,
    new_chat_members: [user]
  });
  const challenge = bot.joinChallenges.get(`-100:${user.id}`);
  assert.ok(challenge);
  return challenge;
}

test('effective mode is resolved per live group, not globally or from config', async () => {
  const { bot } = makeBot({ groups: { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }), '-200': groupState() } });
  const [a, b] = await Promise.all([bot.getGroupCapabilities(-100), bot.getGroupCapabilities(-200)]);
  assert.equal(a.mode, GROUP_MODE_ADMIN);
  assert.equal(a.canRemoveMembers, true);
  assert.equal(a.canObserveBanEvents, true);
  assert.equal(b.mode, GROUP_MODE_OBSERVER);
  assert.equal(b.canRemoveMembers, false);
  assert.equal(b.canObserveBanEvents, false);
  assert.equal(b.coverage.comprehensive, false);
  assert.equal(a.chatId, '-100');
  assert.equal(b.chatId, '-200');
});

test('same bot observes a service-message join in observer group and logs without action', async () => {
  const { bot, calls } = makeBot({
    groups: { '-200': groupState() },
    analyzer: HIGH_ANALYZER,
    config: { joinAutoRemove: true }
  });
  await bot.handleNewMembers({
    chat: GROUP_B,
    from: { id: 1, username: 'admin' },
    message_id: 10,
    date: 1000,
    new_chat_members: [{ id: 4242, username: 'new_user', first_name: 'New', is_bot: false }]
  });
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_protection_check' && event.user?.id === 4242));
  await bot.startJoinChallenge({ chat: GROUP_B, from: { id: 1 }, message_id: 11 }, { id: 4243, username: 'challenged', is_bot: false });
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_skipped_no_admin'));
  await assert.rejects(() => bot.deleteMessage(-200, 12), /delete permission unavailable|not an active member/);
  await assert.rejects(() => bot.unbanMember(-200, 4242), /restrict\/ban permission unavailable|not an active member/);
  assert.equal(calls.some((call) => ['banChatMember', 'restrictChatMember', 'deleteMessage', 'unbanChatMember'].includes(call.method)), false);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -200), false);
});

test('ordinary message visibility distinguishes privacy mode from admin event access', async () => {
  const limited = makeBot({ groups: { '-200': groupState() }, privacy: false });
  const limitedCaps = await limited.bot.getGroupCapabilities(-200);
  assert.equal(limitedCaps.ordinaryMessageVisibility, 'limited');
  assert.equal(limitedCaps.coverage.ordinaryMessages, 'privacy_limited');

  const open = makeBot({ groups: { '-200': groupState() }, privacy: true });
  const openCaps = await open.bot.getGroupCapabilities(-200);
  assert.equal(openCaps.ordinaryMessageVisibility, 'broader_delivery_unverified');
  assert.equal(openCaps.broaderDeliveryUnverified, true);
  assert.equal(openCaps.coverage.ordinaryMessages, 'broader_delivery_unverified');

  const admin = makeBot({ groups: { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) }, privacy: false });
  const adminCaps = await admin.bot.getGroupCapabilities(-100);
  assert.equal(adminCaps.ordinaryMessageVisibility, 'all');
  assert.equal(adminCaps.canReadAllGroupMessages, false);

  const removedWithBroaderDelivery = makeBot({ groups: { '-200': groupState({ status: 'kicked' }) }, privacy: true });
  for (const status of ['kicked', 'left']) {
    const removed = makeBot({ groups: { '-200': groupState({ status }) }, privacy: true });
    const removedCaps = await removed.bot.getGroupCapabilities(-200);
    assert.equal(removedCaps.removed, true);
    assert.equal(removedCaps.ordinaryMessageVisibility, 'none');
    assert.equal(removedCaps.coverage.ordinaryMessages, 'none');
    assert.equal(removedCaps.canPostMessages, false);
  }
  const removedCaps = await removedWithBroaderDelivery.bot.getGroupCapabilities(-200);
  assert.equal(removedCaps.removed, true);
});

test('observer mode is quiet by default across automatic notification branches', async () => {
  const { bot, calls } = makeBot({ groups: { '-200': groupState() }, analyzer: HIGH_ANALYZER, config: { observerAdvisories: false } });
  const message = { chat: GROUP_B, from: { id: 4242, username: 'member' }, message_id: 20 };
  await bot.record('risk_review_needed', message, { confidence: 90, evidence: ['review evidence'] }, { writeDkg: false });
  await bot.record('risk_action_suppressed', message, { confidence: 90, evidence: ['suppressed evidence'] }, { writeDkg: false });
  await bot.record('proactive_cross_group_warning', message, { confidence: 90, evidence: ['prior admin action'] }, { writeDkg: false });
  await bot.handleMessage({ ...message, text: 'scam support verify wallet now' });

  assert.equal(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -200), false);
  assert.equal(await bot.alertAdmins(message, { confidence: 90, evidence: [] }, null), null);
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_review_needed'));
  assert.ok(bot.store.all().some((event) => event.event_type === 'proactive_cross_group_warning'));
});

test('explicit observer advisories are bounded, evidence-backed, and safe when send is denied', async () => {
  const { bot, calls } = makeBot({
    groups: { '-200': groupState() },
    analyzer: HIGH_ANALYZER,
    config: { observerAdvisories: true }
  });
  const message = { chat: GROUP_B, from: { id: 4242, username: 'private_member_name' }, message_id: 21 };
  await bot.record('risk_review_needed', message, { confidence: 90, evidence: ['observed link pattern'] }, { writeDkg: false });
  await bot.record('risk_review_needed', { ...message, message_id: 22 }, { confidence: 92, evidence: ['second signal'] }, { writeDkg: false });

  const advisories = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -200);
  assert.equal(advisories.length, 1);
  assert.match(advisories[0].payload.text, /observer note/i);
  assert.match(advisories[0].payload.text, /not a confirmed scam finding/i);
  assert.match(advisories[0].payload.text, /coverage is partial/i);
  assert.doesNotMatch(advisories[0].payload.text, /private_member_name|confirmed scam is|banned|scammer/i);

  const denied = makeBot({
    groups: { '-200': groupState({ sendFails: true }) },
    analyzer: HIGH_ANALYZER,
    config: { observerAdvisories: true }
  });
  const event = await denied.bot.record('risk_review_needed', message, { confidence: 90, evidence: ['observed link pattern'] }, { writeDkg: false });
  assert.ok(event.id);
  assert.ok(denied.bot.store.all().some((item) => item.id === event.id));
});

test('observer advisories never send unsupported allegations or low-confidence reviews', async () => {
  const { bot, calls } = makeBot({ groups: { '-200': groupState() }, config: { observerAdvisories: true } });
  const message = { chat: GROUP_B, from: { id: 4242, username: 'member' }, message_id: 30 };
  await bot.record('risk_review_needed', message, { confidence: 20, evidence: ['weak note'] }, { writeDkg: false });
  await bot.record('risk_review_needed', { ...message, message_id: 31 }, { confidence: 95, evidence: [] }, { writeDkg: false });
  await bot.record('risk_review_needed', { ...message, message_id: 32 }, { confidence: 95, target: { id: 4242, username: 'name_only' } }, { writeDkg: false });
  assert.equal(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -200), false);
});

test('one bot keeps admin and observer groups isolated for notices and ban capture', async () => {
  const { bot, calls } = makeBot({
    groups: {
      '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }),
      '-200': groupState()
    }
  });
  await bot.record('risk_review_needed', { chat: GROUP_A, from: { id: 11 }, message_id: 51 }, { confidence: 90, evidence: ['admin group signal'] }, { writeDkg: false });
  await bot.record('risk_review_needed', { chat: GROUP_B, from: { id: 12 }, message_id: 52 }, { confidence: 90, evidence: ['observer group signal'] }, { writeDkg: false });
  assert.equal(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100 && /pending review item/i.test(call.payload.text)), true);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -200), false);

  const member = { id: 610, username: 'admin_banned', is_bot: false };
  bot.currentUpdateId = 901;
  await bot.handleChatMemberUpdate({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    date: 4000,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed' && event.user?.id === 610);
  assert.ok(ban);
  assert.equal(ban.payload.bot_mode, GROUP_MODE_ADMIN);
  assert.equal((await bot.getGroupCapabilities(-200)).mode, GROUP_MODE_OBSERVER);
});

test('delete permission requires explicit admin true and blocks callEffect without it', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: false }) };
  const { bot, calls } = makeBot({ groups });
  const caps = await bot.getGroupCapabilities(-100);
  assert.equal(caps.mode, GROUP_MODE_ADMIN);
  assert.equal(caps.canDeleteMessages, false);
  await assert.rejects(() => bot.deleteMessage(-100, 55), /delete permission unavailable/);
  assert.equal(calls.some((call) => call.method === 'deleteMessage'), false);
});

test('demotion deactivates an active challenge and resumed DM answers never post to the group', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups, config: { joinChallenge: true, observerAdvisories: false } });
  const user = { id: 909, username: 'challenged', first_name: 'Challenged', is_bot: false };
  await bot.handleNewMembers({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    message_id: 100,
    new_chat_members: [user]
  });
  const stale = bot.joinChallenges.get('-100:909');
  assert.ok(stale);
  const groupSendsBefore = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  const destructiveBefore = calls.filter((call) => ['banChatMember', 'restrictChatMember', 'deleteMessage'].includes(call.method)).length;

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  assert.equal(bot.joinChallenges.has('-100:909'), false);

  stale.attempts = bot.config.joinChallengeMaxAttempts || 3;
  await bot.handleJoinChallengeMessage(
    { chat: GROUP_A, from: user, message_id: 2, text: 'wrong' },
    stale,
    { dm: true, sourceChatId: 909 }
  );
  await bot.handleJoinChallengeMessage(
    { chat: GROUP_A, from: user, message_id: 3, text: 'A' },
    stale,
    { dm: true, sourceChatId: 909 }
  );
  await bot.maybeFailJoinChallenge(
    { chat: GROUP_A, from: user, message_id: 4, text: 'wrong' },
    stale,
    { dm: true, sourceChatId: 909 }
  );
  await bot.completeJoinChallenge(
    { chat: GROUP_A, from: user, message_id: 5, text: 'A' },
    stale,
    { dm: true, sourceChatId: 909 },
    { answer: 'A', validationReason: 'test' }
  );
  await bot.handleMessage({ chat: { id: 909, type: 'private' }, from: user, message_id: 6, text: 'A' });

  const groupSendsAfter = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  const destructiveAfter = calls.filter((call) => ['banChatMember', 'restrictChatMember', 'deleteMessage'].includes(call.method)).length;
  assert.equal(groupSendsAfter, groupSendsBefore);
  assert.equal(destructiveAfter, destructiveBefore);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === 909 && /Verification is paused/.test(call.payload.text)));
});

test('demotion before the initial challenge prompt suppresses the group post', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups, config: { joinChallenge: true } });
  const user = { id: 911, username: 'prompt_pending', first_name: 'Prompt', is_bot: false };
  let releaseRestrict = null;
  const baseRestrict = bot.restrict.bind(bot);
  bot.restrict = async (...args) => {
    const result = await baseRestrict(...args);
    await new Promise((resolve) => { releaseRestrict = resolve; });
    return result;
  };
  const pending = bot.handleNewMembers({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    message_id: 901,
    new_chat_members: [user]
  });
  await waitFor(() => Boolean(releaseRestrict));

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  releaseRestrict();
  await pending;

  assert.equal(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_start_failed'));
});

test('demotion during a pending bad-attempt record suppresses the group reminder', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups, config: { joinChallenge: true } });
  const user = { id: 912, username: 'reminder_pending', first_name: 'Reminder', is_bot: false };
  const challenge = await startActiveChallenge(bot, user);
  const groupSendsBefore = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  const delayed = delayRecordOnce(bot, 'join_challenge_bad_attempt');
  const pending = bot.handleJoinChallengeMessage(
    { chat: GROUP_A, from: user, message_id: 902, text: 'wrong answer' },
    challenge,
    {}
  );
  await waitFor(delayed.pending);

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  delayed.release();
  await pending;

  const groupSendsAfter = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  assert.equal(groupSendsAfter, groupSendsBefore);
});

test('demotion while join_challenge_solved is pending suppresses only the group success post', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups, config: { joinChallenge: true } });
  const user = { id: 913, username: 'success_pending', first_name: 'Success', is_bot: false };
  const challenge = await startActiveChallenge(bot, user);
  challenge.memoryCard = { id: 'test-card', question: 'Pick A', options: ['A', 'B'], answerIndex: 0 };
  const groupSendsBefore = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  const delayed = delayRecordOnce(bot, 'join_challenge_solved');
  const pending = bot.handleJoinChallengeMessage(
    { chat: GROUP_A, from: user, message_id: 903, text: 'A' },
    challenge,
    { dm: true, sourceChatId: 913 }
  );
  await waitFor(delayed.pending);

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  delayed.release();
  await pending;

  const groupSendsAfter = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  assert.equal(groupSendsAfter, groupSendsBefore);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === 913 && /You’re in/.test(call.payload.text)));
});

test('demotion while join_challenge_failed record is pending suppresses only the group failure post', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups, config: { joinChallenge: true, joinChallengeAction: 'none' } });
  const user = { id: 914, username: 'failure_pending', first_name: 'Failure', is_bot: false };
  const challenge = await startActiveChallenge(bot, user);
  challenge.attempts = bot.config.joinChallengeMaxAttempts || 3;
  const groupSendsBefore = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  const delayed = delayRecordOnce(bot, 'join_challenge_failed_max_attempts');
  const pending = bot.maybeFailJoinChallenge(
    { chat: GROUP_A, from: user, message_id: 904, text: 'wrong' },
    challenge,
    { dm: true, sourceChatId: 914 }
  );
  await waitFor(delayed.pending);

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  delayed.release();
  await pending;

  const groupSendsAfter = calls.filter((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === -100).length;
  assert.equal(groupSendsAfter, groupSendsBefore);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && Number(call.payload.chat_id) === 914 && /Verification failed too many times/.test(call.payload.text)));
});

test('observer group does not manufacture a native ban from a membership transition', async () => {
  const { bot } = makeBot({ groups: { '-200': groupState() } });
  const member = { id: 620, username: 'left_member', is_bot: false };
  bot.currentUpdateId = 910;
  await bot.handleChatMemberUpdate({
    chat: GROUP_B,
    from: { id: 1, username: 'admin' },
    date: 5000,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });
  assert.equal(bot.store.all().some((event) => event.event_type === 'ban_executed'), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'chat_member_observation_unavailable'));
});

test('admin group captures a live native ban with bounded pre-ban context', async () => {
  const { bot, calls } = makeBot({ groups: { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) } });
  const member = { id: 500, username: 'banned_user', first_name: 'Banned', is_bot: false };
  bot.rememberUserMessage({ chat: GROUP_A, from: member, message_id: 1, date: 1900, text: 'claim your wallet now' });
  bot.currentUpdateId = 777;
  await bot.handleChatMemberUpdate({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    date: 2000,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });
  const ban = bot.store.all().find((event) => event.event_type === 'ban_executed' && event.payload?.source === 'native_chat_member_admin_ban');
  assert.ok(ban);
  assert.equal(ban.payload.bot_mode, GROUP_MODE_ADMIN);
  assert.equal(ban.payload.ban_capture_coverage, 'live_chat_member');
  assert.equal(ban.payload.ban_context.observed_message_count, 1);
  assert.ok(calls.some((call) => call.method === 'getChatMember' && String(call.payload.user_id) === '999'));
});

test('my_chat_member promotion and demotion refresh capabilities immediately and block stale enforcement', async () => {
  const groups = { '-100': groupState() };
  const { bot, calls } = makeBot({ groups });
  assert.equal((await bot.getGroupCapabilities(-100)).mode, GROUP_MODE_OBSERVER);

  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'member', user: BOT },
    new_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT }
  });
  assert.equal((await bot.getGroupCapabilities(-100)).mode, GROUP_MODE_ADMIN);
  assert.equal((await bot.getGroupCapabilities(-100)).canRemoveMembers, true);

  // Simulate a demotion that has not produced an update yet. The per-call live
  // check must override the stale admin cache before the destructive call.
  groups['-100'] = groupState();
  await assert.rejects(() => bot.ban(-100, 505), /restrict\/ban permission unavailable/);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);

  groups['-100'] = groupState({ status: 'administrator', canRestrict: true, canDelete: true });
  await bot.getGroupCapabilities(-100, { force: true });
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  const demoted = await bot.getGroupCapabilities(-100);
  assert.equal(demoted.mode, GROUP_MODE_OBSERVER);
  assert.equal(demoted.canRemoveMembers, false);
});

test('stale in-flight admin lookup cannot overwrite a my_chat_member demotion', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups });
  const delayed = delayNextBotLookup(bot, calls, { status: 'administrator', can_restrict_members: true, can_delete_messages: true });
  const pending = bot.getGroupCapabilities(-100, { force: true });
  await waitFor(delayed.pending);

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  delayed.release();

  const capabilities = await pending;
  assert.equal(capabilities.mode, GROUP_MODE_OBSERVER);
  assert.equal(capabilities.canRemoveMembers, false);
  await assert.rejects(() => bot.ban(-100, 777), /permission unavailable/);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('pending callEffect after removal cannot use a stale admin lookup', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups });
  const delayed = delayNextBotLookup(bot, calls, { status: 'administrator', can_restrict_members: true, can_delete_messages: true });
  const pendingBan = bot.ban(-100, 778).then(() => 'resolved', () => 'rejected');
  await waitFor(delayed.pending);

  groups['-100'] = groupState({ status: 'kicked' });
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'kicked', user: BOT }
  });
  delayed.release();

  assert.equal(await pendingBan, 'rejected');
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('pending callEffect after demotion cannot use a stale admin lookup for ban or delete', async () => {
  const groups = { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true }) };
  const { bot, calls } = makeBot({ groups });
  const delayed = delayNextBotLookup(bot, calls, { status: 'administrator', can_restrict_members: true, can_delete_messages: true });
  const pendingBan = bot.ban(-100, 779).then(() => 'resolved', () => 'rejected');
  const pendingDelete = bot.deleteMessage(-100, 55).then(() => 'resolved', () => 'rejected');
  await waitFor(delayed.pending);

  groups['-100'] = groupState();
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_A,
    from: BOT,
    old_chat_member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true, user: BOT },
    new_chat_member: { status: 'member', user: BOT }
  });
  delayed.release();

  assert.equal(await pendingBan, 'rejected');
  assert.equal(await pendingDelete, 'rejected');
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(calls.some((call) => call.method === 'deleteMessage'), false);
});

test('admin without restrict right observes admin events but cannot remove', async () => {
  const { bot, calls } = makeBot({ groups: { '-100': groupState({ status: 'administrator', canRestrict: false, canDelete: true, adminUsers: [1] }) } });
  const caps = await bot.getGroupCapabilities(-100);
  assert.equal(caps.mode, GROUP_MODE_ADMIN);
  assert.equal(caps.canObserveChatMember, true);
  assert.equal(caps.canRemoveMembers, false);

  const member = { id: 600, username: 'observed_ban', is_bot: false };
  await bot.handleChatMemberUpdate({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    date: 3000,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });
  assert.ok(bot.store.all().some((event) => event.event_type === 'ban_executed' && event.user?.id === 600));

  await bot.handleCommand({
    chat: GROUP_A,
    from: { id: 1, username: 'admin' },
    message_id: 40,
    text: '/ban 60000 test reason'
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'ban_requested_no_rights'));
});

test('unknown permission lookup degrades to observer and blocks destructive calls', async () => {
  const { bot, calls } = makeBot({ groups: { '-200': groupState({ failBotLookup: true }) } });
  const caps = await bot.getGroupCapabilities(-200);
  assert.equal(caps.mode, GROUP_MODE_OBSERVER);
  assert.equal(caps.degraded, true);
  assert.equal(caps.canRemoveMembers, false);
  await assert.rejects(() => bot.ban(-200, 707), /not an active member|permission unavailable/);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('removed bot disables group operations and clears active challenges', async () => {
  const groups = { '-200': groupState() };
  const { bot, calls } = makeBot({ groups });
  bot.joinChallenges.set('-200:808', { chat: GROUP_B, user: { id: 808 }, expiresAt: Date.now() + 60000, attempts: 0 });
  groups['-200'] = groupState({ status: 'kicked' });
  await bot.handleMyChatMemberUpdate({
    chat: GROUP_B,
    from: BOT,
    old_chat_member: { status: 'member', user: BOT },
    new_chat_member: { status: 'kicked', user: BOT }
  });
  const caps = await bot.getGroupCapabilities(-200);
  assert.equal(caps.removed, true);
  assert.equal(caps.botOperationsEnabled, false);
  assert.equal(bot.joinChallenges.has('-200:808'), false);
  await assert.rejects(() => bot.ban(-200, 808), /not an active member/);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('private /status reports per-group mode and coverage only to live group admins', async () => {
  const { bot, calls } = makeBot({ groups: { '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true, adminUsers: [1] }), '-200': groupState() } });
  bot.rememberSeenChat(GROUP_A);
  bot.rememberSeenChat(GROUP_B);
  await bot.handleCommand({ chat: { id: 1, type: 'private' }, from: { id: 1, username: 'admin' }, message_id: 1, text: '/status' });
  const text = String(calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '');
  assert.match(text, /Admin Group/);
  assert.match(text, /Admin protection/);
  assert.match(text, /live chat_member/);
  assert.doesNotMatch(text, /Observer Group/);

  await bot.handleCommand({ chat: { id: 2, type: 'private' }, from: { id: 2, username: 'not_admin' }, message_id: 2, text: '/status' });
  const scoped = String(calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '');
  assert.match(scoped, /No groups were found where you are a current Telegram admin/);
  assert.doesNotMatch(scoped, /Admin Group|Observer Group/);
});

test('private /status reports observer coverage for a group the caller administers', async () => {
  const { bot, calls } = makeBot({
    groups: {
      '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true, adminUsers: [1] }),
      '-200': groupState({ adminUsers: [1] })
    }
  });
  bot.rememberSeenChat(GROUP_A);
  bot.rememberSeenChat(GROUP_B);
  await bot.handleCommand({ chat: { id: 1, type: 'private' }, from: { id: 1, username: 'admin' }, message_id: 3, text: '/status' });
  const text = String(calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '');
  assert.match(text, /Admin Group/);
  assert.match(text, /Observer Group/);
  assert.match(text, /Observer \(partial coverage\)/);
  assert.match(text, /ban feed none/);
  assert.match(text, /service messages only \(partial\)/);
  assert.match(text, /history: never available/);
});

test('private /status qualifies broader delivery for observer groups', async () => {
  const { bot, calls } = makeBot({
    groups: {
      '-100': groupState({ status: 'administrator', canRestrict: true, canDelete: true, adminUsers: [1] }),
      '-200': groupState({ adminUsers: [1] })
    },
    privacy: true
  });
  bot.rememberSeenChat(GROUP_A);
  bot.rememberSeenChat(GROUP_B);
  await bot.handleCommand({ chat: { id: 1, type: 'private' }, from: { id: 1, username: 'admin' }, message_id: 5, text: '/status' });
  const text = String(calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '');
  assert.match(text, /broader delivery configured; effective coverage unverified/);
  assert.match(text, /Observer \(partial coverage\)/);
  assert.doesNotMatch(text, /privacy-limited visibility/);
});

test('pure capability normalizer fails closed on unknown or missing membership', () => {
  const unknown = resolveGroupCapabilities({ chatId: '-1', member: null, error: 'lookup failed' });
  assert.equal(unknown.mode, GROUP_MODE_OBSERVER);
  assert.equal(unknown.degraded, true);
  assert.equal(unknown.canRemoveMembers, false);
  assert.equal(unknown.unseenHistoryAvailable, false);
  const adminWithoutRestrict = resolveGroupCapabilities({
    chatId: '-1',
    member: { status: 'administrator', can_restrict_members: false, can_delete_messages: true },
    botProfile: { can_read_all_group_messages: false }
  });
  assert.equal(adminWithoutRestrict.mode, GROUP_MODE_ADMIN);
  assert.equal(adminWithoutRestrict.canRemoveMembers, false);
  assert.equal(adminWithoutRestrict.canDeleteMessages, true);
  assert.equal(adminWithoutRestrict.coverage.eventFeedComprehensive, true);
  assert.equal(adminWithoutRestrict.coverage.enforcementComprehensive, false);

  const adminExplicitDelete = resolveGroupCapabilities({
    chatId: '-1',
    member: { status: 'administrator', can_restrict_members: true, can_delete_messages: true }
  });
  const adminAbsentDelete = resolveGroupCapabilities({
    chatId: '-1',
    member: { status: 'administrator', can_restrict_members: true }
  });
  const adminFalseDelete = resolveGroupCapabilities({
    chatId: '-1',
    member: { status: 'administrator', can_restrict_members: true, can_delete_messages: false }
  });
  const creatorDelete = resolveGroupCapabilities({
    chatId: '-1',
    member: { status: 'creator' }
  });
  assert.equal(adminExplicitDelete.canDeleteMessages, true);
  assert.equal(adminAbsentDelete.canDeleteMessages, false);
  assert.equal(adminFalseDelete.canDeleteMessages, false);
  assert.equal(creatorDelete.canDeleteMessages, true);
});

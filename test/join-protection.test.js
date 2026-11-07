import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TelegramShieldBot } from '../src/telegram.js';
import { EventStore } from '../src/store.js';
import { revokeCreatorAttestation } from '../src/creator-curator.js';
import { createPublicServer } from '../src/public-server.js';

const LOW_ANALYZER = () => ({ is_scam: false, confidence: 0, local_confidence: 0, scam_type: 'unknown', evidence: [], recommended_action: 'ignore' });
const LOW_INTEL = { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] };

function makeBot({ canBan = true, protection = { ok: true, evidence: [], error: '' }, config = {}, chatAdmins = [] } = {}) {
  const calls = [];
  const dkg = {
    async queryRiskIndicators() { return LOW_INTEL; },
    async queryAdminHistoryForActor() { return { hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] }; },
    async queryCampaignModerationRoots() { return { events: [] }; },
    async queryProtectionEvidence() { return protection; },
    async writeEvent(event) { return { eventId: event.id, ual: 'did:dkg:context-graph:tracabot/_shared_memory' }; },
    async runtimeStatus() { return { capabilities: {} }; },
    async getStats() { return { total: 0, source: 'local' }; },
    async validateUal() { return { ok: true }; }
  };
  const bot = new TelegramShieldBot({
    config: {
      telegramToken: 'test',
      adminIds: new Set(['1234']),
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
      joinTrustedLayers: ['verified-memory', 'local'],
      submitSharedEvidence: false,
      channelMemory: false,
      wmArtifacts: false,
      pendingReviewNotifications: false,
      ...config
    },
    analyzer: LOW_ANALYZER,
    dkg,
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-join-protection-')), 'events.jsonl')),
    llm: null
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') {
      if (payload.user_id === 999) return { status: canBan ? 'administrator' : 'member', can_restrict_members: canBan, can_delete_messages: canBan };
      return chatAdmins.some((user) => String(user.id) === String(payload.user_id))
        ? { status: 'administrator', user: { id: payload.user_id } }
        : { status: 'member', user: { id: payload.user_id } };
    }
    if (method === 'getChatAdministrators') return chatAdmins.map((user) => ({ status: 'administrator', user }));
    if (method === 'exportChatInviteLink') return 'https://t.me/+invite';
    if (method === 'sendMessage') return { message_id: calls.length, ...payload };
    return { ok: true };
  };
  return { bot, calls };
}

function confirmedEvidence(overrides = {}) {
  return {
    eventId: 'evt-confirmed-1',
    eventType: 'review_upheld',
    claimLevel: 'confirmed_scam',
    confidence: 96,
    created: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    adminVerified: true,
    exactActorMatch: true,
    trustLayer: 'local',
    source: 'local_admin_review',
    localApproval: true,
    ...overrides
  };
}

async function joinUser(bot, userId = 4242, { messageId = undefined, date = undefined } = {}) {
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    from: { id: 1, username: 'admin' },
    ...(messageId !== undefined ? { message_id: messageId } : {}),
    ...(date !== undefined ? { date } : {}),
    new_chat_members: [{ id: userId, username: 'new_user', first_name: 'New', is_bot: false }]
  });
}

function seedLocalReview(bot, userId, targetEventId, { chatId = -100, created = new Date().toISOString() } = {}) {
  if (!bot.store.all().some((event) => event.id === targetEventId)) {
    bot.store.append({
      id: targetEventId,
      event_type: 'risk_review_needed',
      timestamp: new Date().toISOString(),
      chat: { id: chatId, type: 'supergroup' },
      user: { id: userId },
      payload: { target: { id: userId }, target_key: `id:${userId}`, confidence: 90, recommended_action: 'admin_review' }
    });
  }
  bot.store.append({
    id: `local-review:${chatId}:${userId}:${targetEventId}`,
    event_type: 'review_upheld',
    timestamp: created,
    chat: { id: chatId, type: 'supergroup' },
    user: { id: 1, username: 'admin' },
    payload: {
      target_event_id: targetEventId,
      reviewed_target: { id: userId, first_name: 'Reviewed' },
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

test('genuine join with no model config performs a silent deterministic check', async () => {
  const { bot, calls } = makeBot();
  await joinUser(bot);
  const check = bot.store.all().find((event) => event.event_type === 'join_protection_check');
  assert.ok(check);
  assert.equal(check.payload.decision, 'allow');
  assert.equal(check.payload.graph_ok, true);
  assert.equal(check.local_only, true);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('untrusted community evidence only flags and never bans', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence({ trustLayer: 'shared-working-memory', source: 'fork-instance', localApproval: false })] }
  });
  await joinUser(bot);
  const check = bot.store.all().find((event) => event.event_type === 'join_protection_check');
  assert.equal(check.payload.decision, 'flag');
  assert.match(check.payload.reason, /untrusted_evidence_layer/);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('verified-memory records without authenticated publisher approval never ban', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true, joinTrustedLayers: ['verified-memory', 'local'] },
    protection: { ok: true, evidence: [confirmedEvidence({
      trustLayer: 'verified-memory',
      source: 'spoofed-creator-curator',
      localApproval: false,
      publisherApprovalVerified: false
    })] }
  });
  await joinUser(bot);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const check = bot.store.all().find((event) => event.event_type === 'join_protection_check');
  assert.equal(check.payload.decision, 'flag');
  assert.equal(check.payload.reason, 'missing_authenticated_approval');
});

test('exact confirmed local review removes silently when operator opted in', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence()] }
  });
  await joinUser(bot);
  const ban = calls.find((call) => call.method === 'banChatMember');
  assert.ok(ban);
  assert.equal(String(ban.payload.user_id), '4242');
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
  const outcome = bot.store.all().find((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4242');
  assert.ok(outcome);
  assert.equal(outcome.local_only, true);
  assert.equal(outcome.payload.admin_verified, false);
  assert.match(JSON.stringify(outcome.payload.evidence), /silent|confirmed exact-identity/i);
});

test('admin and owner targets are protected from automatic join removal', async () => {
  const admin = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence()] },
    chatAdmins: [{ id: 4242 }]
  });
  await joinUser(admin.bot);
  assert.equal(admin.calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(admin.bot.store.all().find((event) => event.event_type === 'join_protection_check').payload.decision, 'allow');

  const owner = makeBot({
    config: { joinAutoRemove: true, botOwnerIds: new Set(['4242']) },
    protection: { ok: true, evidence: [confirmedEvidence()] }
  });
  await joinUser(owner.bot);
  assert.equal(owner.calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(owner.bot.store.all().find((event) => event.event_type === 'join_protection_check').payload.decision, 'allow');
});

test('missing ban rights fails closed and records a private suppression', async () => {
  const { bot, calls } = makeBot({
    canBan: false,
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence()] }
  });
  await joinUser(bot);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const suppressed = bot.store.all().find((event) => event.event_type === 'join_protection_suppressed');
  assert.ok(suppressed);
  assert.match(suppressed.payload.reason, /missing_ban_rights/);
  assert.equal(suppressed.local_only, true);
});

test('graph outage flags locally without banning or spamming the group', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: false, error: 'graph timeout', evidence: [] }
  });
  await joinUser(bot);
  const degraded = bot.store.all().find((event) => event.event_type === 'join_protection_degraded');
  assert.ok(degraded);
  assert.equal(degraded.payload.graph_ok, false);
  assert.match(degraded.payload.graph_error, /graph timeout/);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
});

test('stale and retracted evidence suppress an otherwise exact match', async () => {
  const stale = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence({ created: '2024-01-01T00:00:00.000Z' })] }
  });
  await joinUser(stale.bot);
  assert.equal(stale.calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(stale.bot.store.all().find((event) => event.event_type === 'join_protection_check').payload.reason, 'stale_evidence');

  const retracted = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [
      confirmedEvidence(),
      confirmedEvidence({ eventId: 'evt-retraction', eventType: 'review_overturned', claimLevel: 'retracted', created: new Date().toISOString() })
    ] }
  });
  await joinUser(retracted.bot);
  assert.equal(retracted.calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(retracted.bot.store.all().find((event) => event.event_type === 'join_protection_check').payload.reason, 'retracted_evidence');
});

test('duplicate join events do not repeat the destructive action', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence()] }
  });
  await joinUser(bot);
  await joinUser(bot);
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  assert.equal(bot.store.all().filter((event) => event.event_type === 'join_protection_check').length, 1);
});

test('join, native unban, and rejoin use a new membership episode without stale success', async () => {
  const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
  seedLocalReview(bot, 4242, 'finding-A');
  await joinUser(bot, 4242, { messageId: 1001, date: 100 });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  const firstBan = bot.store.all().find((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4242');
  assert.ok(firstBan);

  await bot.handleNativeAdminUnban({
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    from: { id: 1, username: 'admin' },
    date: 200,
    old_chat_member: { status: 'kicked', user: { id: 4242 } },
    new_chat_member: { status: 'member', user: { id: 4242 } }
  }, { id: 4242, first_name: 'New' });
  const retraction = bot.store.all().find((event) => event.event_type === 'review_overturned');
  assert.equal(retraction.payload.target_event_id, firstBan.id);
  assert.ok(retraction.payload.evidence_root_ids.includes('local-review:-100:4242:finding-A'));

  await joinUser(bot, 4242, { messageId: 1002, date: 300 });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  const suppressed = bot.store.all().filter((event) => event.event_type === 'join_protection_check').at(-1);
  assert.equal(suppressed.payload.decision, 'allow');
  assert.equal(suppressed.payload.reason, 'local_overturn');

  seedLocalReview(bot, 4242, 'finding-B');
  await joinUser(bot, 4242, { messageId: 1003, date: 400 });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 2);
  assert.equal(bot.store.all().filter((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4242').length, 2);

  await joinUser(bot, 4242, { messageId: 1003, date: 400 });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 2);
});

test('self-ban close blocks delayed original join from reopening a new episode', async () => {
  const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
  seedLocalReview(bot, 4242, 'finding-self-ban');
  const chat = { id: -100, title: 'demo', type: 'supergroup' };
  const member = { id: 4242, username: 'new_user', first_name: 'New', is_bot: false };
  bot.currentUpdateId = 100;
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, message_id: 5001, date: 500, new_chat_members: [member] });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);

  // The bot's own join-protection ban produces a kicked chat_member update.
  bot.currentUpdateId = 110;
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 999, username: 'tracethembot', is_bot: true },
    date: 501,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });

  // Delayed original join notification is older than the close boundary.
  bot.currentUpdateId = 99;
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 1, username: 'admin' },
    date: 500,
    old_chat_member: { status: 'left', user: member },
    new_chat_member: { status: 'member', user: member }
  });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  assert.equal(bot.store.all().filter((event) => event.event_type === 'join_protection_check').length, 1);

  // A genuinely later join has later event time/update id and creates a new action.
  bot.currentUpdateId = 200;
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 1, username: 'admin' },
    date: 700,
    old_chat_member: { status: 'left', user: member },
    new_chat_member: { status: 'member', user: member }
  });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 2);
  assert.equal(bot.store.all().filter((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4242').length, 2);
});

test('membership episode close boundary survives a restart', async () => {
  const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
  seedLocalReview(bot, 4242, 'finding-restart');
  const chat = { id: -100, title: 'demo', type: 'supergroup' };
  const member = { id: 4242, username: 'new_user', first_name: 'New', is_bot: false };
  bot.currentUpdateId = 100;
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, message_id: 8001, date: 800, new_chat_members: [member] });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  bot.currentUpdateId = 110;
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 999, username: 'tracethembot', is_bot: true },
    date: 801,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });

  const restarted = new TelegramShieldBot({
    config: bot.config,
    analyzer: LOW_ANALYZER,
    dkg: bot.dkg,
    store: bot.store
  });
  restarted.call = bot.call;
  restarted.currentUpdateId = 90;
  await restarted.handleChatMemberUpdate({
    chat,
    from: { id: 1, username: 'admin' },
    date: 800,
    old_chat_member: { status: 'left', user: member },
    new_chat_member: { status: 'member', user: member }
  });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
});

test('self-ban close blocks a delayed service-message join when chat_member arrived first', async () => {
  const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
  seedLocalReview(bot, 4242, 'finding-self-ban-reverse');
  const chat = { id: -100, title: 'demo', type: 'supergroup' };
  const member = { id: 4242, username: 'new_user', first_name: 'New', is_bot: false };
  bot.currentUpdateId = 100;
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 1, username: 'admin' },
    date: 900,
    old_chat_member: { status: 'left', user: member },
    new_chat_member: { status: 'member', user: member }
  });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  bot.currentUpdateId = 110;
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 999, username: 'tracethembot', is_bot: true },
    date: 901,
    old_chat_member: { status: 'member', user: member },
    new_chat_member: { status: 'kicked', user: member }
  });
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, message_id: 9001, date: 900, new_chat_members: [member] });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, message_id: 9101, date: 1000, new_chat_members: [member] });
  assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 2);
});

test('same-second close boundary ignores newer update/message identity after restart', async () => {
  for (const order of ['service-first', 'chat-member-first']) {
    const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
    seedLocalReview(bot, 4242, `finding-same-second-${order}`);
    const chat = { id: -100, title: 'demo', type: 'supergroup' };
    const member = { id: 4242, username: 'new_user', first_name: 'New', is_bot: false };
    const serviceJoin = (actor) => actor.handleNewMembers({
      chat,
      from: { id: 1, username: 'admin' },
      message_id: 9001,
      date: 900,
      new_chat_members: [member]
    });
    const memberJoin = (actor, updateId, date = 900) => {
      actor.currentUpdateId = updateId;
      return actor.handleChatMemberUpdate({
        chat,
        from: { id: 1, username: 'admin' },
        date,
        old_chat_member: { status: 'left', user: member },
        new_chat_member: { status: 'member', user: member }
      });
    };
    if (order === 'service-first') {
      bot.currentUpdateId = 100;
      await serviceJoin(bot);
    } else {
      await memberJoin(bot, 100, 900);
    }
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1, order);

    bot.currentUpdateId = 110;
    await bot.handleChatMemberUpdate({
      chat,
      from: { id: 999, username: 'tracethembot', is_bot: true },
      date: 900,
      old_chat_member: { status: 'member', user: member },
      new_chat_member: { status: 'kicked', user: member }
    });

    const restarted = new TelegramShieldBot({
      config: bot.config,
      analyzer: LOW_ANALYZER,
      dkg: bot.dkg,
      store: bot.store
    });
    restarted.call = bot.call;
    if (order === 'service-first') {
      await memberJoin(restarted, 111, 900);
    } else {
      restarted.currentUpdateId = 111;
      await serviceJoin(restarted);
    }
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1, `${order} delayed same-second`);
    assert.equal(bot.store.all().filter((event) => event.event_type === 'membership_episode_opened').length, 1, `${order} episode`);
    assert.equal(bot.store.all().filter((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4242').length, 1, `${order} audit`);

    await memberJoin(restarted, 120, 901);
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 2, `${order} date901`);
    restarted.currentUpdateId = 130;
    await restarted.handleChatMemberUpdate({
      chat,
      from: { id: 999, username: 'tracethembot', is_bot: true },
      date: 901,
      old_chat_member: { status: 'member', user: member },
      new_chat_member: { status: 'kicked', user: member }
    });
    await memberJoin(restarted, 140, 902);
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 3, `${order} date902`);
  }
});

test('service-message and chat_member notifications share one membership episode in either order', async () => {
  for (const order of ['service-first', 'chat-member-first']) {
    const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
    seedLocalReview(bot, 4242, 'finding-episode');
    const chat = { id: -100, title: 'demo', type: 'supergroup' };
    const member = { id: 4242, username: 'new_user', first_name: 'New', is_bot: false };
    const serviceJoin = async () => bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, message_id: 5001, date: 500, new_chat_members: [member] });
    const laterServiceJoin = async () => bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, message_id: 7001, date: 700, new_chat_members: [member] });
    const memberJoin = async () => bot.handleChatMemberUpdate({
      chat,
      from: { id: 1, username: 'admin' },
      date: 500,
      old_chat_member: { status: 'left', user: member },
      new_chat_member: { status: 'member', user: member }
    });
    if (order === 'service-first') {
      await serviceJoin();
      await memberJoin();
    } else {
      await memberJoin();
      await serviceJoin();
    }
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1, order);
    const checks = bot.store.all().filter((event) => event.event_type === 'join_protection_check');
    const episodes = new Set(checks.map((event) => event.payload.membership_episode));
    assert.equal(episodes.size, 1, order);
    await serviceJoin();
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1, `${order} duplicate replay`);

    await bot.handleChatMemberUpdate({
      chat,
      from: { id: 1, username: 'admin' },
      date: 600,
      old_chat_member: { status: 'member', user: member },
      new_chat_member: { status: 'left', user: member }
    });
    await laterServiceJoin();
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 2, `${order} genuine rejoin`);
    assert.equal(bot.store.all().filter((event) => event.event_type === 'ban_executed' && String(event.user?.id) === '4242').length, 2, `${order} new audit`);
  }
});

test('genuine chat_member joins go through strict policy before campaign identity logic', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: false, error: 'graph timeout', evidence: [], complete: false }
  });
  const chat = { id: -100, title: 'demo', type: 'supergroup' };
  bot.store.append({
    id: 'prior-join-identity',
    event_type: 'join_challenge_start_failed',
    timestamp: new Date().toISOString(),
    chat,
    user: { id: 8420821339, first_name: 'Rodasio', last_name: 'Viela nueva' },
    payload: {}
  });
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 1, username: 'admin' },
    date: 1784509240,
    old_chat_member: { status: 'left', user: { id: 8420821339, first_name: 'BC GAME', is_bot: false } },
    new_chat_member: { status: 'member', user: { id: 8420821339, first_name: 'BC GAME', is_bot: false } }
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(bot.store.all().some((event) => event.event_type === 'identity_campaign_check'), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_protection_degraded'));
});

test('local admin review evidence is isolated to the same chat', async () => {
  const { bot, calls } = makeBot({ config: { joinAutoRemove: true } });
  seedLocalReview(bot, 4242, 'finding-other-chat', { chatId: -200 });
  await joinUser(bot);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);

  const sameChat = makeBot({ config: { joinAutoRemove: true } });
  seedLocalReview(sameChat.bot, 4242, 'finding-same-chat', { chatId: -100 });
  await joinUser(sameChat.bot);
  assert.equal(sameChat.calls.some((call) => call.method === 'banChatMember'), true);
});

test('genuine join with stale local review still does not bypass into campaign ban', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true, joinEvidenceMaxAgeDays: 1 },
    protection: { ok: true, evidence: [], complete: true }
  });
  const chat = { id: -100, title: 'demo', type: 'supergroup' };
  seedLocalReview(bot, 8420821339, 'old-finding', { created: '2024-01-01T00:00:00.000Z' });
  bot.store.append({
    id: 'prior-join-identity-stale',
    event_type: 'join_challenge_start_failed',
    timestamp: new Date().toISOString(),
    chat,
    user: { id: 8420821339, first_name: 'Rodasio' },
    payload: {}
  });
  await bot.handleChatMemberUpdate({
    chat,
    from: { id: 1, username: 'admin' },
    date: 1784509241,
    old_chat_member: { status: 'left', user: { id: 8420821339, first_name: 'BC GAME', is_bot: false } },
    new_chat_member: { status: 'member', user: { id: 8420821339, first_name: 'BC GAME', is_bot: false } }
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const check = bot.store.all().find((event) => event.event_type === 'join_protection_check');
  assert.equal(check.payload.reason, 'stale_evidence');
});

test('display-name-only matches are not sent as confirmed evidence', async () => {
  const { bot, calls } = makeBot({
    config: { joinAutoRemove: true },
    protection: { ok: true, evidence: [confirmedEvidence({ exactActorMatch: false })] }
  });
  await joinUser(bot);
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.equal(bot.store.all().find((event) => event.event_type === 'join_protection_check').payload.decision, 'flag');
});

test('native admin unban overrides an active creator attestation for this group on a later genuine join', async () => {
  const keys = generateKeyPairSync('ed25519');
  const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
  const issuer = 'tracabot-creator-curator';
  const token = 'creator-read-token-123456';
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-native-unban-'));
  const storePath = join(dir, 'creator-attestations.json');
  const server = createPublicServer({
    config: { creatorCuratorStorePath: storePath, creatorCuratorPrivateKey: privateKey, creatorCuratorToken: token, creatorCuratorReadToken: token, creatorCuratorIssuer: issuer, publicMaxBodyBytes: 8192 },
    store: new EventStore(join(dir, 'public-events.sqlite')),
    dkg: null,
    autoPromote: false
  });
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const created = await fetch(`${base}/api/creator/attestations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({
        subject: { platform: 'telegram', user_id: '5151' },
        classification: 'fraud', confidence: 96, ttl_days: 30,
        roots: [
          { id: 'native-root-a', event_type: 'ban_executed', community_id: '-100', user_id: '5151' },
          { id: 'native-root-b', event_type: 'ban_executed', community_id: '-200', user_id: '5151' }
        ]
      })
    });
    assert.equal(created.status, 201);
    const { bot, calls } = makeBot({
      config: {
        joinAutoRemove: true,
        joinTrustedLayers: ['creator-curator'],
        creatorCuratorUrl: base,
        creatorCuratorPublicKey: publicKey,
        creatorCuratorReadToken: token,
        creatorCuratorIssuer: issuer,
        creatorCuratorMinConfidence: 90,
        creatorCuratorMinRoots: 2,
        creatorCuratorMaxAgeDays: 180,
        creatorCuratorTimeoutMs: 2000
      },
      protection: { ok: true, evidence: [], complete: true }
    });
    await joinUser(bot, 5151, { messageId: 9201, date: 920 });
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
    await bot.handleChatMemberUpdate({
      chat: { id: -100, title: 'demo', type: 'supergroup' },
      from: { id: 1, username: 'admin' },
      date: 921,
      old_chat_member: { status: 'kicked', user: { id: 5151 } },
      new_chat_member: { status: 'member', user: { id: 5151 } }
    });
    const correction = bot.store.all().find((event) => event.event_type === 'review_overturned' && event.payload?.correction_source === 'native_chat_member_unban');
    assert.ok(correction);
    await joinUser(bot, 5151, { messageId: 9202, date: 922 });
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
    const check = bot.store.all().filter((event) => event.event_type === 'join_protection_check').at(-1);
    assert.equal(check.payload.reason, 'local_overturn');
    assert.equal(check.payload.decision, 'allow');
    const status = await fetch(`${base}/api/creator/attestations/telegram/5151`, { headers: { authorization: `Bearer ${token}` } }).then((response) => response.json());
    assert.equal(status.payload.status, 'active');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('only an active unretracted independent approval clears a local override while creator evidence stays active', async () => {
  const keys = generateKeyPairSync('ed25519');
  const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
  const issuer = 'tracabot-creator-curator';
  const token = 'creator-read-token-123456';
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-retraction-'));
  const storePath = join(dir, 'creator-attestations.json');
  const server = createPublicServer({
    config: { creatorCuratorStorePath: storePath, creatorCuratorPrivateKey: privateKey, creatorCuratorToken: token, creatorCuratorReadToken: token, creatorCuratorIssuer: issuer, publicMaxBodyBytes: 8192 },
    store: new EventStore(join(dir, 'public-events.sqlite')),
    dkg: null,
    autoPromote: false
  });
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    await fetch(`${base}/api/creator/attestations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({
        subject: { platform: 'telegram', user_id: '5252' },
        classification: 'scam', confidence: 97, ttl_days: 30,
        roots: [
          { id: 'retain-root-a', event_type: 'ban_executed', community_id: '-100', user_id: '5252' },
          { id: 'retain-root-b', event_type: 'ban_executed', community_id: '-200', user_id: '5252' }
        ]
      })
    });
    const { bot, calls } = makeBot({
      config: {
        joinAutoRemove: true,
        joinTrustedLayers: ['creator-curator'],
        creatorCuratorUrl: base,
        creatorCuratorPublicKey: publicKey,
        creatorCuratorReadToken: token,
        creatorCuratorIssuer: issuer,
        creatorCuratorMinConfidence: 90,
        creatorCuratorMinRoots: 2,
        creatorCuratorMaxAgeDays: 180,
        creatorCuratorTimeoutMs: 2000
      },
      protection: { ok: true, evidence: [], complete: true },
      chatAdmins: [{ id: 1, username: 'admin' }]
    });
    const chat = { id: -100, type: 'supergroup', title: 'Demo Group' };
    const now = Date.now();
    const finding = (id) => ({
      id,
      event_type: 'risk_review_needed',
      timestamp: new Date(now - 6000).toISOString(),
      chat,
      user: { id: 5252, username: 'accused' },
      payload: { target: { id: 5252 }, target_key: 'id:5252', confidence: 90, recommended_action: 'admin_review' }
    });
    const review = (id, targetEventId, stamp) => ({
      id,
      event_type: 'review_upheld',
      timestamp: new Date(stamp).toISOString(),
      chat,
      user: { id: 1, username: 'admin' },
      payload: {
        target_event_id: targetEventId,
        reviewed_target: { id: 5252, username: 'accused' },
        reviewed_target_key: 'id:5252',
        target_chat_id: '-100',
        local_approval: true,
        approval_source: 'telegram_admin_review',
        admin_verified: true,
        confidence: 96,
        community_id: '-100'
      }
    });
    bot.store.append(finding('finding-original'));
    bot.store.append(review('review-original', 'finding-original', now - 5000));
    bot.store.append({
      id: 'ban-original',
      event_type: 'ban_executed',
      timestamp: new Date(now - 4500).toISOString(),
      chat,
      user: { id: 5252, username: 'accused' },
      payload: { target: { id: 5252 }, target_key: 'id:5252', evidence_root_ids: ['review-original'], confidence: 100, admin_verified: true }
    });
    bot.store.append({
      id: 'appeal-original',
      event_type: 'appeal_submitted',
      timestamp: new Date(now - 4000).toISOString(),
      chat: { id: 5252, type: 'private' },
      user: { id: 5252 },
      payload: { appeal_ref: 'ap-original', ban_event_id: 'ban-original', case_ref: 'case-original', appealant_id: '5252', target: { id: 5252 }, target_chat_id: '-100', reason: 'local correction', local_only: true }
    });
    const resolved = await bot.resolveAppeal({ appealRef: 'ap-original', admin: { id: 1 }, decision: 'overturn', sourceChat: { id: 1, type: 'private' } });
    assert.equal(resolved.ok, true);
    assert.ok(bot.localProtectionOverride({ id: 5252 }, -100));

    bot.store.append(finding('finding-independent'));
    bot.store.append(review('review-independent', 'finding-independent', now + 1000));
    assert.equal(bot.localProtectionOverride({ id: 5252 }, -100), null);

    bot.store.append({
      id: 'retract-independent',
      event_type: 'review_overturned',
      timestamp: new Date(now + 2000).toISOString(),
      chat,
      user: { id: 1, username: 'admin' },
      payload: {
        target_event_id: 'finding-independent',
        reviewed_target: { id: 5252, username: 'accused' },
        reviewed_target_key: 'id:5252',
        target_chat_id: '-100',
        evidence_root_ids: ['finding-independent'],
        review_decision: 'reject',
        correction_source: 'telegram_admin_review',
        retracted: true,
        evidence: ['underlying independent finding retracted']
      }
    });
    assert.equal(bot.localProtectionDecision({ id: 5252 }, -100).reason, 'retracted_evidence');
    assert.ok(bot.localProtectionOverride({ id: 5252 }, -100));
    bot.closeMembershipEpisode(-100, 5252, { eventDate: 930, updateId: 930, messageId: 930 });
    await joinUser(bot, 5252, { messageId: 9301, date: 931 });
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 0);
    const check = bot.store.all().filter((event) => event.event_type === 'join_protection_check').at(-1);
    assert.equal(check.payload.reason, 'local_overturn');
    const status = await fetch(`${base}/api/creator/attestations/telegram/5252`, { headers: { authorization: `Bearer ${token}` } }).then((response) => response.json());
    assert.equal(status.payload.status, 'active');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('authenticated creator-curator attestation authorizes opt-in removal and revocation stops it', async () => {
  const keys = generateKeyPairSync('ed25519');
  const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
  const issuer = 'tracabot-creator-curator';
  const token = 'creator-read-token-123456';
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-join-'));
  const storePath = join(dir, 'creator-attestations.json');
  const server = createPublicServer({
    config: { creatorCuratorStorePath: storePath, creatorCuratorPrivateKey: privateKey, creatorCuratorToken: token, creatorCuratorReadToken: token, creatorCuratorIssuer: issuer, publicMaxBodyBytes: 8192 },
    store: new EventStore(join(dir, 'public-events.sqlite')),
    dkg: null,
    autoPromote: false
  });
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const created = await fetch(`${base}/api/creator/attestations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({
        subject: { platform: 'telegram', user_id: '4242' },
        classification: 'fraud',
        confidence: 96,
        ttl_days: 30,
        roots: [
          { id: 'ban-root-a', event_type: 'ban_executed', community_id: '-100', user_id: '4242' },
          { id: 'ban-root-b', event_type: 'ban_executed', community_id: '-200', user_id: '4242' }
        ]
      })
    });
    assert.equal(created.status, 201);
    const { bot, calls } = makeBot({
      config: {
        joinAutoRemove: true,
        joinTrustedLayers: ['creator-curator'],
        creatorCuratorUrl: base,
        creatorCuratorPublicKey: publicKey,
        creatorCuratorReadToken: token,
        creatorCuratorIssuer: issuer,
        creatorCuratorMinConfidence: 90,
        creatorCuratorMinRoots: 2,
        creatorCuratorMaxAgeDays: 180,
        creatorCuratorTimeoutMs: 2000
      },
      protection: { ok: true, evidence: [], complete: true }
    });
    await joinUser(bot, 4242, { messageId: 7001, date: 700 });
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
    const check = bot.store.all().find((event) => event.event_type === 'join_protection_check');
    assert.equal(check.payload.creator_ok, true);
    assert.equal(check.payload.creator_status, 'active');

    revokeCreatorAttestation({ storePath, privateKey, issuer, subject: { platform: 'telegram', user_id: '4242' }, reason: 'curator correction' });
    await joinUser(bot, 4242, { messageId: 7002, date: 701 });
    assert.equal(calls.filter((call) => call.method === 'banChatMember').length, 1);
    const after = bot.store.all().filter((event) => event.event_type === 'join_protection_check').at(-1);
    assert.equal(after.payload.creator_status, 'revoked');
    assert.notEqual(after.payload.decision, 'remove');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

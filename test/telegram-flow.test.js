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
    async runtimeStatus() {
      return {
        dkgReleaseVersion: '10.0.0-rc.9',
        adapterVersion: '10.0.0-rc.9',
        capabilities: { workingMemoryAssertions: true, sharedWorkingMemory: true, verifiedMemoryPublish: true, query: true }
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
      autoDeleteBotMessages: true,
      botMessageTtlSeconds: 60,
      challengeMessageTtlSeconds: 120,
      successMessageTtlSeconds: 45,
      joinChallenge: false,
      joinChallengeMode: 'qa',
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
      channelMemory: true,
      channelMemoryMinConfidence: 80,
      channelMemoryMaxTextChars: 1000,
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
    if (method === 'exportChatInviteLink') return 'https://t.me/+invitecode';
    if (method === 'unbanChatMember') return { ok: true };
    if (method === 'sendMessage') return { message_id: calls.length, ...payload };
    return { ok: true };
  };
  return { bot, calls, dkgWrites };
}

test('new high-risk join is sent to admin review when bot has admin rights', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 42, username: 'fake_support', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 42), false);
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 42), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('learning fraud patterns')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_review_needed' && event.user.id === 42));
});

test('local-only high-risk first post is deleted and published but not banned', async () => {
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
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 66), false);
  const finding = bot.store.all().find((event) => event.event_type === 'fraud_finding' && event.user.id === 66);
  assert.match(JSON.stringify(finding.payload.evidence), /no ban\/restrict without DKG backing/);
});

test('recent joiner renamed to admin-like identity is deleted and published before DM bait', async () => {
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
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 67), false);
  const finding = bot.store.all().find((event) => event.event_type === 'fraud_finding' && event.user.id === 67);
  assert.match(JSON.stringify(finding.payload.evidence), /changed identity to resemble admin/);
});

test('DKG-backed high-risk first post is deleted and sent to admin review when bot has rights', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 166, username: 'known_bad', is_bot: false },
    message_id: 127,
    text: 'known scam actor returns'
  });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 127));
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 166), false);
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 166), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('learning fraud patterns')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_review_needed' && event.user.id === 166 && event.payload.recommended_action === 'admin_review'));
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
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 88), false);
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 40));
  const finding = bot.store.all().find((event) => event.event_type === 'fraud_finding' && event.user.id === 88);
  assert.match(JSON.stringify(finding.payload.evidence), /no ban\/restrict without DKG backing/);
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
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 89), false);
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 41));
  const finding = bot.store.all().find((event) => event.event_type === 'fraud_finding' && event.user.id === 89);
  assert.match(JSON.stringify(finding.payload.evidence), /changed identity to resemble admin/);
});

test('DKG-backed high-risk join asks for admin review without ban-rights wording', async () => {
  const { bot, calls } = makeBot({ canBan: false });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 43, username: 'fake_support2', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('learning fraud patterns')));
  const alert = calls.find((call) => call.method === 'sendMessage' && String(call.payload.text).includes('learning fraud patterns'))?.payload.text || '';
  assert.match(alert, /Ask an admin to review/);
  assert.match(alert, /\/appeal/);
  assert.doesNotMatch(alert, /ban rights|Recommendation: ban/i);
  assert.doesNotMatch(alert, /DKG UAL|DKG event|did:dkg:context-graph|event ID/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_review_needed' && event.local_only));
});

test('join challenge is skipped when bot is not group admin', async () => {
  const { bot, calls } = makeBot({
    canBan: false,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    analyzer: () => ({ is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' }),
    configOverrides: { joinChallenge: true }
  });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 4242, username: 'new_user', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'sendMessage' && /quick check before posting/.test(call.payload.text)), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_skipped_no_admin'));
});

test('auto-actions are suppressed for Telegram chat admins', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    trustedUserIds: [77],
    dkgIntel: { riskScore: 90, reportsAcrossCommunities: 1, wallets: [], domains: [], patterns: [], evidence: [{ source: 'https://tracabot.org/ontology#event/admin-risk', eventId: 'admin-risk', ual: 'did:dkg:context-graph:tracabot/_shared_memory' }] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 77, username: 'chat_admin', is_bot: false },
    message_id: 29,
    text: 'URGENT official support admin says verify wallet now'
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 77), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_action_suppressed' && event.local_only));
});

test('ordinary wallet and token flow discussion does not trigger scam alert', async () => {
  const { bot, calls } = makeBot({
    canBan: false,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 4242, username: 'askme42', is_bot: false },
    message_id: 43,
    text: 'I’m assuming we have no evidence of where these tokens are going?\n\nNo significant outflows from cb wallets?'
  });
  assert.equal(calls.some((call) => call.method === 'sendMessage' && /Admin heads-up|fraud risk|TRACaBot risk/i.test(String(call.payload.text || ''))), false);
  assert.equal(calls.some((call) => ['deleteMessage', 'restrictChatMember', 'banChatMember'].includes(call.method)), false);
  const riskEvents = bot.store.all().filter((event) => ['scam_detection', 'risk_review_needed', 'risk_action_suppressed'].includes(event.event_type));
  assert.equal(riskEvents.length, 0);
});

test('high-confidence public channel scam promo writes bounded channel observation to DKG', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: false,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    from: { id: 4242, username: 'profit_signals', is_bot: false },
    message_id: 99,
    text: 'From Zero to $685K profit I joined Alpha Trading (https://t.me/alpha_trading_circle) 16 months ago and within the past 3 months I earned $685,000 thanks to the coaching Mr Theo provides.'
  });
  const observation = dkgWrites.find((event) => event.event_type === 'channel_observation');
  assert.ok(observation);
  assert.equal(observation.payload.lifecycle_stage, 'shared_memory');
  assert.equal(observation.payload.publication_status, 'shared_memory');
  assert.match(observation.payload.message_text, /Alpha Trading/);
  assert.ok(observation.payload.text_fingerprint);
});

test('ordinary scam coin discussion does not write raw channel observation to DKG', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: false,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    from: { id: 5151, username: 'member', is_bot: false },
    message_id: 100,
    text: 'Lots of scam coins launch every week. We should discuss how to protect users and avoid fake airdrops.'
  });
  assert.equal(dkgWrites.some((event) => event.event_type === 'channel_observation'), false);
});

test('benign governance conversation is learned as WM draft, not shared without commit', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: false,
    analyzer: () => ({ is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    from: { id: 5152, username: 'builder', is_bot: false },
    message_id: 101,
    text: 'Working Memory to Shared Memory should use a commit receipt governance gate before publish.'
  });
  const artifact = bot.store.all().find((event) => event.event_type === 'conversation_artifact' && event.payload.artifact_kind === 'benign_conversation_flow');
  assert.ok(artifact);
  assert.equal(artifact.payload.lifecycle_stage, 'working_memory_draft');
  assert.equal(artifact.payload.publication_status, 'working_memory');
  assert.equal(artifact.payload.commit_policy, 'draft_only');
  assert.equal(artifact.local_only, true);
  assert.equal(dkgWrites.some((event) => event.event_type === 'conversation_artifact'), false);
});

test('committed false-positive artifact carries receipt before Shared Memory write', async () => {
  const { bot, dkgWrites } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo', type: 'supergroup' };
  bot.store.append({
    id: 'evt-fp-governance',
    event_type: 'risk_review_needed',
    timestamp: new Date().toISOString(),
    chat,
    user: { id: 86, username: 'guerodelosbajos', is_bot: false },
    payload: { confidence: 90, scam_type: 'impersonation', evidence: ['false positive candidate'] }
  });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 35, text: '/review evt-fp-governance overturn SynthID discussion, not impersonation' });
  const artifact = dkgWrites.find((event) => event.event_type === 'conversation_artifact' && event.payload.artifact_kind === 'false_positive_signal');
  assert.ok(artifact);
  assert.match(artifact.payload.commit_receipt_id, /^commit:/);
  assert.equal(artifact.payload.commit_policy, 'human_or_admin_verified');
  assert.equal(artifact.payload.lifecycle_stage, 'shared_memory');
});

test('ordinary scam discussion does not trigger conversational reply', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'This looks like a scam risk. Do not click links.' }; } };
  const { bot, calls } = makeBot({
    canBan: false,
    conversational: true,
    llm,
    analyzer: () => ({ is_scam: false, confidence: 78, scam_type: 'other', evidence: [], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] },
    configOverrides: { proactiveReplyThreshold: 75 }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 4245, username: 'discussing', is_bot: false },
    message_id: 46,
    text: 'Lots of groups are talking about scam prevention lately.'
  });
  assert.equal(llmCalls.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('high-confidence proactive message does not trigger public conversation reply', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'This looks like a scam risk. Do not click links.' }; } };
  const { bot, calls } = makeBot({
    canBan: false,
    conversational: true,
    llm,
    analyzer: () => ({ is_scam: true, confidence: 82, scam_type: 'phishing', evidence: ['Suspicious link or claim-link pattern'], recommended_action: 'warn' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] },
    configOverrides: { proactiveReplyThreshold: 75 }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 4247, username: 'maybe_bad', is_bot: false },
    message_id: 48,
    text: 'scam link talk'
  });
  assert.equal(llmCalls.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('support username alone is not treated as scam evidence without a lure', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 4246, username: 'supportive_member', first_name: 'Supportive', is_bot: false },
    message_id: 47,
    text: 'We should discuss scam prevention in the next community call.'
  });
  const check = bot.store.all().find((event) => event.event_type === 'risk_check');
  assert.ok(check);
  assert.equal(check.payload.confidence, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('local-only moderate crypto wording is held below autonomous alert threshold', async () => {
  const { bot, calls } = makeBot({
    canBan: false,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 4243, username: 'maybe_sales', is_bot: false },
    message_id: 44,
    text: 'official support says claim now'
  });
  const check = bot.store.all().find((event) => event.event_type === 'risk_check');
  assert.ok(check);
  assert.equal(check.payload.confidence, 45);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && /Admin heads-up|confirmed fraud signal|TRACaBot risk/i.test(String(call.payload.text || ''))), false);
});

test('obvious wallet verification scam is deleted and published without DKG evidence but not banned', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 4244, username: 'wallet_helper', is_bot: false },
    message_id: 45,
    text: 'URGENT official support admin says verify wallet now at https://claim.example'
  });
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 45));
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 4244), false);
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 4244), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'fraud_finding' && event.user.id === 4244));
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_review_needed' && event.user.id === 4244 && event.payload.recommended_action === 'delete_and_review'));
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

test('low-risk new members receive plain-language Knowledge Asset address join challenge', async () => {
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
  assert.equal(restriction.payload.permissions.can_send_messages, false);
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
  assert.match(challenge, /quick check/);
  assert.match(challenge, /Copy any Knowledge Asset address/);
  assert.doesNotMatch(challenge, /A Knowledge Asset is a verifiable data item/);
  assert.match(challenge, /Send that address to me in DM: https:\/\/t\.me\/tracethembot\?start=verify_m100_44/);
  assert.match(challenge, /You are restricted here until verified/);
  assert.match(challenge, /starts with did:dkg/);
  assert.doesNotMatch(challenge, /\bUAL\b/);
  assert.doesNotMatch(challenge, /prove that you’re human and ready to join/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_started' && event.local_only));
});

test('chat_member joins receive Knowledge Asset address join challenge', async () => {
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
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 48 && call.payload.permissions.can_send_messages === false));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('quick check')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_started' && event.user.id === 48));
});

test('polling requests chat member updates for joins', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.pollOnce();
  const poll = calls.find((call) => call.method === 'getUpdates');
  assert.deepEqual(poll.payload.allowed_updates, ['message', 'chat_member', 'my_chat_member']);
});

test('group-pasted DKG UAL does not solve join challenge before DM verification', async () => {
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
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 45 && call.payload.permissions.can_send_photos === true), false);
  assert.equal(bot.joinChallenges.has('-100:45'), true);
  assert.ok(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 45));
  const reminder = calls.filter((call) => call.method === 'sendMessage').at(-1)?.payload.text || '';
  assert.match(reminder, /verification only works in DM/);
  assert.match(reminder, /https:\/\/t\.me\/tracethembot\?start=verify_m100_45/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.payload.verification_channel === 'group'));
});

test('DM DKG UAL solves join challenge and restores group permissions', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: true, reason: 'resolved' })
  });
  const group = { id: -100, title: 'demo', type: 'supergroup', username: 'traccommunity' };
  await bot.handleNewMembers({ chat: group, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 145, username: 'dmlearner', first_name: 'Dm', is_bot: false }] });
  await bot.handleMessage({ chat: { id: 145, type: 'private' }, from: { id: 145, username: 'dmlearner', is_bot: false }, message_id: 1, text: '/start verify_m100_145' });
  await bot.handleMessage({ chat: { id: 145, type: 'private' }, from: { id: 145, username: 'dmlearner', is_bot: false }, message_id: 2, text: 'did:dkg:knowledge-asset-valid-123456' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('Paste the Knowledge Asset address here')));
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 145 && call.payload.permissions.can_send_photos === true));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('✅ You’re in') && String(call.payload.text).includes('https://t.me/traccommunity')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('You shared a did:dkg: address')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('future of trusted, decentralized AI')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 145 && String(call.payload.text).includes('For more information: https://x.com/BranaRakic/status/2040159452431560995')));
  const groupSuccess = calls.find((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('DKG-verified'))?.payload || {};
  assert.match(groupSuccess.text, /@dmlearner/);
  assert.equal(groupSuccess.parse_mode, 'HTML');
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_solved' && event.payload.verification_channel === 'dm'));
});

test('DKG asset Q&A challenge verifies correct answer and unlocks user', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: {
      joinChallenge: true,
      joinChallengeMode: 'qa',
      joinChallengeAssetUrl: 'https://dkg.origintrail.io/explore?ual=did:dkg:challenge-asset',
      joinChallengeQaBank: [{ id: 'signal-color', question: 'What is the signal color?', answers: ['amber'] }]
    }
  });
  const group = { id: -100, title: 'demo', type: 'supergroup', username: 'traccommunity' };
  const user = { id: 246, username: 'qahuman', first_name: 'QA', is_bot: false };
  await bot.handleNewMembers({ chat: group, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
  const challenge = calls.find((call) => call.method === 'sendMessage' && call.payload.chat_id === -100)?.payload.text || '';
  assert.match(challenge, /Open this Knowledge Asset/);
  assert.match(challenge, /What is the signal color/);
  assert.match(challenge, /did:dkg:challenge-asset/);
  assert.equal(bot.joinChallenges.get('-100:246').mode, 'qa');

  await bot.handleMessage({ chat: { id: 246, type: 'private' }, from: user, message_id: 1, text: '/start verify_m100_246' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 246 && String(call.payload.text).includes('What is the signal color?')));
  await bot.handleMessage({ chat: { id: 246, type: 'private' }, from: user, message_id: 2, text: 'Amber!' });

  assert.equal(bot.joinChallenges.has('-100:246'), false);
  assert.ok(calls.some((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 246 && call.payload.until_date === 0));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 246 && String(call.payload.text).includes('https://t.me/traccommunity')));
  const solved = bot.store.all().find((event) => event.event_type === 'join_challenge_solved' && event.user.id === 246);
  assert.equal(solved.payload.challenge_type, 'dkg_asset_qa');
  assert.equal(solved.payload.answer, 'amber');
});

test('DKG asset Q&A challenge rejects wrong answer without unlocking', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: {
      joinChallenge: true,
      joinChallengeMode: 'qa',
      joinChallengeAssetUrl: 'https://dkg.origintrail.io/explore?ual=did:dkg:challenge-asset',
      joinChallengeQaBank: [{ id: 'checkpoint-word', question: 'What is the checkpoint word?', answers: ['atlas'] }]
    }
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  const user = { id: 247, username: 'wrongqa', first_name: 'Wrong', is_bot: false };
  await bot.handleNewMembers({ chat: group, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
  await bot.handleMessage({ chat: { id: 247, type: 'private' }, from: user, message_id: 1, text: 'discord' });

  assert.equal(bot.joinChallenges.has('-100:247'), true);
  assert.ok(!calls.some((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 247 && call.payload.until_date === 0));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 247 && String(call.payload.text).includes('did not match')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.payload.challenge_type === 'dkg_asset_qa'));
});

test('join challenge falls back to Knowledge Asset address mode when Q&A asset is not configured', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeMode: 'qa', joinChallengeAssetUrl: '', joinChallengeQaBank: [] }
  });
  await bot.handleNewMembers({ chat: { id: -100, title: 'demo' }, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 248, username: 'fallback', is_bot: false }] });
  const challenge = calls.find((call) => call.method === 'sendMessage' && call.payload.chat_id === -100)?.payload.text || '';
  assert.match(challenge, /Copy any Knowledge Asset address/);
  assert.doesNotMatch(challenge, /\bUAL\b/);
  assert.equal(bot.joinChallenges.get('-100:248').mode, 'ual');
});

test('solved join challenge ignores Telegram restriction update instead of starting duplicate challenge', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: true, reason: 'resolved' })
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  const user = { id: 245, username: 'onceverified', first_name: 'Once', is_bot: false };
  await bot.handleChatMemberUpdate({ chat: group, from: { id: 1, username: 'admin' }, old_chat_member: { status: 'left', user }, new_chat_member: { status: 'member', user } });
  await bot.handleMessage({ chat: { id: 245, type: 'private' }, from: user, message_id: 1, text: '/start verify_m100_245' });
  await bot.handleMessage({ chat: { id: 245, type: 'private' }, from: user, message_id: 2, text: 'did:dkg:knowledge-asset-valid-123456' });
  await bot.handleChatMemberUpdate({ chat: group, from: { id: 999, username: 'tracethembot' }, old_chat_member: { status: 'restricted', user }, new_chat_member: { status: 'restricted', user } });

  assert.equal(bot.joinChallenges.has('-100:245'), false);
  const challengeMessages = calls.filter((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('quick check'));
  assert.equal(challengeMessages.length, 1);
  const textOnlyRestrictions = calls.filter((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 245 && call.payload.permissions.can_send_messages === false && call.payload.permissions.can_send_photos === false);
  assert.equal(textOnlyRestrictions.length, 1);
  const unlocks = calls.filter((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 245 && call.payload.permissions.can_send_photos === true);
  assert.equal(unlocks.length, 1);
  assert.equal(unlocks[0].payload.until_date, 0);
  const success = calls.find((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('DKG-verified'))?.payload.text || '';
  assert.match(success, /@onceverified/);
});

test('verified user is challenged again after leaving and rejoining', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: true, reason: 'resolved' })
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  const user = { id: 345, username: 'rejoiner', first_name: 'Re', is_bot: false };
  await bot.handleChatMemberUpdate({ chat: group, from: { id: 1, username: 'admin' }, old_chat_member: { status: 'left', user }, new_chat_member: { status: 'member', user } });
  await bot.handleMessage({ chat: { id: 345, type: 'private' }, from: user, message_id: 1, text: '/start verify_m100_345' });
  await bot.handleMessage({ chat: { id: 345, type: 'private' }, from: user, message_id: 2, text: 'did:dkg:knowledge-asset-valid-123456' });
  assert.equal(bot.joinChallenges.has('-100:345'), false);
  await bot.handleChatMemberUpdate({ chat: group, from: user, old_chat_member: { status: 'member', user }, new_chat_member: { status: 'left', user } });
  await bot.handleChatMemberUpdate({ chat: group, from: user, old_chat_member: { status: 'left', user }, new_chat_member: { status: 'member', user } });
  assert.equal(bot.joinChallenges.has('-100:345'), true);
  const challengeMessages = calls.filter((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('quick check'));
  assert.equal(challengeMessages.length, 2);
  const textOnlyRestrictions = calls.filter((call) => call.method === 'restrictChatMember' && call.payload.chat_id === -100 && call.payload.user_id === 345 && call.payload.permissions.can_send_messages === false && call.payload.permissions.can_send_photos === false);
  assert.equal(textOnlyRestrictions.length, 2);
});

test('restricted membership update without join does not start challenge', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true }
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  const user = { id: 445, username: 'restrictedjoiner', first_name: 'Restricted', is_bot: false };
  await bot.handleChatMemberUpdate({
    chat: group,
    from: { id: 1, username: 'admin' },
    old_chat_member: { status: 'restricted', user },
    new_chat_member: { status: 'restricted', user }
  });
  assert.equal(bot.joinChallenges.has('-100:445'), false);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('quick check')), false);
});

test('member leaving does not start join challenge', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true }
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  const user = { id: 446, username: 'leaver', first_name: 'Leave', is_bot: false };
  await bot.handleChatMemberUpdate({
    chat: group,
    from: user,
    old_chat_member: { status: 'member', user },
    new_chat_member: { status: 'left', user }
  });
  assert.equal(bot.joinChallenges.has('-100:446'), false);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('quick check')), false);
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
  assert.match(reminder, /verification only works in DM/);
  assert.equal(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id !== 46), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.local_only));
});

test('pending challenge group reminders are sent once while repeated messages are deleted silently', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, challengeMessageTtlSeconds: 120 },
    validateUal: async () => ({ ok: false, reason: 'not_found' })
  });
  const chat = { id: -100, title: 'demo' };
  const user = { id: 149, username: 'chattynewbie', first_name: 'Chatty', is_bot: false };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
  await bot.handleMessage({ chat, from: user, message_id: 101, text: 'hello?' });
  await bot.handleMessage({ chat, from: user, message_id: 102, text: 'why removed?' });
  await bot.handleMessage({ chat, from: user, message_id: 103, text: 'let me talk' });

  const reminders = calls.filter((call) => call.method === 'sendMessage' && call.payload.chat_id === -100 && String(call.payload.text).includes('verification only works in DM'));
  assert.equal(reminders.length, 1);
  assert.equal(reminders[0].payload.parse_mode, 'HTML');
  const deletedUserMessages = calls.filter((call) => call.method === 'deleteMessage' && call.payload.chat_id === -100 && [101, 102, 103].includes(call.payload.message_id));
  assert.equal(deletedUserMessages.length, 3);
  const badAttempts = bot.store.all().filter((event) => event.event_type === 'join_challenge_bad_attempt' && event.user.id === 149);
  assert.equal(badAttempts.length, 3);
});

test('join challenge max attempts kicks unresolved users locally', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeMaxAttempts: 2, joinChallengeAction: 'kick' }
  });
  const chat = { id: -100, title: 'demo' };
  const user = { id: 150, username: 'twostrikes', first_name: 'Two', is_bot: false };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
  await bot.handleMessage({ chat, from: user, message_id: 201, text: 'hello?' });
  await bot.handleMessage({ chat, from: user, message_id: 202, text: 'still not dkg' });
  assert.equal(bot.joinChallenges.has('-100:150'), false);
  assert.ok(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 150));
  assert.ok(calls.some((call) => call.method === 'unbanChatMember' && call.payload.user_id === 150));
  const failed = bot.store.all().find((event) => event.event_type === 'join_challenge_failed_max_attempts' && event.user.id === 150);
  assert.equal(failed.local_only, true);
  assert.equal(failed.payload.attempts, 2);
  assert.equal(failed.payload.max_attempts, 2);
});

test('noisy group replies and scan replies are scheduled for cleanup', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { botMessageTtlSeconds: 60 }
  });
  const scheduled = [];
  bot.scheduleDelete = (chatId, messageId, ttlSeconds) => scheduled.push({ chatId, messageId, ttlSeconds });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 1947, username: 'BRX86' }, message_id: 39, text: '@tracethembot is Dmitry a scammer?' });
  assert.equal(scheduled.length, 1);
  assert.equal(scheduled[0].ttlSeconds, 60);
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 86, username: 'BRX86' }, message_id: 14, text: '/scan Dmitry' });
  assert.equal(scheduled.length, 2);
  assert.equal(scheduled[1].ttlSeconds, 60);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('@Dmitry')));
});

test('private DM challenge replies are not scheduled for cleanup', async () => {
  const { bot } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true }
  });
  const scheduled = [];
  bot.scheduleDelete = (chatId, messageId, ttlSeconds) => scheduled.push({ chatId, messageId, ttlSeconds });
  await bot.handleNewMembers({ chat: { id: -100, title: 'demo', type: 'supergroup' }, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 546, username: 'dmuser', first_name: 'Dm', is_bot: false }] });
  await bot.handleMessage({ chat: { id: 546, type: 'private' }, from: { id: 546, username: 'dmuser', is_bot: false }, message_id: 1, text: '/start verify_m100_546' });
  assert.equal(scheduled.length, 0);
});

test('invalid group-pasted DKG UAL challenge attempt is deleted and not accepted', async () => {
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
  assert.match(reminder, /verification only works in DM/);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.payload.verification_channel === 'group'));
});

test('invalid DM DKG UAL is validated and rejected without unlocking', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true },
    validateUal: async () => ({ ok: false, reason: 'not_found' })
  });
  const group = { id: -100, title: 'demo', type: 'supergroup' };
  await bot.handleNewMembers({ chat: group, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 147, username: 'baddmual', first_name: 'Bad DM', is_bot: false }] });
  await bot.handleMessage({ chat: { id: 147, type: 'private' }, from: { id: 147, username: 'baddmual', is_bot: false }, message_id: 1, text: '/start verify_m100_147' });
  await bot.handleMessage({ chat: { id: 147, type: 'private' }, from: { id: 147, username: 'baddmual', is_bot: false }, message_id: 2, text: 'did:dkg:knowledge-asset-missing-123456' });
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 147 && call.payload.permissions.can_send_photos === true), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 147 && String(call.payload.text).includes('could not validate')));
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_bad_attempt' && event.payload.verification_channel === 'dm' && event.payload.validation_reason === 'not_found'));
  assert.equal(bot.joinChallenges.has('-100:147'), true);
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

test('one-off expired DKG join challenge stays local-only without DKG write', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: true,
    analyzer: () => ({ is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeAction: 'kick' }
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 470, username: 'timeout_once', first_name: 'Timeout', is_bot: false }] });
  bot.joinChallenges.get('-100:470').expiresAt = Date.now() - 1;
  await bot.expireJoinChallenges();
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_expired' && event.local_only));
  assert.equal(dkgWrites.length, 0);
});

test('repeated DKG join challenge failures write aggregate Shared Memory once', async () => {
  const { bot, dkgWrites } = makeBot({
    canBan: true,
    analyzer: () => ({ is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeAction: 'kick' }
  });
  const chat = { id: -100, title: 'demo' };
  const user = { id: 471, username: 'repeatfail', first_name: 'Repeat', is_bot: false };
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
  bot.joinChallenges.get('-100:471').expiresAt = Date.now() - 1;
  await bot.expireJoinChallenges();
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
  bot.joinChallenges.get('-100:471').expiresAt = Date.now() - 1;
  await bot.expireJoinChallenges();
  assert.equal(dkgWrites.length, 1);
  assert.equal(dkgWrites[0].event_type, 'join_challenge_repeat_failure');
  assert.equal(dkgWrites[0].payload.challenge_failure_count, 2);
  assert.equal(dkgWrites[0].payload.target_key, 'id:471');
});

test('join challenge repeat failures cluster normalized 1win alias variants', async () => {
  const { bot, dkgWrites, calls } = makeBot({
    canBan: true,
    analyzer: () => ({ is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    configOverrides: { joinChallenge: true, joinChallengeAction: 'kick' }
  });
  const chat = { id: -100, title: 'demo' };
  for (const user of [
    { id: 481, username: '1win', first_name: 'One', is_bot: false },
    { id: 482, username: '1-win', first_name: 'Other', is_bot: false },
    { id: 483, username: '１WIN', first_name: 'Third', is_bot: false }
  ]) {
    await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [user] });
    bot.joinChallenges.get(`-100:${user.id}`).expiresAt = Date.now() - 1;
    await bot.expireJoinChallenges();
  }
  assert.equal(dkgWrites.length, 1);
  assert.equal(dkgWrites[0].payload.campaign_key, 'alias:1win');
  assert.ok(dkgWrites[0].payload.alias_keys.includes('1win'));
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 88, text: '/stats campaigns' });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 89, text: '/digest' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('join challenge repeat alias:1win')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('repeated join-challenge failure cluster')));
});

test('telegram command descriptions match the public bot command list', () => {
  assert.deepEqual(TELEGRAM_COMMANDS, [
    { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
    { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
    { command: 'dmreport', description: 'Report off-platform DM impersonation scams' },
    { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
    { command: 'stats', description: 'Show recent fraud checks and detections' },
    { command: 'why', description: 'Explain a tracabot event decision' },
    { command: 'watch', description: 'Admin: watch a suspicious actor' },
    { command: 'unwatch', description: 'Admin: remove a watched actor' },
    { command: 'watchlist', description: 'Admin: show watches, mutes, and review items' },
    { command: 'challenge', description: 'Admin: turn new-user join challenge on or off' },
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

test('repeated bot mentions stay silent when confidence is low', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'This looks risky. Do not click links or share wallet secrets. Ask an admin to review.' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 2, username: 'member' }, message_id: 35, text: '@tracethembot is this a scam?@tracethembot is this a scam?' });
  assert.equal(llmCalls.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('high-confidence legitimacy questions trigger bounded safety replies', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'It may be fake. Do not click links or share wallet secrets until an admin reviews it.' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  const chat = { id: -100, title: 'demo' };
  await bot.handleMessage({ chat, from: { id: 2, username: 'member' }, message_id: 36, text: '@tracethembot is this legit?', reply_to_message: { chat, from: { id: 90, username: 'fake_support' }, text: 'URGENT free USDT airdrop. Verify wallet with support admin at t.me/fakeclaim now.' } });
  assert.equal(llmCalls.length, 1);
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /fake|wallet secrets/);
});

test('bot mention does not answer low-confidence real-or-legit chatter', async () => {
  const llmCalls = [];
  const llm = { async complete(input) { llmCalls.push(input); return { ok: true, text: 'No strong warning from me.' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 1947, username: 'BRX86' }, message_id: 361, text: '@tracethembot is Sid E. Real real?' });
  assert.equal(llmCalls.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('legitimacy questions target mentioned user instead of bot or asker', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  await bot.handleMessage({ chat: { id: -100, title: 'demo' }, from: { id: 5150, username: 'a_51_50' }, message_id: 37, text: '@tracethembot is @BRX86 legit?' });
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('low-confidence legitimacy questions target named user but stay silent', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  const chat = { id: -100, title: 'demo' };
  bot.rememberUser(chat, { id: 777, first_name: 'Dmitry' }, 'recent chat context');
  await bot.handleMessage({ chat, from: { id: 1947, username: 'BRX86' }, message_id: 38, text: '@tracethembot is Dmitry legit?' });
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
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

test('conversation ignores unrelated chat when LLM is unavailable', async () => {
  const llm = { async complete() { return { ok: false, text: '' }; } };
  const { bot, calls } = makeBot({ canBan: true, conversational: true, llm, analyzer: analyzeMessage, dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] } });
  bot.config.restrictThreshold = 90;
  bot.config.banThreshold = 95;
  const chat = { id: -100, title: 'demo' };
  await bot.handleMessage({ chat, from: { id: 3, username: 'member' }, message_id: 33, text: 'nice weather today' });
  assert.equal(calls.some((call) => call.method === 'sendMessage'), false);
});

test('/why explains local event decisions', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  bot.store.append({
    id: 'evt-why',
    event_type: 'ban_executed',
    timestamp: new Date().toISOString(),
    user: { id: 55, username: 'badactor' },
    payload: { confidence: 91, local_confidence: 80, dkg_confidence: 20, scam_type: 'phishing', recommended_action: 'ban', publication_status: 'context_graph_auto_publish_eligible', lifecycle_stage: 'verified_memory', evidence: ['scam domain'], dkg_evidence: [{ ual: 'did:dkg:context-graph:tracabot/_shared_memory', eventId: 'prior' }] },
    dkg: { ual: 'did:dkg:context-graph:tracabot/_shared_memory', shareOperation: 'swm-why', subject: 'https://tracabot.org/ontology#event/evt-why', publish: { status: 'published' } }
  });
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 1, username: 'admin' }, message_id: 32, text: '/why evt-why' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /Why evt-why/);
  assert.match(reply, /Confidence: 91%/);
  assert.match(reply, /scam domain/);
  assert.match(reply, /Share operation: swm-why/);
  assert.match(reply, /Context Graph publish: published/);
  assert.match(reply, /Publication status: context_graph_auto_publish_eligible/);
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

test('/appeal and /review infer latest target event from user or reply', async () => {
  const { bot, dkgWrites } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  bot.store.append({
    id: 'evt-auto-review',
    event_type: 'risk_review_needed',
    timestamp: new Date().toISOString(),
    chat,
    user: { id: 86, username: 'guerodelosbajos', is_bot: false },
    payload: { confidence: 90, scam_type: 'impersonation', evidence: ['false positive candidate'] }
  });
  await bot.handleCommand({ chat, from: { id: 86, username: 'guerodelosbajos' }, message_id: 33, text: '/appeal this was SynthID discussion' });
  await bot.handleCommand({
    chat,
    from: { id: 1, username: 'admin' },
    message_id: 34,
    text: '/review overturn agreed false positive',
    reply_to_message: { chat, from: { id: 86, username: 'guerodelosbajos' }, text: 'Soo... vididentifier is synthid?' }
  });
  assert.ok(dkgWrites.some((event) => event.event_type === 'appeal_submitted' && event.payload.target_event_id === 'evt-auto-review'));
  assert.ok(dkgWrites.some((event) => event.event_type === 'review_overturned' && event.payload.target_event_id === 'evt-auto-review'));
});

test('/review overturn suppresses future enforcement for the reviewed user', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const chat = { id: -100, title: 'demo' };
  bot.store.append({
    id: 'evt-false-positive',
    event_type: 'risk_review_needed',
    timestamp: new Date().toISOString(),
    chat,
    user: { id: 4242, username: 'askme42', is_bot: false },
    payload: { confidence: 99, scam_type: 'other', evidence: ['bad prior signal'] }
  });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 34, text: '/review evt-false-positive overturn false positive' });
  await bot.handleNewMembers({
    chat,
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 4242, username: 'askme42', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 4242), false);
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 4242), false);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('learning fraud patterns')), false);
  const checks = bot.store.all().filter((event) => event.event_type === 'risk_check' && event.user.id === 4242);
  assert.ok(checks.some((event) => event.payload.confidence <= 10 && event.payload.recommended_action === 'ignore'));
});

test('/watch boosts scrutiny until /unwatch closes it', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    analyzer: () => ({ is_scam: false, confidence: 50, scam_type: 'other', evidence: ['thin signal'], recommended_action: 'ignore' }),
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  const scheduled = [];
  bot.scheduleDelete = (chatId, messageId, ttlSeconds) => scheduled.push({ chatId, messageId, ttlSeconds });
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
  assert.equal(scheduled.length, 0);
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

test('/review with no args shows latest pending review items', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  const scheduled = [];
  bot.scheduleDelete = (chatId, messageId, ttlSeconds) => scheduled.push({ chatId, messageId, ttlSeconds });
  const chat = { id: -100, title: 'demo' };
  bot.store.append({ id: 'review-old', event_type: 'risk_review_needed', timestamp: new Date(Date.now() - 60_000).toISOString(), chat, user: { id: 87, username: 'old_review' }, payload: { confidence: 65, evidence: ['old signal'] } });
  bot.store.append({ id: 'review-new', event_type: 'report_review_needed', timestamp: new Date().toISOString(), chat, user: { id: 88, username: 'new_review' }, payload: { confidence: 70, evidence: ['new signal'] } });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 45, text: '/review' });
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload || {};
  assert.match(reply.text || '', /Latest pending review items/);
  assert.match(reply.text || '', /review-new/);
  assert.match(reply.text || '', /review-old/);
  assert.ok((reply.text || '').indexOf('review-new') < (reply.text || '').indexOf('review-old'));
  assert.equal(reply.parse_mode, 'HTML');
  assert.equal(scheduled.length, 1);
  assert.equal(scheduled[0].ttlSeconds, 60);
});

test('/watchlist rejects non-admin requesters', async () => {
  const { bot, calls } = makeBot({ canBan: true, trustedUserIds: [] });
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 2, username: 'member' }, message_id: 46, text: '/watchlist' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('restricted')));
});

test('/challenge lets admins toggle new-user join challenge per chat', async () => {
  const { bot, calls } = makeBot({
    canBan: true,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], patterns: [], evidence: [] },
    analyzer: () => ({ is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' })
  });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 47, text: '/challenge on' });
  assert.equal(bot.chatJoinChallengeEnabled(chat.id), true);
  assert.ok(bot.store.all().some((event) => event.event_type === 'join_challenge_setting_changed' && event.payload.enabled === true && event.local_only));
  await bot.handleNewMembers({ chat, from: { id: 1, username: 'admin' }, new_chat_members: [{ id: 9001, username: 'new_user', is_bot: false }] });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && /quick check before posting/.test(call.payload.text)));
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 48, text: '/challenge off' });
  assert.equal(bot.chatJoinChallengeEnabled(chat.id), false);
});

test('/challenge rejects non-admin requesters', async () => {
  const { bot, calls } = makeBot({ canBan: true, trustedUserIds: [] });
  await bot.handleCommand({ chat: { id: -100, title: 'demo' }, from: { id: 2, username: 'member' }, message_id: 49, text: '/challenge on' });
  assert.equal(bot.chatJoinChallengeEnabled(-100), false);
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
  bot.store.append({ id: 'evt-c1', event_type: 'fraud_finding', timestamp, payload: { domains: ['fake.example'], confidence: 80, local_confidence: 75, evidence: ['fake.example'] } });
  bot.store.append({ id: 'evt-c2', event_type: 'report_submitted', timestamp, payload: { domains: ['fake.example'], confidence: 90, local_confidence: 85, report_decision: 'accepted', evidence: ['fake.example'] } });
  const chat = { id: -100, title: 'demo' };
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 37, text: '/stats campaigns' });
  await bot.handleCommand({ chat, from: { id: 1, username: 'admin' }, message_id: 38, text: '/digest' });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('domain:fake.example')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('tracabot digest')));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Recommended follow-up')));
});

test('campaign summaries include evidence roots and affected communities', async () => {
  const { bot } = makeBot({ canBan: true, testMode: false });
  const timestamp = new Date().toISOString();
  bot.store.append({ id: 'evt-root-1', event_type: 'fraud_finding', timestamp, chat: { id: '-1001' }, payload: { domains: ['fake.example'], patterns: ['wallet-drain'], confidence: 95, local_confidence: 90, community_id: '-1001', evidence: ['fake.example'] } });
  bot.store.append({ id: 'evt-root-2', event_type: 'report_submitted', timestamp, chat: { id: '-1002' }, payload: { domains: ['fake.example'], patterns: ['wallet-drain'], confidence: 90, local_confidence: 85, community_id: '-1002', evidence: ['fake.example'] } });
  const campaign = await bot.maybeRecordCampaign({ chat: { id: -1003, title: 'demo' }, from: { id: 1, username: 'admin' } }, { scam_type: 'phishing', confidence: 91, local_confidence: 88 });
  assert.equal(campaign.event_type, 'fraud_campaign');
  assert.deepEqual(campaign.payload.evidence_root_ids, ['evt-root-1', 'evt-root-2']);
  assert.deepEqual(campaign.payload.affected_community_ids, ['-1001', '-1002']);
  assert.equal(campaign.payload.campaign_event_count, 2);
  assert.equal(campaign.payload.campaign_community_count, 2);
  assert.deepEqual(campaign.payload.domains, ['fake.example']);
  assert.deepEqual(campaign.payload.patterns, ['wallet-drain']);
  assert.equal(campaign.payload.lifecycle_stage, 'campaign_summary');
  assert.equal(campaign.payload.publication_status, 'context_graph_auto_publish_eligible');
});

test('campaign summaries ignore weak local-only and prior campaign events as roots', async () => {
  const { bot } = makeBot({ canBan: true, testMode: false });
  const timestamp = new Date().toISOString();
  bot.store.append({ id: 'evt-weak', event_type: 'scam_detection', timestamp, payload: { domains: ['fake.example'], confidence: 95, evidence: ['fake.example'] } });
  bot.store.append({ id: 'evt-campaign', event_type: 'fraud_campaign', timestamp, payload: { domains: ['fake.example'], confidence: 95, evidence: ['prior campaign'] } });
  assert.equal(await bot.maybeRecordCampaign({ chat: { id: -1003 }, from: { id: 1 } }, { confidence: 95, local_confidence: 90 }), null);

  bot.store.append({ id: 'evt-root-1', event_type: 'fraud_finding', timestamp, payload: { domains: ['fake.example'], confidence: 95, local_confidence: 90, evidence: ['fake.example'] } });
  assert.equal(await bot.maybeRecordCampaign({ chat: { id: -1003 }, from: { id: 1 } }, { confidence: 95, local_confidence: 90 }), null);

  bot.store.append({ id: 'evt-root-2', event_type: 'report_submitted', timestamp, payload: { domains: ['fake.example'], confidence: 90, local_confidence: 85, report_decision: 'accepted', evidence: ['fake.example'] } });
  const campaign = await bot.maybeRecordCampaign({ chat: { id: -1003 }, from: { id: 1 } }, { confidence: 95, local_confidence: 90 });
  assert.deepEqual(campaign.payload.evidence_root_ids, ['evt-root-1', 'evt-root-2']);
});

test('medium-risk domain-only message is capped below action without DKG evidence', async () => {
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
  assert.equal(calls.some((call) => call.method === 'deleteMessage' && call.payload.message_id === 31), false);
  assert.equal(calls.some((call) => call.method === 'restrictChatMember' && call.payload.user_id === 68), false);
  assert.equal(calls.some((call) => call.method === 'banChatMember' && call.payload.user_id === 68), false);
  assert.ok(bot.store.all().some((event) => event.event_type === 'risk_check' && event.payload.confidence === 59));
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

test('/dmreport publishes cross-community DM impersonation evidence without group target', async () => {
  const { bot, calls, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 221,
    text: '/dmreport Branimir Rakic impersonator claiming CTO from OriginTrail is DMing users to connect wallet for support'
  });
  const report = dkgWrites.find((event) => event.event_type === 'dm_scam_report');
  assert.ok(report);
  assert.equal(report.payload.reported_alias, 'Branimir Rakic');
  assert.match(report.payload.claimed_role, /cto/);
  assert.equal(report.payload.report_decision, 'accepted');
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  const reply = calls.find((call) => call.method === 'sendMessage')?.payload.text || '';
  assert.match(reply, /DM scam report saved/);
  assert.match(reply, /cross-community warnings/);
});

test('private SangMata reports only process for configured bot owner', async () => {
  const { bot, calls, dkgWrites } = makeBot({ canBan: false, adminIds: ['1354777145'] });
  const text = 'User 8367741707 changed name from Joo Woklf to beldex Support';

  await bot.handleMessage({ chat: { id: 1354777145, type: 'private' }, from: { id: 1354777145, username: 'BRX86', is_bot: false }, message_id: 1, text });

  assert.ok(dkgWrites.some((event) => event.event_type === 'report_submitted' && String(event.user?.id) === '8367741707'));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && call.payload.chat_id === 1354777145 && String(call.payload.text).includes('beldex Support')));
});

test('private SangMata reports from non-owner do not flag DM sender', async () => {
  const { bot, calls, dkgWrites } = makeBot({ canBan: false, adminIds: ['1354777145'] });
  const text = 'User 8367741707 changed name from Joo Woklf to beldex Support';

  await bot.handleMessage({ chat: { id: 999, type: 'private' }, from: { id: 999, username: 'random_reporter', is_bot: false }, message_id: 1, text });

  assert.equal(dkgWrites.length, 0);
  assert.equal(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('TRACaBot risk for @random_reporter')), false);
});

test('/dmreport accepts screenshot caption metadata but rejects screenshot-only reports', async () => {
  const { bot, calls, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 222,
    text: '/dmreport',
    caption: 'Fake founder DM asks to verify wallet for support',
    photo: [{ file_id: 'small' }, { file_id: 'large-screenshot' }]
  });
  const accepted = dkgWrites.find((event) => event.event_type === 'dm_scam_report');
  assert.ok(accepted);
  assert.deepEqual(accepted.payload.screenshot_file_ids, ['large-screenshot']);
  assert.match(accepted.payload.claimed_role, /founder/);

  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 87, username: 'reporter' },
    message_id: 223,
    text: '/dmreport',
    photo: [{ file_id: 'only-shot' }]
  });
  const weak = bot.store.all().find((event) => event.event_type === 'report_review_needed' && event.payload?.screenshot_file_ids?.includes('only-shot'));
  assert.ok(weak);
  assert.equal(weak.local_only, true);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('need stronger details')));
});

test('bot mention can submit DM scam report without replying to random low-confidence chatter', async () => {
  const { bot, calls, dkgWrites } = makeBot({
    canBan: true,
    analyzer: analyzeMessage,
    dkgIntel: { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [] }
  });
  await bot.handleMessage({
    chat: { id: -100, title: 'demo' },
    from: { id: 86, username: 'BRX86' },
    message_id: 224,
    text: '@tracethembot report DM scam: fake CEO from another community is DMing people to validate wallet'
  });
  assert.ok(dkgWrites.some((event) => event.event_type === 'dm_scam_report'));
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('DM scam report saved')));
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

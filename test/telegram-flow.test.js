import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TELEGRAM_COMMANDS, TelegramShieldBot } from '../src/telegram.js';
import { analyzeMessage } from '../src/scam-analyzer.js';
import { EventStore } from '../src/store.js';

function makeBot({ canBan, trustedUserIds = [1], analyzer: analyzerOverride = null, dkgIntel = null, adminIds = ['1234'] }) {
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
      proactiveScanMinutes: 30,
      agentDid: 'did:dkg:agent:test'
    },
    analyzer: analyzerOverride || analyzer,
    dkg,
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-flow-')), 'events.jsonl'))
  });
  bot.call = async (method, payload) => {
    calls.push({ method, payload });
    if (method === 'getMe') return { id: 999, username: 'tracethembot' };
    if (method === 'getChatMember') {
      if (payload.user_id === 999) return { status: canBan ? 'administrator' : 'member', can_restrict_members: canBan, can_delete_messages: canBan };
      return { status: trustedUserIds.includes(payload.user_id) ? 'administrator' : 'member', can_restrict_members: false };
    }
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

test('new high-risk join alerts admins when bot lacks ban rights', async () => {
  const { bot, calls } = makeBot({ canBan: false });
  await bot.handleNewMembers({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    new_chat_members: [{ id: 43, username: 'fake_support2', is_bot: false }]
  });
  assert.equal(calls.some((call) => call.method === 'banChatMember'), false);
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Admin heads-up')));
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

test('telegram command descriptions match the public bot command list', () => {
  assert.deepEqual(TELEGRAM_COMMANDS, [
    { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
    { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
    { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
    { command: 'stats', description: 'Show recent fraud checks and detections' },
    { command: 'why', description: 'Explain a tracabot event decision' },
    { command: 'watch', description: 'Admin: watch a suspicious actor' },
    { command: 'unwatch', description: 'Admin: remove a watched actor' },
    { command: 'appeal', description: 'Submit an appeal or correction for an event' },
    { command: 'review', description: 'Admin: uphold or overturn an event' },
    { command: 'digest', description: 'Show recent moderation digest' },
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
  assert.match(help, /Context Graph tracabot/);
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
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('UAL: did:dkg:context-graph:tracabot/_shared_memory')));
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
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('UAL: did:dkg:context-graph:tracabot/_shared_memory')));
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
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Report not published to DKG')));
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
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('duplicate report')));
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
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('needs a replied message')));
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

test('/stats pulls DKG aggregate data', async () => {
  const { bot, calls } = makeBot({ canBan: true });
  await bot.handleCommand({
    chat: { id: -100, title: 'demo' },
    from: { id: 1, username: 'admin' },
    message_id: 13,
    text: '/stats'
  });
  assert.ok(calls.some((call) => call.method === 'sendMessage' && String(call.payload.text).includes('Shield report (7d)')));
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

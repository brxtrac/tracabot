import { randomUUID } from 'node:crypto';
import { combineRisk, formatBanReply, formatDkgReference, formatReportReply, formatRiskAssessment, formatScanReply, formatStatsReply } from './risk-engine.js';
import { extractWallets } from './dkg-client.js';

export const TELEGRAM_COMMANDS = [
  { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
  { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
  { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
  { command: 'stats', description: 'Show recent fraud checks and detections' }
];

const MAX_TEXT_CHARS = 4096;
const MAX_CONTEXT_CHARS = 500;

function boundedText(value = '', max = MAX_TEXT_CHARS) {
  return String(value || '').slice(0, max);
}

async function telegram(token, method, payload, timeoutMs = 30000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    const body = await response.json();
    if (!body.ok) throw new Error(`Telegram ${method} failed: ${body.description || response.statusText}`);
    return body.result;
  } finally {
    clearTimeout(timeout);
  }
}

function actorFromMessage(message) {
  return message.from || {};
}

function actorKey(actor = {}) {
  return actor.id ? `id:${actor.id}` : actor.username ? `username:${actor.username.toLowerCase()}` : '';
}

function targetKey(target = {}) {
  if (target.kind === 'wallet') return `wallet:${target.id}`;
  return target.id ? `id:${target.id}` : target.username ? `username:${target.username.toLowerCase()}` : target.label || '';
}

export class TelegramShieldBot {
  constructor({ config, analyzer, dkg, store }) {
    this.config = config;
    this.analyzer = analyzer;
    this.dkg = dkg;
    this.store = store;
    this.offset = 0;
    this.botId = null;
    this.observedUsers = new Map();
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;
  }

  async call(method, payload) {
    return telegram(this.config.telegramToken, method, payload, this.config.telegramTimeoutMs);
  }

  async send(chatId, text, extra = {}) {
    return this.call('sendMessage', { chat_id: chatId, text, ...extra });
  }

  async ban(chatId, userId) {
    return this.call('banChatMember', { chat_id: chatId, user_id: userId });
  }

  async getBotId() {
    if (this.botId) return this.botId;
    const me = await this.call('getMe', {});
    this.botId = me.id;
    return this.botId;
  }

  async hasBanRights(chatId) {
    try {
      const member = await this.call('getChatMember', { chat_id: chatId, user_id: await this.getBotId() });
      return member.status === 'administrator' && member.can_restrict_members !== false;
    } catch {
      return false;
    }
  }

  async isTelegramChatAdmin(chatId, userId) {
    if (!userId) return false;
    try {
      const member = await this.call('getChatMember', { chat_id: chatId, user_id: userId });
      return ['creator', 'administrator'].includes(member.status);
    } catch {
      return false;
    }
  }

  rememberUser(chat, user, context = '') {
    if (user?.id && !user.label && user.is_bot !== true) {
      this.observedUsers.set(`${chat.id}:${user.id}`, {
        chat,
        user,
        context,
        lastSeen: new Date().toISOString()
      });
    }
  }

  targetFromMention(message) {
    const username = (message.text || '').match(/@([A-Za-z0-9_]{3,32})/)?.[1];
    if (!username || /^(tracabot|tracethembot)$/i.test(username)) return null;
    return { id: '', username, kind: 'user' };
  }

  targetFromPlainArgument(argText = '') {
    const firstToken = argText.trim().split(/\s+/)[0] || '';
    const normalized = firstToken.replace(/^@/, '').replace(/[^\p{L}\p{N}_-]/gu, '');
    if (!normalized || /^(tracabot|tracethembot)$/i.test(normalized)) return null;
    if (extractWallets(firstToken).length) return null;
    if (/^https?:/i.test(firstToken)) return null;
    return {
      id: '',
      username: normalized,
      label: normalized.startsWith('@') ? normalized : `@${normalized}`,
      kind: 'user'
    };
  }

  targetFromWallet(text = '') {
    const wallet = extractWallets(text)[0];
    return wallet ? { id: wallet, label: wallet, kind: 'wallet' } : null;
  }

  isConfiguredAdmin(user = {}) {
    return this.config.adminIds.has(String(user.id).toLowerCase()) || this.config.adminIds.has(String(user.username || '').replace(/^@/, '').toLowerCase());
  }

  async isTrustedModerator(message) {
    const user = actorFromMessage(message);
    return this.isConfiguredAdmin(user) || await this.isTelegramChatAdmin(message.chat.id, user.id);
  }

  commandText(message, command) {
    return boundedText(message.text || '').replace(new RegExp(`^/${command}(?:@\\w+)?\\s*`, 'i'), '').trim();
  }

  resolveCommandTarget(message, command) {
    const argText = this.commandText(message, command);
    const reply = message.reply_to_message;
    const mentioned = this.targetFromMention(message);
    const walletTarget = this.targetFromWallet(argText || reply?.text || '');
    const plainTarget = this.targetFromPlainArgument(argText);
    const target = mentioned || walletTarget || plainTarget || (reply ? actorFromMessage(reply) : actorFromMessage(message));
    const text = boundedText([argText, reply?.text || ''].filter(Boolean).join('\n') || message.text || '');
    return { target, text, reply };
  }

  async alertAdmins(message, risk, event) {
    const ref = formatDkgReference(event);
    const text = [
      '🚨 Admin heads-up: high-confidence fraud risk, but I do not have ban rights here.',
      formatRiskAssessment({ target: actorFromMessage(message), risk }),
      ref ? `DKG UAL: ${ref}` : `DKG event: ${event.id}`,
      message.text ? `Context: ${boundedText(message.text, MAX_CONTEXT_CHARS)}` : ''
    ].filter(Boolean).join('\n');
    await this.send(message.chat.id, text, { reply_to_message_id: message.message_id });
    for (const adminId of this.config.adminIds) {
      try {
        await this.send(adminId, text);
      } catch {
        // Telegram only allows DM after an admin starts the bot.
      }
    }
  }

  async record(eventType, message, payload, { writeDkg = true } = {}) {
    const event = {
      id: randomUUID(),
      event_type: eventType,
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: message.chat,
      user: actorFromMessage(message),
      payload
    };
    if (writeDkg) {
      try {
        event.dkg = await this.dkg.writeEvent(event);
      } catch (error) {
        event.dkg_error = error instanceof Error ? error.message : String(error);
      }
    } else {
      event.local_only = true;
    }
    this.store.append(event);
    return event;
  }

  isRiskQuery(message) {
    const text = message.text || '';
    const mentionsBot = /@tracabot\b|@tracethembot\b/i.test(text);
    const asksFraud = /\b(fraudster|scammer|scam|bot|blacklisted|safe|risk)\b/i.test(text);
    return (mentionsBot && asksFraud) || Boolean(message.reply_to_message && asksFraud);
  }

  async assess(message, targetUser = actorFromMessage(message), text = message.text || '') {
    const bounded = boundedText(text);
    this.rememberUser(message.chat, targetUser, bounded);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: targetUser.username, text: bounded });
    const analysis = this.analyzer({ text: bounded, user: targetUser, globalIntel: dkgIntel });
    return combineRisk({ analysis, dkgIntel, threshold: this.config.actionThreshold });
  }

  reportHistory(reporter, target) {
    const reporterId = actorKey(reporter);
    const targetId = targetKey(target);
    const now = Date.now();
    const reports = this.store.all().filter((event) => actorKey(event.payload?.reporter || {}) === reporterId);
    const recent = reports.filter((event) => now - Date.parse(event.timestamp) <= 10 * 60 * 1000);
    const duplicate = reports.some((event) => {
      if (now - Date.parse(event.timestamp) > 24 * 60 * 60 * 1000) return false;
      return event.payload?.target_key === targetId && ['accepted', 'weak'].includes(event.payload?.report_decision);
    });
    const accepted = reports.filter((event) => event.payload?.report_decision === 'accepted').length;
    const rejected = reports.filter((event) => event.payload?.report_decision === 'rejected').length;
    return {
      recentCount: recent.length,
      duplicate,
      accepted,
      rejected,
      reporterScore: accepted + rejected ? Math.round((accepted / (accepted + rejected)) * 100) : 50
    };
  }

  evaluateReport({ message, target, targetText, risk }) {
    const reporter = actorFromMessage(message);
    const history = this.reportHistory(reporter, target);
    const isAdmin = this.isConfiguredAdmin(reporter);
    const suppliedEvidence = Boolean(message.reply_to_message?.text) || targetText.replace(/^@\w+\s*/, '').trim().length >= 16 || risk.wallets.length > 0;
    const independentEvidence = risk.local_confidence >= 60 || risk.wallets.length > 0 || risk.patterns.length >= 2;
    const selfReportWithoutEvidence = actorKey(reporter) && actorKey(reporter) === actorKey(target) && !suppliedEvidence;
    if (!isAdmin && history.recentCount >= 3) {
      return { accepted: false, decision: 'rejected', reason: 'report rate limit reached for this reporter', history, suppliedEvidence, independentEvidence };
    }
    if (!isAdmin && history.duplicate) {
      return { accepted: false, decision: 'rejected', reason: 'duplicate report for the same target in the last 24 hours', history, suppliedEvidence, independentEvidence };
    }
    if (selfReportWithoutEvidence) {
      return { accepted: false, decision: 'rejected', reason: 'report has no target evidence', history, suppliedEvidence, independentEvidence };
    }
    if (!suppliedEvidence) {
      return { accepted: false, decision: 'rejected', reason: 'report needs a replied message, wallet, link, or suspicious text', history, suppliedEvidence, independentEvidence };
    }
    if (!independentEvidence && !isAdmin) {
      return { accepted: true, decision: 'weak', reason: 'stored locally for review because independent scam evidence is weak', history, suppliedEvidence, independentEvidence };
    }
    return { accepted: true, decision: 'accepted', reason: 'independent evidence present', history, suppliedEvidence, independentEvidence };
  }

  async publishHighConfidenceFinding(message, risk) {
    return this.record('fraud_finding', message, {
      ...risk,
      evidence: [...risk.evidence, 'high-confidence finding published for cross-community reuse']
    });
  }

  async applyRiskAction(message, risk) {
    const check = await this.record('risk_check', message, risk);
    if (risk.confidence < this.config.actionThreshold) return check;

    const finding = await this.publishHighConfidenceFinding(message, risk);
    const canBan = this.config.autoBan && await this.hasBanRights(message.chat.id);
    if (canBan) {
      await this.ban(message.chat.id, actorFromMessage(message).id);
      await this.record('ban_executed', message, {
        ...risk,
        evidence: [...risk.evidence, `auto-ban threshold ${this.config.actionThreshold}% met`, `finding event ${finding.id}`]
      });
      await this.send(message.chat.id, `tracabot banned ${actorFromMessage(message).username || actorFromMessage(message).id}. ${formatRiskAssessment({ target: actorFromMessage(message), risk })} DKG finding: ${finding.id}`, { reply_to_message_id: message.message_id });
      return finding;
    }

    await this.alertAdmins(message, risk, finding);
    return finding;
  }

  async handleCommand(message) {
    const text = message.text || '';
    const chatId = message.chat.id;
    if (text.startsWith('/stats')) {
      const stats = await this.dkg.getStats(7);
      await this.send(chatId, formatStatsReply(stats));
      return;
    }
    if (text.startsWith('/scan')) {
      const { target, text: targetText } = this.resolveCommandTarget(message, 'scan');
      const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      const finding = risk.confidence >= 80 ? await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk) : null;
      await this.send(chatId, formatScanReply({ target, risk, eventId: event.id, findingId: finding?.id }), { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/report')) {
      const { target, text: targetText } = this.resolveCommandTarget(message, 'report');
      const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
      const reportDecision = this.evaluateReport({ message, target, targetText, risk });
      const reportPayload = {
        ...risk,
        reporter: actorFromMessage(message),
        target_key: targetKey(target),
        report_decision: reportDecision.decision,
        report_reason: reportDecision.reason,
        reporter_score: reportDecision.history.reporterScore,
        reporter_recent_reports: reportDecision.history.recentCount,
        evidence: [...risk.evidence, `manual Telegram report submitted by ${actorFromMessage(message).username || actorFromMessage(message).id}`, `report decision: ${reportDecision.decision} (${reportDecision.reason})`]
      };
      if (!reportDecision.accepted || reportDecision.decision !== 'accepted') {
        const event = await this.record(reportDecision.decision === 'weak' ? 'report_review_needed' : 'report_rejected', { ...message, from: target }, reportPayload, { writeDkg: false });
        await this.send(chatId, formatReportReply(event, reportDecision), { reply_to_message_id: message.message_id });
        return;
      }
      const event = await this.record('report_submitted', { ...message, from: target }, {
        ...reportPayload,
        confidence: Math.max(risk.confidence, risk.local_confidence)
      });
      const trustedReporter = await this.isTrustedModerator(message);
      const canEscalate = trustedReporter && risk.local_confidence >= 60 && risk.confidence >= this.config.actionThreshold;
      if (canEscalate && target.id && target.kind !== 'wallet') {
        await this.applyRiskAction({ ...message, from: target, text: targetText }, risk);
      } else if (risk.local_confidence >= 60 && risk.confidence >= this.config.actionThreshold) {
        await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk);
      }
      await this.send(chatId, formatReportReply(event, reportDecision), { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/ban')) {
      const { target, text: targetText } = this.resolveCommandTarget(message, 'ban');
      const replyUser = message.reply_to_message?.from;
      if (!await this.isTrustedModerator(message)) {
        const event = await this.record('ban_rejected_unauthorized', { ...message, from: target }, {
          reason: 'manual /ban rejected because requester is not a configured admin or Telegram chat admin',
          requester: actorFromMessage(message),
          evidence: ['manual /ban requires trusted moderator privileges']
        }, { writeDkg: false });
        await this.send(chatId, `⚠️ /ban is restricted to configured admins or Telegram chat admins. Request logged locally as ${event.id}.`, { reply_to_message_id: message.message_id });
        return;
      }
      if (!replyUser) {
        const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
        const event = await this.record('ban_requested_no_reply', { ...message, from: target }, {
          ...risk,
          evidence: [...risk.evidence, 'manual /ban requested without a replied Telegram user ID']
        });
        await this.send(chatId, `⚠️ I can scan/report ${target.label || target.username || 'that target'}, but Telegram needs a replied message so I can ban the exact user. Evidence logged to DKG event ${event.id}.`, { reply_to_message_id: message.message_id });
        return;
      }
      const reason = this.commandText(message, 'ban') || 'admin requested ban';
      const context = [reason, message.reply_to_message?.text || ''].filter(Boolean).join('\n');
      const risk = await this.assess({ ...message, from: replyUser, text: context }, replyUser, context);
      if (!await this.hasBanRights(chatId)) {
        const event = await this.record('ban_requested_no_rights', { ...message, from: replyUser }, {
          ...risk,
          reason,
          evidence: [...risk.evidence, 'manual /ban requested but bot lacks Telegram ban rights']
        });
        await this.alertAdmins({ ...message, from: replyUser, text: context }, risk, event);
        return;
      }
      await this.ban(chatId, replyUser.id);
      const event = await this.record('ban_executed', { ...message, from: replyUser }, {
        ...risk,
        reason,
        confidence: Math.max(100, risk.confidence),
        scam_type: risk.scam_type || 'admin_action',
        evidence: [...risk.evidence, reason, 'manual /ban command']
      });
      await this.send(chatId, formatBanReply(replyUser, event.id));
    }
  }

  async handleMessage(message) {
    if (message.new_chat_members?.length) {
      await this.handleNewMembers(message);
      return;
    }
    if (!message.text) return;
    if (message.text.startsWith('/')) {
      await this.handleCommand(message);
      return;
    }
    if (this.isRiskQuery(message)) {
      const targetMessage = message.reply_to_message || message;
      const target = this.targetFromMention(message) || actorFromMessage(targetMessage);
      const risk = await this.assess({ ...message, from: target }, target, `${message.text}\n${targetMessage.text || ''}`);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      const finding = risk.confidence >= 80 ? await this.publishHighConfidenceFinding({ ...message, from: target }, risk) : null;
      await this.send(message.chat.id, formatScanReply({ target, risk, eventId: event.id, findingId: finding?.id }), { reply_to_message_id: message.message_id });
      return;
    }
    const user = actorFromMessage(message);
    const risk = await this.assess(message, user, message.text);
    if (risk.confidence < this.config.actionThreshold) {
      await this.record('risk_check', message, risk);
    }
    if (risk.confidence >= 60) {
      await this.record('scam_detection', message, risk);
    }
    if (risk.confidence >= this.config.actionThreshold) {
      await this.applyRiskAction(message, risk);
    }
  }

  async handleNewMembers(message) {
    for (const member of message.new_chat_members) {
      const joinMessage = { ...message, from: member, text: `new member joined @${member.username || member.id}` };
      const risk = await this.assess(joinMessage, member, joinMessage.text);
      await this.applyRiskAction(joinMessage, risk);
    }
  }

  async proactiveScan() {
    if (Date.now() < this.nextProactiveScanAt) return;
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;
    for (const entry of this.observedUsers.values()) {
      const message = {
        chat: entry.chat,
        from: entry.user,
        text: entry.context || `proactive scan @${entry.user.username || entry.user.id}`
      };
      const risk = await this.assess(message, entry.user, message.text);
      if (risk.confidence >= this.config.actionThreshold) await this.applyRiskAction(message, risk);
    }
  }

  async pollOnce() {
    const updates = await this.call('getUpdates', {
      offset: this.offset,
      timeout: 25,
      allowed_updates: ['message']
    });
    for (const update of updates) {
      this.offset = update.update_id + 1;
      if (update.message) await this.handleMessage(update.message);
    }
    await this.proactiveScan();
  }

  async run() {
    if (!this.config.telegramToken) throw new Error('TELEGRAM_BOT_TOKEN is required');
    await this.dkg.ensureContextGraph();
    try {
      await this.call('setMyCommands', { commands: TELEGRAM_COMMANDS });
    } catch (error) {
      console.error(`setMyCommands failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    for (;;) {
      try {
        await this.pollOnce();
      } catch (error) {
        console.error(error instanceof Error ? error.message : String(error));
        await new Promise((resolve) => setTimeout(resolve, 3000));
      }
    }
  }
}

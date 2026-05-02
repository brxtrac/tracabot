import { randomUUID } from 'node:crypto';
import { combineRisk, formatBanReply, formatDkgReference, formatReportReply, formatRiskAssessment, formatScanReply, formatStatsReply, formatStatsSourcesReply } from './risk-engine.js';
import { extractWallets } from './dkg-client.js';

export const TELEGRAM_COMMANDS = [
  { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
  { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
  { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
  { command: 'stats', description: 'Show recent fraud checks and detections' },
  { command: 'help', description: 'Show tracabot commands and autonomous policy' }
];

const MAX_TEXT_CHARS = 4096;
const MAX_CONTEXT_CHARS = 500;
const OBSERVED_CONTEXT_TTL_MS = 24 * 60 * 60 * 1000;
const RECENT_JOIN_RENAME_WINDOW_MS = 30 * 60 * 1000;

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

function normalizedIdentity(user = {}) {
  return [user.username, user.first_name, user.last_name]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
    .replace(/^@/, '')
    .replace(/[^a-z0-9]/g, '');
}

function actorAliases(user = {}) {
  return [
    user.username,
    user.first_name,
    [user.first_name, user.last_name].filter(Boolean).join(' ')
  ].filter(Boolean);
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

  async restrict(chatId, userId, untilDate = Math.floor(Date.now() / 1000) + 24 * 60 * 60) {
    return this.call('restrictChatMember', {
      chat_id: chatId,
      user_id: userId,
      until_date: untilDate,
      permissions: {
        can_send_messages: false,
        can_send_audios: false,
        can_send_documents: false,
        can_send_photos: false,
        can_send_videos: false,
        can_send_video_notes: false,
        can_send_voice_notes: false,
        can_send_polls: false,
        can_send_other_messages: false,
        can_add_web_page_previews: false,
        can_change_info: false,
        can_invite_users: false,
        can_pin_messages: false,
        can_manage_topics: false
      }
    });
  }

  async deleteMessage(chatId, messageId) {
    if (!messageId) return null;
    return this.call('deleteMessage', { chat_id: chatId, message_id: messageId });
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

  async hasRestrictRights(chatId) {
    return this.hasBanRights(chatId);
  }

  async hasDeleteRights(chatId) {
    try {
      const member = await this.call('getChatMember', { chat_id: chatId, user_id: await this.getBotId() });
      return member.status === 'administrator' && member.can_delete_messages !== false;
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
      const key = `${chat.id}:${user.id}`;
      const existing = this.observedUsers.get(key);
      const firstSeen = existing?.firstSeen || new Date().toISOString();
      const firstIdentity = existing?.firstIdentity || normalizedIdentity(user);
      this.observedUsers.set(key, {
        chat,
        user,
        firstUser: existing?.firstUser || user,
        firstIdentity,
        firstSeen,
        context,
        lastSeen: new Date().toISOString()
      });
    }
  }

  adminRenameCopycat(chat, user = {}) {
    if (!user?.id) return null;
    const entry = this.observedUsers.get(`${chat.id}:${user.id}`);
    if (!entry?.firstIdentity) return null;
    if (Date.now() - Date.parse(entry.firstSeen) > RECENT_JOIN_RENAME_WINDOW_MS) return null;
    const currentIdentity = normalizedIdentity(user);
    if (!currentIdentity || currentIdentity === entry.firstIdentity) return null;
    const matchedAdmin = [...this.config.adminIds]
      .filter((id) => !/^\d+$/.test(id))
      .map((id) => normalizedIdentity({ username: id }))
      .find((admin) => admin && currentIdentity !== admin && (currentIdentity.includes(admin) || admin.includes(currentIdentity)));
    return matchedAdmin ? { matchedAdmin, firstIdentity: entry.firstIdentity, currentIdentity } : null;
  }

  observedContextFor(chat, target = {}) {
    const now = Date.now();
    const targetUsername = String(target.username || '').toLowerCase();
    const targetId = target.id ? String(target.id) : '';
    for (const entry of this.observedUsers.values()) {
      if (String(entry.chat?.id) !== String(chat?.id)) continue;
      if (now - Date.parse(entry.lastSeen) > OBSERVED_CONTEXT_TTL_MS) continue;
      const entryUsername = String(entry.user?.username || '').toLowerCase();
      const entryId = entry.user?.id ? String(entry.user.id) : '';
      if ((targetId && entryId === targetId) || (targetUsername && entryUsername === targetUsername)) {
        return entry.context || '';
      }
    }
    return '';
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

  resolveReportTarget(message) {
    const resolved = this.resolveCommandTarget(message, 'report');
    const argText = this.commandText(message, 'report');
    const mentionOnly = /^@\w{3,32}$/i.test(argText.trim());
    const observedContext = this.observedContextFor(message.chat, resolved.target);
    const textParts = [];
    if (!mentionOnly) textParts.push(argText);
    if (resolved.reply?.text) textParts.push(resolved.reply.text);
    if (observedContext && !textParts.some((part) => part.includes(observedContext))) textParts.push(observedContext);
    const text = boundedText(textParts.filter(Boolean).join('\n') || resolved.text || message.text || '');
    return { ...resolved, text, observedContext, mentionOnly };
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

  formatHelp() {
    const graph = this.config.contextGraph || 'tracabot';
    const warn = this.config.warnThreshold ?? 60;
    const restrict = this.config.restrictThreshold ?? 75;
    const ban = this.config.banThreshold ?? this.config.actionThreshold ?? 85;
    return [
      'tracabot commands:',
      '/scan <user|wallet|message> - check risk using local analysis + DKG shared memory.',
      '/report <user|wallet|text> - submit suspicious evidence to DKG when it has independent signal.',
      '/ban - admin-only; reply to a user to ban and publish evidence.',
      '/stats - show recent DKG threat activity. Use /stats sources for receipts.',
      '/help - show this command guide.',
      '',
      `Autonomous policy: warn/log at ${warn}%, delete/restrict at ${restrict}%, delete/ban at ${ban}%.`,
      `DKG memory: reads and writes shared fraud evidence in Context Graph ${graph}, including actors, wallets, domains, scam patterns, reports, findings, and bans.`,
      'Safeguards: no auto-action against Telegram admins or bot accounts; weak reports stay local.'
    ].join('\n');
  }

  async record(eventType, message, payload, { writeDkg = true } = {}) {
    const decoratedPayload = this.config.testMode
      ? { ...payload, source: payload?.source || 'test-command-loop', test_mode: true }
      : payload;
    const event = {
      id: randomUUID(),
      event_type: eventType,
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: message.chat,
      user: actorFromMessage(message),
      payload: decoratedPayload
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
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: targetUser.username, userId: targetUser.id, aliases: actorAliases(targetUser), text: bounded });
    const adminUsernames = [...this.config.adminIds].filter((id) => !/^\d+$/.test(id));
    const renameCopycat = this.adminRenameCopycat(message.chat, targetUser);
    const analysis = this.analyzer({ text: bounded, user: { ...targetUser, adminUsernames, adminRenameCopycat: Boolean(renameCopycat) }, globalIntel: dkgIntel });
    if (renameCopycat) {
      analysis.confidence = Math.max(analysis.confidence || 0, this.config.actionThreshold);
      analysis.is_scam = true;
      analysis.recommended_action = 'ban';
      analysis.scam_type = 'impersonation';
      analysis.evidence = [...(analysis.evidence || []), `Joined as ${renameCopycat.firstIdentity}, then changed identity to resemble admin ${renameCopycat.matchedAdmin}`];
    }
    return combineRisk({ analysis, dkgIntel, threshold: this.config.actionThreshold });
  }

  reportHistory(reporter, target) {
    const reporterId = actorKey(reporter);
    const targetId = targetKey(target);
    const now = Date.now();
    const reports = this.store.all().filter((event) => ['report_submitted', 'report_review_needed', 'report_rejected'].includes(event.event_type) && actorKey(event.payload?.reporter || {}) === reporterId);
    const recent = reports.filter((event) => now - Date.parse(event.timestamp) <= 10 * 60 * 1000);
    const duplicate = reports.some((event) => {
      if (now - Date.parse(event.timestamp) > 24 * 60 * 60 * 1000) return false;
      return event.payload?.target_key === targetId && ['accepted', 'weak'].includes(event.payload?.report_decision);
    });
    const accepted = reports.filter((event) => event.payload?.report_decision === 'accepted').length;
    const rejected = reports.filter((event) => event.payload?.report_decision === 'rejected').length;
    const successful = reports.filter((event) => event.payload?.report_outcome === 'context_graph_published' || event.payload?.report_outcome === 'high_confidence_dkg_report' || Number(event.payload?.confidence || 0) >= 80).length;
    const weak = reports.filter((event) => event.payload?.report_decision === 'weak').length;
    const reporterScore = accepted + rejected + weak
      ? Math.max(0, Math.min(100, Math.round(((accepted * 70) + (successful * 30) - (weak * 15) - (rejected * 35)) / Math.max(accepted + rejected + weak, 1))))
      : 50;
    return {
      recentCount: recent.length,
      duplicate,
      accepted,
      rejected,
      weak,
      successful,
      reporterScore,
      trustedReporter: successful >= 2 || reporterScore >= 75
    };
  }

  evaluateReport({ message, target, targetText, risk }) {
    const reporter = actorFromMessage(message);
    const history = this.reportHistory(reporter, target);
    const isAdmin = this.isConfiguredAdmin(reporter);
    const targetOnlyReport = target.kind !== 'wallet' && /^@\w{3,32}$/i.test(this.commandText(message, 'report').trim()) && !message.reply_to_message?.text;
    const hasTargetReference = target.kind === 'wallet' || Boolean(target.username || target.id || target.label);
    const suppliedEvidence = Boolean(message.reply_to_message?.text) || targetText.replace(/^@\w+\s*/, '').trim().length >= 16 || risk.wallets.length > 0 || (targetOnlyReport && hasTargetReference);
    const reportWorthyLocalPattern = risk.local_confidence >= 40 && ['impersonation', 'phishing', 'giveaway'].includes(risk.scam_type) && (risk.evidence?.length || 0) > 0;
    const trustedReporterEvidence = history.trustedReporter && hasTargetReference;
    const independentEvidence = risk.local_confidence >= 60 || reportWorthyLocalPattern || trustedReporterEvidence || risk.wallets.length > 0 || risk.patterns.length >= 1;
    const selfReportWithoutEvidence = actorKey(reporter) && actorKey(reporter) === actorKey(target) && !suppliedEvidence;
    if (!isAdmin && history.recentCount >= 3) {
      return { accepted: false, decision: 'rejected', reason: 'report rate limit reached for this reporter', history, suppliedEvidence, independentEvidence, reportWorthyLocalPattern };
    }
    if (!isAdmin && history.duplicate) {
      return { accepted: false, decision: 'rejected', reason: 'duplicate report for the same target in the last 24 hours', history, suppliedEvidence, independentEvidence, reportWorthyLocalPattern };
    }
    if (selfReportWithoutEvidence) {
      return { accepted: false, decision: 'rejected', reason: 'report has no target evidence', history, suppliedEvidence, independentEvidence, reportWorthyLocalPattern };
    }
    if (!suppliedEvidence) {
      return { accepted: false, decision: 'rejected', reason: 'report needs a replied message, wallet, link, or suspicious text', history, suppliedEvidence, independentEvidence, reportWorthyLocalPattern };
    }
    if (!independentEvidence && !isAdmin) {
      return { accepted: true, decision: 'weak', reason: 'stored locally for review because no scam pattern, wallet, link, or DKG match was strong enough', history, suppliedEvidence, independentEvidence, reportWorthyLocalPattern };
    }
    const reason = trustedReporterEvidence && !reportWorthyLocalPattern ? 'trusted reporter target submitted for DKG review' : reportWorthyLocalPattern ? 'local scam pattern detected' : 'independent evidence present';
    return { accepted: true, decision: 'accepted', reason, history, suppliedEvidence, independentEvidence, reportWorthyLocalPattern, trustedReporterEvidence };
  }

  async recordReporterReputation(message, target, reportEvent, reportDecision) {
    const reporter = actorFromMessage(message);
    const outcome = reportEvent.dkg?.publish ? 'context_graph_published' : Number(reportEvent.payload?.confidence || 0) >= 80 ? 'high_confidence_dkg_report' : 'accepted_dkg_report';
    await this.record('reporter_reputation_update', { ...message, from: reporter }, {
      reporter,
      target_key: targetKey(target),
      report_event_id: reportEvent.id,
      report_decision: reportDecision.decision,
      report_outcome: outcome,
      reporter_score: reportDecision.history.reporterScore,
      reporter_successful_reports: reportDecision.history.successful,
      evidence: [`reporter reputation updated after ${outcome}`]
    }, { writeDkg: false });
  }

  async publishHighConfidenceFinding(message, risk) {
    return this.record('fraud_finding', message, {
      ...risk,
      publication_status: 'context_graph_auto_publish_eligible',
      evidence: [...risk.evidence, 'high-confidence finding automatically published to the Context Graph for cross-community reuse']
    });
  }

  async applyRiskAction(message, risk) {
    const check = await this.record('risk_check', message, risk);
    if (risk.confidence < (this.config.warnThreshold ?? 60)) return check;

    const actor = actorFromMessage(message);
    if (actor.is_bot === true || await this.isTelegramChatAdmin(message.chat.id, actor.id)) {
      const review = await this.record('risk_action_suppressed', message, {
        ...risk,
        evidence: [...risk.evidence, actor.is_bot === true ? 'auto-action suppressed for Telegram bot account' : 'auto-action suppressed for Telegram chat admin']
      }, { writeDkg: false });
      await this.alertAdmins(message, risk, review);
      return review;
    }

    const canDelete = this.config.autoDelete !== false && await this.hasDeleteRights(message.chat.id);
    const deletedMessage = canDelete ? await this.deleteMessage(message.chat.id, message.message_id).then(() => true).catch(() => false) : false;
    const banThreshold = this.config.banThreshold ?? this.config.actionThreshold;
    const restrictThreshold = this.config.restrictThreshold ?? 75;

    if (risk.confidence >= banThreshold && this.config.autoBan && await this.hasBanRights(message.chat.id)) {
      const finding = await this.publishHighConfidenceFinding(message, risk);
      await this.ban(message.chat.id, actorFromMessage(message).id);
      await this.record('ban_executed', message, {
        ...risk,
        evidence: [...risk.evidence, `auto-ban threshold ${banThreshold}% met`, deletedMessage ? 'triggering message removed' : 'triggering message removal unavailable', `finding event ${finding.id}`]
      });
      await this.send(message.chat.id, `tracabot banned ${actorFromMessage(message).username || actorFromMessage(message).id}. ${formatRiskAssessment({ target: actorFromMessage(message), risk })} DKG finding: ${finding.id}`, { reply_to_message_id: message.message_id });
      return finding;
    }

    if (risk.confidence >= restrictThreshold && this.config.autoRestrict !== false && await this.hasRestrictRights(message.chat.id)) {
      const finding = await this.publishHighConfidenceFinding(message, risk);
      await this.restrict(message.chat.id, actorFromMessage(message).id);
      await this.record('restrict_executed', message, {
        ...risk,
        evidence: [...risk.evidence, `auto-restrict threshold ${restrictThreshold}% met`, deletedMessage ? 'triggering message removed' : 'triggering message removal unavailable', `finding event ${finding.id}`]
      });
      await this.send(message.chat.id, `tracabot restricted ${actorFromMessage(message).username || actorFromMessage(message).id}. ${formatRiskAssessment({ target: actorFromMessage(message), risk })} DKG finding: ${finding.id}`, { reply_to_message_id: message.message_id });
      return finding;
    }

    const review = await this.record('risk_review_needed', message, {
      ...risk,
      evidence: [...risk.evidence, deletedMessage ? 'triggering message removed' : 'no autonomous restriction available']
    }, { writeDkg: false });
    await this.alertAdmins(message, risk, review);
    return review;
  }

  async handleCommand(message) {
    const text = message.text || '';
    const chatId = message.chat.id;
    if (text.startsWith('/stats')) {
      const stats = await this.dkg.getStats(7);
      const wantsSources = /\b(source|sources|evidence|receipts)\b/i.test(text);
      await this.send(chatId, wantsSources ? formatStatsSourcesReply(stats) : formatStatsReply(stats));
      return;
    }
    if (text.startsWith('/help') || text.startsWith('/start')) {
      await this.send(chatId, this.formatHelp(), { reply_to_message_id: message.message_id });
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
      const { target, text: targetText, observedContext } = this.resolveReportTarget(message);
      const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
      const reportDecision = this.evaluateReport({ message, target, targetText, risk });
      const contextBoost = message.reply_to_message?.text || observedContext ? 20 : 0;
      const reporterBoost = reportDecision.history.trustedReporter ? 15 : 0;
      const contextGraphReportFloor = reportDecision.reportWorthyLocalPattern || reportDecision.trustedReporterEvidence ? 80 : 0;
      const localContextGraphFloor = reportDecision.reportWorthyLocalPattern || reportDecision.trustedReporterEvidence ? 60 : 0;
      const reportConfidence = reportDecision.decision === 'accepted'
        ? Math.max(risk.confidence, risk.local_confidence, Math.min(95, risk.local_confidence + contextBoost + reporterBoost), contextGraphReportFloor)
        : Math.max(risk.confidence, risk.local_confidence);
      const reportLocalConfidence = reportDecision.decision === 'accepted'
        ? Math.max(risk.local_confidence, Math.min(90, risk.local_confidence + contextBoost + reporterBoost), localContextGraphFloor)
        : risk.local_confidence;
      const reportPayload = {
        ...risk,
        confidence: reportConfidence,
        local_confidence: reportLocalConfidence,
        reporter: actorFromMessage(message),
        target_key: targetKey(target),
        report_decision: reportDecision.decision,
        report_reason: reportDecision.reason,
        report_outcome: reportDecision.decision === 'accepted' && reportConfidence >= 80 ? 'high_confidence_dkg_report' : reportDecision.decision,
        reporter_trusted: reportDecision.history.trustedReporter,
        reporter_successful_reports: reportDecision.history.successful,
        reporter_score: reportDecision.history.reporterScore,
        reporter_recent_reports: reportDecision.history.recentCount,
        evidence: [
          ...risk.evidence,
          observedContext ? `recent observed message used as report context: ${boundedText(observedContext, MAX_CONTEXT_CHARS)}` : '',
          `manual Telegram report submitted by ${actorFromMessage(message).username || actorFromMessage(message).id}`,
          `report decision: ${reportDecision.decision} (${reportDecision.reason})`
        ].filter(Boolean)
      };
      if (!reportDecision.accepted || reportDecision.decision !== 'accepted') {
        const event = await this.record(reportDecision.decision === 'weak' ? 'report_review_needed' : 'report_rejected', { ...message, from: target }, reportPayload, { writeDkg: false });
        await this.send(chatId, formatReportReply(event, reportDecision), { reply_to_message_id: message.message_id });
        return;
      }
      const event = await this.record('report_submitted', { ...message, from: target }, reportPayload);
      await this.recordReporterReputation(message, target, event, reportDecision);
      const trustedReporter = await this.isTrustedModerator(message);
      const canEscalate = trustedReporter && reportLocalConfidence >= 60 && reportConfidence >= this.config.actionThreshold;
      if (canEscalate && target.id && target.kind !== 'wallet') {
        await this.applyRiskAction({ ...message, from: target, text: targetText }, reportPayload);
      } else if (reportLocalConfidence >= 60 && reportConfidence >= this.config.actionThreshold) {
        await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, reportPayload);
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
    if (risk.confidence >= (this.config.warnThreshold ?? 60)) {
      await this.record('scam_detection', message, risk);
    }
    if (risk.confidence >= (this.config.restrictThreshold ?? this.config.actionThreshold)) {
      await this.applyRiskAction(message, risk);
    }
  }

  async handleNewMembers(message) {
    for (const member of message.new_chat_members) {
      const botId = await this.getBotId().catch(() => null);
      if (member.is_bot === true || (botId && String(member.id) === String(botId))) continue;
      const joinMessage = { ...message, from: member, text: `new member joined @${member.username || member.id}` };
      this.rememberUser(message.chat, member, joinMessage.text);
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
    try {
      await this.dkg.ensureContextGraph();
    } catch (error) {
      console.error(`DKG startup check failed; continuing with Telegram polling: ${error instanceof Error ? error.message : String(error)}`);
    }
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

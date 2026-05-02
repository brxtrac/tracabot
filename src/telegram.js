import { randomUUID } from 'node:crypto';
import { combineRisk, formatBanReply, formatDkgReference, formatReportReply, formatRiskAssessment, formatScanReply, formatStatsReply, formatStatsSourcesReply } from './risk-engine.js';
import { extractWallets } from './dkg-client.js';

export const TELEGRAM_COMMANDS = [
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

function eventAgeMs(event = {}) {
  const timestamp = Date.parse(event.timestamp || '');
  return Number.isNaN(timestamp) ? Infinity : Date.now() - timestamp;
}

function eventMatchesTarget(event = {}, target = {}) {
  const key = targetKey(target);
  const eventUser = event.user || {};
  return actorKey(eventUser) === key || event.payload?.target_key === key || event.payload?.watch_target_key === key;
}

function textFingerprint(text = '') {
  const words = String(text).toLowerCase().replace(/https?:\/\/\S+/g, '').replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((word) => word.length > 2);
  return words.slice(0, 16).join(' ');
}

function plural(count, singular, pluralWord = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralWord}`;
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
      '/why <event-id> - explain local + DKG evidence behind a decision.',
      '/watch @user reason - admin-only; increase scrutiny without banning by itself.',
      '/unwatch @user reason - admin-only; close a watch entry.',
      '/appeal <event-id> reason - submit a correction or appeal to DKG.',
      '/review <event-id> uphold|overturn reason - admin-only DKG review decision.',
      '/stats campaigns - show repeated domains, wallets, patterns, or text fingerprints.',
      '/digest - summarize recent actions, reports, watches, appeals, and campaigns.',
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

  findEvent(eventId = '') {
    if (!eventId) return null;
    return this.store.all().find((event) => event.id === eventId || event.payload?.report_event_id === eventId || event.payload?.target_event_id === eventId) || null;
  }

  activeWatchFor(target = {}) {
    const key = targetKey(target);
    if (!key) return null;
    const events = this.store.all().filter((event) => event.payload?.watch_target_key === key);
    let active = null;
    for (const event of events) {
      if (event.event_type === 'watch_started') active = event;
      if (event.event_type === 'watch_ended') active = null;
    }
    return active;
  }

  formatWhy(eventId = '') {
    const event = this.findEvent(eventId);
    if (!event) return `No local tracabot event found for ${eventId}. Try /stats sources for recent DKG receipts.`;
    const risk = event.payload || {};
    const evidence = risk.evidence?.length ? risk.evidence.slice(0, 8).map((item) => `- ${item}`).join('\n') : '- No evidence recorded.';
    const dkgRefs = risk.dkg_evidence?.length ? risk.dkg_evidence.slice(0, 4).map((item) => `- ${item.ual || 'DKG'}${item.eventId ? ` event ${item.eventId}` : ''}`).join('\n') : '- No DKG source refs on this event.';
    const action = event.event_type;
    const ref = formatDkgReference(event) || event.id;
    return [
      `Why ${event.id}: ${action}`,
      `Confidence: ${risk.confidence ?? 0}% (local ${risk.local_confidence ?? 0}%, DKG ${risk.dkg_confidence ?? 0}%). Type: ${risk.scam_type || 'unknown'}.`,
      `Recommendation/action: ${risk.recommended_action || action}. Ref: ${ref}`,
      'Evidence:',
      evidence,
      'DKG sources:',
      dkgRefs
    ].join('\n');
  }

  recentEvents(ms = 24 * 60 * 60 * 1000) {
    return this.store.all().filter((event) => eventAgeMs(event) <= ms);
  }

  campaignSummary(windowMs = 24 * 60 * 60 * 1000) {
    const buckets = new Map();
    for (const event of this.recentEvents(windowMs)) {
      const payload = event.payload || {};
      for (const domain of payload.domains || []) {
        const key = `domain:${domain}`;
        buckets.set(key, [...(buckets.get(key) || []), event]);
      }
      for (const wallet of payload.wallets || []) {
        const key = `wallet:${wallet}`;
        buckets.set(key, [...(buckets.get(key) || []), event]);
      }
      for (const pattern of payload.patterns || []) {
        const key = `pattern:${pattern}`;
        buckets.set(key, [...(buckets.get(key) || []), event]);
      }
      const fp = textFingerprint((payload.evidence || []).join(' '));
      if (fp) {
        const key = `text:${fp}`;
        buckets.set(key, [...(buckets.get(key) || []), event]);
      }
    }
    return [...buckets.entries()]
      .map(([key, events]) => ({ key, events: [...new Map(events.map((event) => [event.id, event])).values()] }))
      .filter((item) => item.events.length >= 2)
      .sort((a, b) => b.events.length - a.events.length || a.key.localeCompare(b.key));
  }

  async maybeRecordCampaign(message, risk) {
    const campaigns = this.campaignSummary(24 * 60 * 60 * 1000).filter((campaign) => !this.store.all().some((event) => event.event_type === 'fraud_campaign' && event.payload?.campaign_key === campaign.key));
    const campaign = campaigns[0];
    if (!campaign) return null;
    return this.record('fraud_campaign', message, {
      scam_type: risk.scam_type || 'campaign',
      confidence: Math.max(80, risk.confidence || 0),
      local_confidence: risk.local_confidence || risk.confidence || 0,
      campaign_key: campaign.key,
      related_event_ids: campaign.events.slice(0, 10).map((event) => event.id),
      evidence: [`Campaign signal ${campaign.key} repeated across ${campaign.events.length} recent events`]
    }, { writeDkg: !this.config.testMode });
  }

  formatCampaigns() {
    const campaigns = this.campaignSummary(7 * 24 * 60 * 60 * 1000).slice(0, 6);
    if (!campaigns.length) return 'No repeated fraud campaigns found in recent local memory.';
    return ['Recent campaign signals:', ...campaigns.map((campaign) => `- ${campaign.key} across ${plural(campaign.events.length, 'event')}: ${campaign.events.slice(0, 4).map((event) => event.id).join(', ')}`)].join('\n');
  }

  formatDigest() {
    const events = this.recentEvents(24 * 60 * 60 * 1000);
    const count = (types) => events.filter((event) => types.includes(event.event_type)).length;
    const campaigns = this.campaignSummary(24 * 60 * 60 * 1000);
    const high = events.filter((event) => Number(event.payload?.confidence || 0) >= 80).length;
    return [
      `tracabot digest (24h): ${plural(events.length, 'event')}, ${plural(high, 'high-confidence signal')}.`,
      `Actions: ${plural(count(['ban_executed']), 'ban')}, ${plural(count(['restrict_executed']), 'restriction')}, ${plural(count(['report_submitted']), 'accepted report')}.`,
      `Review: ${plural(count(['risk_review_needed', 'risk_action_suppressed']), 'admin review item')}, ${plural(count(['appeal_submitted']), 'appeal')}, ${plural(count(['review_upheld', 'review_overturned']), 'review decision')}.`,
      `Watchlist: ${plural(count(['watch_started']), 'watch started')}, ${plural(count(['watch_ended']), 'watch ended')}.`,
      campaigns.length ? `Top campaign: ${campaigns[0].key} across ${campaigns[0].events.length} events.` : 'No repeated campaign cluster in the last 24h.',
      'Use /stats sources for DKG receipts or /why <event-id> for a decision explanation.'
    ].join('\n');
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
    const watch = this.activeWatchFor(targetUser);
    if (watch) {
      analysis.confidence = Math.min(99, Math.max(analysis.confidence || 0, (analysis.confidence || 0) + 15));
      analysis.evidence = [...(analysis.evidence || []), `Active watchlist entry ${watch.id}: ${watch.payload?.reason || 'admin watch'}`];
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
      if (/\bcampaigns?\b/i.test(text)) {
        await this.send(chatId, this.formatCampaigns(), { reply_to_message_id: message.message_id });
        return;
      }
      const stats = await this.dkg.getStats(7);
      const wantsSources = /\b(source|sources|evidence|receipts)\b/i.test(text);
      await this.send(chatId, wantsSources ? formatStatsSourcesReply(stats) : formatStatsReply(stats));
      return;
    }
    if (text.startsWith('/help') || text.startsWith('/start')) {
      await this.send(chatId, this.formatHelp(), { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/why')) {
      const eventId = this.commandText(message, 'why').split(/\s+/)[0] || '';
      await this.send(chatId, this.formatWhy(eventId), { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/digest')) {
      await this.send(chatId, this.formatDigest(), { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/watch')) {
      if (!await this.isTrustedModerator(message)) {
        await this.send(chatId, '⚠️ /watch is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const { target } = this.resolveCommandTarget(message, 'watch');
      const reason = this.commandText(message, 'watch').replace(/^@?\S+\s*/, '').trim() || 'admin watch';
      const event = await this.record('watch_started', { ...message, from: target }, {
        watch_target_key: targetKey(target),
        target,
        reason,
        moderator: actorFromMessage(message),
        evidence: [`admin watch started: ${reason}`]
      });
      await this.send(chatId, `👀 Watching ${target.label || target.username || target.id}. Evidence logged as ${event.id}.`, { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/unwatch')) {
      if (!await this.isTrustedModerator(message)) {
        await this.send(chatId, '⚠️ /unwatch is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const { target } = this.resolveCommandTarget(message, 'unwatch');
      const reason = this.commandText(message, 'unwatch').replace(/^@?\S+\s*/, '').trim() || 'admin unwatch';
      const event = await this.record('watch_ended', { ...message, from: target }, {
        watch_target_key: targetKey(target),
        target,
        reason,
        moderator: actorFromMessage(message),
        evidence: [`admin watch ended: ${reason}`]
      });
      await this.send(chatId, `✅ Removed watch for ${target.label || target.username || target.id}. Logged as ${event.id}.`, { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/appeal')) {
      const [eventId, ...reasonParts] = this.commandText(message, 'appeal').split(/\s+/);
      const reason = reasonParts.join(' ').trim() || 'appeal submitted';
      const event = await this.record('appeal_submitted', message, {
        target_event_id: eventId || '',
        reason,
        appellant: actorFromMessage(message),
        evidence: [`appeal submitted for ${eventId || 'unknown event'}: ${reason}`]
      });
      await this.send(chatId, `📝 Appeal logged to DKG as ${event.id}. Admins can /review ${eventId || '<event-id>'} uphold|overturn reason.`, { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/review')) {
      if (!await this.isTrustedModerator(message)) {
        await this.send(chatId, '⚠️ /review is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const [eventId, decisionRaw, ...reasonParts] = this.commandText(message, 'review').split(/\s+/);
      const decision = /^(uphold|upheld)$/i.test(decisionRaw || '') ? 'upheld' : /^(overturn|overturned|reject)$/i.test(decisionRaw || '') ? 'overturned' : '';
      if (!eventId || !decision) {
        await this.send(chatId, 'Usage: /review <event-id> uphold|overturn reason', { reply_to_message_id: message.message_id });
        return;
      }
      const reason = reasonParts.join(' ').trim() || `review ${decision}`;
      const eventType = decision === 'upheld' ? 'review_upheld' : 'review_overturned';
      const event = await this.record(eventType, message, {
        target_event_id: eventId,
        review_decision: decision,
        reason,
        reviewer: actorFromMessage(message),
        evidence: [`admin review ${decision} ${eventId}: ${reason}`]
      });
      await this.send(chatId, `✅ Review ${decision} for ${eventId}. DKG event ${event.id}.`, { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/scan')) {
      const { target, text: targetText } = this.resolveCommandTarget(message, 'scan');
      const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      const finding = risk.confidence >= 80 ? await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk) : null;
      await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, risk);
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
        await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, reportPayload);
        await this.send(chatId, formatReportReply(event, reportDecision), { reply_to_message_id: message.message_id });
        return;
      }
      const event = await this.record('report_submitted', { ...message, from: target }, reportPayload);
      await this.recordReporterReputation(message, target, event, reportDecision);
      await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, reportPayload);
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
      await this.maybeRecordCampaign({ ...message, from: replyUser, text: context }, risk);
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
      await this.maybeRecordCampaign({ ...message, from: target }, risk);
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
      await this.maybeRecordCampaign(message, risk);
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

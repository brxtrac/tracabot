import { randomUUID } from 'node:crypto';
import { combineRisk, formatRiskAssessment } from './risk-engine.js';

async function telegram(token, method, payload) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const body = await response.json();
  if (!body.ok) throw new Error(`Telegram ${method} failed: ${body.description || response.statusText}`);
  return body.result;
}

function actorFromMessage(message) {
  return message.from || {};
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
    return telegram(this.config.telegramToken, method, payload);
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

  rememberUser(chat, user, context = '') {
    if (user?.id && user.is_bot !== true) {
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
    return { id: '', username };
  }

  async alertAdmins(message, risk, event) {
    const text = [
      'tracabot admin alert: high-confidence fraud risk and no ban rights available.',
      formatRiskAssessment({ target: actorFromMessage(message), risk }),
      `DKG event: ${event.id}`,
      message.text ? `Context: ${message.text.slice(0, 500)}` : ''
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

  async record(eventType, message, payload) {
    const event = {
      id: randomUUID(),
      event_type: eventType,
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: message.chat,
      user: actorFromMessage(message),
      payload
    };
    this.store.append(event);
    try {
      event.dkg = await this.dkg.writeEvent(event);
    } catch (error) {
      event.dkg_error = error instanceof Error ? error.message : String(error);
    }
    return event;
  }

  isRiskQuery(message) {
    const text = message.text || '';
    const mentionsBot = /@tracabot\b|@tracethembot\b/i.test(text);
    const asksFraud = /\b(fraudster|scammer|scam|bot|blacklisted|safe|risk)\b/i.test(text);
    return (mentionsBot && asksFraud) || Boolean(message.reply_to_message && asksFraud);
  }

  async assess(message, targetUser = actorFromMessage(message), text = message.text || '') {
    this.rememberUser(message.chat, targetUser, text);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: targetUser.username, text });
    const analysis = this.analyzer({ text, user: targetUser, globalIntel: dkgIntel });
    return combineRisk({ analysis, dkgIntel, threshold: this.config.actionThreshold });
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
      const stats = this.store.stats();
      await this.send(chatId, `tracabot stats: ${stats.total} local events in 7 days. Types: ${JSON.stringify(stats.byType)}`);
      return;
    }
    if (text.startsWith('/scan') || text.startsWith('/report')) {
      const targetMessage = message.reply_to_message || message;
      const mentionedTarget = this.targetFromMention(message);
      const target = mentionedTarget || actorFromMessage(targetMessage);
      const targetText = text.replace(/^\/(scan|report)(@\w+)?\s*/i, '') || targetMessage.text || '';
      const risk = await this.assess({ ...message, from: target }, target, targetText);
      const event = await this.record('report_submitted', { ...message, from: target }, risk);
      if (risk.confidence >= this.config.actionThreshold && target.id) await this.applyRiskAction({ ...message, from: target, text: targetText }, risk);
      await this.send(chatId, `${formatRiskAssessment({ target, risk })} DKG event: ${event.id}`, { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/ban')) {
      const replyUser = message.reply_to_message?.from;
      if (!replyUser) {
        await this.send(chatId, 'Reply to a user message with /ban <reason> so tracabot can preserve evidence.');
        return;
      }
      const reason = text.replace(/^\/ban(@\w+)?\s*/i, '') || 'admin requested ban';
      await this.ban(chatId, replyUser.id);
      const event = await this.record('ban_executed', { ...message, from: replyUser }, { reason, confidence: 100, scam_type: 'admin_action', evidence: [reason] });
      await this.send(chatId, `Banned ${replyUser.username || replyUser.id}. Logged to DKG Shared Memory event ${event.id}.`);
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
      await this.send(message.chat.id, `${formatRiskAssessment({ target, risk })} DKG event: ${event.id}`, { reply_to_message_id: message.message_id });
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

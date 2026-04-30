import { randomUUID } from 'node:crypto';

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
  }

  async send(chatId, text) {
    return telegram(this.config.telegramToken, 'sendMessage', { chat_id: chatId, text });
  }

  async ban(chatId, userId) {
    return telegram(this.config.telegramToken, 'banChatMember', { chat_id: chatId, user_id: userId });
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

  async handleCommand(message) {
    const text = message.text || '';
    const chatId = message.chat.id;
    if (text.startsWith('/stats')) {
      const stats = this.store.stats();
      await this.send(chatId, `tracabot stats: ${stats.total} local events in 7 days. Types: ${JSON.stringify(stats.byType)}`);
      return;
    }
    if (text.startsWith('/scan') || text.startsWith('/report')) {
      const targetText = text.replace(/^\/(scan|report)(@\w+)?\s*/i, '') || message.reply_to_message?.text || '';
      const globalIntel = await this.dkg.queryActor(actorFromMessage(message).username);
      const analysis = this.analyzer({ text: targetText, user: actorFromMessage(message), globalIntel });
      const event = await this.record('report_submitted', message, analysis);
      await this.send(chatId, `Scan: ${analysis.confidence}% ${analysis.scam_type}. Action: ${analysis.recommended_action}. Event: ${event.id}`);
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
    if (!message.text) return;
    if (message.text.startsWith('/')) {
      await this.handleCommand(message);
      return;
    }
    const user = actorFromMessage(message);
    const globalIntel = await this.dkg.queryActor(user.username);
    const analysis = this.analyzer({ text: message.text, user, globalIntel });
    if (!analysis.is_scam) return;
    const event = await this.record('scam_detection', message, analysis);
    const warning = `tracabot: ${analysis.confidence}% ${analysis.scam_type} risk. ${analysis.evidence.join('; ')}. DKG event ${event.id}.`;
    await this.send(message.chat.id, warning);
    if (this.config.autoBan && analysis.confidence >= 95) {
      await this.ban(message.chat.id, user.id);
      await this.record('ban_executed', message, { ...analysis, evidence: [...analysis.evidence, 'auto-ban threshold met'] });
    }
  }

  async pollOnce() {
    const updates = await telegram(this.config.telegramToken, 'getUpdates', {
      offset: this.offset,
      timeout: 25,
      allowed_updates: ['message']
    });
    for (const update of updates) {
      this.offset = update.update_id + 1;
      if (update.message) await this.handleMessage(update.message);
    }
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

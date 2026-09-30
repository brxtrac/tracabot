import { createHash } from 'node:crypto';
import { analyzeMessage } from './scam-analyzer.js';
import { extractDomains, extractPatterns, extractWallets, pseudonym } from './dkg-client.js';
import { reviewBan } from './curator.js';

export function artifactFromUpdate(update, config) {
  const message = update.message || update.channel_post;
  if (!message?.chat?.id || !message.message_id || !message.from?.id || message.from.is_bot) return null;
  const text = String(message.text || message.caption || '').slice(0, 700);
  if (!text) return null;
  const risk = analyzeMessage({ text, user: message.from });
  const domains = extractDomains(text);
  const wallets = extractWallets(text);
  const patterns = extractPatterns(text);
  const confidence = Number(risk.local_confidence || risk.confidence || 0);
  if (confidence < 40 && !domains.length && !wallets.length && !patterns.length) return null;
  const key = config.dkgPseudonymKey;
  const hash = (kind, value) => pseudonym(key, kind, value);
  const safeText = text.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[email]')
    .replace(/\+?\d[\d\s().-]{8,}\d/g, '[phone]');
  const id = `tg-${createHash('sha256').update(`${message.chat.id}:${message.message_id}`).digest('hex').slice(0, 24)}`;
  return {
    id, event_type: 'conversation_artifact', timestamp: new Date(message.date * 1000 || Date.now()).toISOString(),
    chat: { id: hash('telegram-chat', String(message.chat.id)) },
    user: { id: hash('telegram-user', String(message.from.id)) },
    payload: {
      source_message_id: String(message.message_id), message_text: safeText,
      confidence, artifact_quality: Math.min(100, Math.round(confidence + (domains.length + wallets.length + patterns.length ? 15 : 0))),
      scam_type: risk.scam_type || '', expires_at: new Date(Date.now() + 48 * 3600000).toISOString(),
      publication_status: 'working_memory', lifecycle_stage: 'working_memory_draft'
    }
  };
}

export function highConfidenceAutoBan(message) {
  const text = String(message?.text || message?.caption || '').normalize('NFKC');
  if (!message?.chat?.id || !message?.from?.id || message.from.is_bot || message.sender_chat || message.chat.type === 'private') return false;
  if (/\b(?:warning|beware|report(?:ing)?|scam alert|don't|do not|never)\b/i.test(text)) return false;
  const walletRequest = /\b(?:verify|validate|sync|connect|restore|unlock)\s+(?:your\s+)?wallet\b|\b(?:enter|send|share)\s+(?:your\s+)?(?:seed|recovery)\s+phrase\b/i.test(text);
  const link = /https?:\/\/[^\s]+|\b[a-z\d-]+(?:\.[a-z\d-]+)+\/[\w/?#=&%-]+/i.test(text);
  const pressure = /\b(?:urgent|now|immediately|suspend(?:ed)?|expire(?:s|d)?|last chance|claim)\b/i.test(text);
  const authority = /\b(?:admin|support|official|moderator)\b/i.test(text);
  return walletRequest && link && (pressure || authority);
}

async function telegramCall(config, method, params, fetcher) {
  const response = await fetcher(`https://api.telegram.org/bot${config.telegramToken}/${method}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params), signal: AbortSignal.timeout(15000)
  });
  if (!response.ok) throw new Error(`Telegram ${method} HTTP ${response.status}`);
  const payload = await response.json();
  if (!payload.ok) throw new Error(`Telegram ${method}: ${String(payload.description || 'failed').slice(0, 120)}`);
  return payload.result;
}

export async function enforceHighConfidenceAutoBan(message, { config, store, dkg, fetcher = fetch, reviewer = reviewBan }) {
  if (!highConfidenceAutoBan(message)) return false;
  if (config.dkgReads === false) return false;
  if (!dkg?.confirmedSwmScamHistory) return false;
  let history;
  try {
    history = await dkg.confirmedSwmScamHistory(message.from.id);
    if (!history.length) return false;
    const decision = await reviewer(message, history);
    if (decision.action !== 'ban' || typeof decision.evidence !== 'string' || decision.evidence.length < 12
      || !history.some((row) => row.eventId === decision.historyEventId)
      || !String(message.text || message.caption || '').toLowerCase().includes(String(decision.evidence || '').toLowerCase())) return false;
  } catch (error) {
    console.error(`Auto-ban verification unavailable: ${error instanceof Error ? error.message : String(error)}`);
    return false;
  }
  const chat = message.chat.id;
  const user = message.from.id;
  const [target, bot] = await Promise.all([
    telegramCall(config, 'getChatMember', { chat_id: chat, user_id: user }, fetcher),
    telegramCall(config, 'getMe', {}, fetcher)
  ]);
  if (!bot?.id || String(bot.id) === String(user) || !['member', 'restricted'].includes(target?.status)) return false;
  const botMember = await telegramCall(config, 'getChatMember', { chat_id: chat, user_id: bot.id }, fetcher);
  if (botMember?.status !== 'administrator' || botMember.can_restrict_members !== true) return false;
  const key = `tracabot-auto-ban:${chat}:${user}:${message.message_id}`;
  const params = { chat_id: chat, user_id: user, revoke_messages: true };
  const claim = store.beginEffect(key, 'banChatMember', params, { staleAction: 'uncertain' });
  if (claim.completed) return true;
  if (claim.inProgress || claim.uncertain) return false;
  try {
    const result = await telegramCall(config, 'banChatMember', params, fetcher);
    store.completeEffect(key, result);
    store.incrementMetric?.('high_confidence_auto_bans');
    return true;
  } catch (error) {
    store.markEffectUncertain(key, error);
    throw error;
  }
}

function isTransientPollError(error) {
  if (error?.name === 'AbortError') return false;
  const message = `${error instanceof Error ? error.message : String(error || '')} ${error?.cause?.code || ''}`;
  return /timeout|timed?\s*out|econnreset|econnrefused|enetunreach|socket|fetch failed|temporar|429|502|503|504/i.test(message);
}

function pollBackoffMs(failures) {
  const exponential = Math.min(60000, 1000 * (2 ** Math.min(Math.max(failures, 1) - 1, 6)));
  return Math.round(exponential * (0.75 + Math.random() * 0.5));
}

export async function pollArtifacts({ config, store, dkg, fetcher = fetch, signal, once = false, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  if (!config.telegramToken) throw new Error('TELEGRAM_BOT_TOKEN missing');
  if (!config.dkgWrites) throw new Error('DKG writes disabled');
  if (Buffer.byteLength(config.dkgPseudonymKey || '') < 32) throw new Error('TRACABOT_DKG_PSEUDONYM_KEY must be at least 32 bytes');
  const botKey = createHash('sha256').update(config.telegramToken).digest('hex');
  let offset = store.pollingOffset(botKey) ?? 0;
  let pollFailures = 0;
  do {
    let response;
    try {
      response = await fetcher(`https://api.telegram.org/bot${config.telegramToken}/getUpdates`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ offset, timeout: once ? 0 : 20, limit: 50, allowed_updates: ['message', 'channel_post'] }),
        signal: AbortSignal.any([signal || new AbortController().signal, AbortSignal.timeout(35000)])
      });
    } catch (error) {
      if (signal?.aborted || once || !isTransientPollError(error)) throw error;
      pollFailures += 1;
      console.error(`Telegram getUpdates failed (consecutive=${pollFailures}): ${error instanceof Error ? error.message : String(error)}`);
      await sleep(pollBackoffMs(pollFailures));
      continue;
    }
    if (!response.ok) {
      const error = new Error(`Telegram HTTP ${response.status}`);
      if (once || ![429, 502, 503, 504].includes(response.status)) throw error;
      pollFailures += 1;
      console.error(`Telegram getUpdates failed (consecutive=${pollFailures}): ${error.message}`);
      await sleep(pollBackoffMs(pollFailures));
      continue;
    }
    const data = await response.json();
    if (!data.ok || !Array.isArray(data.result)) throw new Error('Telegram getUpdates failed');
    if (pollFailures) {
      console.error(`Telegram getUpdates recovered after ${pollFailures} consecutive failure(s)`);
      pollFailures = 0;
    }
    for (const update of data.result) {
      const claim = store.claimUpdate(botKey, update);
      if (claim === 'processing') throw new Error(`Update ${update.update_id} claimed elsewhere`);
      if (claim !== 'completed') {
        try {
          const event = artifactFromUpdate(update, config);
          if (event) await dkg.stageConversationArtifact(event);
          if (event && config.highConfidenceAutoBan === true && highConfidenceAutoBan(update.message || update.channel_post)) {
            store.enqueueBanCandidate(update.message || update.channel_post);
          }
          store.completeUpdate(botKey, update.update_id, update.update_id + 1);
        } catch (error) {
          store.failUpdate(botKey, update.update_id, error);
          throw error;
        }
      }
      offset = update.update_id + 1;
    }
  } while (!once && !signal?.aborted);
}

export async function processBanCandidates({ config, store, dkg, fetcher = fetch, reviewer = reviewBan, signal }) {
  while (!signal?.aborted) {
    if (!store.banReviewBudget()) { await new Promise((resolve) => setTimeout(resolve, 30000)); continue; }
    const candidate = store.nextBanCandidate();
    if (!candidate) { await new Promise((resolve) => setTimeout(resolve, 3000)); continue; }
    try {
      if (!Number.isFinite(candidate.message.date) || Date.now() - candidate.message.date * 1000 > 30 * 60000) {
        store.finishBanCandidate(candidate.key, 'Candidate older than 30 minutes');
        continue;
      }
      await enforceHighConfidenceAutoBan(candidate.message, { config, store, dkg, fetcher, reviewer });
      store.finishBanCandidate(candidate.key);
    } catch (error) {
      store.finishBanCandidate(candidate.key, error instanceof Error ? error.message : String(error));
      console.error('Ban candidate failed:', error);
    }
  }
}

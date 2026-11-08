import { createHash } from 'node:crypto';
import { analyzeMessage } from './scam-analyzer.js';
import { extractDomains, extractPatterns, extractWallets, pseudonym } from './dkg-client.js';
import { reviewBan } from './curator.js';

function artifactSharingAllowed(update, config, message) {
  if (config.dkgWrites === false || config.wmArtifacts === false) return false;
  // Absent settings are not authorization. loadConfig supplies explicit true
  // defaults for the real pipeline; partial configs stay non-shareable.
  if (config.autoPromoteEvidence !== true) return false;
  if (message?.consent_to_share === false || message?.privacy_opt_out === true) return false;
  const optOutChats = new Set((Array.isArray(config.artifactOptOutChats) ? config.artifactOptOutChats : [])
    .map((value) => String(value)));
  if (optOutChats.has(String(message?.chat?.id ?? ''))) return false;
  const isChannel = Boolean(update.channel_post || message?.chat?.type === 'channel');
  if (isChannel && config.channelMemory !== true) return false;
  return true;
}

export function artifactFromUpdate(update, config) {
  if (config.wmArtifacts === false || config.dkgWrites === false) return null;
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
  const sharingAllowed = artifactSharingAllowed(update, config, message);
  return {
    id, event_type: 'conversation_artifact', timestamp: new Date(message.date * 1000 || Date.now()).toISOString(),
    chat: { id: hash('telegram-chat', String(message.chat.id)) },
    user: { id: hash('telegram-user', String(message.from.id)) },
    payload: {
      source_message_id: String(message.message_id), message_text: safeText,
      confidence, artifact_quality: Math.min(100, Math.round(confidence + (domains.length + wallets.length + patterns.length ? 15 : 0))),
      scam_type: risk.scam_type || '', consent_to_share: sharingAllowed,
      ...(sharingAllowed ? {} : { privacy_opt_out: true }),
      expires_at: new Date(Date.now() + 48 * 3600000).toISOString(),
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

export async function enforceHighConfidenceAutoBan(message, { config, store, dkg, fetcher = fetch, reviewer = reviewBan }) {
  // Retired destructive legacy path: no model, pattern, or ordinary ban may
  // authorize a Telegram sanction. Automatic removals use the exact-identity
  // evidence policy through the main bot runtime.
  void message; void config; void store; void dkg; void fetcher; void reviewer;
  return false;
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
  // Retired worker: drain any candidates queued by older deployments without
  // performing a destructive action. Exact-identity join protection remains in
  // the main bot runtime.
  void config; void dkg; void fetcher; void reviewer;
  while (!signal?.aborted) {
    const candidate = store.nextBanCandidate();
    if (!candidate) { await new Promise((resolve) => setTimeout(resolve, 3000)); continue; }
    store.finishBanCandidate(candidate.key, 'legacy_destructive_worker_retired');
  }
}

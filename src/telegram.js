import { randomUUID } from 'node:crypto';
import { canAutonomouslyEscalate, combineRisk, displayName, formatBanReply, formatDkgReference, formatReportReply, formatReviewNeededSummary, formatRiskAssessment, formatScanReply, formatStatsReply, formatStatsSourcesReply, isObviousLocalScam } from './risk-engine.js';
import { extractDomains, extractPatterns, extractWallets } from './dkg-client.js';
import { buildAgentIntentPrompt, buildAlertReplyClassifierPrompt, buildGeneralPrompt, buildSafetyPrompt, fallbackSafetyReply, isOnTopicDirectAddress, isSafetyQuestion, offTopicRedirect, sanitizeGeneralReply, sanitizeSafetyReply, shouldConversationallyReply } from './conversation.js';
import { redactedOpenClawStatus } from './openclaw-config.js';
import { TracabotSkillService } from './skill-service.js';

export const TELEGRAM_COMMANDS = [
  { command: 'start', description: 'Open Tracabot protection menu' },
  { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
  { command: 'report', description: 'Report suspicious users, messages, links, wallets, or forwarded DMs' },
  { command: 'ban', description: 'Ban a replied user and publish ban evidence (admin)' },
  { command: 'mute', description: 'Admin: mute a replied or mentioned user for a duration' }
];

const MAX_TEXT_CHARS = 4096;
const MAX_CONTEXT_CHARS = 500;
const CONVERSATION_HISTORY_LIMIT = 8;
const OBSERVED_CONTEXT_TTL_MS = 24 * 60 * 60 * 1000;
const RECENT_JOIN_RENAME_WINDOW_MS = 30 * 60 * 1000;
const ADMIN_CACHE_TTL_MS = 10 * 60 * 1000;
const SOLVED_JOIN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const DKG_UAL_RE = /^did:dkg:[^\s<>"']{8,}$/i;
const DM_REPORT_RE = /\b(?:dm|direct message|private message|inbox|pm)\b/i;
const REPORT_INTENT_RE = /\b(?:report|warn|alert|heads?\s*up|ongoing|impersonator|impersonating|pretending|fake)\b/i;
const ROLE_RE = /\b(?:cto|ceo|cfo|coo|founder|co-?founder|admin|moderator|mod|support|team|core team|vc|investor|partner|ambassador|lead|manager|director|official|developer|devrel)\b/i;
const DM_SCAM_REQUEST_RE = /\b(?:connect|verify|validate|sync|link|unlock|restore|claim|airdrop|giveaway|seed phrase|private key|recovery phrase|wallet|funds?|send|deposit|investment|support)\b/i;
const PUBLIC_CHAT_TYPES = new Set(['group', 'supergroup', 'channel']);
const ADMIN_DM_LURE_RE = /\b(?:admin|support|moderator|mod|official|team)\b[\s\S]{0,120}\b(?:dm|pm|message|inbox|contact|reach out)\b|\b(?:dm|pm|message|inbox|contact|reach out)\b[\s\S]{0,120}\b(?:admin|support|moderator|mod|official|team)\b/i;
const SCAM_PROMO_RE = /\b(?:join|follow|subscribe|signal|signals|pump|alpha|trading|profit|earn|airdrop|giveaway|presale|launch|gem|coin|token|listing)\b/i;
const BENIGN_FLOW_RE = /\b(?:working memory|shared memory|governance|commit|receipt|draft|promot(?:e|ed|ion)|publish|verified knowledge|synthid|deepmind|watermark|model|agent|policy|review|threshold)\b/i;
const PRIVATE_INFO_RE = /\b(?:status|config|token|secret|env|endpoint|admin list|private|logs?)\b/i;
const DIGEST_INTENT_RE = /\b(?:digest|daily summary|24h summary|what happened today|what's happening|whats happening)\b/i;
const STATS_INTENT_RE = /\b(?:stats?|statistics|metrics|activity|report|summary)\b/i;
const REVIEW_QUEUE_INTENT_RE = /\b(?:pending reviews?|review queue|anything to review|needs review|items to review)\b/i;
const WATCHLIST_INTENT_RE = /\b(?:muted|mutes)\b/i;
const CAMPAIGN_INTENT_RE = /\b(?:campaigns?|repeated patterns?|repeated domains?|scam wave|clusters?)\b/i;
const HELP_INTENT_RE = /\b(?:help|commands?|what can you do|who are you|what are you|purpose|hello|hi|are you alive)\b/i;
const BOT_REPLY_CONTEXT_TTL_MS = 2 * 60 * 1000;
const START_PUNCH_LINES = [
  'Bots forget. TRACaBot remembers.',
  'Simple bots react. TRACaBot remembers, connects context, and evolves.',
  'Scammers move across communities. TRACaBot memory moves faster.',
  'Every scam signal makes TRACaBot smarter for the next community.',
  'TRACaBot turns scam activity into shared defense memory.',
  'From moderation bot to anti-scam agent: memory, context, action.',
  'TRACaBot does not just block scams. It learns the pattern.',
  'Persistent memory beats repeated scams.',
  'TRACaBot gives communities an anti-scam agent that learns, remembers, and acts with context.',
  'Scam defense is moving from bots to agents. TRACaBot is already there.',
  'One community scam signal becomes another community early warning.',
  'TRACaBot connects scam context so communities do not start from zero.',
  'The future of anti-scam defense is agentic, shared, and memory-driven.',
  'TRACaBot builds protection that compounds with every processed signal.',
  'Scammers repeat patterns. TRACaBot remembers them.',
  'Not just moderation. Agentic anti-scam memory.',
  'TRACaBot brings persistent memory to community protection.',
  'Every report, review, and action becomes context for stronger defense.',
  'TRACaBot is an anti-scam agent layer for communities that need memory, not guesswork.',
  'The next generation of protection is not a bot command. It is an agent with memory.'
];

function boundedText(value = '', max = MAX_TEXT_CHARS) {
  return String(value || '').slice(0, max);
}

function entityUrls(message = {}) {
  return [...(message.entities || []), ...(message.caption_entities || [])]
    .map((entity) => entity?.url)
    .filter(Boolean);
}

function messageText(message = {}) {
  return boundedText([message.text, message.caption, ...entityUrls(message)].filter(Boolean).join('\n'));
}

function repliedText(message = {}) {
  const reply = message.reply_to_message || {};
  return boundedText([reply.text, reply.caption, ...entityUrls(reply)].filter(Boolean).join('\n'));
}

function isCommand(text = '', command = '') {
  return new RegExp(`^/${command}(?:@\\w+)?(?:\\s|$)`, 'i').test(String(text || ''));
}

function callbackData(action = '', ...parts) {
  const data = ['tc', 'v1', action, ...parts].map((part) => encodeURIComponent(String(part || ''))).join(':');
  if (data.length > 64) throw new Error(`callback data too long for action ${action}`);
  return data;
}

function parseCallbackData(data = '') {
  let parts;
  try {
    parts = String(data || '').split(':').map((part) => decodeURIComponent(part));
  } catch {
    return null;
  }
  if (parts[0] !== 'tc' || parts[1] !== 'v1') return null;
  return { action: parts[2] || '', parts: parts.slice(3) };
}

function inlineKeyboard(rows = []) {
  return { inline_keyboard: rows };
}

function button(text, data) {
  return { text, callback_data: data };
}

function parseDurationSeconds(text = '') {
  const value = String(text || '').toLowerCase();
  const match = value.match(/\b(\d+)\s*(minutes?|mins?|m|hours?|hrs?|h|days?|d)\b/i);
  if (!match) return 24 * 60 * 60;
  const amount = Math.max(1, Number(match[1]) || 1);
  const unit = match[2];
  if (/^m/.test(unit)) return amount * 60;
  if (/^h/.test(unit)) return amount * 60 * 60;
  return amount * 24 * 60 * 60;
}

function humanDuration(seconds = 24 * 60 * 60) {
  if (seconds % (24 * 60 * 60) === 0) return `${seconds / (24 * 60 * 60)} day${seconds === 24 * 60 * 60 ? '' : 's'}`;
  if (seconds % (60 * 60) === 0) return `${seconds / (60 * 60)} hour${seconds === 60 * 60 ? '' : 's'}`;
  if (seconds % 60 === 0) return `${seconds / 60} minute${seconds === 60 ? '' : 's'}`;
  return `${seconds} seconds`;
}

function evidenceText(message = {}) {
  return boundedText([messageText(message), repliedText(message)].filter(Boolean).join('\n'));
}

function forwardedEvidenceText(message = {}) {
  const forward = [
    message.forward_from?.username ? `forwarded_from_username: @${message.forward_from.username}` : '',
    message.forward_from?.id ? `forwarded_from_id: ${message.forward_from.id}` : '',
    message.forward_sender_name ? `forwarded_sender_name: ${message.forward_sender_name}` : '',
    message.forward_from_chat?.username ? `forwarded_from_chat: @${message.forward_from_chat.username}` : '',
    message.forward_from_chat?.title ? `forwarded_chat_title: ${message.forward_from_chat.title}` : '',
    message.forward_date ? `forwarded_date: ${message.forward_date}` : ''
  ].filter(Boolean).join('\n');
  return boundedText([forward, evidenceText(message)].filter(Boolean).join('\n'));
}

function screenshotFileIds(message = {}) {
  const ids = [];
  const collect = (item = {}) => {
    if (Array.isArray(item.photo) && item.photo.length) ids.push(item.photo[item.photo.length - 1]?.file_id);
    if (item.document?.file_id && /^image\//i.test(item.document.mime_type || '')) ids.push(item.document.file_id);
  };
  collect(message);
  collect(message.reply_to_message || {});
  return [...new Set(ids.filter(Boolean))].slice(0, 4);
}

function cleanDmReportText(text = '') {
  return String(text || '')
    .replace(/^\/(?:report|dmreport)(?:@\w+)?\s*/i, '')
    .replace(/@(?:tracabot|tracethembot)\b/ig, ' ')
    .replace(/^\s*(?:report|warn|alert|heads?\s*up)\s*(?:dm\s*)?(?:scam|impersonator|impersonation)?\s*[:\-]?\s*/i, '')
    .trim();
}

function extractQuoted(text = '', key = '') {
  const re = new RegExp(`${key}\\s*=\\s*["']([^"']{2,120})["']`, 'i');
  return text.match(re)?.[1]?.trim() || '';
}

function extractReportedAlias(text = '') {
  const explicit = extractQuoted(text, 'name|alias|target');
  if (explicit) return explicit;
    const patterns = [
      /^([A-Z][\p{L}.'-]+(?:\s+[A-Z][\p{L}.'-]+){1,4})\s+impersonator\b/iu,
      /(?:impersonat(?:ing|or)|pretending to be|fake)\s+([A-Z][\p{L}.'-]+(?:\s+[A-Z][\p{L}.'-]+){0,4})/iu,
      /([A-Z][\p{L}.'-]+(?:\s+[A-Z][\p{L}.'-]+){1,4})\s+(?:impersonat(?:or|ing)|fake|scam)/iu,
    /(?:called|named|as)\s+([A-Z][\p{L}.'-]+(?:\s+[A-Z][\p{L}.'-]+){0,4})/iu
  ];
  for (const pattern of patterns) {
    const alias = text.match(pattern)?.[1]?.trim();
    if (alias) return alias.replace(/\s+(?:impersonator|impersonating|fake|scam|cto|ceo|founder|admin|support|team)$/i, '').trim();
  }
  return '';
}

function extractClaimedRole(text = '') {
  const explicit = extractQuoted(text, 'role|title');
  if (explicit) return explicit;
  const matches = String(text || '').match(new RegExp(ROLE_RE.source, 'ig')) || [];
  return [...new Set(matches.map((value) => value.toLowerCase()))].slice(0, 3).join(', ');
}

function extractClaimedOrganization(text = '') {
  const explicit = extractQuoted(text, 'org|organization|community|project');
  if (explicit) return explicit;
  const match = text.match(/\b(?:from|of|for|at)\s+([A-Z][\p{L}\p{N}.'-]+(?:\s+[A-Z][\p{L}\p{N}.'-]+){0,3})/u);
  return match?.[1]?.trim() || '';
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

function normalizedLookup(value = '') {
  return String(value || '').toLowerCase().replace(/^@/, '').replace(/[^a-z0-9]/g, '');
}

function adminIdentityValues(user = {}) {
  return [
    user.id ? String(user.id) : '',
    user.username,
    user.first_name,
    user.last_name,
    [user.first_name, user.last_name].filter(Boolean).join(' ')
  ].filter(Boolean);
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
  const lookup = normalizedLookup(target.username || target.label || target.id || '');
  const eventLookup = normalizedLookup(eventUser.username || eventUser.label || eventUser.id || '');
  return actorKey(eventUser) === key || event.payload?.target_key === key || event.payload?.watch_target_key === key || (lookup && lookup === eventLookup);
}

function textFingerprint(text = '') {
  const words = String(text).toLowerCase().replace(/https?:\/\/\S+/g, '').replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((word) => word.length > 2);
  return words.slice(0, 16).join(' ');
}

function hasBoundedRawMessageEvidence(message = {}, risk = {}, text = '') {
  if (!PUBLIC_CHAT_TYPES.has(message.chat?.type || '')) return false;
  if (Number(risk.local_confidence || risk.confidence || 0) < 80) return false;
  if (ADMIN_DM_LURE_RE.test(text)) return true;
  if ((risk.patterns || []).some((pattern) => ['fake-airdrop', 'wallet-drain', 'impersonation', 'investment-partnership-lure', 'urgency-pressure'].includes(pattern))) return true;
  if ((risk.domains || []).length && SCAM_PROMO_RE.test(text)) return true;
  if (/\bt\.me\//i.test(text) && SCAM_PROMO_RE.test(text)) return true;
  if (/Investment-profit testimonial lure|Suspicious request to move help\/support into DMs|Identity impersonation indicators|Username resembles configured admin|changed identity after joining/i.test((risk.evidence || []).join('\n'))) return true;
  return false;
}

function conversationKey(message = {}, target = {}) {
  const chat = message.chat?.id || 'chat';
  const actor = targetKey(target) || actorKey(actorFromMessage(message)) || 'target';
  return `${chat}:${actor}:${textFingerprint(message.text || message.reply_to_message?.text || '').slice(0, 80)}`;
}

function verifyStartPayload(chatId = '', userId = '') {
  return `verify_${String(chatId).replace(/^-/, 'm')}_${userId}`;
}

function parseVerifyStartPayload(payload = '') {
  const match = String(payload || '').match(/^verify_(m?\d+)_(\d+)$/);
  if (!match) return null;
  return { chatId: match[1].startsWith('m') ? `-${match[1].slice(1)}` : match[1], userId: match[2] };
}

function plural(count, singular, pluralWord = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralWord}`;
}

function shortId(id = '') {
  return String(id || '').slice(0, 16) || 'unknown';
}

function ageLabel(timestamp = '') {
  const age = Date.now() - Date.parse(timestamp || '');
  if (!Number.isFinite(age) || age < 0) return 'unknown age';
  const minutes = Math.floor(age / 60000);
  if (minutes < 60) return `${minutes || 1}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function escapeHtml(value = '') {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function normalizeChallengeAnswer(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[()]/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim()
    .replace(/\s+/g, ' ');
}

function normalizeAliasSignal(value = '') {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKC')
    .replace(/^@/, '')
    .replace(/[^\p{L}\p{N}]+/gu, '');
}

function challengeAliasSignals(user = {}) {
  const displayName = [user.first_name, user.last_name].filter(Boolean).join(' ');
  return [...new Set([user.username, user.first_name, user.last_name, displayName]
    .map(normalizeAliasSignal)
    .filter((value) => value.length >= 3))];
}

function userMention(user = {}) {
  if (user.kind === 'wallet') return escapeHtml(user.label || user.id || 'wallet');
  const username = String(user.username || '').replace(/^@/, '');
  const label = username ? `@${username}` : [user.first_name, user.last_name].filter(Boolean).join(' ').trim() || user.label || user.id || 'this account';
  return user.id ? `<a href="tg://user?id=${encodeURIComponent(user.id)}">${escapeHtml(label)}</a>` : escapeHtml(label);
}

function sangmataTargetFromText(text = '') {
  const match = String(text || '').match(/\bUser\s+(\d{5,})\s+changed\s+name\s+from\s+(.+?)\s+to\s+(.+?)(?:\.|$)/i);
  if (!match) return null;
  const [, id, oldName, newName] = match;
  return {
    id,
    first_name: newName.trim(),
    label: newName.trim(),
    kind: 'user',
    source: 'sangmata',
    sangmata: {
      oldName: oldName.trim(),
      newName: newName.trim(),
      evidence: `SangMata rename alert: ${oldName.trim()} -> ${newName.trim()}`
    }
  };
}

function hasEvidenceForDkg(eventType = '', payload = {}) {
  if (['risk_check', 'risk_query', 'scam_detection'].includes(eventType)) return false;
  if (['watch_started', 'watch_ended', 'reporter_reputation_update'].includes(eventType)) return false;
  if (eventType.startsWith('join_challenge_') && eventType !== 'join_challenge_repeat_failure') return false;
  if (['ban_executed', 'restrict_executed', 'fraud_finding', 'report_submitted', 'dm_scam_report', 'fraud_campaign', 'join_challenge_repeat_failure', 'channel_observation', 'conversation_artifact', 'appeal_submitted', 'review_upheld', 'review_overturned', 'proactive_cross_group_warning'].includes(eventType)) return true;
  if (['risk_review_needed', 'risk_action_suppressed', 'report_review_needed'].includes(eventType)) {
    return Number(payload.confidence || 0) >= 60 || Boolean(payload.dkg_evidence?.length || payload.wallets?.length || payload.domains?.length || payload.patterns?.length);
  }
  return false;
}

function isCampaignRootEvent(event = {}) {
  if (event.event_type === 'fraud_campaign') return false;
  return hasEvidenceForDkg(event.event_type, event.payload || {}) && Boolean(event.payload?.evidence?.length);
}

function formatDmReportReply(event, decision = {}) {
  if (!decision.accepted) {
    return '⚠️ I logged this DM scam note for admin review, but stronger details help: impersonated name/role, the request they made, wallet/link, or screenshot caption.';
  }
  const alias = event.payload?.reported_alias || event.payload?.reportedAlias || 'reported DM impersonator';
  const role = event.payload?.claimed_role ? ` (${event.payload.claimed_role})` : '';
  return `⚠️ DM scam report saved: ${alias}${role}. I added it to the admin review queue. Warn users not to trust unsolicited DMs; verify through official channels.`;
}

export class TelegramShieldBot {
  constructor({ config, analyzer, dkg, store, llm = null }) {
    this.config = config;
    this.analyzer = analyzer;
    this.dkg = dkg;
    this.store = store;
    this.llm = llm;
    this.offset = 0;
    this.botId = null;
    this.observedUsers = new Map();
    this.chatAdmins = new Map();
    this.joinChallenges = new Map();
    this.solvedJoinChallenges = new Map();
    this.reviewMessageEvents = new Map();
    this.lastPendingReviewsByChat = new Map(); // chatId -> displayed review groups for natural follow-up corrections
    this._reviewCache = { pending: null, watches: null, lastUpdate: 0 };
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;
    this.conversationLastReply = new Map();
    this.naturalLanguageLastReply = new Map();
    this.conversationHistory = new Map();
    this.lastBotReplyByThread = new Map();
    this.lastCrossGroupWarningAt = new Map(); // chatId:targetKey -> timestamp for rate limiting proactive cross-group alerts
    this.skillService = null;
    this.seenChats = new Map();
  }

  conversationThreadKey(message = {}) {
    const chat = message.chat?.id || 'chat';
    const user = message.from?.id || message.from?.username || 'user';
    return `${chat}:${user}`;
  }

  rememberConversationTurn(message = {}, role = 'user', text = '') {
    const value = String(text || '').replace(/\s+/g, ' ').trim();
    if (!value) return;
    const key = this.conversationThreadKey(message);
    const history = this.conversationHistory.get(key) || [];
    history.push({ role, text: value.slice(0, 500) });
    this.conversationHistory.set(key, history.slice(-CONVERSATION_HISTORY_LIMIT));
  }

  rememberSeenChat(chat = {}) {
    if (!chat?.id || !PUBLIC_CHAT_TYPES.has(chat.type || '')) return;
    this.seenChats.set(String(chat.id), chat);
  }

  conversationContext(message = {}) {
    return (this.conversationHistory.get(this.conversationThreadKey(message)) || [])
      .map((turn) => `${turn.role}: ${turn.text}`)
      .join('\n');
  }

  async call(method, payload) {
    return telegram(this.config.telegramToken, method, payload, this.config.telegramTimeoutMs);
  }

  async send(chatId, text, extra = {}) {
    try {
      const sent = await this.call('sendMessage', { chat_id: chatId, text, ...extra });
      this.rememberBotReply(chatId, sent, text, extra);
      return sent;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (extra.reply_to_message_id && /message to be replied not found/i.test(message)) {
        const { reply_to_message_id, ...fallbackExtra } = extra;
        const sent = await this.call('sendMessage', { chat_id: chatId, text, ...fallbackExtra });
        this.rememberBotReply(chatId, sent, text, fallbackExtra);
        return sent;
      }
      throw error;
    }
  }

  rememberBotReply(chatId, sent = {}, text = '', extra = {}) {
    if (!sent?.message_id) return;
    const key = `${chatId}:${extra.reply_to_message_id || '*'}`;
    this.lastBotReplyByThread.set(key, { chatId, messageId: sent.message_id, text: String(text || '').slice(0, 500), timestamp: Date.now() });
    this.lastBotReplyByThread.set(`${chatId}:*`, { chatId, messageId: sent.message_id, text: String(text || '').slice(0, 500), timestamp: Date.now() });
  }

  async sendTyping(chatId) {
    // Fire and forget — don't block on this
    this.call('sendChatAction', { chat_id: chatId, action: 'typing' }).catch(() => {});
  }

  scheduleDelete(chatId, messageId, ttlSeconds = this.config.botMessageTtlSeconds || 60) {
    if (!this.config.autoDeleteBotMessages || !messageId || Number(ttlSeconds) <= 0) return;
    setTimeout(() => {
      this.deleteMessage(chatId, messageId).catch(() => null);
    }, Number(ttlSeconds) * 1000).unref?.();
  }

  async sendEphemeral(chatId, text, extra = {}, ttlSeconds = this.config.botMessageTtlSeconds || 60) {
    const sent = await this.send(chatId, text, extra);
    const isPrivate = extra.private === true || Number(chatId) > 0;
    // Only auto-delete bot messages for /help and challenge flows during testing.
    // Normal conversations and most commands should not auto-delete.
    const shouldAutoDelete = extra.autoDelete === true;
    if (!isPrivate && shouldAutoDelete) {
      this.scheduleDelete(chatId, sent?.message_id, ttlSeconds);
    }
    return sent;
  }

  async sendCommandReply(chatId, text, extra = {}, ttlSeconds = this.config.botMessageTtlSeconds || 60) {
    return this.sendEphemeral(chatId, text, extra, ttlSeconds);
  }

  async sendInteractiveReply(chatId, text, rows = [], extra = {}) {
    return this.sendCommandReply(chatId, text, { ...extra, reply_markup: inlineKeyboard(rows) });
  }

  cleanupMenuTrigger(message = {}) {
    if (message.chat?.type === 'private' || !message.chat?.id || !message.message_id) return;
    this.deleteMessage(message.chat.id, message.message_id).catch(() => null);
  }

  async menuIntro(message = {}) {
    if (this.llm && this.chatConversationalEnabled(message?.chat?.id)) {
      const reply = await this.generalConversationReply({ ...message, text: message.text || 'Open the Tracabot protection menu.' }).catch(() => '');
      if (reply && reply.length > 5) return reply;
    }
    return 'I’m here to help protect the group. Choose an action below, or use /scan, /report, /ban, or /mute as a reply when you need a direct action.';
  }

  async sendMenu(message = {}, extra = {}) {
    const chatId = message.chat?.id;
    const requester = message.from?.id || message.from?.username || '';
    const text = await this.menuIntro(message);
    const sent = await this.sendInteractiveReply(chatId, text, this.dashboardKeyboard(requester), { reply_to_message_id: message.message_id, ...extra });
    this.cleanupMenuTrigger(message);
    return sent;
  }

  async editInteractiveMessage(chatId, messageId, text, rows = [], extra = {}) {
    return this.call('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text,
      ...extra,
      reply_markup: inlineKeyboard(rows)
    });
  }

  async answerCallback(callbackId, text = '') {
    if (!callbackId) return null;
    return this.call('answerCallbackQuery', { callback_query_id: callbackId, text }).catch(() => null);
  }

  async sendPersistentCommandReply(chatId, text, extra = {}) {
    return this.send(chatId, text, extra);
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

  async allowTextOnly(chatId, userId, untilDate = Math.floor(Date.now() / 1000) + 24 * 60 * 60) {
    return this.call('restrictChatMember', {
      chat_id: chatId,
      user_id: userId,
      until_date: untilDate,
      permissions: {
        can_send_messages: true,
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

  async muteMember(chatId, userId, untilDate = Math.floor(Date.now() / 1000) + 24 * 60 * 60) {
    return this.call('restrictChatMember', {
      chat_id: chatId,
      user_id: userId,
      until_date: untilDate,
      use_independent_chat_permissions: true,
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

  async restoreMemberPermissions(chatId, userId) {
    return this.call('restrictChatMember', {
      chat_id: chatId,
      user_id: userId,
      until_date: 0,
      use_independent_chat_permissions: true,
      permissions: {
        can_send_messages: true,
        can_send_audios: true,
        can_send_documents: true,
        can_send_photos: true,
        can_send_videos: true,
        can_send_video_notes: true,
        can_send_voice_notes: true,
        can_send_polls: true,
        can_send_other_messages: true,
        can_add_web_page_previews: true,
        can_change_info: false,
        can_invite_users: true,
        can_pin_messages: false,
        can_manage_topics: false
      }
    });
  }

  async groupAccessLink(chat = {}) {
    if (chat.username) return `https://t.me/${String(chat.username).replace(/^@/, '')}`;
    if (chat.invite_link) return chat.invite_link;
    return '';
  }

  async botUsername() {
    const me = await this.call('getMe', {});
    return me.username || 'tracethembot';
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

  async dkgReachable() {
    try {
      await this.dkg.ensureContextGraph();
      return true;
    } catch {
      return false;
    }
  }

  async isTelegramChatAdmin(chatId, userId) {
    if (!userId) return false;
    const admins = await this.getChatAdmins(chatId);
    if (admins.some((admin) => String(admin.id) === String(userId))) return true;
    try {
      const member = await this.call('getChatMember', { chat_id: chatId, user_id: userId });
      return ['creator', 'administrator'].includes(member.status);
    } catch {
      return false;
    }
  }

  async getChatAdmins(chatId) {
    const key = String(chatId || '');
    const cached = this.chatAdmins.get(key);
    if (cached && Date.now() - cached.timestamp < ADMIN_CACHE_TTL_MS) return cached.admins;
    try {
      const members = await this.call('getChatAdministrators', { chat_id: chatId });
      const admins = (members || []).map((member) => member.user).filter((user) => user?.id && user.is_bot !== true);
      this.chatAdmins.set(key, { timestamp: Date.now(), admins });
      return admins;
    } catch {
      return cached?.admins || [];
    }
  }

  async adminIdentities(chatId) {
    const discovered = await this.getChatAdmins(chatId);
    return [
      ...this.config.adminIds,
      ...discovered.flatMap(adminIdentityValues)
    ].map((value) => String(value).replace(/^@/, '').toLowerCase()).filter(Boolean);
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

  adminRenameCopycat(chat, user = {}, adminIds = []) {
    if (!user?.id) return null;
    const entry = this.observedUsers.get(`${chat.id}:${user.id}`);
    if (!entry?.firstIdentity) return null;
    if (Date.now() - Date.parse(entry.firstSeen) > RECENT_JOIN_RENAME_WINDOW_MS) return null;
    const currentIdentity = normalizedIdentity(user);
    if (!currentIdentity || currentIdentity === entry.firstIdentity) return null;
    const matchedAdmin = [...adminIds]
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

  observedUserForName(chat, name = '') {
    const needle = normalizedLookup(name);
    if (!needle) return null;
    const matches = [];
    for (const entry of this.observedUsers.values()) {
      if (String(entry.chat?.id) !== String(chat?.id)) continue;
      if (Date.now() - Date.parse(entry.lastSeen) > OBSERVED_CONTEXT_TTL_MS) continue;
      const user = entry.user || {};
      const aliases = [user.username, user.first_name, user.last_name, [user.first_name, user.last_name].filter(Boolean).join(' ')].filter(Boolean);
      if (aliases.some((alias) => normalizedLookup(alias) === needle)) matches.push(user);
    }
    return matches.length === 1 ? { ...matches[0], kind: 'user', source: 'observed_name' } : null;
  }

  targetFromMention(message) {
    const mentions = [...String(message.text || '').matchAll(/@([A-Za-z0-9_]{3,32})/g)].map((match) => match[1]);
    const username = mentions.find((candidate) => !/^(tracabot|tracethembot)$/i.test(candidate));
    if (!username) return null;
    const observed = this.observedUserForName(message.chat, username);
    if (observed) return observed;
    return { id: '', username, kind: 'user' };
  }

  targetFromTelegramId(argText = '') {
    const id = argText.trim().split(/\s+/)[0] || '';
    return /^\d{5,}$/.test(id) ? { id, label: id, kind: 'user', source: 'telegram_id' } : null;
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

  targetFromSafetyQuestion(message) {
    const text = String(message.text || '').replace(/@(?:tracabot|tracethembot)\b/ig, ' ').replace(/\s+/g, ' ').trim();
    const match = text.match(/\b(?:is|are)\s+(@?[\p{L}\p{N}_-]{2,32})\s+(?:a\s+|an\s+)?(?:legit(?:imate)?|safe|unsafe|real|fake|scam(?:mer|ming)?|fraud(?:ster)?|risky?|trusted|trustworthy|blacklisted|flagged|suspicious|sus|dangerous|malicious)\b/iu)
      || text.match(/\b(?:can|should)\s+i\s+trust\s+(@?[\p{L}\p{N}_-]{2,32})\b/iu);
    const token = match?.[1] || '';
    if (!token || /^(this|that|it|he|she|they|them|him|her|me|i)$/i.test(token)) return null;
    return token.startsWith('@') ? this.targetFromPlainArgument(token) : this.observedUserForName(message.chat, token);
  }

  targetFromWallet(text = '') {
    const wallet = extractWallets(text)[0];
    return wallet ? { id: wallet, label: wallet, kind: 'wallet' } : null;
  }

  isConfiguredAdmin(user = {}) {
    return this.config.adminIds.has(String(user.id).toLowerCase()) || this.config.adminIds.has(String(user.username || '').replace(/^@/, '').toLowerCase());
  }

  isBotOwner(user = {}) {
    return this.config.botOwnerIds?.has(String(user.id).toLowerCase()) || this.config.botOwnerIds?.has(String(user.username || '').replace(/^@/, '').toLowerCase());
  }

  hasVerifiedMemoryAuthority(user = {}) {
    return this.isBotOwner(user) && Boolean(this.config.publishContextGraphId);
  }

  reviewTrustPayload(user = {}) {
    const verifiedMemoryAuthority = this.hasVerifiedMemoryAuthority(user);
    const scope = verifiedMemoryAuthority ? 'global_verified_memory' : 'local_community';
    return {
      admin_verified: verifiedMemoryAuthority,
      local_admin_verified: true,
      decision_scope: scope,
      trust_basis: verifiedMemoryAuthority ? 'bot_owner_verified_memory_trac' : 'telegram_local_admin',
      verified_memory_authority: verifiedMemoryAuthority,
      trac_backed_global_authority: verifiedMemoryAuthority,
      publish_false_positive: verifiedMemoryAuthority
    };
  }

  chatJoinChallengeEnabled(chatId) {
    const key = String(chatId || '');
    const latest = [...this.store.all()].reverse().find((event) => event.event_type === 'join_challenge_setting_changed' && String(event.chat?.id || '') === key);
    if (latest) return latest.payload?.enabled === true;
    return Boolean(this.config.joinChallenge);
  }

  chatConversationalEnabled(chatId) {
    const key = String(chatId || '');
    const latest = [...this.store.all()].reverse().find((event) => event.event_type === 'conversational_setting_changed' && String(event.chat?.id || '') === key);
    if (latest) return latest.payload?.enabled !== false;
    return this.config.conversational !== false;
  }

  skillServiceOrNull() {
    if (this.config.testMode) return null;
    if (this.skillService) return this.skillService;
    try {
      this.skillService = TracabotSkillService.fromEnv();
      return this.skillService;
    } catch {
      return null;
    }
  }

  async isTrustedModerator(message) {
    const user = actorFromMessage(message);
    return this.isConfiguredAdmin(user) || await this.isTelegramChatAdmin(message.chat.id, user.id);
  }

  isPrivateOwnerMessage(message) {
    return message.chat?.type === 'private' && this.isConfiguredAdmin(actorFromMessage(message));
  }

  async rejectNonOwnerPrivateReport(message) {
    if (message.chat?.type !== 'private' || this.isPrivateOwnerMessage(message)) return false;
    await this.send(message.chat.id, '⚠️ Private reports are restricted to bot owner. Use /report in the group, or ask group admins to review.', { reply_to_message_id: message.message_id, private: true });
    return true;
  }

  commandText(message, command) {
    return boundedText(message.text || '').replace(new RegExp(`^/${command}(?:@\\w+)?(?:\\s+|$)`, 'i'), '').trim();
  }

  resolveCommandTarget(message, command) {
    const argText = this.commandText(message, command);
    const reply = message.reply_to_message;
    const mentioned = this.targetFromMention(message);
    const telegramIdTarget = this.targetFromTelegramId(argText);
    const sangmataTarget = sangmataTargetFromText(reply?.text || '') || sangmataTargetFromText(argText);
    const walletTarget = this.targetFromWallet(argText || reply?.text || '');
    const plainTarget = this.targetFromPlainArgument(argText);
    const replyTarget = reply ? actorFromMessage(reply) : null;
    const target = ['watch', 'unwatch'].includes(command)
      ? mentioned || telegramIdTarget || sangmataTarget || replyTarget || walletTarget || plainTarget || actorFromMessage(message)
      : mentioned || telegramIdTarget || walletTarget || sangmataTarget || plainTarget || replyTarget || actorFromMessage(message);
    const text = boundedText([argText, reply?.text || ''].filter(Boolean).join('\n') || message.text || '');
    return { target, text, reply, sangmataTarget, telegramIdTarget };
  }

  commandReason(message, command, fallback = 'admin action') {
    const argText = this.commandText(message, command);
    const reason = argText.replace(/^@?\w{3,32}\s*/, '').trim();
    const sangmata = sangmataTargetFromText(message.reply_to_message?.text || '') || sangmataTargetFromText(argText);
    return reason || sangmata?.sangmata?.evidence || fallback;
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
    const backed = canAutonomouslyEscalate(risk);
    const target = actorFromMessage(message);

    // Use centralized humble review language (no absolute "HIGH RISK 100%" on items awaiting human decision without strong DKG evidence)
    const riskLine = formatReviewNeededSummary({ target, risk, hasDkgBacking: backed });

    const text = [
      backed
        ? 'TRACaBot flagged this for admin review.'
        : 'TRACaBot needs an admin review.',
      riskLine,
      'Admins: use the buttons below to confirm or reject this flag. Non-admin replies are logged as appeals.'
      // No longer duplicating the full original message as "Context:" — we reply directly to it (see below)
    ].filter(Boolean).join('\n');

    const requesterId = this.config.adminIds.values().next().value || 'admin';
    const reviewButtons = event?.id ? this.reviewActionKeyboard(requesterId, event.id) : [];
    const sent = reviewButtons.length
      ? await this.sendInteractiveReply(message.chat.id, text, reviewButtons, { reply_to_message_id: message.message_id })
      : await this.send(message.chat.id, text, { reply_to_message_id: message.message_id });
    if (sent?.message_id && event?.id) {
      this.reviewMessageEvents.set(`${message.chat.id}:${sent.message_id}`, event.id);
    }
    for (const adminId of this.config.adminIds) {
      try {
        await this.send(adminId, text);
      } catch {
        // Telegram only allows DM after an admin starts the bot.
      }
    }
  }

  formatHelp() {
    const punchLine = START_PUNCH_LINES[Math.floor(Math.random() * START_PUNCH_LINES.length)];
    return [
      '🛡️ TRACaBot Agent online',
      '',
      punchLine
    ].join('\n');
  }

  formatMenuHelp() {
    return [
      '❔ TRACaBot Help',
      '',
      'TRACaBot helps communities spot scams, learn from every attack, and turn shared memory into stronger protection across agents and communities.',
      '',
      'Commands',
      '',
      '/start - open the TRACaBot Agent menu.',
      '/scan - check a user, wallet, link, or replied message for scam risk. Best used as a reply to the exact message or user.',
      '/report - send suspicious users, messages, wallets, links, or forwarded DMs to admin review.',
      '/ban - admin only; ban a replied user and record enforcement evidence.',
      '/mute - admin only; mute a replied or mentioned user. Examples: /mute 5 minutes, /mute 1 day.'
    ].join('\n');
  }

  async formatStatus(message) {
    const chatId = message.chat.id;
    const [dkgOk, dkgRuntime, canBan, canDelete] = await Promise.all([
      this.dkgReachable(),
      this.dkg.runtimeStatus(),
      this.hasBanRights(chatId),
      this.hasDeleteRights(chatId)
    ]);
    const openclaw = redactedOpenClawStatus(this.config);
    const caps = dkgRuntime.capabilities || {};
    return [
      '🩺 Tracabot status',
      '',
      'Telegram',
      `• Delete messages: ${canDelete ? '✅ yes' : '❌ no'}`,
      `• Restrict / ban: ${canBan ? '✅ yes' : '❌ no'}`,
      '',
      'Protection',
      `• Warn at ${this.config.warnThreshold}%`,
      `• Restrict at ${this.config.restrictThreshold}%`,
      `• Ban at ${this.config.banThreshold}%`,
      `• Join challenge: ${this.chatJoinChallengeEnabled(chatId) ? `✅ on (${this.config.joinChallengeTtlSeconds || 60}s, ${this.config.joinChallengeMaxAttempts || 3} tries)` : '⚪ off'}`,
      `• Natural language: ${this.chatConversationalEnabled(chatId) ? '✅ on' : '⚪ off'}`,
      '',
      'DKG memory',
      `• Node: ${dkgOk ? '✅ reachable' : '⚠️ unreachable'}`,
      `• Adapter: ${dkgRuntime.adapterVersion || 'unknown'}`,
      `• Release: ${dkgRuntime.dkgReleaseVersion || 'unknown'}`,
      `• Working memory: ${caps.workingMemoryAssertions ? '✅' : '⚪'}  Shared memory: ${caps.sharedWorkingMemory ? '✅' : '⚪'}  Verified publish: ${caps.verifiedMemoryPublish ? '✅' : '⚪'}`,
      '',
      'Agent',
      `• LLM: ${this.llm ? '✅ available' : '⚪ disabled'} (${this.config.llmProvider || 'auto'})`,
      `• Learning drafts: ${this.config.wmArtifacts === false ? '⚪ off' : '✅ on'}`,
      `• Cross-group alerts: ${this.config.proactiveAlertCrossGroup !== false ? '✅ on' : '⚪ off'}`
    ].join('\n');
  }

  async record(eventType, message, payload, { writeDkg = null } = {}) {
    const communityId = this.config.communityId || String(message.chat?.id || '');
    const decoratedPayload = this.config.testMode
      ? { ...payload, source: payload?.source || 'test-command-loop', test_mode: true }
      : { ...payload };
    decoratedPayload.community_id = decoratedPayload.community_id || communityId;
    decoratedPayload.community_name = decoratedPayload.community_name || this.config.communityName || '';
    decoratedPayload.community_type = decoratedPayload.community_type || this.config.communityType || 'telegram_group';
    decoratedPayload.policy_id = decoratedPayload.policy_id || this.config.policyId || 'default';
    const event = {
      id: randomUUID(),
      event_type: eventType,
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: message.chat,
      user: actorFromMessage(message),
      payload: decoratedPayload
    };
    const shouldWriteDkg = writeDkg ?? (!this.config.testMode && hasEvidenceForDkg(eventType, decoratedPayload));
    if (shouldWriteDkg) {
      try {
        event.dkg = await this.dkg.writeEvent(event);
      } catch (error) {
        event.dkg_error = error instanceof Error ? error.message : String(error);
      }
    } else {
      event.local_only = true;
    }
    this.store.append(event);
    if (['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'review_upheld', 'review_overturned', 'ban_executed'].includes(eventType)) {
      this._reviewCache = { pending: null, watches: null, lastUpdate: 0 };
    }
    return event;
  }

  findEvent(eventId = '') {
    if (!eventId) return null;
    const id = String(eventId);
    const exact = this.store.all().find((event) => event.id === id || event.payload?.report_event_id === id || event.payload?.target_event_id === id);
    if (exact) return exact;
    if (id.length < 12) return null;
    const matches = this.store.all().filter((event) => event.id?.startsWith(id));
    return matches.length === 1 ? matches[0] : null;
  }

  reviewResolutionFor(eventId = '') {
    if (!eventId) return null;
    return this.store.all().find((event) => ['review_upheld', 'review_overturned', 'ban_executed'].includes(event.event_type) && (event.payload?.target_event_id === eventId || event.payload?.report_event_id === eventId)) || null;
  }

  isPendingReviewEvent(event = {}) {
    return Boolean(event?.id && ['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'ban_requested_no_reply', 'ban_requested_no_rights', 'proactive_cross_group_warning'].includes(event.event_type) && !this.reviewResolutionFor(event.id));
  }

  findAppealableEvent(message, target = {}) {
    const repliedBotEventId = this.reviewMessageEvents.get(`${message.chat?.id}:${message.reply_to_message?.message_id}`);
    const repliedBotEvent = this.findEvent(repliedBotEventId);
    if (repliedBotEvent) return repliedBotEvent;
    const targetId = target.id ? String(target.id) : '';
    const targetUsername = target.username ? String(target.username).replace(/^@/, '').toLowerCase() : '';
    const replyUser = actorFromMessage(message.reply_to_message || {});
    const replyId = replyUser.id ? String(replyUser.id) : '';
    const replyUsername = replyUser.username ? String(replyUser.username).replace(/^@/, '').toLowerCase() : '';
    const actor = actorFromMessage(message);
    const actorId = actor.id ? String(actor.id) : '';
    const actorUsername = actor.username ? String(actor.username).replace(/^@/, '').toLowerCase() : '';
    const candidates = [[targetId, targetUsername], [replyId, replyUsername], [actorId, actorUsername]];
    const reviewTypes = new Set(['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'fraud_finding', 'ban_executed', 'restrict_executed']);
    return [...this.store.all()].reverse().find((event) => {
      if (!reviewTypes.has(event.event_type)) return false;
      const user = event.user || event.payload?.target || {};
      const userId = user.id ? String(user.id) : '';
      const username = user.username ? String(user.username).replace(/^@/, '').toLowerCase() : '';
      return candidates.some(([id, name]) => (id && userId === id) || (name && username === name));
    }) || null;
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

  activeWatches() {
    const active = new Map();
    for (const event of this.store.all()) {
      const key = event.payload?.watch_target_key;
      if (!key) continue;
      if (event.event_type === 'watch_started') active.set(key, event);
      if (['watch_ended', 'ban_executed', 'review_overturned'].includes(event.event_type)) active.delete(key);
    }
    return [...active.values()].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }

  recentRestrictions() {
    const now = Date.now();
    return this.store.all()
      .filter((event) => event.event_type === 'restrict_executed')
      .filter((event) => !event.payload?.restricted_until || Date.parse(event.payload.restricted_until) >= now)
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }

  pendingReviewItems() {
    const now = Date.now();
    const CACHE_TTL = 8000; // 8 seconds — good balance for responsiveness
    if (this._reviewCache.pending && (now - this._reviewCache.lastUpdate) < CACHE_TTL) {
      return this._reviewCache.pending;
    }

    const resolved = new Set(this.store.all().filter((event) => ['review_upheld', 'review_overturned', 'ban_executed'].includes(event.event_type)).map((event) => event.payload?.target_event_id || event.payload?.report_event_id).filter(Boolean));
    const items = this.store.all()
      .filter((event) => ['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'ban_requested_no_reply', 'ban_requested_no_rights', 'proactive_cross_group_warning'].includes(event.event_type))
      .filter((event) => !resolved.has(event.id))
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));

    this._reviewCache.pending = items;
    this._reviewCache.lastUpdate = now;
    return items;
  }

  falsePositiveReviewFor(target = {}, text = '', dkgIntel = {}) {
    const key = targetKey(target);
    const id = target.id ? String(target.id) : '';
    const username = target.username ? String(target.username).replace(/^@/, '').toLowerCase() : '';
    if (!key && !id && !username) return null;
    return this.store.all().find((event) => {
      if (event.event_type !== 'review_overturned') return false;
      if (eventAgeMs(event) > 7 * 24 * 60 * 60 * 1000) return false;
      const reviewed = event.payload?.reviewed_target || {};
      const reviewedKey = event.payload?.reviewed_target_key || targetKey(reviewed);
      const sameTarget = Boolean(
        (key && reviewedKey === key)
        || (id && reviewed.id && String(reviewed.id) === id)
        || (username && reviewed.username && String(reviewed.username).replace(/^@/, '').toLowerCase() === username)
      );
      const original = this.findEvent(event.payload?.target_event_id || '');
      const sameOriginalTarget = Boolean(original && key && targetKey(original.user || original.payload?.target || {}) === key);
      if (!sameTarget && !sameOriginalTarget) return false;
      const originalText = [original?.payload?.message_text, original?.payload?.evidence?.join('\n'), original?.text].filter(Boolean).join('\n');
      const originalFingerprint = textFingerprint(originalText);
      const currentFingerprint = textFingerprint(text);
      const sameEvidence = Boolean(originalFingerprint && currentFingerprint && originalFingerprint === currentFingerprint);
      const concreteAdminSafeDecision = Boolean(event.payload?.reviewed_target_key || event.payload?.reviewed_target?.id || event.payload?.reviewed_target?.username);
      if (!sameEvidence && !concreteAdminSafeDecision) return false;
      if ((dkgIntel.wallets || []).length || (dkgIntel.domains || []).length || (dkgIntel.evidence || []).length) return false;
      return true;
    }) || null;
  }

  formatWatchItem(event, index) {
    const target = event.payload?.target || event.user || {};
    const reason = event.payload?.reason || event.payload?.evidence?.[0] || event.payload?.report_reason || 'watching';
    const key = event.payload?.watch_target_key || targetKey(target) || 'unknown';
    return `${index}. ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}\n   ${ageLabel(event.timestamp)} | Event ${shortId(event.id)} | ${escapeHtml(reason)}\n   Actions: /scan ${escapeHtml(String(target.id || target.username || key))} | ask “why event ${event.id}?”`;
  }

  formatRestrictionItem(event, index) {
    const target = event.user || {};
    const until = event.payload?.restricted_until ? `until ${event.payload.restricted_until.replace(/\.\d{3}Z$/, 'Z')}` : 'expiry unknown';
    const evidence = event.payload?.evidence?.slice(-2).join('; ') || event.payload?.scam_type || 'restriction';
    return `${index}. ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}\n   ${ageLabel(event.timestamp)} | ${until} | Event ${shortId(event.id)}\n   ${escapeHtml(evidence)}\n   Actions: /scan ${escapeHtml(String(target.id || target.username || ''))} | ask “why event ${event.id}?”`;
  }

  reviewSummary(event = {}) {
    if (event.event_type === 'proactive_cross_group_warning') {
      const prior = (event.payload?.prior_admin_events || []).length;
      return `Prior admin action in another community (${prior} recorded). Current risk: ${event.payload?.current_risk?.confidence || '?'}%. Review recommended.`;
    }
    return (event.payload?.evidence?.slice(0, 1).join('; ') || event.payload?.reason || event.event_type).slice(0, 120);
  }

  formatReviewItem(event, index) {
    const target = event.user || event.payload?.target || {};
    const confidence = event.payload?.confidence !== undefined ? `${event.payload.confidence}%` : 'n/a';
    const prefix = event.event_type === 'proactive_cross_group_warning' ? '⚠️ CROSS-GROUP ' : '';
    return `${index}. ${prefix}${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''} | ${confidence} | ${shortId(event.id)}\n   ${escapeHtml(this.reviewSummary(event))}`;
  }

  formatWatchlist(filter = '') {
    const restrictions = this.recentRestrictions();
    const reviews = this.pendingReviewItems();
    const sections = [`🛡️ Review manager`, `${restrictions.length} active mutes | ${reviews.length} review items`];
    const addSection = (title, items, formatter) => {
      if (!items.length) return;
      sections.push('', title, ...items.slice(0, 8).map((event, index) => formatter.call(this, event, index + 1)));
    };
    if (!filter || filter === 'all' || filter === 'muted' || filter === 'mutes') addSection('Temp mutes', restrictions, this.formatRestrictionItem);
    if (!filter || filter === 'all' || filter === 'review') addSection('Needs review', reviews, this.formatReviewItem);
    if (sections.length === 2) sections.push('', 'Nothing matching that filter. Use the buttons to switch between reviews and mutes.');
    return sections.join('\n');
  }

  formatReviewPanel(filter = 'flags') {
    if (filter === 'mutes') return this.formatWatchlist('muted');
    if (filter === 'all') return this.formatWatchlist('all');
    return this.formatPendingReviews();
  }

  pendingReviewGroups() {
    const reviews = this.pendingReviewItems();
    const groups = new Map();
    for (const event of reviews) {
      const target = event.user || event.payload?.target || {};
      const key = targetKey(target) || event.id;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(event);
    }
    return [...groups.values()];
  }

  formatPendingReviews() {
    const reviews = this.pendingReviewItems();
    if (!reviews.length) return 'No pending review items.';
    const groups = this.pendingReviewGroups();
    const visibleCount = Math.min(groups.length, 5);
    const lines = groups.slice(0, 5).map((events, index) => {
      const suffix = events.length > 1 ? ` (+${events.length - 1} more)` : '';
      return `${this.formatReviewItem(events[0], index + 1)}${suffix}`;
    });
    const queueNote = groups.length > visibleCount ? `Showing the first ${visibleCount} targets. Clear a few and reopen the review panel to continue through the queue.` : 'Tap a button below to open a review item.';
    return [
      `Latest pending review items (${reviews.length})`,
      ...lines,
      '',
      queueNote
    ].join('\n');
  }

  pendingReviewsKeyboard(requesterId) {
    const groups = this.pendingReviewGroups().slice(0, 5);
    const rows = groups.flatMap((events, index) => {
      const event = events[0];
      const label = `🔎 ${index + 1}. ${displayName(event.user || event.payload?.target || {})}`.slice(0, 28);
      return [[button(label, callbackData('review-open', requesterId, shortId(event.id)))]];
    });
    rows.push(...this.mainNavKeyboard(requesterId, { includeReview: false }));
    return rows;
  }

  reviewPanelKeyboard(requesterId, filter = 'flags') {
    const rows = [[
      button('🚨 Reviews', callbackData('review-tab', requesterId, 'flags')),
      button('🔇 Mutes', callbackData('review-tab', requesterId, 'mutes'))
    ]];
    if (filter === 'flags') rows.push(...this.pendingReviewsKeyboard(requesterId).filter((row) => row[0]?.callback_data?.includes('review-open')));
    rows.push(...this.mainNavKeyboard(requesterId, { includeReview: false }));
    return rows;
  }

  reviewActionKeyboard(requesterId, eventId) {
    return [
      [
        button('🚫 Confirm scam', callbackData('review-confirm', requesterId, shortId(eventId))),
        button('✅ Reject flag', callbackData('review-reject', requesterId, shortId(eventId)))
      ],
      [button('↩️ Back to queue', callbackData('review-list', requesterId))]
    ];
  }

  async sendPendingReviews(message, extra = {}) {
    const requesterId = message.from?.id || message.from?.username || '';
    const text = this.formatPendingReviews();
    const rows = this.pendingReviewsKeyboard(requesterId);
    const sent = await this.sendInteractiveReply(message.chat.id, text, rows, { reply_to_message_id: message.message_id, parse_mode: 'HTML', disable_web_page_preview: true, ...extra });
    this.lastPendingReviewsByChat.set(String(message.chat.id), this.pendingReviewGroups().slice(0, 15));
    return sent;
  }

  formatReviewDetail(event) {
    const target = event.user || event.payload?.target || {};
    const evidence = (event.payload?.evidence || []).slice(0, 5).map((item) => `- ${escapeHtml(item)}`).join('\n') || '- No evidence recorded.';
    return [
      `Review ${shortId(event.id)}`,
      `${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}`,
      `Confidence: ${event.payload?.confidence ?? 0}% | Type: ${escapeHtml(event.payload?.scam_type || event.event_type)}`,
      '',
      'Evidence:',
      evidence,
      '',
      'Choose the final admin decision below.'
    ].join('\n');
  }

  formatWhy(eventId = '') {
    const event = this.findEvent(eventId);
    if (!event) return `No local tracabot event found for ${eventId}. Open Stats > Sources for recent DKG receipts.`;
    const risk = event.payload || {};
    const evidence = risk.evidence?.length ? risk.evidence.slice(0, 8).map((item) => `- ${item}`).join('\n') : '- No evidence recorded.';
    const dkgRefs = risk.dkg_evidence?.length ? risk.dkg_evidence.slice(0, 4).map((item) => `- ${item.ual || 'DKG'}${item.eventId ? ` event ${item.eventId}` : ''}`).join('\n') : '- No DKG source refs on this event.';
    const action = event.event_type;
    const ref = formatDkgReference(event) || event.id;
    const dkg = event.dkg || {};
    const dkgLines = [
      event.local_only ? '- Stored locally only.' : '',
      event.dkg_error ? `- DKG write error: ${event.dkg_error}` : '',
      dkg.ual ? `- Shared Memory graph: ${dkg.ual}` : '',
      dkg.shareOperation ? `- Share operation: ${dkg.shareOperation}` : '',
      dkg.subject ? `- Subject: ${dkg.subject}` : '',
      dkg.publish ? `- Context Graph publish: ${dkg.publish.status || 'requested'}` : '',
      dkg.publish_error ? `- Context Graph publish error: ${dkg.publish_error}` : '',
      risk.publication_status ? `- Publication status: ${risk.publication_status}` : '',
      risk.lifecycle_stage ? `- Lifecycle stage: ${risk.lifecycle_stage}` : '',
      risk.review_decision ? `- Review decision: ${risk.review_decision}` : '',
      risk.report_decision ? `- Report decision: ${risk.report_decision}` : '',
      risk.campaign_key ? `- Campaign key: ${risk.campaign_key}` : '',
      risk.evidence_root_ids?.length ? `- Evidence roots: ${risk.evidence_root_ids.slice(0, 6).join(', ')}` : ''
    ].filter(Boolean);
    return [
      `Why ${event.id}: ${action}`,
      `Confidence: ${risk.confidence ?? 0}% (local ${risk.local_confidence ?? 0}%, DKG ${risk.dkg_confidence ?? 0}%). Type: ${risk.scam_type || 'unknown'}.`,
      `Recommendation/action: ${risk.recommended_action || action}. Ref: ${ref}`,
      'Evidence:',
      evidence,
      'DKG sources:',
      dkgRefs,
      'DKG write/publish:',
      dkgLines.length ? dkgLines.join('\n') : '- No local DKG write metadata recorded.'
    ].join('\n');
  }

  async formatBanlist(limit = 10) {
    const enforcementEvents = this.store.all()
      .filter((e) => ['ban_executed', 'restrict_executed', 'review_upheld'].includes(e.event_type))
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))
      .slice(0, limit);

    if (!enforcementEvents.length) {
      return [
        '👮 Enforcement',
        '',
        'No recent bans, mutes, or confirmed scam reviews recorded.',
        '',
        'Use Reviews for pending items or /ban and /mute as replies when action is needed.'
      ].join('\n');
    }

    const lines = ['👮 Enforcement', '', 'Recent actions'];

    for (const ev of enforcementEvents) {
      const target = ev.user || ev.payload?.target || {};
      const name = userMention(target) || target.id || 'unknown';
      const actionType = ev.event_type === 'ban_executed' ? 'BAN' : ev.event_type === 'restrict_executed' ? 'RESTRICT' : 'UPHELD REVIEW';
      const reason = (ev.payload?.reason || ev.payload?.evidence?.[0] || 'admin action').slice(0, 120);

      const summary = reason;

      const time = ageLabel(ev.timestamp);
      lines.push(`• ${actionType} ${name}`);
      lines.push(`  ${escapeHtml(summary)} · ${time}`);
    }

    lines.push('', 'Use Reviews to handle pending items. Event IDs stay in Sources for admins who need receipts.');
    return lines.join('\n');
  }

  statsKeyboard(requesterId) {
    return [
      [button('📎 Sources', callbackData('stats-sources', requesterId)), button('🧬 Campaigns', callbackData('campaigns', requesterId)), button('👮 Enforcement', callbackData('banlist', requesterId))],
      ...this.mainNavKeyboard(requesterId)
    ];
  }

  banlistKeyboard(requesterId) {
    return [
      [button('🛡️ Pending reviews', callbackData('review-list', requesterId)), button('🔇 Mutes', callbackData('review-tab', requesterId, 'mutes'))],
      ...this.mainNavKeyboard(requesterId)
    ];
  }

  toggleKeyboard(requesterId, action) {
    return [
      [button('🟢 On', callbackData(action, requesterId, 'on')), button('⚪ Off', callbackData(action, requesterId, 'off')), button('ℹ️ Status', callbackData(action, requesterId, 'status'))],
      ...this.mainNavKeyboard(requesterId)
    ];
  }

  scanKeyboard(requesterId, target = {}, eventId = '') {
    const rows = [[button('📊 Stats', callbackData('stats', requesterId))]];
    if (target.id || target.username) rows.push([button('❔ Explain', callbackData('why', requesterId, shortId(eventId)))]);
    rows.push(...this.mainNavKeyboard(requesterId));
    return rows;
  }

  replyScanKeyboard(requesterId, target = {}, eventId = '') {
    const rows = [];
    if (target.id || target.username) rows.push([button('❔ Explain', callbackData('why', requesterId, shortId(eventId)))]);
    rows.push([button('📊 Stats', callbackData('stats', requesterId)), button('🛡️ Reviews', callbackData('review-list', requesterId))]);
    rows.push([button('🏠 Menu', callbackData('dashboard', requesterId)), button('✖️ Close', callbackData('close', requesterId))]);
    return rows;
  }

  mainNavKeyboard(requesterId, options = {}) {
    const includeReview = options.includeReview !== false;
    const rows = [[
      button('🏠 Menu', callbackData('dashboard', requesterId)),
      button('📊 Stats', callbackData('stats', requesterId)),
      ...(includeReview ? [button('🛡️ Reviews', callbackData('review-list', requesterId))] : [])
    ]];
    rows.push([button('⚙️ Settings', callbackData('settings', requesterId)), button('✖️ Close', callbackData('close', requesterId))]);
    return rows;
  }

  dashboardKeyboard(requesterId) {
    return [
      [button('📊 Stats', callbackData('stats', requesterId)), button('🛡️ Reviews', callbackData('review-list', requesterId))],
      [button('❔ Help', callbackData('help', requesterId)), button('🧾 Explain event', callbackData('why', requesterId))],
      [button('👮 Enforcement', callbackData('banlist', requesterId)), button('⚙️ Settings', callbackData('settings', requesterId))],
      [button('✖️ Close', callbackData('close', requesterId))]
    ];
  }

  settingsText(chatId) {
    const challengeOn = this.chatJoinChallengeEnabled(chatId);
    const languageOn = this.chatConversationalEnabled(chatId);
    return [
      '⚙️ Tracabot settings',
      '',
      `🚪 Join challenge: ${challengeOn ? '✅ on' : '⚪ off'}`,
      `🧠 Natural language: ${languageOn ? '✅ on' : '⚪ off'}`,
      '',
      'Tap a toggle below to switch the setting for this chat.'
    ].join('\n');
  }

  settingsKeyboard(requesterId, chatId = '') {
    const challengeOn = this.chatJoinChallengeEnabled(chatId);
    const languageOn = this.chatConversationalEnabled(chatId);
    return [
      [button(`${challengeOn ? '✅' : '⚪'} Join challenge`, callbackData('challenge-set', requesterId, challengeOn ? 'off' : 'on')), button(`${languageOn ? '✅' : '⚪'} Natural language`, callbackData('conversation-set', requesterId, languageOn ? 'off' : 'on'))],
      [button('🩺 Status', callbackData('status', requesterId))],
      ...this.mainNavKeyboard(requesterId)
    ];
  }

  recentEvents(ms = 24 * 60 * 60 * 1000) {
    return this.store.all().filter((event) => eventAgeMs(event) <= ms);
  }

  campaignSummary(windowMs = 24 * 60 * 60 * 1000) {
    const buckets = new Map();
    for (const event of this.recentEvents(windowMs)) {
      if (!isCampaignRootEvent(event)) continue;
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
      .map(([key, events]) => {
        const uniqueEvents = [...new Map(events.map((event) => [event.id, event])).values()];
        const affectedCommunities = [...new Set(uniqueEvents.map((event) => event.payload?.community_id || event.chat?.id || '').filter(Boolean))];
        const domains = [...new Set(uniqueEvents.flatMap((event) => event.payload?.domains || []))];
        const wallets = [...new Set(uniqueEvents.flatMap((event) => event.payload?.wallets || []))];
        const patterns = [...new Set(uniqueEvents.flatMap((event) => event.payload?.patterns || []))];
        return { key, events: uniqueEvents, affectedCommunities, domains, wallets, patterns };
      })
      .filter((item) => item.events.length >= 2)
      .sort((a, b) => b.events.length - a.events.length || a.key.localeCompare(b.key));
  }

  challengeFailureSummary(windowMs = 24 * 60 * 60 * 1000) {
    const failureTypes = new Set(['join_challenge_bad_attempt', 'join_challenge_failed_max_attempts', 'join_challenge_expired']);
    const buckets = new Map();
    const add = (key, event) => {
      if (!key) return;
      buckets.set(key, [...(buckets.get(key) || []), event]);
    };
    for (const event of this.recentEvents(windowMs)) {
      if (!failureTypes.has(event.event_type)) continue;
      const target = event.payload?.target || event.user || {};
      add(`target:${event.payload?.target_key || targetKey(target)}`, event);
      for (const alias of event.payload?.alias_keys || challengeAliasSignals(target)) add(`alias:${alias}`, event);
    }
    return [...buckets.entries()]
      .map(([key, events]) => {
        const uniqueEvents = [...new Map(events.map((event) => [event.id, event])).values()];
        const terminal = uniqueEvents.filter((event) => ['join_challenge_failed_max_attempts', 'join_challenge_expired'].includes(event.event_type));
        const badAttempts = uniqueEvents.filter((event) => event.event_type === 'join_challenge_bad_attempt');
        const targets = [...new Set(uniqueEvents.map((event) => event.payload?.target_key || targetKey(event.payload?.target || event.user || {})).filter(Boolean))];
        const aliases = [...new Set(uniqueEvents.flatMap((event) => event.payload?.alias_keys || challengeAliasSignals(event.payload?.target || event.user || {})))];
        const affectedCommunities = [...new Set(uniqueEvents.map((event) => event.payload?.community_id || event.chat?.id || '').filter(Boolean))];
        return { key, events: uniqueEvents, terminal, badAttempts, targets, aliases, affectedCommunities };
      })
      .filter((item) => item.terminal.length >= (this.config.joinChallengeRepeatFailureThreshold || 2) || (item.terminal.length >= 1 && item.badAttempts.length >= (this.config.joinChallengeRepeatBadAttemptThreshold || 3)))
      .sort((a, b) => b.events.length - a.events.length || a.key.localeCompare(b.key));
  }

  async maybeRecordJoinChallengeRepeatFailure(message, triggeringEvent = null) {
    const signals = this.challengeFailureSummary(24 * 60 * 60 * 1000)
      .filter((signal) => !this.store.all().some((event) => event.event_type === 'join_challenge_repeat_failure' && event.payload?.campaign_key === signal.key));
    const signal = signals[0];
    if (!signal) return null;
    const relatedIds = signal.events.slice(0, 10).map((event) => event.id);
    return this.record('join_challenge_repeat_failure', message, {
      scam_type: 'onboarding_abuse',
      confidence: 85,
      local_confidence: 85,
      campaign_key: signal.key,
      target_key: signal.targets[0] || triggeringEvent?.payload?.target_key || targetKey(message.from),
      alias_keys: signal.aliases.slice(0, 20),
      patterns: ['join_challenge_repeat_failure', 'onboarding_abuse'],
      challenge_failure_count: signal.terminal.length,
      bad_attempt_count: signal.badAttempts.length,
      expired_count: signal.events.filter((event) => event.event_type === 'join_challenge_expired').length,
      failed_max_attempts_count: signal.events.filter((event) => event.event_type === 'join_challenge_failed_max_attempts').length,
      affected_community_ids: signal.affectedCommunities,
      related_event_ids: relatedIds,
      evidence_root_ids: relatedIds,
      publication_status: 'shared_memory',
      lifecycle_stage: 'shared_memory',
      evidence: [
        `Repeated DKG join challenge failures for ${signal.key} across ${signal.events.length} recent events`,
        signal.aliases.length ? `Alias signals: ${signal.aliases.slice(0, 6).join(', ')}` : '',
        `${signal.terminal.length} terminal failures; ${signal.badAttempts.length} bad attempts`
      ].filter(Boolean)
    }, { writeDkg: !this.config.testMode });
  }

  async maybeRecordCampaign(message, risk) {
    if (risk.report_decision && risk.report_decision !== 'accepted') return null;
    const campaigns = this.campaignSummary(24 * 60 * 60 * 1000).filter((campaign) => !this.store.all().some((event) => event.event_type === 'fraud_campaign' && event.payload?.campaign_key === campaign.key));
    const campaign = campaigns[0];
    if (!campaign) return null;
    return this.record('fraud_campaign', message, {
      scam_type: risk.scam_type || 'campaign',
      confidence: Math.max(85, risk.confidence || 0),
      local_confidence: risk.local_confidence || risk.confidence || 0,
      campaign_key: campaign.key,
      related_event_ids: campaign.events.slice(0, 10).map((event) => event.id),
      evidence_root_ids: campaign.events.slice(0, 10).map((event) => event.id),
      affected_community_ids: campaign.affectedCommunities,
      campaign_event_count: campaign.events.length,
      campaign_community_count: campaign.affectedCommunities.length,
      domains: campaign.domains,
      wallets: campaign.wallets,
      patterns: campaign.patterns,
      publication_status: 'context_graph_auto_publish_eligible',
      lifecycle_stage: 'campaign_summary',
      evidence: [
        `Campaign signal ${campaign.key} repeated across ${campaign.events.length} recent events`,
        campaign.affectedCommunities.length ? `Affected communities: ${campaign.affectedCommunities.join(', ')}` : 'Affected community not disclosed',
        campaign.domains.length ? `Repeated domains: ${campaign.domains.join(', ')}` : '',
        campaign.patterns.length ? `Repeated patterns: ${campaign.patterns.join(', ')}` : ''
      ].filter(Boolean)
    }, { writeDkg: !this.config.testMode });
  }

  formatCampaigns() {
    const campaigns = this.campaignSummary(7 * 24 * 60 * 60 * 1000).slice(0, 6);
    const challengeFailures = this.challengeFailureSummary(7 * 24 * 60 * 60 * 1000).slice(0, 6);
    if (!campaigns.length && !challengeFailures.length) return '🧬 Campaign signals\n\nNo repeated scam waves found in recent local memory.';
    const describeKey = (key = '') => {
      const [type, value = ''] = String(key).split(/:(.*)/s).filter(Boolean);
      const clean = value.replace(/\s+/g, ' ').trim();
      if (type === 'domain') return `Repeated link domain: ${clean}`;
      if (type === 'wallet') return `Repeated wallet: ${clean.slice(0, 10)}…${clean.slice(-6)}`;
      if (type === 'pattern') return `Repeated tactic: ${clean.replace(/[_-]/g, ' ')}`;
      if (type === 'text') return 'Repeated scam wording';
      if (type === 'alias') return `Repeated join alias: ${clean}`;
      if (type === 'target') return 'Repeated join challenge failures';
      return clean || key;
    };
    const details = (item) => {
      const bits = [];
      if (item.domains?.length) bits.push(`domains: ${item.domains.slice(0, 2).join(', ')}`);
      if (item.wallets?.length) bits.push(`wallets: ${item.wallets.length}`);
      if (item.patterns?.length) bits.push(`tactics: ${item.patterns.slice(0, 2).map((p) => String(p).replace(/[_-]/g, ' ')).join(', ')}`);
      if (item.aliases?.length) bits.push(`aliases: ${item.aliases.slice(0, 3).join(', ')}`);
      if (item.affectedCommunities?.length) bits.push(`${plural(item.affectedCommunities.length, 'community')}`);
      return bits.length ? `  ${bits.join(' · ')}` : '';
    };
    return [
      '🧬 Campaign signals',
      '',
      'Repeated patterns seen in recent local memory. Event receipts are hidden here to keep this readable.',
      '',
      ...campaigns.map((campaign) => [`• ${describeKey(campaign.key)} (${plural(campaign.events.length, 'event')})`, details(campaign)].filter(Boolean).join('\n')),
      ...challengeFailures.map((signal) => [`• ${describeKey(signal.key)} (${plural(signal.events.length, 'event')})`, details(signal)].filter(Boolean).join('\n'))
    ].join('\n');
  }

  formatDigest() {
    const events = this.recentEvents(24 * 60 * 60 * 1000);
    const count = (types) => events.filter((event) => types.includes(event.event_type)).length;
    const campaigns = [...this.campaignSummary(24 * 60 * 60 * 1000), ...this.challengeFailureSummary(24 * 60 * 60 * 1000)];
    const challengeFailures = this.challengeFailureSummary(24 * 60 * 60 * 1000);
    const high = events.filter((event) => Number(event.payload?.confidence || 0) >= 80).length;
    const restrictions = this.recentRestrictions();
    const reviews = this.pendingReviewItems();
    return [
      '📌 tracabot digest (24h)',
      '',
      'Risk movement',
      `- ${plural(events.length, 'local event')}; ${plural(high, 'high-confidence signal')}`,
      `- ${plural(count(['ban_executed']), 'ban')}; ${plural(count(['restrict_executed']), 'temp mute')}; ${plural(count(['report_submitted']), 'accepted report')}`,
      `- ${plural(count(['appeal_submitted']), 'appeal')}; ${plural(count(['review_upheld', 'review_overturned']), 'review decision')}`,
      `- ${plural(challengeFailures.length, 'repeated join-challenge failure cluster')}`,
      '',
      'Review queue',
      `- ${plural(restrictions.length, 'active temp mute')}; ${plural(reviews.length, 'pending review item')}`,
      campaigns.length ? `- Top campaign: ${campaigns[0].key} across ${campaigns[0].events.length} events` : '- No repeated campaign cluster in the last 24h',
      '',
      'Recommended follow-up',
      '- Open the review panel from /start',
      '- Use Stats > Sources for receipts',
      '- Ask naturally: “why was this flagged?”'
    ].join('\n');
  }

  campaignStatsLabel(campaign = null) {
    if (!campaign) return 'No repeated scam wave in the last 24h.';
    const label = (campaign.patterns || []).map((item) => String(item).replace(/[_-]/g, ' ')).find(Boolean)
      || (campaign.domains || [])[0]
      || (campaign.aliases || [])[0]
      || String(campaign.key || '').replace(/^[^:]+:/, '').replace(/[_-]/g, ' ').slice(0, 48)
      || 'repeated signal';
    return `${label} across ${campaign.events.length} events`;
  }

  latestEnforcementStatsLine() {
    const event = this.store.all()
      .filter((item) => ['ban_executed', 'restrict_executed', 'review_upheld'].includes(item.event_type))
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];
    if (!event) return 'No recent bans, mutes, or confirmed scam reviews.';
    const target = event.user || event.payload?.target || event.payload?.reviewed_target || {};
    const action = event.event_type === 'ban_executed' ? 'Ban' : event.event_type === 'restrict_executed' ? 'Mute' : 'Confirmed scam review';
    const name = displayName(target) || target.id || 'target';
    return `${action}: ${name} · ${ageLabel(event.timestamp)}`;
  }

  formatStatsDashboard(stats) {
    const events = this.recentEvents(24 * 60 * 60 * 1000);
    const count = (types) => events.filter((event) => types.includes(event.event_type)).length;
    const campaigns = [...this.campaignSummary(24 * 60 * 60 * 1000), ...this.challengeFailureSummary(24 * 60 * 60 * 1000)];
    const reviews = this.pendingReviewItems();
    const restrictions = this.recentRestrictions();
    const high = events.filter((event) => Number(event.payload?.confidence || 0) >= 80).length;
    const total = Number(stats.total || 0);
    const verifiedHigh = Number(stats.highConfidence || 0);
    const protectedActions = count(['risk_query', 'risk_check']) + count(['report_review_needed', 'report_submitted']) + count(['review_upheld', 'review_overturned']) + count(['ban_executed', 'restrict_executed']);
    const bans = count(['ban_executed']);
    const mutes = count(['restrict_executed']);
    const reports = count(['report_review_needed', 'report_submitted']);
    const decisions = count(['review_upheld', 'review_overturned']);
    const queueLine = reviews.length
      ? `${reviews.length} admin reviews waiting. Open Reviews to clear the queue.`
      : 'Review queue clear.';
    const actionLine = [
      protectedActions ? `${protectedActions} protection actions` : '',
      high ? `${high} high-risk signals` : '',
      reports ? `${reports} reports queued` : '',
      decisions ? `${decisions} admin decisions` : '',
      bans ? `${bans} bans` : '',
      mutes ? `${mutes} mutes` : ''
    ].filter(Boolean).join(' · ') || 'No urgent local threats handled today.';
    const graphLine = total
      ? `${verifiedHigh} high-confidence receipts from ${total} verified events this week.`
      : 'No verified 7d events yet.';
    return [
      '📊 TRACaBot Stats',
      '',
      '✅ Protected today',
      actionLine,
      '',
      '🧠 Shared memory',
      graphLine,
      '',
      '🚨 Review queue',
      `${queueLine}${restrictions.length ? ` ${restrictions.length} active mutes.` : ''}`,
      '',
      '🧬 Pattern watch',
      this.campaignStatsLabel(campaigns[0]),
      '',
      '👮 Latest enforcement',
      this.latestEnforcementStatsLine()
    ].join('\n');
  }

  isRiskQuery(message) {
    return this.isDirectlyAddressed(message) && isSafetyQuestion(message);
  }

  isDmReportMention(message) {
    const text = messageText(message);
    return /@(?:tracabot|tracethembot)\b/i.test(text) && DM_REPORT_RE.test(text) && REPORT_INTENT_RE.test(text);
  }

  isNaturalFalsePositiveReview(message) {
    const text = messageText(message);
    const correctionLanguage = /\b(?:not\s+(?:a\s+)?scammer|not\s+(?:a\s+)?scam|not a (?:bad|risky) (?:actor|guy|person)|legit(?:imate)?|trusted|safe|false positive|long[- ]term community member|community member|innocent|mistake)\b/i.test(text);
    return (this.isDirectlyAddressed(message) || this.numberedReviewSelection(message)) && correctionLanguage;
  }

  numberedReviewSelection(message = {}) {
    const match = messageText(message).match(/^\s*#?(\d{1,2})\b/);
    if (!match) return null;
    const groups = this.lastPendingReviewsByChat.get(String(message.chat?.id)) || [];
    const group = groups[Number(match[1]) - 1];
    if (!group?.length) return null;
    return group;
  }

  async handleNaturalFalsePositiveReview(message) {
    const trusted = await this.isTrustedModerator(message);
    const selectedGroup = this.numberedReviewSelection(message);

    if (!trusted) {
      if (!selectedGroup?.length) return false;
      const reviewedEvent = selectedGroup[0];
      const reviewedTarget = reviewedEvent?.user || reviewedEvent?.payload?.target || {};
      const reason = messageText(message).replace(/@(?:tracabot|tracethembot)\b/ig, '').trim() || 'natural-language appeal from review list';
      const event = await this.record('appeal_submitted', message, {
        target_event_id: reviewedEvent.id,
        reason,
        appellant: actorFromMessage(message),
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        implicit_detection: true,
        detection_method: 'numbered_review_list_reply',
        evidence: [`non-admin review-list reply logged as appeal for ${reviewedEvent.id}: ${reason}`]
      });
      await this.sendCommandReply(message.chat.id, `📝 Appeal logged for ${userMention(reviewedTarget)} as ${event.id}. Admins can confirm or reject the scam flag.`, { reply_to_message_id: message.message_id, parse_mode: 'HTML' });
      return true;
    }

    this.sendTyping(message.chat.id);

    // Strong context: if replying to one of our review alert messages, use the stored event id
    const repliedMsgId = message.reply_to_message?.message_id;
    let extraEvent = null;
    if (repliedMsgId) {
      const storedEventId = this.reviewMessageEvents.get(`${message.chat?.id}:${repliedMsgId}`);
      if (storedEventId) extraEvent = this.findEvent(storedEventId);
    }

    // Natural verdicts like "Not a scammer" are not command arguments. Do not
    // treat their first word as a username (the old path produced @Not).
    let target = this.targetFromMention(message) || selectedGroup?.[0]?.user || selectedGroup?.[0]?.payload?.target || extraEvent?.user || extraEvent?.payload?.target || null;

    // If we don't have a strong target from the current message, try to resolve from recent context the bot just showed
    if (!target || !target.username) {
      const recent = this.lastPendingReviewsByChat.get(String(message.chat?.id)) || [];
      // Try to find a username mentioned in the correction text inside the recent list
      const mentioned = (messageText(message).match(/@([A-Za-z0-9_]{3,32})/) || [])[1];
      if (mentioned) {
        const matchGroup = recent.find(group => {
          const candidate = group?.[0]?.user || group?.[0]?.payload?.target || {};
          return normalizedLookup(candidate.username || candidate.label || '') === normalizedLookup(mentioned);
        });
        const match = matchGroup?.[0]?.user || matchGroup?.[0]?.payload?.target;
        if (match) target = { ...match, kind: 'user' };
      }
    }

    let targetEvents = selectedGroup?.length ? selectedGroup : target ? this.pendingReviewItems().filter((event) => eventMatchesTarget(event, target)) : [];

    if (extraEvent && !targetEvents.some(e => e.id === extraEvent.id)) {
      targetEvents = [extraEvent, ...targetEvents];
    }

    if (!targetEvents.length) return false;
    const reason = messageText(message).replace(/@(?:tracabot|tracethembot)\b/ig, '').trim() || 'natural-language false positive review';
    const reviewed = targetEvents;
    const displayTarget = reviewed[0]?.user || reviewed[0]?.payload?.target || target;
    const artifactWrites = await Promise.all(reviewed.map(async (reviewedEvent) => {
      const reviewedTarget = reviewedEvent?.user || reviewedEvent?.payload?.target || target;
      const event = await this.record('review_overturned', message, {
        target_event_id: reviewedEvent.id,
        review_decision: 'reject',
        reason,
        reviewer: actorFromMessage(message),
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        ...this.reviewTrustPayload(actorFromMessage(message)),
        false_positive_reason: reason,
        evidence: [`natural language admin rejected scam flag ${reviewedEvent.id}: ${reason}`]
      });
      return { reviewedEvent, event };
    }));
    await this.sendCommandReply(message.chat.id, `✅ Marked ${userMention(displayTarget)} as false positive and cleared ${reviewed.length} pending review${reviewed.length === 1 ? '' : 's'}.`, { reply_to_message_id: message.message_id, parse_mode: 'HTML' });
    for (const { reviewedEvent, event } of artifactWrites) {
      this.recordConversationArtifact(message, { risk: { confidence: 80, local_confidence: 80, scam_type: 'false_positive', evidence: [`false positive correction for ${reviewedEvent.id}: ${reason}`] }, text: reason, artifactKind: 'false_positive_signal', conversationRole: 'moderator', sourceEventIds: [reviewedEvent.id, event.id], operatorNote: reason, forceDkg: true })
        .catch((error) => console.error(`False positive artifact write failed after review ${event.id}: ${error instanceof Error ? error.message : String(error)}`));
    }
    return true;
  }

  canPublishFindingFromRisk(risk = {}) {
    return Number(risk.confidence || 0) >= 80 && Number(risk.local_confidence || 0) >= 60 && (risk.evidence?.length || 0) > 0;
  }

  redactArtifactText(text = '') {
    const max = this.config.wmArtifactMaxTextChars || 700;
    let value = boundedText(text, max);
    if (this.config.wmArtifactRedact === false) return value;
    value = value.replace(/0x[a-fA-F0-9]{40}/g, (wallet) => `${wallet.slice(0, 8)}...${wallet.slice(-6)}`);
    value = value.replace(/\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g, (wallet) => `${wallet.slice(0, 8)}...${wallet.slice(-6)}`);
    value = value.replace(/\b\d{7,}\b/g, '[telegram-id]');
    return value;
  }

  artifactQuality({ risk = {}, text = '', artifactKind = '' } = {}) {
    let score = 0;
    const confidence = Number(risk.local_confidence || risk.confidence || 0);
    if (confidence >= 40) score += 25;
    if (confidence >= 60) score += 20;
    if ((risk.domains || extractDomains(text)).length) score += 20;
    if ((risk.wallets || extractWallets(text)).length) score += 20;
    if ((risk.patterns || extractPatterns(text)).length) score += 15;
    if ((risk.dkg_evidence || []).length) score += 20;
    if (/report|warn|alert|fake|impersonat|phish|scam|wallet|airdrop|support|admin/i.test(text)) score += 10;
    if (/false positive|not scam|legit|reject|overturn|appeal/i.test(text) || artifactKind === 'false_positive_signal') score += 20;
    if (artifactKind === 'benign_conversation_flow') score += 45;
    return Math.min(100, score);
  }

  shouldWriteConversationArtifact(risk = {}, quality = 0, force = false) {
    if (this.config.testMode || this.config.wmArtifacts === false) return false;
    if (force) return true;
    if (quality >= 70) return true;
    return Boolean(this.config.wmArtifactShareLowConfidence && Number(risk.local_confidence || risk.confidence || 0) >= (this.config.wmArtifactMinConfidence || 40));
  }

  commitReceiptId({ artifactKind = '', quality = 0, risk = {}, sourceEventIds = [], text = '' } = {}) {
    const basis = [artifactKind, quality, risk.scam_type || '', risk.confidence || 0, sourceEventIds.join(','), textFingerprint(text)].join(':');
    return `commit:${randomUUID().slice(0, 8)}:${Buffer.from(basis).toString('base64url').slice(0, 16)}`;
  }

  async recordConversationArtifact(message, { risk = {}, text = '', artifactKind = 'conversation_artifact', conversationRole = 'observer', sourceEventIds = [], operatorNote = '', forceDkg = false } = {}) {
    if (this.config.wmArtifacts === false) return null;
    const rawText = boundedText(text || message.text || '', this.config.wmArtifactMaxTextChars || 700);
    const domains = risk.domains?.length ? risk.domains : extractDomains(rawText);
    const wallets = risk.wallets?.length ? risk.wallets : extractWallets(rawText);
    const patterns = risk.patterns?.length ? risk.patterns : extractPatterns(rawText);
    const quality = this.artifactQuality({ risk: { ...risk, domains, wallets, patterns }, text: rawText, artifactKind });
    const confidence = Number(risk.local_confidence || risk.confidence || 0);
    const useful = forceDkg || quality >= 40 || confidence >= (this.config.wmArtifactMinConfidence || 40) || domains.length || wallets.length || patterns.length;
    if (!useful) return null;
    const commitStamped = this.shouldWriteConversationArtifact(risk, quality, forceDkg);
    const commitReceiptId = commitStamped ? this.commitReceiptId({ artifactKind, quality, risk, sourceEventIds, text: rawText }) : '';
    const normalized = this.redactArtifactText(rawText).toLowerCase().replace(/https?:\/\/\S+/g, '[url]').replace(/\s+/g, ' ').trim();
    return this.record('conversation_artifact', message, {
      ...risk,
      artifact_kind: artifactKind,
      artifact_quality: quality,
      conversation_role: conversationRole,
      redaction_level: this.config.wmArtifactRedact === false ? 'bounded_raw' : 'redacted',
      normalized_text: normalized,
      message_text: this.redactArtifactText(rawText),
      text_fingerprint: textFingerprint(rawText),
      source_event_ids: sourceEventIds.filter(Boolean),
      operator_note: operatorNote,
      learning_value: quality >= 70 ? 'high' : quality >= 45 ? 'medium' : 'low',
      teaches_tactics: patterns,
      domains,
      wallets,
      patterns,
      commit_receipt_id: commitReceiptId,
      commit_policy: commitStamped ? (forceDkg ? 'human_or_admin_verified' : 'artifact_quality_threshold') : 'draft_only',
      commit_authority: commitStamped ? (forceDkg ? 'admin_review' : 'policy_rule') : '',
      publication_status: commitStamped ? 'shared_memory' : 'working_memory',
      lifecycle_stage: commitStamped ? 'shared_memory' : 'working_memory_draft',
      evidence: [
        ...(risk.evidence || []),
        `conversation artifact ${artifactKind} captured for scam/fraud working-memory learning`,
        commitStamped ? `commit receipt ${commitReceiptId} authorizes Shared Memory projection` : 'draft only; not eligible for Shared Memory until committed',
        operatorNote ? `operator note: ${operatorNote}` : ''
      ].filter(Boolean)
    }, { writeDkg: commitStamped });
  }

  async recordBenignConversationFlow(message, risk = {}) {
    if (risk.confidence >= (this.config.warnThreshold ?? 60)) return null;
    const text = message.text || '';
    if (!BENIGN_FLOW_RE.test(text)) return null;
    return this.recordConversationArtifact(message, {
      risk: {
        ...risk,
        scam_type: 'benign_conversation_flow',
        evidence: [...(risk.evidence || []), 'low-risk governance or technical conversation captured as non-fraud contrast example']
      },
      text,
      artifactKind: 'benign_conversation_flow',
      conversationRole: 'observer',
      operatorNote: 'non-fraud flow example for distinguishing technical governance discussion from impersonation or scam claims'
    });
  }

  shouldShareChannelObservation(message, risk = {}) {
    if (this.config.channelMemory === false || this.config.testMode) return false;
    if (!PUBLIC_CHAT_TYPES.has(message.chat?.type || '')) return false;
    if (message.from?.is_bot === true) return false;
    const confidence = Number(risk.local_confidence || risk.confidence || 0);
    if (confidence < (this.config.channelMemoryMinConfidence || 80)) return false;
    return hasBoundedRawMessageEvidence(message, risk, message.text || '');
  }

  async recordChannelObservation(message, risk = {}, observationType = 'high_confidence_channel_message') {
    if (!this.shouldShareChannelObservation(message, risk)) return null;
    const text = boundedText(message.text || '', this.config.channelMemoryMaxTextChars || 1000);
    return this.record('channel_observation', message, {
      ...risk,
      observation_type: observationType,
      target_key: targetKey(actorFromMessage(message)),
      target: actorFromMessage(message),
      message_id: message.message_id || '',
      reply_to_message_id: message.reply_to_message?.message_id || '',
      message_text: text,
      text_fingerprint: textFingerprint(text),
      domains: risk.domains?.length ? risk.domains : extractDomains(text),
      wallets: risk.wallets?.length ? risk.wallets : extractWallets(text),
      patterns: risk.patterns?.length ? risk.patterns : extractPatterns(text),
      publication_status: 'shared_memory',
      lifecycle_stage: 'shared_memory',
      evidence: [
        ...(risk.evidence || []),
        'high-confidence public channel message stored in DKG v10 Shared Memory for spam/scam/fraud pattern analysis'
      ]
    }, { writeDkg: true });
  }

  shouldSendConversation(message, target, risk, explicit = false) {
    if (!this.chatConversationalEnabled(message?.chat?.id)) return false;
    if (!this.isDirectlyAddressed(message)) return false;
    if (!shouldConversationallyReply({ message, risk, explicit, config: this.config })) return false;
    const key = conversationKey(message, target);
    const last = this.conversationLastReply.get(key) || 0;
    if (Date.now() - last < (this.config.conversationRateLimitSeconds || 0) * 1000) return false;
    this.conversationLastReply.set(key, Date.now());
    return true;
  }

  isReplyToBot(message) {
    const reply = message?.reply_to_message;
    if (!reply?.from) return false;
    if (reply.from.is_bot !== true) return false;
    const uname = (reply.from.username || '').toLowerCase();
    return uname === 'tracabot' || uname === 'tracethembot' || (this.botId && reply.from.id === this.botId);
  }

  isDirectlyAddressed(message) {
    return /@(?:tracabot|tracethembot)\b/i.test(messageText(message)) || this.isReplyToBot(message);
  }

  isBareBotMention(message = {}) {
    return /^@(?:tracabot|tracethembot)$/i.test(String(messageText(message) || '').trim());
  }

  isBotMentionReplyScan(message = {}) {
    return this.isBareBotMention(message) && Boolean(message.reply_to_message?.from);
  }

  isRecentBotNearReply(message = {}) {
    if (message.text?.startsWith('/')) return false;
    if (!this.isReplyToBot(message)) return false;
    const recent = this.lastBotReplyByThread.get(`${message.chat?.id}:*`);
    if (!recent || Date.now() - recent.timestamp > BOT_REPLY_CONTEXT_TTL_MS) return false;
    return message.from?.is_bot !== true;
  }

  shouldHandleNaturalLanguage(message) {
    if (!this.chatConversationalEnabled(message?.chat?.id)) return false;
    return this.isDirectlyAddressed(message) || this.isRecentBotNearReply(message);
  }

  naturalLanguageRateLimited(message = {}) {
    const seconds = Number(this.config.conversationRateLimitSeconds || 0);
    if (seconds <= 0) return false;
    const key = this.conversationThreadKey(message);
    const last = this.naturalLanguageLastReply.get(key) || 0;
    if (Date.now() - last < seconds * 1000) return true;
    this.naturalLanguageLastReply.set(key, Date.now());
    return false;
  }

  async handleDeterministicNaturalLanguage(text = '', message = {}, trusted = false, replyOptions = {}) {
    const chatId = message.chat.id;
    if (PRIVATE_INFO_RE.test(text)) {
      await this.sendEphemeral(chatId, trusted && /\bstatus\b/i.test(text) ? 'Open /start and use Settings > Status.' : 'I do not share private details.', replyOptions);
      return true;
    }
    if (DIGEST_INTENT_RE.test(text)) {
      const stats = await this.dkg.getStats(7);
      await this.sendInteractiveReply(chatId, this.formatStatsDashboard(stats), this.statsKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return true;
    }
    if (CAMPAIGN_INTENT_RE.test(text)) {
      await this.sendInteractiveReply(chatId, this.formatCampaigns(), this.statsKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return true;
    }
    if (REVIEW_QUEUE_INTENT_RE.test(text)) {
      if (!trusted) await this.sendEphemeral(chatId, 'Pending reviews / review queue is admin-only. You can still ask me to scan specific users or explain events.', replyOptions);
      else {
        await this.sendPendingReviews(message, replyOptions);
      }
      return true;
    }
    if (WATCHLIST_INTENT_RE.test(text)) {
      if (!trusted) await this.sendEphemeral(chatId, 'Mutes and review details are admin-only. I can still check scam risk for you.', replyOptions);
      else await this.sendInteractiveReply(chatId, this.formatReviewPanel('mutes'), this.reviewPanelKeyboard(message.from?.id || message.from?.username || '', 'mutes'), { ...replyOptions, parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (STATS_INTENT_RE.test(text)) {
      const stats = await this.dkg.getStats(7);
      await this.sendInteractiveReply(chatId, this.formatStatsDashboard(stats), this.statsKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return true;
    }
    if (HELP_INTENT_RE.test(text) && !/\b(?:scan|report|watch|review|appeal|ban)\b/i.test(text)) {
      const reply = this.llm && !this.naturalLanguageRateLimited(message)
        ? await this.generalConversationReply(message).catch(() => '')
        : '';
      await this.sendInteractiveReply(chatId, reply || 'I am the community anti-scam bodyguard: I scan users, take reports, explain evidence, and use verifiable cross-community memory to spot repeat threats.', this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return true;
    }
    if (!isOnTopicDirectAddress(message)) {
      await this.sendInteractiveReply(chatId, offTopicRedirect(), this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return true;
    }
    return false;
  }

  async handleNaturalLanguageRequest(message) {
    const rawText = messageText(message);
    const mentionsBot = /@(?:tracabot|tracethembot)\b/i.test(rawText);
    const safetyLike = isSafetyQuestion(message) || /\b(?:safe|unsafe|legit(?:imate)?|real|fake|scam(?:mer|ming)?|fraud(?:ster)?|risky?|trusted|trustworthy|blacklisted|flagged|suspicious|sus|dangerous|malicious)\b/i.test(rawText);
    if (safetyLike) return false;
    if (!this.shouldHandleNaturalLanguage(message)) return false;
    const text = rawText.replace(/@(?:tracabot|tracethembot)\b/ig, ' ').trim();
    const lower = text.toLowerCase();
    const trusted = await this.isTrustedModerator(message).catch(() => false);
    const replyOptions = { reply_to_message_id: message.message_id };

    if (await this.handleDeterministicNaturalLanguage(lower, message, trusted, replyOptions)) {
      return true;
    }

    // Let the LLM agent handle the vast majority of direct addresses (greetings, purpose, help, queries, implicit actions, etc.)

    // Primary agentic path (LLM interprets the request and chooses the right capability)
    if (this.isDirectlyAddressed(message) || this.isRecentBotNearReply(message)) {
      if (this.naturalLanguageRateLimited(message)) {
        await this.sendInteractiveReply(message.chat.id, 'I’m here. Pick an action below, or use /scan and /report as replies when you need to check or report a specific message.', this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
        return true;
      }
      this.sendTyping(message.chat.id).catch(() => {});
      this.rememberConversationTurn(message, 'user', rawText);

      let responded = false;

      try {
        const agentDecision = await this.runAgentTurn(message);
        const chatId = message.chat.id;

        if (agentDecision.action === 'ignore') {
          await this.sendInteractiveReply(chatId, offTopicRedirect(), this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
          responded = true;
        } else if (agentDecision.needs_clarification) {
          await this.sendEphemeral(chatId, agentDecision.needs_clarification, replyOptions);
          responded = true;
        } else {
          const result = await this.executeAgentAction(agentDecision.action, agentDecision.parameters || {}, message, trusted, replyOptions);
          if (result && result.handled) {
            responded = true;
          }
        }

        if (!responded) {
          const generalReply = await this.generalConversationReply(message);
          if (generalReply && generalReply.length > 3) {
            await this.sendInteractiveReply(chatId, generalReply, this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
            responded = true;
          }
        }

      } catch (err) {
        console.error('Natural language agent path error:', err);
        const errorFallback = await this.generalConversationReply(message).catch(() => null);
        if (errorFallback && errorFallback.length > 3) {
          await this.sendInteractiveReply(message.chat.id, errorFallback, this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
          responded = true;
        }
      }

      // Absolute guarantee: if we still haven't responded to a direct address, send a clear helpful message.
      // This keeps the bot in bodyguard mode instead of opening a general chat loop.
      if (!responded) {
        await this.sendInteractiveReply(message.chat.id, offTopicRedirect(), this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      }

      return true;
    }
    return false;
  }

  async generalConversationReply(message) {
    const fallback = offTopicRedirect();
    if (!this.llm || !this.chatConversationalEnabled(message?.chat?.id)) return fallback;
    const prompt = buildGeneralPrompt({ message, maxChars: this.config.conversationMaxChars, history: this.conversationContext(message) });
    const response = await this.llm.complete(prompt).catch(() => ({ ok: false, text: '' }));
    const reply = sanitizeGeneralReply(response.text, { maxChars: this.config.conversationMaxChars, fallback });
    this.rememberConversationTurn(message, 'assistant', reply || fallback);
    return reply || fallback;
  }

  async runAgentTurn(message) {
    const fallback = { action: 'ignore', parameters: {}, needs_clarification: null, reasoning: 'llm failed or returned unusable output' };
    if (!this.llm || !this.chatConversationalEnabled(message?.chat?.id)) return fallback;

    const prompt = buildAgentIntentPrompt({ message, maxChars: 600, history: this.conversationContext(message) });
    const response = await this.llm.complete(prompt).catch(() => ({ ok: false, text: '' }));

    const rawText = String(response.text || '').trim();

    // Try strict JSON first
    try {
      let raw = rawText;
      raw = raw.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').replace(/^`+|`+$/g, '').trim();
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        return {
          action: String(parsed.action || 'general_on_topic'),
          parameters: parsed.parameters && typeof parsed.parameters === 'object' ? parsed.parameters : {},
          needs_clarification: parsed.needs_clarification || null,
          reasoning: parsed.reasoning || ''
        };
      }
    } catch {}

    // Fallback: if the LLM gave plain text instead of JSON, treat it as a general answer
    if (rawText.length > 5) {
      return {
        action: 'general_on_topic',
        parameters: { response_text: rawText.slice(0, 600) },
        needs_clarification: null,
        reasoning: 'llm returned plain text instead of structured action'
      };
    }

    return fallback;
  }

  alertReplyContext(message = {}) {
    const repliedMsgId = message.reply_to_message?.message_id;
    const eventId = repliedMsgId ? this.reviewMessageEvents.get(`${message.chat?.id}:${repliedMsgId}`) : '';
    const event = this.findEvent(eventId);
    if (!event) return null;
    const target = event.user || event.payload?.target || {};
    return {
      event,
      eventId: event.id,
      target,
      eventType: event.event_type,
      summary: this.reviewSummary(event)
    };
  }

  senderMatchesTarget(message = {}, target = {}) {
    const actor = actorFromMessage(message);
    if (actor.id && target.id && String(actor.id) === String(target.id)) return true;
    const actorUsername = normalizedLookup(actor.username || '');
    const targetUsername = normalizedLookup(target.username || '');
    return Boolean(actorUsername && targetUsername && actorUsername === targetUsername);
  }

  async classifyAlertReply(message, context, trusted) {
    if (!this.llm || !this.chatConversationalEnabled(message?.chat?.id)) return null;
    const prompt = buildAlertReplyClassifierPrompt({
      message,
      alert: context,
      senderTrusted: trusted,
      senderIsFlagged: this.senderMatchesTarget(message, context?.target || {}),
      maxChars: this.config.conversationMaxChars || 700
    });
    const response = await this.llm.complete(prompt).catch(() => ({ ok: false, text: '' }));
    try {
      const raw = String(response.text || '').replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      const intent = ['admin_review', 'appeal', 'clarify', 'ignore'].includes(parsed.intent) ? parsed.intent : 'clarify';
      const decision = ['confirm', 'reject'].includes(parsed.decision) ? parsed.decision : null;
      return {
        intent,
        decision,
        target_event_id: String(parsed.target_event_id || context?.eventId || ''),
        reason: String(parsed.reason || messageText(message) || '').slice(0, 500),
        confidence: Math.max(0, Math.min(100, Number(parsed.confidence || 0))),
        user_reply: String(parsed.user_reply || '').slice(0, this.config.conversationMaxChars || 700)
      };
    } catch {
      return null;
    }
  }

  async handleAlertReply(message) {
    const context = this.alertReplyContext(message);
    if (!context) return false;
    const chatId = message.chat.id;
    const replyOptions = { reply_to_message_id: message.message_id };
    const trusted = await this.isTrustedModerator(message).catch(() => false);
    const explicitAdminDecision = /\b(confirm(?:ed)?\s+(?:scam|flag)|uphold(?:ed)?\s+(?:scam|flag)|reject(?:ed)?\s+(?:flag|as\s+not\s+(?:a\s+)?scam)|overturn(?:ed)?|false\s+positive|not\s+(?:a\s+)?scam)\b/i.test(messageText(message));
    const classified = await this.classifyAlertReply(message, context, trusted);
    if (!classified) return false;
    const reason = classified.reason || messageText(message).trim() || 'natural reply to TRACaBot alert';
    const targetEvent = context.event;
    const reviewedTarget = targetEvent?.user || targetEvent?.payload?.target || context.target || {};

    if (trusted && classified.intent === 'admin_review' && classified.decision && explicitAdminDecision) {
      const eventType = classified.decision === 'reject' ? 'review_overturned' : 'review_upheld';
      const event = await this.record(eventType, message, {
        target_event_id: targetEvent.id,
        review_decision: classified.decision,
        reason,
        reviewer: actorFromMessage(message),
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        ...this.reviewTrustPayload(actorFromMessage(message)),
        false_positive_reason: classified.decision === 'reject' ? reason : '',
        implicit_detection: true,
        detection_method: 'llm_alert_reply_classifier',
        llm_intent: classified.intent,
        llm_confidence: classified.confidence,
        original_flag_event: targetEvent.id,
        evidence: [`LLM classified admin alert reply as ${classified.decision} for ${targetEvent.id}: ${reason}`]
      });
      if (classified.decision === 'reject') {
        this.recordConversationArtifact(message, { risk: { confidence: 80, local_confidence: 80, scam_type: 'false_positive', evidence: [`false positive correction for ${targetEvent.id}: ${reason}`] }, text: reason, artifactKind: 'false_positive_signal', conversationRole: 'moderator', sourceEventIds: [targetEvent.id, event.id], operatorNote: reason, forceDkg: true })
          .catch((error) => console.error(`False positive artifact write failed after alert reply ${event.id}: ${error instanceof Error ? error.message : String(error)}`));
      }
      const verb = classified.decision === 'reject' ? 'Rejected' : 'Confirmed';
      const suffix = classified.user_reply ? escapeHtml(classified.user_reply) : `${verb} the scam flag for ${userMention(reviewedTarget)}. Event: ${escapeHtml(event.id)}.`;
      await this.sendCommandReply(chatId, `✅ ${suffix}`, { ...replyOptions, parse_mode: 'HTML' });
      return true;
    }

    if (trusted && classified.intent === 'admin_review' && classified.decision && !explicitAdminDecision) {
      await this.sendEphemeral(chatId, 'I need an explicit verdict before writing review memory. Reply “confirm scam” or “reject flag” to this alert, or open Reviews from /start.', replyOptions);
      return true;
    }

    if (!trusted && (classified.intent === 'appeal' || classified.decision === 'reject')) {
      const event = await this.record('appeal_submitted', message, {
        target_event_id: targetEvent.id,
        reason,
        appellant: actorFromMessage(message),
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        implicit_detection: true,
        detection_method: 'llm_alert_reply_classifier',
        llm_intent: classified.intent,
        llm_confidence: classified.confidence,
        original_flag_event: targetEvent.id,
        evidence: [`LLM classified non-admin alert reply as appeal for ${targetEvent.id}: ${reason}`]
      });
      await this.sendCommandReply(chatId, classified.user_reply ? escapeHtml(classified.user_reply) : `📝 Appeal logged for ${userMention(reviewedTarget)} as ${escapeHtml(event.id)}. Admins can confirm or reject the scam flag.`, { ...replyOptions, parse_mode: 'HTML' });
      return true;
    }

    if (classified.intent === 'clarify') {
      await this.sendEphemeral(chatId, classified.user_reply ? escapeHtml(classified.user_reply) : (trusted ? 'Do you want me to confirm this as a scam or reject it as not a scam?' : 'I can log an appeal if you think this flag is wrong. What should admins review?'), replyOptions);
      return true;
    }

    if (classified.intent === 'ignore') return true;
    return false;
  }

  async executeAgentAction(action, parameters, message, trusted, replyOptions) {
    const chatId = message.chat.id;

    const getSkillService = () => this.skillServiceOrNull();

    if (action === 'list_pending_reviews' || action === 'show_reviews') {
      const svc = getSkillService();
      if (svc && trusted) {
        svc.getWatchlist({ filter: 'review' });
      }
      if (!trusted) {
        await this.sendEphemeral(chatId, 'Pending reviews / review queue is admin-only. You can still ask me to scan specific users or explain events.', replyOptions);
      } else {
        await this.sendPendingReviews(message, replyOptions);
      }
      return { handled: true };
    }

    if (action === 'settings') {
      if (!trusted) await this.sendEphemeral(chatId, 'Settings are admin-only.', replyOptions);
      else await this.sendInteractiveReply(chatId, this.settingsText(chatId), this.settingsKeyboard(message.from?.id || message.from?.username || '', chatId), replyOptions);
      return { handled: true };
    }

    if (action === 'show_watchlist') {
      const filter = parameters.filter === 'muted' ? 'mutes' : parameters.filter === 'mutes' ? 'mutes' : 'all';
      const svc = getSkillService();
      if (svc && trusted) {
        svc.getWatchlist({ filter });
      }
      if (!trusted) {
        await this.sendEphemeral(chatId, 'Review details and mutes are admin-only. I can still check scam risk for you.', replyOptions);
      } else {
        await this.sendInteractiveReply(chatId, this.formatReviewPanel(filter), this.reviewPanelKeyboard(message.from?.id || message.from?.username || '', filter), { ...replyOptions, parse_mode: 'HTML', disable_web_page_preview: true });
      }
      return { handled: true };
    }

    if (action === 'get_stats' || action === 'get_digest' || action === 'stats' || action === 'digest') {
      const svc = getSkillService();
      if (svc) {
        // Prefer skill for consistency (even though get_digest is mostly local)
        svc.getDigest();
      }
      const stats = await this.dkg.getStats(7);
      await this.sendInteractiveReply(chatId, this.formatStatsDashboard(stats), this.statsKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return { handled: true };
    }

    if (action === 'banlist' || action === 'modlog' || action === 'recent_actions') {
      if (!trusted) {
        await this.sendEphemeral(chatId, 'Banlist / recent enforcement actions are admin-only.', replyOptions);
      } else {
        const bl = await this.formatBanlist();
        await this.sendInteractiveReply(chatId, bl, this.banlistKeyboard(message.from?.id || message.from?.username || ''), { ...replyOptions, parse_mode: 'HTML' });
      }
      return { handled: true };
    }

    if (action === 'show_campaigns' || action === 'memory_query') {
      await this.sendInteractiveReply(chatId, this.formatCampaigns(), this.statsKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return { handled: true };
    }

    if (action === 'explain_event' || action === 'why') {
      const eventId = parameters.event_id || parameters.eventId || '';
      const svc = getSkillService();
      if (svc && eventId) {
        svc.explainEvent({ eventId });
      }
      await this.sendInteractiveReply(chatId, this.formatWhy(eventId), this.mainNavKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      return { handled: true };
    }

    if (action === 'help' || action === 'greeting' || action === 'general_on_topic') {
      // Delegate to the general conversational LLM so the agent actually answers intelligently
      const generalReply = await this.generalConversationReply(message);
      if (generalReply && generalReply.length > 5) {
        await this.sendInteractiveReply(chatId, generalReply, this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      } else {
        const greeting = action === 'greeting' ? 'Hi. ' : '';
        await this.sendInteractiveReply(chatId, `${greeting}I am the community anti-scam bodyguard: I scan users, take reports, explain evidence, and use verifiable cross-community memory to spot repeat threats.`, this.dashboardKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
      }
      return { handled: true };
    }

    if (action === 'report') {
      const text = [parameters.target?.username ? `@${parameters.target.username}` : '', parameters.reason, parameters.details, messageText(message).replace(/@(?:tracabot|tracethembot)\b/ig, '').replace(/\breport\b/i, '').trim()].filter(Boolean).join(' ');
      const target = parameters.target?.username || parameters.target?.id
        ? { id: parameters.target.id || '', username: parameters.target.username || '', is_bot: false }
        : null;
      if (target) {
        const risk = await this.assess({ ...message, from: target, text }, target, text);
        const event = await this.record('report_review_needed', { ...message, from: target }, {
          ...risk,
          reporter: actorFromMessage(message),
          target_key: targetKey(target),
          report_decision: 'needs_admin_review',
          report_reason: 'natural language report queued for admin review',
          evidence: [...(risk.evidence || []), `manual Telegram report submitted by ${actorFromMessage(message).username || actorFromMessage(message).id}`]
        }, { writeDkg: false });
        await this.recordConversationArtifact({ ...message, from: target }, { risk, text, artifactKind: 'report_review_observation', conversationRole: 'reporter', sourceEventIds: [event.id] });
        await this.sendCommandReply(chatId, '✅ Reported. I added this to the admin review queue. Admins can review it from the Tracabot menu.', replyOptions);
        return { handled: true };
      }
      await this.handleCommand({ ...message, text: `/report ${text || message.text || ''}`.trim(), reply_to_message: target ? { chat: message.chat, from: target, text: parameters.reason || parameters.details || text } : message.reply_to_message });
      return { handled: true };
    }

    if (action === 'false_positive_review' || action === 'reject' || action === 'overturn' || (!['review', 'appeal'].includes(action) && this.isNaturalFalsePositiveReview(message))) {
      if (trusted) {
        const didOverturn = await this.handleNaturalFalsePositiveReview(message);
        if (didOverturn) return { handled: true };

        // Give explicit helpful feedback instead of silence
        await this.sendEphemeral(chatId, 'I understood you want to mark that as a false positive. I could not match it to a current pending review item for that user. Open Reviews from /start or tell me the event id.', replyOptions);
      } else {
        await this.sendEphemeral(chatId, 'Only admins can reject scam flags. If you are an admin, open Settings from /start to verify admin recognition.', replyOptions);
      }
      return { handled: true };
    }

    // For actions that require more interaction (scan, report, etc.), give clear guidance
    // Phase 8: many of these are now also handled implicitly via context in the cases below.
    if (action === 'mute') {
      if (!trusted) await this.sendEphemeral(chatId, 'Admin-only. I can scan or report suspicious users, but muting requires a trusted moderator.', replyOptions);
      else await this.handleMuteCommand({ ...message, text: `/mute ${parameters.duration || ''} ${parameters.reason || ''}`.trim() });
      return { handled: true };
    }

    if (action === 'scan') {
      const hint = action === 'scan' ? 'Reply to a user or message and ask me to scan them, or use /scan.'
        : 'Reply to suspicious evidence with /report, forward a suspicious DM, or describe it and include the @username when available.';
      await this.sendEphemeral(chatId, `Understood. ${hint}`, replyOptions);
      return { handled: true };
    }

    // Actually perform a scan when the LLM requests "scan_target"
    if (action === 'scan_target') {
      const svc = getSkillService();
      if (svc) {
        const scanInput = {
          telegramUserId: parameters.target?.id || '',
          username: parameters.target?.username || '',
          text: message.text || '',
          label: parameters.target?.label || ''
        };
        const result = await svc.scanTarget(scanInput);
        const risk = result.risk || {};
        const target = result.target || { username: parameters.target?.username };
        await this.sendInteractiveReply(chatId, formatScanReply({ target, risk, eventId: '', findingId: '' }), this.scanKeyboard(message.from?.id || message.from?.username || '', target, ''), replyOptions);
      } else {
        await this.sendEphemeral(chatId, 'I can run a risk scan for you. Reply to the user/message and say “scan this”.', replyOptions);
      }
      return { handled: true };
    }

    // Phase 8 / robustness: support when LLM returns plain text for general questions
    if (action === 'general_on_topic' && parameters.response_text) {
      await this.sendEphemeral(chatId, parameters.response_text, replyOptions);
      return { handled: true };
    }

    if (action === 'appeal') {
      // Phase 8: Real implicit appeal detection when the speaker replies to one of our recent flags
      const repliedMsgId = message.reply_to_message?.message_id;
      const key = repliedMsgId ? `${chatId}:${repliedMsgId}` : null;
      const targetEventId = (parameters.event_id || parameters.eventId || parameters.target_event_id || (key ? this.reviewMessageEvents.get(key) : null));

      if (targetEventId) {
        // This is a reply to one of our alerts — treat as implicit appeal
        const reason = (message.text || '').replace(/^@?tracabot\b/i, '').trim() || 'implicit appeal via reply to flag';
        const event = await this.record('appeal_submitted', message, {
          target_event_id: targetEventId,
          reason,
          implicit_detection: true,
          detection_method: 'llm_context_reply_to_flag',
          original_flag_event: targetEventId
        });
        await this.sendEphemeral(chatId, `Appeal recorded for event ${shortId(targetEventId)}. Admins will review. Event: ${event.id}`, replyOptions);
        return { handled: true };
      }

      // Fallback for explicit or less clear cases
      await this.sendEphemeral(chatId, 'I understand this may be an appeal or correction. Reply directly to the specific flag message with what is wrong, or ask an admin to say confirm/reject.', replyOptions);
      return { handled: true };
    }

    if (action === 'review' && trusted) {
      // Phase 8: Real implicit review (confirm/reject) from admin context after flag
      const repliedMsgId = message.reply_to_message?.message_id;
      const key = repliedMsgId ? `${chatId}:${repliedMsgId}` : null;
      const eventId = parameters.event_id || parameters.eventId || parameters.target_event_id || (key ? this.reviewMessageEvents.get(key) : null);
      const decisionRaw = (parameters.decision || parameters.verdict || '').toLowerCase();
      const isReject = decisionRaw.includes('reject') || decisionRaw.includes('overturn') || decisionRaw.includes('false') || decisionRaw.includes('fake') || decisionRaw.includes('not');
      const isConfirm = decisionRaw.includes('confirm') || decisionRaw.includes('uphold') || decisionRaw.includes('real') || decisionRaw.includes('yes');

      if (!eventId) {
        await this.sendEphemeral(chatId, 'Understood — you want to review. Please include the event ID or reply directly to the flag message.', replyOptions);
        return { handled: true };
      }

      if (!isReject && !isConfirm) {
        await this.sendEphemeral(chatId, 'I need an explicit verdict before recording a review. Say “confirm scam” or “reject as not a scam”.', replyOptions);
        return { handled: true };
      }

      const targetEvent = this.findEvent(eventId);
      if (!targetEvent || !this.isPendingReviewEvent(targetEvent)) {
        await this.sendEphemeral(chatId, 'I could not find an active pending review for that event. Reopen Reviews and try from the current queue.', replyOptions);
        return { handled: true };
      }
      if (targetEvent.chat?.id && message.chat?.id && String(targetEvent.chat.id) !== String(message.chat.id)) {
        await this.sendEphemeral(chatId, 'That review item belongs to a different chat. Reopen Reviews in the original chat before recording a decision.', replyOptions);
        return { handled: true };
      }

      const decision = isReject ? 'reject' : 'confirm';
      const reason = parameters.reason || `implicit review decision via LLM context: ${decisionRaw || 'admin verdict'}`;

      const reviewEventType = decision === 'reject' ? 'review_overturned' : 'review_upheld';
      const event = await this.record(reviewEventType, message, {
        target_event_id: eventId,
        review_decision: decision,
        reason,
        reviewer: actorFromMessage(message),
        reviewed_target: targetEvent.user || targetEvent.payload?.target || {},
        reviewed_target_key: targetKey(targetEvent.user || targetEvent.payload?.target || {}),
        ...this.reviewTrustPayload(actorFromMessage(message)),
        implicit_detection: true,
        detection_method: 'llm_context_after_flag',
        moderator: actorFromMessage(message)
      });

      const msg = decision === 'reject'
        ? `Rejected the scam flag for ${shortId(eventId)}. Correction recorded. Event: ${event.id}.`
        : `Confirmed the scam flag for ${shortId(eventId)}. Event: ${event.id}.`;
      await this.sendEphemeral(chatId, msg, replyOptions);
      return { handled: true };
    }

    // Ultimate safety net for direct addresses: never go completely silent
    // if the LLM picked something we don't have a perfect handler for.
    const generalReply = await this.generalConversationReply(message);
    if (generalReply && generalReply.length > 3) {
      await this.sendEphemeral(chatId, generalReply, replyOptions);
    } else {
      await this.sendEphemeral(chatId, "I'm Tracabot — the community anti-scam bodyguard. I scan users, take reports, show reviews/stats, and use verifiable cross-community memory to catch repeat scammers.", replyOptions);
    }
    return { handled: true };
  }

  async conversationReply(message, target, risk, event, explicit = false) {
    if (!this.shouldSendConversation(message, target, risk, explicit)) return '';
    const fallback = fallbackSafetyReply({ target, risk, event });
    if (!this.llm) return fallback;
    const prompt = buildSafetyPrompt({ message, target, risk, event, maxChars: this.config.conversationMaxChars });
    const response = await this.llm.complete(prompt).catch(() => ({ ok: false, text: '' }));
    return sanitizeSafetyReply(response.text, { risk, maxChars: this.config.conversationMaxChars, fallback });
  }

  async extractDmReportWithLlm(text, message) {
    if (!this.llm || !this.chatConversationalEnabled(message?.chat?.id)) return {};
    const system = [
      'Extract structured fields from a Telegram DM scam report.',
      'Return compact JSON only. Do not accuse beyond the supplied report.',
      'Fields: reportedAlias, claimedRole, claimedOrganization, scamRequest, summary.'
    ].join('\n');
    const user = `Report text:\n${boundedText(text, 1500)}\nScreenshot attached: ${screenshotFileIds(message).length ? 'yes' : 'no'}`;
    const response = await this.llm.complete({ system, user }).catch(() => ({ ok: false, text: '' }));
    try {
      const raw = String(response.text || '').replace(/^```json\s*/i, '').replace(/```$/i, '').trim();
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch {
      return {};
    }
  }

  async buildDmReport(message, explicitText = '') {
    const rawText = explicitText || evidenceText(message);
    const commandText = messageText(message);
    const contextText = [rawText, commandText].filter(Boolean).join('\n');
    const text = cleanDmReportText(rawText);
    const files = screenshotFileIds(message);
    const llm = await this.extractDmReportWithLlm(text, message);
    const reportedAlias = String(extractReportedAlias(text) || llm.reportedAlias || '').slice(0, 120);
    const claimedRole = String(llm.claimedRole || extractClaimedRole(text) || '').slice(0, 120);
    const claimedOrganization = String(llm.claimedOrganization || extractClaimedOrganization(text) || '').slice(0, 120);
    const scamRequest = String(llm.scamRequest || (DM_SCAM_REQUEST_RE.test(text) ? text.match(DM_SCAM_REQUEST_RE)?.[0] : '') || '').slice(0, 160);
    const domains = [...new Set([...(String(text).match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})(?:\/\S*)?/gi) || [])])].slice(0, 8);
    const wallets = extractWallets(text);
    const patterns = ['dm-impersonation', claimedRole ? 'role-impersonation' : '', scamRequest ? 'solicitation-lure' : '', files.length ? 'screenshot-evidence' : ''].filter(Boolean);
    const hasRole = ROLE_RE.test(text) || Boolean(claimedRole);
    const hasDmContext = DM_REPORT_RE.test(contextText) || Boolean(message.forward_from || message.forward_sender_name || message.forward_from_chat) || /\b(?:impersonat|pretend|fake|unsolicited)\b/i.test(text);
    const hasRequest = DM_SCAM_REQUEST_RE.test(text) || Boolean(wallets.length || domains.length || scamRequest);
    const hasAlias = Boolean(reportedAlias);
    const trusted = await this.isTrustedModerator(message).catch(() => false);
    const boundIdentity = Boolean(message.forward_from?.id || message.forward_from?.username || /@\w{3,32}/.test(text));
    const verifiableIndicator = Boolean(wallets.length || domains.length || message.forward_from?.id || message.forward_from?.username);
    let confidence = 35;
    if (hasDmContext) confidence += 15;
    if (hasAlias) confidence += 15;
    if (hasRole) confidence += 15;
    if (hasRequest) confidence += 20;
    if (files.length) confidence += 10;
    if (trusted) confidence += 10;
    confidence = Math.min(95, confidence);
    const accepted = confidence >= 75 && hasDmContext && (hasAlias || hasRole) && (hasRequest || files.length || trusted) && (trusted || (boundIdentity && verifiableIndicator));
    const reason = accepted ? 'dm impersonation evidence accepted' : boundIdentity ? 'needs stronger dm impersonation evidence' : 'needs verifiable Telegram username, user id, wallet, link, or admin review before DKG sharing';
    const evidence = [
      reportedAlias ? `reported alias: ${reportedAlias}` : '',
      claimedRole ? `claimed role/title: ${claimedRole}` : '',
      claimedOrganization ? `claimed organization/community: ${claimedOrganization}` : '',
      scamRequest ? `reported DM request: ${scamRequest}` : '',
      domains.length ? `reported domains: ${domains.join(', ')}` : '',
      wallets.length ? `reported wallets: ${wallets.join(', ')}` : '',
      files.length ? `screenshot file IDs attached: ${files.length}` : '',
      text ? `report text: ${boundedText(text, MAX_CONTEXT_CHARS)}` : '',
      hasDmContext ? 'reported as off-platform/private DM scam' : ''
    ].filter(Boolean);
    return {
      accepted,
      reason,
      payload: {
        confidence,
        local_confidence: confidence,
        dkg_confidence: 0,
        scam_type: 'dm_impersonation',
        recommended_action: 'warn',
        reporter: actorFromMessage(message),
        reported_alias: reportedAlias,
        claimed_role: claimedRole,
        claimed_organization: claimedOrganization,
        scam_request: scamRequest,
        dm_platform: 'telegram_dm',
        screenshot_file_ids: files,
        screenshot_caption: boundedText([message.caption, message.reply_to_message?.caption].filter(Boolean).join('\n'), MAX_CONTEXT_CHARS),
        forwarded_from_id: message.forward_from?.id || '',
        forwarded_from_username: message.forward_from?.username || '',
        forwarded_sender_name: message.forward_sender_name || '',
        forwarded_from_chat: message.forward_from_chat?.username || message.forward_from_chat?.title || '',
        identity_bound: boundIdentity,
        verifiable_indicator: verifiableIndicator,
        allegation_only: !accepted,
        admin_verified: trusted,
        has_telegram_username: /@\w{3,32}/.test(text),
        report_decision: accepted ? 'accepted' : 'weak',
        report_reason: reason,
        report_outcome: accepted && confidence >= 80 ? 'high_confidence_dm_report' : accepted ? 'accepted_dm_report' : 'local_dm_review',
        source: 'telegram_report',
        domains,
        wallets,
        patterns,
        evidence
      }
    };
  }

  async handleDmReport(message, explicitText = '') {
    const report = await this.buildDmReport(message, explicitText);
    const event = await this.record('report_review_needed', message, report.payload, { writeDkg: false });
      await this.recordConversationArtifact(message, { risk: report.payload, text: explicitText || evidenceText(message), artifactKind: 'dm_report_observation', conversationRole: 'reporter', sourceEventIds: [event.id] });
      if (report.accepted) await this.maybeRecordCampaign({ ...message, text: report.payload.evidence.join('\n') }, report.payload);
    await this.send(message.chat.id, formatDmReportReply(event, report), { reply_to_message_id: message.message_id });
    return event;
  }

  async assess(message, targetUser = actorFromMessage(message), text = message.text || '') {
    const bounded = boundedText(text);
    this.rememberUser(message.chat, targetUser, bounded);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: targetUser.username, userId: targetUser.id, aliases: actorAliases(targetUser), text: bounded });

    // Phase 4: Check for prior high-severity admin actions on this actor across communities
    const adminHistory = (typeof this.dkg.queryAdminHistoryForActor === 'function')
      ? await this.dkg.queryAdminHistoryForActor({
          userId: targetUser.id,
          username: targetUser.username,
          aliases: actorAliases(targetUser)
        }).catch(() => ({ hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] }))
      : { hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] };

    let priorAdminAlertEvent = null;
    const graphFalsePositiveReview = adminHistory.hasPriorFalsePositive ? { id: adminHistory.falsePositiveEvents?.[0]?.eventId || 'context-graph-false-positive' } : null;

    if (!graphFalsePositiveReview && adminHistory.hasPriorAdminAction) {
      dkgIntel.evidence = dkgIntel.evidence || [];
      dkgIntel.evidence.push('Prior admin action/sentence found in Tracabot Context Graph for this actor');
      dkgIntel.riskScore = Math.max(dkgIntel.riskScore || 0, 75);

      // Create a real proactive cross-group alert when risk is meaningful
      const currentRisk = combineRisk({ analysis: { confidence: 0 }, dkgIntel, threshold: this.config.actionThreshold });
      if (currentRisk.confidence >= (this.config.warnThreshold ?? 60)) {
        priorAdminAlertEvent = await this.record('proactive_cross_group_warning', message, {
          target: targetUser,
          target_key: targetKey(targetUser),
          prior_admin_events: adminHistory.events.slice(0, 5),
          current_risk: currentRisk,
          evidence: [
            'User has prior high-severity admin action in another community according to Tracabot Context Graph',
            ...adminHistory.events.slice(0, 3).map(e => `Prior event: ${e.eventType || 'admin_action'} (confidence ${e.confidence || 'n/a'})`)
          ],
          recommended_action: 'review'
        }, { writeDkg: true });

        // Option A: surface the cross-group intelligence as a visible protector alert (in-chat + admin DMs)
        if (priorAdminAlertEvent && this.config.proactiveAlertCrossGroup !== false) {
          await this.maybeSurfaceCrossGroupWarning(priorAdminAlertEvent, message, targetUser).catch(() => {});
        }
      }
    }
    const adminUsernames = (await this.adminIdentities(message.chat.id)).filter((id) => !/^\d+$/.test(id));
    const renameCopycat = this.adminRenameCopycat(message.chat, targetUser, adminUsernames);
    const falsePositiveReview = this.falsePositiveReviewFor(targetUser, bounded, dkgIntel) || graphFalsePositiveReview;
    const effectiveIntel = falsePositiveReview ? { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [], artifactEvidence: [] } : dkgIntel;
    const analysis = this.analyzer({ text: bounded, user: { ...targetUser, adminUsernames, adminRenameCopycat: Boolean(renameCopycat) }, globalIntel: effectiveIntel });
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
    const risk = combineRisk({ analysis, dkgIntel: effectiveIntel, threshold: this.config.actionThreshold });
    if (!falsePositiveReview) return risk;
    return {
      ...risk,
      is_scam: false,
      confidence: Math.min(risk.confidence || 0, 10),
      local_confidence: Math.min(risk.local_confidence || 0, 10),
      dkg_confidence: 0,
      recommended_action: 'ignore',
      dkg_backed: false,
      dkg_evidence: [],
      dkg_artifact_evidence: [],
      evidence: [...(risk.evidence || []), `admin false-positive review ${falsePositiveReview.id} suppresses autonomous enforcement`]
    };
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
    const successful = reports.filter((event) => event.payload?.admin_verified === true || event.payload?.review_confirmed === true).length;
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
      trustedReporter: successful >= 2
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
    const concreteEvidence = Boolean(message.reply_to_message?.text || message.reply_to_message?.caption) || risk.wallets.length > 0 || risk.domains.length > 0 || risk.patterns.length >= 1 || /https?:\/\/|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/i.test(targetText);
    const trustedReporterEvidence = false;
    const independentEvidence = risk.local_confidence >= 60 || reportWorthyLocalPattern || risk.wallets.length > 0 || risk.patterns.length >= 1 || risk.domains.length > 0;
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
    if ((!independentEvidence || !concreteEvidence) && !isAdmin) {
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
    if (!canAutonomouslyEscalate(risk)) {
      if (isObviousLocalScam(risk)) {
        // Auto-delete of user messages disabled during testing period (except join challenges)
        const deletedMessage = false;
        const finding = await this.publishHighConfidenceFinding(message, {
          ...risk,
          recommended_action: 'delete_and_review',
          evidence: [...risk.evidence, 'obvious local scam message removal disabled during testing', 'local-only finding published for cross-community review; no ban/restrict without DKG backing']
        });
        return this.record('risk_review_needed', message, {
          ...risk,
          recommended_action: 'delete_and_review',
          finding_event_id: finding.id,
          evidence: [...risk.evidence, 'triggering message removal disabled during testing', `finding event ${finding.id}`, 'no ban/restrict without DKG backing']
        }, { writeDkg: false });
      }
      return this.record('risk_review_needed', message, {
        ...risk,
        evidence: [...risk.evidence, 'local-only signal held for review; no DKG evidence']
      }, { writeDkg: false });
    }

    const actor = actorFromMessage(message);
    if (actor.is_bot === true || await this.isTelegramChatAdmin(message.chat.id, actor.id)) {
      const review = await this.record('risk_action_suppressed', message, {
        ...risk,
        evidence: [...risk.evidence, actor.is_bot === true ? 'auto-action suppressed for Telegram bot account' : 'auto-action suppressed for Telegram chat admin']
      }, { writeDkg: false });
      await this.alertAdmins(message, risk, review);
      return review;
    }

    // Auto-delete of user messages disabled during testing period (except join challenges)
    const deletedMessage = false;
    const finding = risk.confidence >= (this.config.actionThreshold ?? 85) ? await this.publishHighConfidenceFinding(message, {
      ...risk,
      recommended_action: 'admin_review',
      evidence: [...risk.evidence, 'triggering message removal disabled during testing', 'auto ban/restrict disabled for message classifier decisions; admin review required']
    }) : null;
    const review = await this.record('risk_review_needed', message, {
      ...risk,
      recommended_action: 'admin_review',
      finding_event_id: finding?.id || '',
      evidence: [...risk.evidence, 'triggering message removal disabled during testing', 'auto ban/restrict disabled for message classifier decisions; admin review required']
    }, { writeDkg: false });
    await this.alertAdmins(message, risk, review);
    return review;
  }

  async handleMuteCommand(message) {
    const chatId = message.chat.id;
    const replyOptions = { reply_to_message_id: message.message_id };
    if (!await this.isTrustedModerator(message)) {
      await this.sendEphemeral(chatId, '⚠️ /mute is restricted to configured admins or Telegram chat admins.', replyOptions);
      return;
    }
    if (!await this.hasRestrictRights(chatId)) {
      await this.sendEphemeral(chatId, 'I can advise and log, but I need Telegram admin restrict rights before I can mute users in this group.', replyOptions);
      return;
    }
    const argText = this.commandText(message, 'mute');
    const { target } = this.resolveCommandTarget(message, 'mute');
    const replyUser = target?.id ? target : message.reply_to_message?.from;
    if (!replyUser?.id) {
      await this.sendEphemeral(chatId, 'Reply to the user you want muted, mention them after /mute, or use a Telegram ID. Example: /mute 5 minutes.', replyOptions);
      return;
    }
    if (replyUser.is_bot === true || await this.isTelegramChatAdmin(chatId, replyUser.id)) {
      await this.sendEphemeral(chatId, 'I will not mute bot accounts or Telegram chat admins.', replyOptions);
      return;
    }
    const seconds = parseDurationSeconds(argText);
    const untilDate = Math.floor(Date.now() / 1000) + seconds;
    const reason = argText.replace(/\b\d+\s*(minutes?|mins?|m|hours?|hrs?|h|days?|d)\b/i, '').replace(/^@?\w{3,32}\s*/, '').trim() || `admin mute for ${humanDuration(seconds)}`;
    await this.muteMember(chatId, replyUser.id, untilDate);
    const event = await this.record('restrict_executed', { ...message, from: replyUser }, {
      reason,
      moderator: actorFromMessage(message),
      target: replyUser,
      target_key: targetKey(replyUser),
      restricted_until: new Date(untilDate * 1000).toISOString(),
      action_duration_seconds: seconds,
      action: 'mute',
      admin_verified: true,
      publication_status: 'shared_memory',
      lifecycle_stage: 'shared_memory',
      evidence: [`admin muted ${replyUser.username || replyUser.id} for ${humanDuration(seconds)}: ${reason}`]
    }, { writeDkg: true });
    await this.sendCommandReply(chatId, `🔇 Muted ${userMention(replyUser)} for ${humanDuration(seconds)}. Event: ${event.id}.`, { ...replyOptions, parse_mode: 'HTML' });
  }

  async handleCommand(message) {
    const text = message.text || '';
    const chatId = message.chat.id;
    if (isCommand(text, 'start')) {
      await this.sendInteractiveReply(chatId, this.formatHelp(), this.dashboardKeyboard(message.from?.id || message.from?.username || ''), { reply_to_message_id: message.message_id });
      this.cleanupMenuTrigger(message);
      return;
    }
    if (isCommand(text, 'scan')) {
      if (await this.rejectNonOwnerPrivateReport(message)) return;
      const { target, text: targetText } = this.resolveCommandTarget(message, 'scan');
      const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      await this.recordConversationArtifact({ ...message, from: target }, { risk, text: targetText || message.text, artifactKind: 'safety_question', conversationRole: 'questioner', sourceEventIds: [event.id] });
      const finding = risk.confidence >= 80 ? await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk) : null;
      await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, risk);
      await this.sendInteractiveReply(chatId, formatScanReply({ target, risk, eventId: event.id, findingId: finding?.id }), this.scanKeyboard(message.from?.id || message.from?.username || '', target, event.id), { reply_to_message_id: message.message_id });
      return;
    }

    if (isCommand(text, 'report')) {
      if (await this.rejectNonOwnerPrivateReport(message)) return;
      const reportEvidence = forwardedEvidenceText(message);
      const reportText = [this.commandText(message, 'report'), reportEvidence].filter(Boolean).join('\n');
      if (screenshotFileIds(message).length || message.forward_from || message.forward_sender_name || message.forward_from_chat || (DM_REPORT_RE.test(reportEvidence) && /\b(?:impersonat|pretend|fake|unsolicited|support|admin)\b/i.test(reportEvidence))) {
        await this.handleDmReport(message, reportText);
        return;
      }
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
        report_decision: 'needs_admin_review',
        original_report_decision: reportDecision.decision,
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
          `report decision: needs_admin_review (original ${reportDecision.decision}: ${reportDecision.reason})`
        ].filter(Boolean)
      };
      if (!reportDecision.accepted || reportDecision.decision !== 'accepted') {
        const event = await this.record(reportDecision.decision === 'weak' ? 'report_review_needed' : 'report_rejected', { ...message, from: target }, reportPayload, { writeDkg: false });
        if (reportDecision.decision === 'weak') await this.recordConversationArtifact({ ...message, from: target }, { risk: reportPayload, text: targetText || evidenceText(message), artifactKind: 'weak_report_observation', conversationRole: 'reporter', sourceEventIds: [event.id] });
        await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, reportPayload);
        await this.sendCommandReply(chatId, formatReportReply(event, reportDecision), { reply_to_message_id: message.message_id });
        return;
      }
      const event = await this.record('report_review_needed', { ...message, from: target }, reportPayload, { writeDkg: false });
      await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, reportPayload);
      await this.recordConversationArtifact({ ...message, from: target }, { risk: reportPayload, text: targetText || evidenceText(message), artifactKind: 'report_review_observation', conversationRole: 'reporter', sourceEventIds: [event.id] });
      await this.sendCommandReply(chatId, formatReportReply(event, reportDecision), { reply_to_message_id: message.message_id });
      return;
    }
    if (isCommand(text, 'mute')) {
      await this.handleMuteCommand(message);
      return;
    }
    if (isCommand(text, 'ban')) {
      const { target, text: targetText } = this.resolveCommandTarget(message, 'ban');
      const replyUser = target?.id ? target : message.reply_to_message?.from;
      if (!await this.isTrustedModerator(message)) {
        const event = await this.record('ban_rejected_unauthorized', { ...message, from: target }, {
          reason: 'manual /ban rejected because requester is not a configured admin or Telegram chat admin',
          requester: actorFromMessage(message),
          evidence: ['manual /ban requires trusted moderator privileges']
        }, { writeDkg: false });
        await this.sendEphemeral(chatId, `⚠️ /ban is restricted to configured admins or Telegram chat admins. Request logged locally as ${event.id}.`, { reply_to_message_id: message.message_id });
        return;
      }

      this.sendTyping(chatId);
      await this.sendEphemeral(chatId, 'Processing ban request…', { reply_to_message_id: message.message_id });

      if (!replyUser?.id) {
        const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
        const event = await this.record('ban_requested_no_reply', { ...message, from: target }, {
          ...risk,
          evidence: [...risk.evidence, 'manual /ban requested without a replied Telegram user ID']
        });
        await this.sendEphemeral(chatId, `⚠️ I can scan or report ${target.label || target.username || 'that target'}, but Telegram needs you to reply to the exact user's message before I can ban them. I saved the evidence for admin review.`, { reply_to_message_id: message.message_id });
        return;
      }
      const reason = this.commandReason(message, 'ban', 'admin requested ban');
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
      const replyMessageId = message.reply_to_message?.message_id;
      let repliedMessageDeleted = false;
      let repliedMessageDeleteError = '';
      // Auto-delete of the replied scam message disabled during testing period
      // (except for join challenge flows which keep their own deletion logic)
      repliedMessageDeleted = false;
      repliedMessageDeleteError = 'auto-delete disabled during testing';
      await this.ban(chatId, replyUser.id);
      await this.sendCommandReply(chatId, `${formatBanReply(replyUser, '')} ${repliedMessageDeleted ? 'Removed the replied scam message.' : replyMessageId ? 'Could not remove the replied message.' : 'No replied message to remove.'} DKG evidence logging is continuing.`, { reply_to_message_id: message.message_id });
      const event = await this.record('ban_executed', { ...message, from: replyUser }, {
        ...risk,
        reason,
        replied_message_id: replyMessageId || '',
        replied_message_deleted: repliedMessageDeleted,
        replied_message_delete_error: repliedMessageDeleteError,
        confidence: Math.max(risk.confidence, this.config.actionThreshold || 85),
        admin_verified: true,
        scam_type: risk.scam_type || 'admin_action',
        evidence: [...risk.evidence, reason, replyUser.sangmata?.evidence || '', repliedMessageDeleted ? 'replied scam message deleted' : replyMessageId ? 'replied scam message deletion unavailable' : '', 'manual /ban command'].filter(Boolean)
      });
      await this.maybeRecordCampaign({ ...message, from: replyUser, text: context }, risk);
    }
  }

  async handleMentionReplyScan(message) {
    if (!this.isBotMentionReplyScan(message)) return false;
    if (await this.rejectNonOwnerPrivateReport(message)) return true;
    const targetMessage = message.reply_to_message;
    const target = sangmataTargetFromText(targetMessage.text || '') || actorFromMessage(targetMessage);
    const targetText = messageText(targetMessage) || messageText(message);
    const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
    const event = await this.record('risk_query', { ...message, from: target, text: targetText }, risk);
    await this.recordConversationArtifact({ ...message, from: target }, { risk, text: targetText, artifactKind: 'safety_question', conversationRole: 'questioner', sourceEventIds: [event.id] });
    const finding = risk.confidence >= 80 ? await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk) : null;
    await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, risk);
    await this.sendInteractiveReply(message.chat.id, formatScanReply({ target, risk, eventId: event.id, findingId: finding?.id }), this.replyScanKeyboard(message.from?.id || message.from?.username || '', target, event.id), { reply_to_message_id: message.message_id });
    return true;
  }

  challengeKey(chatId, userId) {
    return `${chatId}:${userId}`;
  }

  markJoinChallengeSolved(chatId, userId) {
    const key = this.challengeKey(chatId, userId);
    this.solvedJoinChallenges.set(key, Date.now() + SOLVED_JOIN_CHALLENGE_TTL_MS);
    return key;
  }

  wasJoinChallengeRecentlySolved(chatId, userId) {
    const key = this.challengeKey(chatId, userId);
    const expiresAt = this.solvedJoinChallenges.get(key) || 0;
    if (expiresAt <= Date.now()) {
      this.solvedJoinChallenges.delete(key);
      return false;
    }
    return true;
  }

  async challengeText(chatId, member) {
    const ttl = this.config.joinChallengeTtlSeconds || 60;
    const username = await this.botUsername().catch(() => 'tracethembot');
    const dmLink = `https://t.me/${username}?start=${verifyStartPayload(chatId, member.id)}`;
    const qa = this.selectJoinChallengeQa(chatId, member);
    if (qa) {
      return [
        '🛡️ TRACaBot',
        '',
        `${userMention(member)}, quick check before posting:`,
        '',
        `1. Open this Knowledge Asset: ${qa.assetUrl}`,
        `2. Answer: ${escapeHtml(qa.question)}`,
        `3. DM the answer to me: ${dmLink}`,
        '',
        'A Knowledge Asset is a verifiable data item on the Decentralized Knowledge Graph. This one explains TRACaBot in plain language.',
        '',
        `You are restricted here until verified. Time limit: ${ttl}s.`
      ].join('\n');
    }
    return [
      '🛡️ TRACaBot',
      '',
      `${userMention(member)}, quick check before posting:`,
      '',
      '1. Go to https://dkg.origintrail.io/',
      '2. Copy any Knowledge Asset address shown there. It starts with did:dkg:',
      `3. Send that address to me in DM: ${dmLink}`,
      '',
      `You are restricted here until verified. Time limit: ${ttl}s.`
    ].join('\n');
  }

  ualChallengeEducationText() {
    return [
      'You shared a did:dkg: address, which points to verifiable knowledge AI agents can use, remember, and trust.',
      '',
      'TRACaBot agent uses this shared knowledge to help agents verify information together and catch scammers across communities.',
      '',
      'Shared memory that agents can verify and reuse is the future of trusted, decentralized AI.',
      '',
      'For more information: https://x.com/BranaRakic/status/2040159452431560995'
    ].join('\n');
  }

  async startJoinChallenge(message, member) {
    const chatId = message.chat.id;
    if (!await this.hasRestrictRights(chatId)) {
      await this.record('join_challenge_skipped_no_admin', { ...message, from: member }, {
        target: member,
        target_key: targetKey(member),
        evidence: ['join challenge skipped because TRACaBot is not a Telegram group admin with restriction rights']
      }, { writeDkg: false });
      return false;
    }
    const expiresAt = Date.now() + (this.config.joinChallengeTtlSeconds || 60) * 1000;
    const key = this.challengeKey(chatId, member.id);
    const qa = this.selectJoinChallengeQa(chatId, member);
    const challenge = { chat: message.chat, user: member, startedAt: Date.now(), expiresAt, messageId: '', attempts: 0, mode: qa ? 'qa' : 'ual', qa, restricted: false };
    this.joinChallenges.set(key, challenge);
    let restricted = false;
    try {
      await this.restrict(chatId, member.id, Math.floor(expiresAt / 1000));
      restricted = true;
      challenge.restricted = true;
      const sent = await this.send(chatId, await this.challengeText(chatId, member), { parse_mode: 'HTML', disable_web_page_preview: true });
      challenge.messageId = sent?.message_id || '';
    } catch (error) {
      this.joinChallenges.delete(key);
      if (restricted) await this.restoreMemberPermissions(chatId, member.id).catch(() => null);
      await this.record('join_challenge_start_failed', { ...message, from: member }, {
        target: member,
        target_key: targetKey(member),
        error: error instanceof Error ? error.message : String(error),
        restricted_text_only: restricted,
        evidence: ['join challenge could not be started safely; restrictions were not left without an active challenge']
      }, { writeDkg: false });
      return false;
    }
    await this.record('join_challenge_started', { ...message, from: member }, {
      target: member,
      target_key: targetKey(member),
      alias_keys: challengeAliasSignals(member),
      challenge_type: qa ? 'dkg_asset_qa' : 'dkg_ual',
      challenge_id: qa?.id || '',
      ttl_seconds: this.config.joinChallengeTtlSeconds || 60,
      restricted_text_only: restricted,
      evidence: [qa ? 'new user asked to answer a DKG Knowledge Asset question' : 'new user asked to verify with a DKG Knowledge Asset UAL']
    }, { writeDkg: false });
  }

  selectJoinChallengeQa(chatId, member = {}) {
    if (this.config.joinChallengeMode === 'ual') return null;
    if (!this.config.joinChallengeAssetUrl || !Array.isArray(this.config.joinChallengeQaBank) || this.config.joinChallengeQaBank.length === 0) return null;
    const bucket = Math.floor(Date.now() / Math.max(1, (this.config.joinChallengeTtlSeconds || 60) * 1000));
    const seed = `${chatId}:${member.id}:${bucket}`;
    let hash = 0;
    for (const char of seed) hash = ((hash * 31) + char.charCodeAt(0)) >>> 0;
    const entry = this.config.joinChallengeQaBank[hash % this.config.joinChallengeQaBank.length];
    return { ...entry, assetUrl: this.config.joinChallengeAssetUrl };
  }

  pendingChallengeFor(message) {
    if (!message.from?.id || !message.chat?.id) return null;
    return this.joinChallenges.get(this.challengeKey(message.chat.id, message.from.id));
  }

  pendingDmChallengeFor(userId) {
    for (const [key, challenge] of this.joinChallenges.entries()) {
      if (String(challenge.user?.id) === String(userId)) return { key, challenge };
    }
    return null;
  }

  async sendJoinChallengeDmIntro(message) {
    const payload = parseVerifyStartPayload(this.commandText(message, 'start'));
    if (!payload || String(payload.userId) !== String(message.from?.id)) {
      await this.send(message.chat.id, 'I could not match this verification link to your Telegram account. Please use the link TRACaBot posted for you in the group.');
      return true;
    }
    const challenge = this.joinChallenges.get(this.challengeKey(payload.chatId, payload.userId));
    if (!challenge) {
      await this.send(message.chat.id, 'I do not see an active DKG join challenge for you. If you just joined, ask an admin to restart the challenge or try rejoining.');
      return true;
    }
    if (challenge.mode === 'qa') {
      await this.send(message.chat.id, `Open the Knowledge Asset from the group challenge, then answer this question here:\n\n${challenge.qa?.question || 'What does the asset ask?'}`);
    } else {
      await this.send(message.chat.id, 'Paste the Knowledge Asset address here. It should start with did:dkg:. I will verify it and unlock your group access.');
    }
    return true;
  }

  async handleJoinChallengeDm(message) {
    if (message.chat?.type !== 'private') return false;
    const pending = this.pendingDmChallengeFor(message.from?.id);
    if (!pending) return false;
    await this.handleJoinChallengeMessage({ ...message, chat: pending.challenge.chat }, pending.challenge, { sourceChatId: message.chat.id, dm: true });
    return true;
  }

  async applyJoinChallengeFailureAction(challenge, reason = 'max_attempts') {
    const action = this.config.joinChallengeAction || 'kick';
    if (!await this.hasRestrictRights(challenge.chat.id)) return false;
    if (action === 'ban') {
      await this.ban(challenge.chat.id, challenge.user.id).catch(() => null);
      return true;
    }
    if (action === 'kick') {
      await this.ban(challenge.chat.id, challenge.user.id)
        .then(() => this.call('unbanChatMember', { chat_id: challenge.chat.id, user_id: challenge.user.id, only_if_banned: true }))
        .catch(() => null);
      return true;
    }
    if (action === 'mute') {
      const restrictedUntil = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
      await this.allowTextOnly(challenge.chat.id, challenge.user.id, restrictedUntil).catch(() => null);
      return true;
    }
    return Boolean(reason);
  }

  async maybeFailJoinChallenge(message, challenge, options = {}) {
    const maxAttempts = this.config.joinChallengeMaxAttempts || 3;
    if (challenge.attempts < maxAttempts) return false;
    const chatId = challenge.chat.id;
    this.joinChallenges.delete(this.challengeKey(chatId, challenge.user.id));
    const actionApplied = await this.applyJoinChallengeFailureAction(challenge, 'max_attempts');
    const event = await this.record('join_challenge_failed_max_attempts', { ...message, chat: challenge.chat, from: challenge.user }, {
      target: challenge.user,
      target_key: targetKey(challenge.user),
      alias_keys: challengeAliasSignals(challenge.user),
      action: this.config.joinChallengeAction || 'kick',
      action_applied: actionApplied,
      attempts: challenge.attempts,
      max_attempts: maxAttempts,
      verification_channel: options.dm ? 'dm' : 'group',
      evidence: [`new user failed DKG join challenge after ${challenge.attempts} attempts`]
    }, { writeDkg: false });
    await this.maybeRecordJoinChallengeRepeatFailure({ ...message, chat: challenge.chat, from: challenge.user }, event);
    if (challenge.messageId && await this.hasDeleteRights(chatId)) await this.deleteMessage(chatId, challenge.messageId).catch(() => null);
    await this.sendEphemeral(chatId, `${userMention(challenge.user)} did not complete DKG verification after ${challenge.attempts} attempts.`, { parse_mode: 'HTML', autoDelete: true }, this.config.successMessageTtlSeconds || 45).catch(() => null);
    if (options.dm && options.sourceChatId) await this.send(options.sourceChatId, 'Verification failed too many times. Ask a group admin to reset your access.', { private: true }).catch(() => null);
    return true;
  }

  async handleJoinChallengeMessage(message, challenge, options = {}) {
    const text = String(message.text || '').trim();
    const chatId = message.chat.id;
    const replyChatId = options.sourceChatId || chatId;
    const key = this.challengeKey(chatId, message.from.id);
    const shouldRemindInGroup = !options.dm && !challenge.groupReminderSent;
    if (!options.dm) {
      challenge.attempts += 1;
      if (this.config.joinChallengeDeleteBadAttempts !== false && await this.hasDeleteRights(chatId)) {
        await this.deleteMessage(chatId, message.message_id).catch(() => null);
      }
      await this.record('join_challenge_bad_attempt', message, {
        target: message.from,
        target_key: targetKey(message.from),
        alias_keys: challengeAliasSignals(message.from),
        attempts: challenge.attempts,
        challenge_type: challenge.mode === 'qa' ? 'dkg_asset_qa' : 'dkg_ual',
        challenge_id: challenge.qa?.id || '',
        verification_channel: 'group',
        evidence: ['pending join challenge user tried to answer in group instead of DM verification link']
      }, { writeDkg: false });
      if (await this.maybeFailJoinChallenge(message, challenge, options)) return true;
      if (shouldRemindInGroup) {
        challenge.groupReminderSent = true;
        const username = await this.botUsername().catch(() => 'tracethembot');
        const dmLink = `https://t.me/${username}?start=${verifyStartPayload(chatId, message.from.id)}`;
        await this.sendEphemeral(replyChatId, `${userMention(message.from)}, verification only works in DM. Use your verification link: ${dmLink}`, { reply_to_message_id: challenge.messageId || message.message_id, parse_mode: 'HTML', disable_web_page_preview: true, autoDelete: true }, this.config.challengeMessageTtlSeconds || 120);
      }
      return true;
    }
    if (challenge.mode === 'qa') {
      const normalized = normalizeChallengeAnswer(text);
      const accepted = (challenge.qa?.answers || []).map(normalizeChallengeAnswer).filter(Boolean);
      if (!accepted.includes(normalized)) {
        challenge.attempts += 1;
        if (this.config.joinChallengeDeleteBadAttempts !== false && !options.dm && await this.hasDeleteRights(chatId)) {
          await this.deleteMessage(chatId, message.message_id).catch(() => null);
        }
        await this.record('join_challenge_bad_attempt', message, {
          target: message.from,
          target_key: targetKey(message.from),
          alias_keys: challengeAliasSignals(message.from),
          attempts: challenge.attempts,
          challenge_type: 'dkg_asset_qa',
          challenge_id: challenge.qa?.id || '',
          verification_channel: options.dm ? 'dm' : 'group',
          evidence: ['pending join challenge user sent an incorrect DKG asset answer']
        }, { writeDkg: false });
        if (await this.maybeFailJoinChallenge(message, challenge, options)) return true;
        const invalidText = `${options.dm ? '' : `${userMention(message.from)}, `}that answer did not match this DKG challenge. Open the Knowledge Asset again and answer: ${escapeHtml(challenge.qa?.question || 'the posted question')}`;
        if (options.dm) await this.send(replyChatId, invalidText, { disable_web_page_preview: true, private: true, parse_mode: 'HTML' });
        else if (shouldRemindInGroup) {
          challenge.groupReminderSent = true;
          await this.sendEphemeral(replyChatId, invalidText, { reply_to_message_id: challenge.messageId || message.message_id, parse_mode: 'HTML', disable_web_page_preview: true, autoDelete: true }, this.config.challengeMessageTtlSeconds || 120);
        }
        return true;
      }
      return this.completeJoinChallenge(message, challenge, options, { answer: normalized, validationReason: 'qa_answer_match' });
    }
    if (!DKG_UAL_RE.test(text)) {
      challenge.attempts += 1;
      if (this.config.joinChallengeDeleteBadAttempts !== false && await this.hasDeleteRights(chatId)) {
        await this.deleteMessage(chatId, message.message_id).catch(() => null);
      }
      await this.record('join_challenge_bad_attempt', message, {
        target: message.from,
        target_key: targetKey(message.from),
        alias_keys: challengeAliasSignals(message.from),
        attempts: challenge.attempts,
        verification_channel: options.dm ? 'dm' : 'group',
        evidence: ['pending join challenge user sent an invalid Knowledge Asset address first message']
      }, { writeDkg: false });
      if (await this.maybeFailJoinChallenge(message, challenge, options)) return true;
      const reminderText = `${options.dm ? '' : `${userMention(message.from)}, `}paste a Knowledge Asset address that starts with did:dkg: to complete verification.`;
      if (options.dm) await this.send(replyChatId, reminderText, { private: true });
      else if (shouldRemindInGroup) {
        challenge.groupReminderSent = true;
        await this.sendEphemeral(replyChatId, reminderText, { reply_to_message_id: challenge.messageId || message.message_id, parse_mode: 'HTML', autoDelete: true }, this.config.challengeMessageTtlSeconds || 120);
      }
      return true;
    }
    const validation = this.config.joinChallengeDkgValidate === false ? { ok: true, reason: 'format_only' } : await this.dkg.validateUal(text);
    if (!validation.ok) {
      challenge.attempts += 1;
      if (this.config.joinChallengeDeleteBadAttempts !== false && await this.hasDeleteRights(chatId)) {
        await this.deleteMessage(chatId, message.message_id).catch(() => null);
      }
      await this.record('join_challenge_bad_attempt', message, {
        target: message.from,
        target_key: targetKey(message.from),
        alias_keys: challengeAliasSignals(message.from),
        attempts: challenge.attempts,
        ual: text.slice(0, 240),
        validation_reason: validation.reason,
        verification_channel: options.dm ? 'dm' : 'group',
        evidence: ['pending join challenge user sent a Knowledge Asset address that did not validate on DKG']
      }, { writeDkg: false });
      if (await this.maybeFailJoinChallenge(message, challenge, options)) return true;
      const invalidText = `${options.dm ? '' : `${userMention(message.from)}, `}I could not validate that Knowledge Asset address. Try another one from https://dkg.origintrail.io/.`;
      if (options.dm) await this.send(replyChatId, invalidText, { disable_web_page_preview: true, private: true });
      else if (shouldRemindInGroup) {
        challenge.groupReminderSent = true;
        await this.sendEphemeral(replyChatId, invalidText, { reply_to_message_id: message.message_id, parse_mode: 'HTML', disable_web_page_preview: true, autoDelete: true }, this.config.challengeMessageTtlSeconds || 120);
      }
      return true;
    }
    return this.completeJoinChallenge(message, challenge, options, { ual: text.slice(0, 240), validationReason: validation.reason });
  }

  async completeJoinChallenge(message, challenge, options = {}, result = {}) {
    const chatId = message.chat.id;
    const replyChatId = options.sourceChatId || chatId;
    const key = this.challengeKey(chatId, message.from.id);
    this.joinChallenges.delete(key);
    this.markJoinChallengeSolved(chatId, message.from.id);
    if (await this.hasRestrictRights(chatId)) await this.restoreMemberPermissions(chatId, message.from.id).catch(() => null);
    if (this.config.joinChallengeDeleteOnPass !== false && await this.hasDeleteRights(chatId)) {
      if (!options.dm) await this.deleteMessage(chatId, message.message_id).catch(() => null);
      if (challenge.messageId) await this.deleteMessage(chatId, challenge.messageId).catch(() => null);
    }
    await this.record('join_challenge_solved', message, {
      target: message.from,
      target_key: targetKey(message.from),
      alias_keys: challengeAliasSignals(message.from),
      ual: result.ual || '',
      answer: result.answer || '',
      validation_reason: result.validationReason || '',
      challenge_type: challenge.mode === 'qa' ? 'dkg_asset_qa' : 'dkg_ual',
      challenge_id: challenge.qa?.id || '',
      verification_channel: options.dm ? 'dm' : 'group',
      evidence: [challenge.mode === 'qa' ? 'new user answered the DKG Knowledge Asset challenge' : 'new user completed DKG Knowledge Asset UAL verification']
    }, { writeDkg: false });
    if (options.dm) {
      const accessLink = await this.groupAccessLink(challenge.chat);
      const accessText = accessLink ? `\n\nReturn to the community: ${accessLink}` : '';
      const ualEducation = challenge.mode === 'ual' ? `\n\n${this.ualChallengeEducationText()}` : '';
      await this.send(replyChatId, `✅ You’re in.${ualEducation}${accessText}`, { disable_web_page_preview: true });
    }
    const successText = `✅ DKG-verified: ${userMention(message.from)}\n\nYou are now on TRAC(k) and protected by our DKG-powered agent with cross-community, persistent memory against scams and impersonators.`;
    if (options.dm) await this.sendEphemeral(chatId, successText, { parse_mode: 'HTML' }, this.config.successMessageTtlSeconds || 45);
    else await this.sendEphemeral(chatId, successText, { reply_to_message_id: message.message_id, parse_mode: 'HTML' }, this.config.successMessageTtlSeconds || 45);
    return true;
  }

  async handleCallbackQuery(query = {}) {
    const parsed = parseCallbackData(query.data || '');
    if (!parsed) return false;
    const message = query.message || {};
    const chatId = message.chat?.id;
    const from = query.from || {};
    const requester = parsed.parts[0] || '';
    const eventId = parsed.parts[1] || '';
    const callbackMessage = { chat: message.chat, from, message_id: message.message_id, text: '' };
    const trusted = await this.isTrustedModerator(callbackMessage).catch(() => false);
    if (parsed.action === 'close') {
      if (requester && String(from.id || from.username || '') !== String(requester) && !trusted) {
        await this.answerCallback(query.id, 'Open your own panel to close it.');
        return true;
      }
      await this.answerCallback(query.id);
      await this.call('deleteMessage', { chat_id: chatId, message_id: message.message_id }).catch(async () => {
        await this.editInteractiveMessage(chatId, message.message_id, 'Closed.', [], {});
      });
      return true;
    }
    if (requester && String(from.id || from.username || '') !== String(requester) && !(trusted && parsed.action.startsWith('review-'))) {
      await this.answerCallback(query.id, 'Open your own panel to use these buttons.');
      return true;
    }
    if (!trusted && parsed.action.startsWith('review-')) {
      await this.answerCallback(query.id, 'Admin only');
      return true;
    }
    await this.answerCallback(query.id);

    if (parsed.action === 'dashboard') {
      await this.editInteractiveMessage(chatId, message.message_id, this.formatHelp(), this.dashboardKeyboard(requester));
      return true;
    }

    if (parsed.action === 'settings') {
      if (!trusted) {
        await this.answerCallback(query.id, 'Admin only');
        return true;
      }
      await this.editInteractiveMessage(chatId, message.message_id, this.settingsText(chatId), this.settingsKeyboard(requester, chatId));
      return true;
    }

    if (parsed.action === 'review-list') {
      await this.editInteractiveMessage(chatId, message.message_id, this.formatReviewPanel('flags'), this.reviewPanelKeyboard(requester, 'flags'), { parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (parsed.action === 'review-tab') {
      if (!trusted) {
        await this.answerCallback(query.id, 'Admin only');
        return true;
      }
      const filter = parsed.parts[1] || 'flags';
      await this.editInteractiveMessage(chatId, message.message_id, this.formatReviewPanel(filter), this.reviewPanelKeyboard(requester, filter), { parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (['stats', 'stats-sources', 'campaigns', 'banlist', 'status', 'challenge-set', 'conversation-set', 'help', 'help-scan', 'why'].includes(parsed.action)) {
      if (requester && String(from.id || from.username || '') !== String(requester)) {
        await this.answerCallback(query.id, 'Open your own panel to use these buttons.');
        return true;
      }
      if (parsed.action === 'stats' || parsed.action === 'stats-sources') {
        const stats = await this.dkg.getStats(7);
        const text = parsed.action === 'stats-sources' ? formatStatsSourcesReply(stats) : this.formatStatsDashboard(stats);
        await this.editInteractiveMessage(chatId, message.message_id, text, this.statsKeyboard(requester));
        return true;
      }
      if (parsed.action === 'campaigns') {
        await this.editInteractiveMessage(chatId, message.message_id, this.formatCampaigns(), this.statsKeyboard(requester));
        return true;
      }
      if (parsed.action === 'banlist') {
        if (!trusted) {
          await this.answerCallback(query.id, 'Admin only');
          return true;
        }
        await this.editInteractiveMessage(chatId, message.message_id, await this.formatBanlist(), this.banlistKeyboard(requester), { parse_mode: 'HTML', disable_web_page_preview: true });
        return true;
      }
      if (parsed.action === 'status') {
        if (!trusted) {
          await this.answerCallback(query.id, 'Admin only');
          return true;
        }
        await this.editInteractiveMessage(chatId, message.message_id, await this.formatStatus(callbackMessage), this.settingsKeyboard(requester, chatId));
        return true;
      }
      if (parsed.action === 'challenge-set' || parsed.action === 'conversation-set') {
        if (!trusted) {
          await this.answerCallback(query.id, 'Admin only');
          return true;
        }
        const value = parsed.parts[1] || 'status';
        const setting = parsed.action === 'challenge-set' ? 'join_challenge_setting_changed' : 'conversational_setting_changed';
        if (value === 'on' || value === 'off') {
          await this.record(setting, callbackMessage, { enabled: value === 'on', moderator: from, evidence: [`admin turned ${parsed.action === 'challenge-set' ? 'new-user join challenge' : 'conversation mode'} ${value}`] }, { writeDkg: false });
        }
        await this.editInteractiveMessage(chatId, message.message_id, this.settingsText(chatId), this.settingsKeyboard(requester, chatId));
        return true;
      }
      if (parsed.action === 'help' || parsed.action === 'help-scan') {
        await this.editInteractiveMessage(chatId, message.message_id, this.formatMenuHelp(), this.mainNavKeyboard(requester));
        return true;
      }
      if (parsed.action === 'why') {
        await this.editInteractiveMessage(chatId, message.message_id, this.formatWhy(parsed.parts[1] || ''), this.statsKeyboard(requester));
        return true;
      }
    }
    if (parsed.action === 'review-open') {
      const event = this.findEvent(eventId);
      if (!event) {
        await this.answerCallback(query.id, 'Review item not found');
        return true;
      }
      if (!this.isPendingReviewEvent(event)) {
        await this.answerCallback(query.id, 'Already reviewed or expired');
        return true;
      }
      await this.editInteractiveMessage(chatId, message.message_id, this.formatReviewDetail(event), this.reviewActionKeyboard(requester, event.id), { parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (parsed.action === 'review-confirm' || parsed.action === 'review-reject') {
      const event = this.findEvent(eventId);
      if (!event) return true;
      if (!this.isPendingReviewEvent(event)) {
        await this.answerCallback(query.id, 'Already reviewed or expired');
        return true;
      }
      const finalDecision = parsed.action === 'review-confirm' ? 'confirm' : 'reject';
      const reason = finalDecision === 'confirm' ? 'admin confirmed scam flag' : 'admin rejected scam flag as false positive';
      const reviewEvent = await this.record(finalDecision === 'confirm' ? 'review_upheld' : 'review_overturned', callbackMessage, {
        target_event_id: event.id,
        review_decision: finalDecision === 'confirm' ? 'confirmed' : 'rejected',
        reason,
        reviewer: from,
        reviewed_target: event.user || event.payload?.target || {},
        reviewed_target_key: targetKey(event.user || event.payload?.target || {}),
        ...this.reviewTrustPayload(from),
        false_positive_reason: finalDecision === 'reject' ? reason : '',
        evidence: [`admin callback ${finalDecision === 'confirm' ? 'confirmed scam flag' : 'rejected scam flag'} ${event.id}: ${reason}`]
      });
      await this.editInteractiveMessage(chatId, message.message_id, `${finalDecision === 'confirm' ? '🚫 Confirmed scam.' : '✅ Rejected flag as false positive.'}\n\nSaved review event: ${reviewEvent.id}`, [[button('↩️ Back to queue', callbackData('review-list', requester)), button('❔ Explain', callbackData('why', requester, shortId(reviewEvent.id))), button('✖️ Close', callbackData('close', requester))]], { parse_mode: 'HTML' });
      return true;
    }
    return false;
  }

  async handleMessage(message) {
    this.rememberSeenChat(message.chat || {});
    if (message.new_chat_members?.length) {
      await this.handleNewMembers(message);
      return;
    }
    const fullMessageText = messageText(message);
    if (!fullMessageText && !(message.forward_from || message.forward_sender_name || message.forward_from_chat)) return;
    if (message.chat?.type === 'private' && /^\/start\s+verify_/i.test(message.text)) {
      await this.sendJoinChallengeDmIntro(message);
      return;
    }
    if (await this.handleJoinChallengeDm(message)) return;
    const challenge = this.pendingChallengeFor(message);
    if (challenge) {
      await this.handleJoinChallengeMessage(message, challenge);
      return;
    }
    if (String(message.text || '').startsWith('/')) {
      await this.handleCommand(message);
      return;
    }
    if (this.isDmReportMention(message)) {
      if (await this.rejectNonOwnerPrivateReport(message)) return;
      await this.handleDmReport(message, evidenceText(message));
      return;
    }
    if (await this.handleMentionReplyScan(message)) return;
    if (this.isBareBotMention(message)) return;
    if (await this.handleAlertReply(message)) return;
    if (this.isNaturalFalsePositiveReview(message) && await this.handleNaturalFalsePositiveReview(message)) return;
    if (await this.handleNaturalLanguageRequest(message)) return;
    if (this.isRiskQuery(message)) {
      if (await this.rejectNonOwnerPrivateReport(message)) return;
      const targetMessage = message.reply_to_message || message;
      const explicitNamedTarget = this.targetFromSafetyQuestion(message);
      if (!message.reply_to_message && !this.targetFromMention(message) && !explicitNamedTarget && /\b(?:is|are)\s+(?!(?:this|that|it|he|she|they|them|him|her|me|i)\b)[\p{L}\p{N}_-]{2,32}\s+(?:a\s+|an\s+)?(?:legit(?:imate)?|safe|unsafe|real|fake|scam(?:mer|ming)?|fraud(?:ster)?|risky?|trusted|trustworthy|blacklisted|flagged|suspicious|sus|dangerous|malicious)\b/iu.test(String(message.text || '').replace(/@(?:tracabot|tracethembot)\b/ig, ' '))) {
        await this.sendEphemeral(message.chat.id, 'I cannot identify that user from a display name alone. Reply to one of their messages and ask “is this a scam?” so I can check the actual Telegram account.', { reply_to_message_id: message.message_id });
        return;
      }
      const target = this.targetFromMention(message) || explicitNamedTarget || sangmataTargetFromText(targetMessage.text || '') || actorFromMessage(targetMessage);
      const targetEvidenceText = [fullMessageText, messageText(targetMessage)].filter(Boolean).join('\n');
      const risk = await this.assess({ ...message, from: target, text: targetEvidenceText }, target, targetEvidenceText);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      await this.recordConversationArtifact({ ...message, from: target }, { risk, text: `${message.text}\n${targetMessage.text || ''}`, artifactKind: 'safety_question', conversationRole: 'questioner', sourceEventIds: [event.id] });
      const finding = this.canPublishFindingFromRisk(risk) ? await this.publishHighConfidenceFinding({ ...message, from: target }, risk) : null;
      await this.maybeRecordCampaign({ ...message, from: target }, risk);
      const conversational = await this.conversationReply(message, target, risk, event, true);
      if (conversational) await this.send(message.chat.id, conversational, { reply_to_message_id: message.message_id });
      return;
    }
    if (this.isPrivateOwnerMessage(message)) {
      const target = sangmataTargetFromText(message.text || '');
      if (target) {
        const targetText = message.text || '';
        const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
        const event = await this.record('report_submitted', { ...message, from: target, text: targetText }, {
          ...risk,
          reporter: actorFromMessage(message),
          target_key: targetKey(target),
          report_decision: 'accepted',
          report_reason: 'bot owner private SangMata report',
          report_outcome: risk.confidence >= 80 ? 'high_confidence_dkg_report' : 'accepted_dkg_report',
          evidence: [...(risk.evidence || []), target.sangmata?.evidence, 'bot owner submitted private SangMata report'].filter(Boolean)
        });
        const finding = this.canPublishFindingFromRisk(risk) ? await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk) : null;
        await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, risk);
        await this.send(message.chat.id, formatScanReply({ target, risk, eventId: event.id, findingId: finding?.id }), { reply_to_message_id: message.message_id });
        return;
      }
    }
    if (message.chat?.type === 'private') return;
    const user = actorFromMessage(message);
      const risk = await this.assess({ ...message, text: fullMessageText }, user, fullMessageText);
    const passiveLowRisk = !this.isDirectlyAddressed(message) && risk.confidence < (this.config.warnThreshold ?? 60);
    if (risk.confidence < this.config.actionThreshold) {
      await this.record('risk_check', message, risk);

      // Phase 3: Consult artefact curator (via skill) — now graph-aware (DKG Context Graph prior admin history)
      const svc = (() => { try { return TracabotSkillService.fromEnv(); } catch { return null; } })();
      let curatorDecision = null;
      if (!passiveLowRisk && svc) {
        curatorDecision = await svc.decideArtefactAction({
          telegramUserId: message.from?.id,
          username: message.from?.username,
          text: message.text,
          artifactKind: 'tactic_candidate'
        }).catch(() => null);
      }

      await this.recordConversationArtifact(message, {
        risk,
        text: message.text,
        artifactKind: 'tactic_candidate',
        conversationRole: 'observer'
      });

      // If the (now graph-aware) curator recommends admin review for this low-confidence artefact, queue it
      if (curatorDecision && curatorDecision.recommendation === 'queue_for_admin_review') {
        await this.record('risk_review_needed', message, {
          ...risk,
          artifact_kind: 'tactic_candidate',
          curator_recommendation: curatorDecision.recommendation,
          curator_reasoning: curatorDecision.reasoning,
          graph_history: curatorDecision.graph_history || null,
          recommended_action: 'admin_review',
          evidence: [...(risk.evidence || []), 'artefact curator (graph-aware) recommended admin review']
        }, { writeDkg: false });
      }

      await this.recordBenignConversationFlow(message, risk);
      await this.recordChannelObservation(message, risk);
      if (passiveLowRisk) return;
    }
    if (risk.confidence >= (this.config.warnThreshold ?? 60)) {
      await this.record('scam_detection', message, risk);
      await this.recordChannelObservation(message, risk);
      await this.maybeRecordCampaign(message, risk);
    }
    if (risk.confidence >= (this.config.restrictThreshold ?? this.config.actionThreshold)) {
      await this.applyRiskAction(message, risk);
      return;
    }
  }

  async handleNewMembers(message) {
    for (const member of message.new_chat_members) {
      const botId = await this.getBotId().catch(() => null);
      if (member.is_bot === true || (botId && String(member.id) === String(botId))) continue;
      const joinMessage = { ...message, from: member, text: `new member joined @${member.username || member.id}` };
      this.rememberUser(message.chat, member, joinMessage.text);
      const risk = await this.assess(joinMessage, member, joinMessage.text);
      if (risk.confidence >= (this.config.restrictThreshold ?? this.config.actionThreshold)) {
        await this.applyRiskAction(joinMessage, risk);
      } else if (this.chatJoinChallengeEnabled(message.chat.id)) {
        await this.startJoinChallenge(message, member);
      } else {
        await this.applyRiskAction(joinMessage, risk);
      }
    }
  }

  async handleChatMemberUpdate(chatMemberUpdate) {
    const oldStatus = chatMemberUpdate.old_chat_member?.status || '';
    const newStatus = chatMemberUpdate.new_chat_member?.status || '';
    const member = chatMemberUpdate.new_chat_member?.user;
    if (!member || member.is_bot) return;
    const key = this.challengeKey(chatMemberUpdate.chat?.id, member.id);
    if (['left', 'kicked'].includes(newStatus)) {
      this.joinChallenges.delete(key);
      this.solvedJoinChallenges.delete(key);
      return;
    }
    const joined = ['left', 'kicked'].includes(oldStatus) && ['member', 'restricted'].includes(newStatus);
    if (!joined) return;
    this.joinChallenges.delete(key);
    await this.handleNewMembers({
      chat: chatMemberUpdate.chat,
      from: chatMemberUpdate.from || member,
      date: chatMemberUpdate.date,
      new_chat_members: [member]
    });
  }

  async expireJoinChallenges() {
    const now = Date.now();
    for (const [key, challenge] of this.joinChallenges.entries()) {
      if (now < challenge.expiresAt) continue;
      this.joinChallenges.delete(key);
      const message = { chat: challenge.chat, from: challenge.user, text: 'join challenge expired' };
      if (await this.hasRestrictRights(challenge.chat.id)) {
        if (this.config.joinChallengeAction === 'ban') await this.ban(challenge.chat.id, challenge.user.id).catch(() => null);
        else if (this.config.joinChallengeAction === 'kick') await this.ban(challenge.chat.id, challenge.user.id).then(() => this.call('unbanChatMember', { chat_id: challenge.chat.id, user_id: challenge.user.id, only_if_banned: true })).catch(() => null);
      }
      const event = await this.record('join_challenge_expired', message, {
        target: challenge.user,
        target_key: targetKey(challenge.user),
        alias_keys: challengeAliasSignals(challenge.user),
        action: this.config.joinChallengeAction || 'kick',
        attempts: challenge.attempts,
        evidence: ['new user did not complete DKG Knowledge Asset UAL verification before timeout']
      }, { writeDkg: false });
      await this.maybeRecordJoinChallengeRepeatFailure(message, event);
      if (challenge.messageId && await this.hasDeleteRights(challenge.chat.id)) await this.deleteMessage(challenge.chat.id, challenge.messageId).catch(() => null);
      await this.sendEphemeral(challenge.chat.id, `${userMention(challenge.user)} did not complete DKG verification in time.`, { parse_mode: 'HTML', autoDelete: true }, this.config.successMessageTtlSeconds || 45).catch(() => null);
    }
  }

  async proactiveScan() {
    if (Date.now() < this.nextProactiveScanAt) return;
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;

    const svc = (() => { try { return TracabotSkillService.fromEnv(); } catch { return null; } })();

    for (const entry of this.observedUsers.values()) {
      const message = {
        chat: entry.chat,
        from: entry.user,
        text: entry.context || `proactive scan @${entry.user.username || entry.user.id}`
      };
      const risk = await this.assess(message, entry.user, message.text);

      if (risk.confidence >= this.config.actionThreshold) {
        await this.applyRiskAction(message, risk);
        continue;
      }

      // Deeper polling enhancement: feed medium-risk proactive scans through the graph-aware artefact curator
      if (svc && risk.confidence >= (this.config.warnThreshold ?? 60) - 10) {
        const curator = await svc.decideArtefactAction({
          telegramUserId: entry.user?.id,
          username: entry.user?.username,
          text: message.text,
          artifactKind: 'proactive_scan_candidate',
          confidence: risk.confidence
        }).catch(() => null);

        if (curator && curator.recommendation === 'queue_for_admin_review') {
          await this.record('risk_review_needed', message, {
            ...risk,
            source: 'proactive_scan_curator',
            curator_recommendation: curator.recommendation,
            curator_reasoning: curator.reasoning,
            graph_history: curator.graph_history || null
          }, { writeDkg: false });
        } else if (curator && curator.recommendation === 'commit_to_swm') {
          await this.recordConversationArtifact(message, {
            risk,
            text: message.text,
            artifactKind: 'proactive_scan_candidate',
            conversationRole: 'guardian'
          });
        }
      }
    }
  }

  async pollOnce() {
    const updates = await this.call('getUpdates', {
      offset: this.offset,
      timeout: 25,
      allowed_updates: ['message', 'callback_query', 'chat_member', 'my_chat_member']
    });
    for (const update of updates) {
      this.offset = update.update_id + 1;
      if (update.callback_query) await this.handleCallbackQuery(update.callback_query);
      if (update.message) await this.handleMessage(update.message);
      if (update.chat_member) await this.handleChatMemberUpdate(update.chat_member);
    }
    await this.proactiveScan();
    await this.expireJoinChallenges();
    await this.maybePostDailySafeTip();
  }

  async maybePostDailySafeTip() {
    // Phase 4: rare (~once per 24h per chat max), low-volume educational posts when conversation mode is on
    if (!this.config.dailySafeTipIntervalHours || this.config.dailySafeTipIntervalHours <= 0) return;
    const interval = this.config.dailySafeTipIntervalHours * 60 * 60 * 1000;
    if (!this.lastSafeTipAt) this.lastSafeTipAt = new Map();
    for (const chatId of this.seenChats.keys()) {
      if (!this.lastSafeTipAt.has(chatId)) this.lastSafeTipAt.set(chatId, 0);
    }

    for (const [chatIdStr, last] of this.lastSafeTipAt) {
      if (Date.now() - last < interval) continue;
      const chatId = Number(chatIdStr);
      if (!this.chatConversationalEnabled(chatId)) continue;

      this.sendTyping(chatId).catch(() => {});

      let tip = await this.generateSafeTip().catch(() => null);
      if (!tip) {
        tip = 'Stay on TRAC: verify through official channels. Never trust unsolicited DMs asking for wallet actions.';
      }

      await this.sendEphemeral(chatId, `🛡️ ${tip}`, {}).catch(() => {});

      this.lastSafeTipAt.set(chatIdStr, Date.now());

      await this.recordConversationArtifact({ chat: { id: chatId } }, {
        risk: { scam_type: 'education' },
        text: tip,
        artifactKind: 'safe_tip',
        conversationRole: 'guardian'
      }).catch(() => {});
    }
  }

  async generateSafeTip() {
    // Prefer the safe-tips skill for consistency (external agents + bot use the same generator)
    try {
      const svc = TracabotSkillService.fromEnv();
      const tip = await svc.generateSafeTip().catch(() => null);
      if (tip && tip.length > 10 && tip.length < 180) return tip;
    } catch {}

    if (!this.llm) return null;

    const system = [
      'You are Tracabot, a calm, professional anti-scam bodyguard for Telegram communities.',
      'Create one short, varied, practical safety sentence (max 140 chars).',
      'Rotate topics naturally: DM impersonators, urgent wallet links, fake support, seed phrases, verification habits, staying on TRAC.',
      'Tone: protective and helpful, never alarmist. Focus on one clear habit.',
      'Output ONLY the sentence. No quotes, no intro, no extra text.'
    ].join('\n');

    const response = await this.llm.complete({ system, user: 'Generate today\'s short safety reminder.' }).catch(() => ({ text: '' }));
    const tip = String(response.text || '').trim().replace(/^["']|["']$/g, '');

    return (tip.length > 15 && tip.length < 160) ? tip : null;
  }

  async maybeSurfaceCrossGroupWarning(warningEvent, message, targetUser) {
    // Option A: make cross-group prior-admin intelligence visible and actionable in real time
    if (!warningEvent || !this.config.proactiveAlertCrossGroup) return null;

    const chatId = message?.chat?.id;
    if (!chatId) return null;

    const key = `${chatId}:${targetKey(targetUser)}`;
    const intervalMs = 24 * 60 * 60 * 1000; // disciplined: once per actor per chat per day max
    const last = this.lastCrossGroupWarningAt.get(key) || 0;
    if (Date.now() - last < intervalMs) return null;

    const priorCount = (warningEvent.payload?.prior_admin_events || []).length;
    const riskConf = warningEvent.payload?.current_risk?.confidence || '?';
    const target = targetUser || warningEvent.payload?.target || {};
    const mention = userMention(target);

    const alertText = [
      '⚠️ CROSS-GROUP WARNING',
      `${mention} has prior admin action(s) in the Tracabot Context Graph from another community (${priorCount} recorded).`,
      `Current risk: ${riskConf}%. Admins: open Reviews from /start to inspect and act.`,
      `Event: ${shortId(warningEvent.id)} — ask “why event ${warningEvent.id}?”`
    ].join('\n');

    let sent = null;
    try {
      sent = await this.send(chatId, alertText, {
        reply_to_message_id: message?.message_id || undefined
      });
      // Enable quick follow-up from the posted alert (same pattern as alertAdmins)
      if (sent?.message_id) {
        this.reviewMessageEvents.set(`${chatId}:${sent.message_id}`, warningEvent.id);
      }
    } catch (e) {
      // non-fatal; still try admin DMs
    }

    // DM configured admins (best-effort; Telegram requires prior DM initiation from user)
    const adminDms = [];
    for (const adminId of this.config.adminIds) {
      try {
        await this.send(adminId, `🛡️ Cross-group alert in chat ${chatId}:\n\n${alertText}`);
        adminDms.push(adminId);
      } catch {
        // silent; user must have DM'd the bot first
      }
    }

    this.lastCrossGroupWarningAt.set(key, Date.now());

    // Lightweight provenance artefact so the action of surfacing is itself part of memory
    await this.recordConversationArtifact({ chat: { id: chatId } }, {
      risk: { scam_type: 'cross_group_prior_action', confidence: 80 },
      text: alertText,
      artifactKind: 'proactive_cross_group_alert',
      conversationRole: 'guardian',
      sourceEventIds: [warningEvent.id]
    }).catch(() => {});

    return { sent, adminDms, warningEventId: warningEvent.id };
  }

  async dropPendingUpdates() {
    if (this.config.dropPendingUpdatesOnStart === false) return;
    const updates = await this.call('getUpdates', { offset: -1, limit: 1, timeout: 0, allowed_updates: ['message', 'callback_query', 'chat_member', 'my_chat_member'] });
    if (updates.length) this.offset = updates[0].update_id + 1;
  }

  async run() {
    if (!this.config.telegramToken) throw new Error('TELEGRAM_BOT_TOKEN is required');
    try {
      await this.dkg.ensureContextGraph();
    } catch (error) {
      console.error(`DKG startup check failed; continuing with Telegram polling: ${error instanceof Error ? error.message : String(error)}`);
    }
    try {
      const commandScopes = [
        null,
        { type: 'all_private_chats' },
        { type: 'all_group_chats' },
        { type: 'all_chat_administrators' }
      ];
      for (const scope of commandScopes) {
        const payload = scope ? { scope } : {};
        await this.call('deleteMyCommands', payload).catch(() => {});
        await this.call('setMyCommands', { ...payload, commands: TELEGRAM_COMMANDS });
      }
    } catch (error) {
      console.error(`setMyCommands failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    try {
      await this.dropPendingUpdates();
    } catch (error) {
      console.error(`dropPendingUpdates failed: ${error instanceof Error ? error.message : String(error)}`);
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

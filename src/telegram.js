import { createHash, randomUUID } from 'node:crypto';
import {
  canAutonomouslyEscalate,
  combineRisk,
  DEFAULT_KNOWN_CAMPAIGN_PATTERNS,
  displayName,
  evaluateKnownCampaignAutoBan,
  formatBanReply,
  formatDkgReference,
  formatReportReply,
  formatReviewNeededSummary,
  formatRiskAssessment,
  formatScanReply,
  formatStatsReply,
  formatStatsSourcesReply,
  isObviousLocalScam,
  matchKnownCampaignFingerprint,
  normalizeCampaignLabel
} from './risk-engine.js';
import { extractDomains, extractPatterns, extractWallets } from './dkg-client.js';
import { buildAgentIntentPrompt, buildAlertReplyClassifierPrompt, buildGeneralPrompt, buildSafetyPrompt, fallbackSafetyReply, isOnTopicDirectAddress, isSafetyQuestion, offTopicRedirect, sanitizeGeneralReply, sanitizeSafetyReply, shouldConversationallyReply } from './conversation.js';
import { redactedOpenClawStatus } from './openclaw-config.js';
import { TracabotSkillService } from './skill-service.js';
import { evaluateEvidence, EVIDENCE_POLICY_VERSION } from './evidence-policy.js';
import { promoteEligibleEvidence } from './evidence-promoter.js';
import { analyzeBanContext, BAN_CONTEXT_LIMITS, emptyBanContext } from './ban-context.js';
import { evaluateJoinProtection, PROTECTION_POLICY_VERSION, protectionSummary } from './protection-policy.js';
import { fetchCreatorAttestation } from './creator-attestation.js';
import { flushFederationQueue } from './federation-client.js';
import { resolveReviewTarget } from './review-target.js';

export const CAMPAIGN_POLICIES = Object.freeze([
  Object.freeze({
    id: 'bcgame',
    label: 'BC GAME',
    patterns: Object.freeze([...DEFAULT_KNOWN_CAMPAIGN_PATTERNS]),
    rule: 'Ban only with an exact Telegram ID trusted prior admin-ban OR an independently confirmed campaign (admin bans from at least two communities) with a shared domain or wallet. Name alone never bans. Overturned decisions are protected.'
  })
]);

export const TELEGRAM_COMMANDS = [
  { command: 'start', description: 'Open Tracabot protection menu' },
  { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
  { command: 'report', description: 'Report suspicious users, messages, links, wallets, or forwarded DMs' },
  { command: 'ban', description: 'Admin: optional ban command; normal admin bans are logged automatically' },
  { command: 'mute', description: 'Admin: mute a replied or mentioned user for a duration' },
  { command: 'appeal', description: 'Private: appeal your own ban and review your local cases' },
  { command: 'appeals', description: 'Admin: review pending ban appeals for chats you moderate' },
  { command: 'controls', description: 'Private: current-admin protection controls and auto-ban overrides' }
];

const MAX_TEXT_CHARS = 4096;
const MAX_CONTEXT_CHARS = 500;
const CONVERSATION_HISTORY_LIMIT = 8;
const AGENT_ACTIONS = new Set([
  'appeal', 'banlist', 'clarify', 'dashboard', 'digest', 'explain_event', 'false_positive_review',
  'general_on_topic', 'generate_safe_tip', 'get_digest', 'get_stats', 'greeting', 'help', 'ignore',
  'list_pending_reviews', 'memory_query', 'modlog', 'mute', 'recent_actions', 'reject', 'report',
  'review', 'scan_target', 'settings', 'show_campaigns', 'show_reviews', 'show_watchlist', 'stats',
  'overturn'
]);
const OBSERVED_CONTEXT_TTL_MS = 24 * 60 * 60 * 1000;
const MEMBERSHIP_EPISODE_DEDUPE_MS = 2 * 60 * 1000;
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
const POLLING_BACKOFF_BASE_MS = 1000;
const POLLING_BACKOFF_MAX_MS = 30000;
const POLLING_ERROR_LOG_INTERVAL_MS = 60000;
const POLLING_RESPONSE_MARGIN_MS = 5000;
const SANGMATA_BOT_ID = '461843263';
const SANGMATA_BOT_USERNAME = 'sangmatainfo_bot';
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

function canonicalJson(value) {
  const serialized = JSON.stringify(value, (_key, current) => {
    if (!current || typeof current !== 'object' || Array.isArray(current)) return current;
    return Object.keys(current).sort().reduce((ordered, key) => {
      ordered[key] = current[key];
      return ordered;
    }, {});
  });
  if (serialized === undefined) throw new TypeError('Telegram payload is not JSON serializable');
  return serialized;
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

function escapeRegExp(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeBotUsername(value = '') {
  return String(value || '').trim().replace(/^@/, '');
}

function commandRegex(command = '', botUsername = '') {
  const user = normalizeBotUsername(botUsername);
  const suffix = user ? `(?:@${escapeRegExp(user)})?` : '(?:@(?:tracabot|tracethembot))?';
  return new RegExp(`^/${escapeRegExp(command)}${suffix}(?:\\s|$)`, 'i');
}

function isCommand(text = '', command = '', botUsername = '') {
  return commandRegex(command, botUsername).test(String(text || ''));
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

function chatKey(chatOrId = '') {
  if (chatOrId && typeof chatOrId === 'object') return String(chatOrId.id || '');
  return String(chatOrId || '');
}

function eventChatKey(event = {}) {
  return chatKey(event.payload?.target_chat_id || event.chat?.id || '');
}

function sourceMessageLink(event = {}) {
  const messageId = event.payload?.source_message_id || event.payload?.message_id || event.message_id || '';
  if (!messageId) return '';
  const chat = event.chat || {};
  const username = chat.username || event.payload?.target_chat_username || '';
  if (username) return `https://t.me/${String(username).replace(/^@/, '')}/${encodeURIComponent(messageId)}`;
  const id = String(event.payload?.target_chat_id || chat.id || '');
  if (id.startsWith('-100')) return `https://t.me/c/${encodeURIComponent(id.slice(4))}/${encodeURIComponent(messageId)}`;
  return '';
}

function sameChat(a = '', b = '') {
  const left = chatKey(a);
  const right = chatKey(b);
  return Boolean(left && right && left === right);
}

function chatLabel(chat = {}) {
  return String(chat.title || chat.username || chat.id || 'unknown chat').slice(0, 80);
}

function button(text, data) {
  return { text, callback_data: data };
}

function urlButton(text, url) {
  return { text, url };
}

const MEMORY_CARD_CHALLENGES = [
  { id: 'mem-id', field: 'ID', value: 'did:dkg:tracabot:7F3A', signal: 'impersonation pattern', use: 'warns communities about repeat scam behavior', question: 'Which item is the memory ID?', options: ['did:dkg:tracabot:7F3A', 'impersonation pattern', 'repeat scam behavior'], answerIndex: 0, explanation: 'The memory ID starts with did:dkg: and names the reusable safety record.' },
  { id: 'signal', field: 'Signal', value: 'fake support DM', memoryId: 'did:dkg:tracabot:91C2', use: 'helps admins spot impersonators', question: 'Which item is the scam signal?', options: ['fake support DM', 'did:dkg:tracabot:91C2', 'helps admins spot impersonators'], answerIndex: 0, explanation: 'The signal describes the risky pattern TRACaBot should remember.' },
  { id: 'use', field: 'Use', value: 'warns users before they connect wallets', memoryId: 'did:dkg:tracabot:4B8E', signal: 'wallet verification lure', question: 'What is this memory record used for?', options: ['warns users before they connect wallets', 'wallet verification lure', 'did:dkg:tracabot:4B8E'], answerIndex: 0, explanation: 'The use explains how the memory helps protect the community.' },
  { id: 'prefix', field: 'ID', value: 'did:dkg:tracabot:C20A', signal: 'copied admin name', use: 'links repeat impersonation evidence', question: 'Which part shows this is verifiable agent memory?', options: ['did:dkg:', 'copied admin name', 'repeat impersonation evidence'], answerIndex: 0, explanation: 'did:dkg: is the verifiable memory ID prefix agents can recognize.' },
  { id: 'scope', field: 'Scope', value: 'reusable across communities', memoryId: 'did:dkg:tracabot:E62D', signal: 'airdrop claim lure', question: 'Which item describes where this signal can help?', options: ['reusable across communities', 'airdrop claim lure', 'did:dkg:tracabot:E62D'], answerIndex: 0, explanation: 'Shared memory helps more than one community reuse the same safety signal.' },
  { id: 'decision', field: 'Decision', value: 'confirmed scam pattern', memoryId: 'did:dkg:tracabot:5A10', signal: 'suspicious DM campaign', question: 'Which item is the reviewed safety decision?', options: ['confirmed scam pattern', 'suspicious DM campaign', 'did:dkg:tracabot:5A10'], answerIndex: 0, explanation: 'The decision is the admin-reviewed conclusion attached to the memory.' },
  { id: 'record', field: 'ID', value: 'did:dkg:tracabot:AA43', signal: 'wallet drain lure', alert: 'be careful with urgent wallet links', question: 'Which item is the reusable memory record, not the alert text?', options: ['did:dkg:tracabot:AA43', 'be careful with urgent wallet links', 'wallet drain lure'], answerIndex: 0, explanation: 'The ID is the reusable record; alerts and signals are details inside it.' },
  { id: 'pattern', field: 'Pattern', value: 'admin impersonation', memoryId: 'did:dkg:tracabot:19DD', use: 'compares new joins with known scam behavior', question: 'Which item names the suspicious behavior?', options: ['admin impersonation', 'compares new joins', 'did:dkg:tracabot:19DD'], answerIndex: 0, explanation: 'The pattern names the behavior TRACaBot should compare against future activity.' },
  { id: 'purpose', field: 'Purpose', value: 'avoids starting from zero in each chat', memoryId: 'did:dkg:tracabot:F807', signal: 'repeated scam wording', question: 'Why does TRACaBot keep this memory?', options: ['avoids starting from zero in each chat', 'repeated scam wording', 'did:dkg:tracabot:F807'], answerIndex: 0, explanation: 'TRACaBot memory lets communities reuse useful safety context.' },
  { id: 'evidence', field: 'Evidence', value: 'scam link pattern', memoryId: 'did:dkg:tracabot:3C77', use: 'supports admin review', question: 'Which item is the type of evidence?', options: ['scam link pattern', 'supports admin review', 'did:dkg:tracabot:3C77'], answerIndex: 0, explanation: 'Evidence is the observed material that supports the safety record.' },
  { id: 'trait', field: 'Trait', value: 'reusable safety signal', memoryId: 'did:dkg:tracabot:B61E', signal: 'fake giveaway message', question: 'Which trait makes this useful to agents?', options: ['reusable safety signal', 'fake giveaway message', 'did:dkg:tracabot:B61E'], answerIndex: 0, explanation: 'Reusable safety signals are what let agents carry protection across communities.' },
  { id: 'shared', field: 'Memory', value: 'shared safety record', memoryId: 'did:dkg:tracabot:D904', signal: 'seed phrase request', question: 'Which item says this can help more than one community?', options: ['shared safety record', 'seed phrase request', 'did:dkg:tracabot:D904'], answerIndex: 0, explanation: 'A shared safety record can help multiple communities recognize the same risk.' }
];

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

async function telegram(token, method, payload, timeoutMs = 30000, signal) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const requestSignal = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
  const requestPayload = Object.fromEntries(Object.entries(payload || {}).filter(([, value]) => value !== null && value !== undefined));
  try {
    let response;
    try {
      response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(requestPayload),
        signal: requestSignal
      });
    } catch (cause) {
      throw new TelegramOutcomeUnknownError(`Telegram ${method} outcome unknown: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    }
    let body;
    try {
      body = await response.json();
    } catch (cause) {
      throw new TelegramOutcomeUnknownError(`Telegram ${method} outcome unknown: invalid response`, { cause });
    }
    if (!body.ok && response.status >= 500) {
      throw new TelegramOutcomeUnknownError(`Telegram ${method} outcome unknown: ${body.description || response.statusText}`);
    }
    if (!body.ok) throw new Error(`Telegram ${method} failed: ${body.description || response.statusText}`);
    return body.result;
  } finally {
    clearTimeout(timeout);
  }
}

class TelegramOutcomeUnknownError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'TelegramOutcomeUnknownError';
    this.telegramOutcomeUnknown = true;
  }
}

function pollingFailureKind(error) {
  let current = error;
  while (current) {
    if (current.name === 'AbortError' || current.code === 'ABORT_ERR' || current.code === 'ETIMEDOUT') return 'timeout';
    current = current.cause;
  }
  return 'transport';
}

function abortableSleep(ms, signal) {
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      signal?.removeEventListener('abort', done);
      resolve();
    }
    signal?.addEventListener('abort', done, { once: true });
  });
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

function targetIdentityKeys(target = {}) {
  if (!target || target.kind === 'wallet') return targetKey(target) ? [targetKey(target)] : [];
  return [...new Set([
    target.id ? `id:${target.id}` : '',
    target.username ? `username:${String(target.username).replace(/^@/, '').toLowerCase()}` : '',
    target.label ? `username:${String(target.label).replace(/^@/, '').toLowerCase()}` : ''
  ].filter(Boolean))];
}

function sameActorTarget(a = {}, b = {}) {
  const aKeys = targetIdentityKeys(a);
  const bKeys = new Set(targetIdentityKeys(b));
  if (aKeys.some((key) => bKeys.has(key))) return true;
  const aLookup = normalizedLookup(a.username || a.label || a.id || '');
  const bLookup = normalizedLookup(b.username || b.label || b.id || '');
  return Boolean(aLookup && bLookup && aLookup === bLookup);
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
    [user.first_name, user.last_name].filter(Boolean).join(' '),
    user.sangmata?.oldName,
    user.sangmata?.newName,
    user.identityChange?.oldName,
    user.identityChange?.newName,
    user.label
  ].filter(Boolean);
}

function isSangMataBotUser(user = {}) {
  if (user.is_bot !== true) return false;
  return String(user.id || '') === SANGMATA_BOT_ID
    || String(user.username || '').toLowerCase() === SANGMATA_BOT_USERNAME;
}

function eventAgeMs(event = {}) {
  const timestamp = Date.parse(event.timestamp || '');
  return Number.isNaN(timestamp) ? Infinity : Date.now() - timestamp;
}

function eventMatchesTarget(event = {}, target = {}) {
  const eventUser = event.user || {};
  const keys = new Set(targetIdentityKeys(target));
  const payloadKeys = [event.payload?.target_key, event.payload?.watch_target_key].filter(Boolean);
  return sameActorTarget(eventUser, target) || payloadKeys.some((key) => keys.has(key));
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

function plainUserLabel(user = {}) {
  if (user.kind === 'wallet') return user.label || user.id || 'wallet';
  const username = String(user.username || '').replace(/^@/, '');
  return username ? `@${username}` : [user.first_name, user.last_name].filter(Boolean).join(' ').trim() || user.label || (user.id ? `ID ${user.id}` : 'this account');
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
  if (payload.consent_to_share === false || payload.privacy_opt_out === true) return false;
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
  const payload = event.payload || {};
  if (payload.campaign_root_eligible === false) return false;
  if (!hasEvidenceForDkg(event.event_type, payload) || !payload.evidence?.length) return false;
  if (event.event_type === 'ban_executed' || event.event_type === 'review_upheld') return true;
  if (event.event_type === 'report_submitted') return payload.report_decision === 'accepted' && Number(payload.local_confidence || 0) >= 60;
  return Number(payload.confidence || 0) >= 80 && Number(payload.local_confidence || 0) >= 60;
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
    this.botKey = createHash('sha256').update(String(this.config.telegramToken || 'tracabot')).digest('hex');
    this.botUsernameCache = normalizeBotUsername(this.config.botUsername || '');
    this.offset = this.store.pollingOffset?.(this.botKey) ?? 0;
    this.currentUpdateId = null;
    this.botId = null;
    this.observedUsers = new Map();
    this.chatAdmins = new Map();
    this.joinChallenges = new Map();
    this.joinChallengeTimers = new Map();
    this.solvedJoinChallenges = new Map();
    this.reviewMessageEvents = new Map();
    this.lastPendingReviewsByChat = new Map(); // chatId -> displayed review groups for natural follow-up corrections
    this._reviewCache = { pending: null, watches: null, lastUpdate: 0 };
    this.optimisticReviewedEventIds = new Set();
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;
    this.conversationLastReply = new Map();
    this.naturalLanguageLastReply = new Map();
    this.conversationHistory = new Map();
    this.lastBotReplyByThread = new Map();
    this.lastPendingReviewNoticeAt = new Map(); // chatId -> timestamp for throttled review notices
    this.skillService = null;
    this.seenChats = new Map();
    this.observedUserMessages = new Map();
    this.pollingFailureCount = 0;
    this.lastPollingErrorLogAt = 0;
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

  rememberUserMessage(message = {}) {
    if (!message.chat?.id || !message.from?.id || !message.message_id || message.from?.is_bot === true) return;
    if (!PUBLIC_CHAT_TYPES.has(message.chat.type || '')) return;
    const key = `${message.chat.id}:${message.from.id}`;
    const ids = this.observedUserMessages.get(key) || [];
    ids.push(message.message_id);
    this.observedUserMessages.set(key, [...new Set(ids)].slice(-100));
    const captureText = this.config.banContext !== false;
    const maxChars = this.config.banContextMaxTextChars || BAN_CONTEXT_LIMITS.maxTextChars;
    const hasMedia = Boolean(message.photo || message.document || message.video || message.animation
      || message.audio || message.voice || message.sticker || message.video_note);
    this.store.rememberMessage?.(message.chat.id, message.from.id, message.message_id, {
      text: captureText ? boundedText([message.text, ...entityUrls(message)].filter(Boolean).join('\n'), maxChars) : '',
      caption: captureText ? boundedText(message.caption, maxChars) : '',
      hasMedia,
      date: message.date
    });
  }

  buildBanContext(chatId, userId, actionAtMs) {
    if (this.config.banContext === false) return emptyBanContext({ reason: 'context_disabled' });
    const maxMessages = this.config.banContextMaxMessages || BAN_CONTEXT_LIMITS.maxMessages;
    const maxAgeMs = (this.config.banContextMaxAgeMinutes || BAN_CONTEXT_LIMITS.maxAgeMs / 60000) * 60 * 1000;
    const actionAtSeconds = Math.floor(actionAtMs / 1000);
    const messages = this.store.recentMessages?.(chatId, userId, {
      before: actionAtSeconds,
      since: actionAtSeconds - Math.floor(maxAgeMs / 1000),
      limit: maxMessages
    }) || [];
    return analyzeBanContext(messages, {
      limits: { ...BAN_CONTEXT_LIMITS, maxMessages, maxAgeMs, maxTextChars: this.config.banContextMaxTextChars || BAN_CONTEXT_LIMITS.maxTextChars }
    });
  }

  async deleteKnownUserMessages(chatId, userId, extraMessageIds = [], effectPrefix = '') {
    if (!chatId || !userId) return { attempted: 0, deleted: 0, failed: 0 };
    const key = `${chatId}:${userId}`;
    const ids = [...new Set([...(this.observedUserMessages.get(key) || []), ...(this.store.knownMessageIds?.(chatId, userId) || []), ...extraMessageIds].filter(Boolean))];
    let deleted = 0;
    let failed = 0;
    await Promise.all(ids.map(async (messageId) => {
      try {
        if (effectPrefix) {
          await this.callEffect('deleteMessage', { chat_id: chatId, message_id: messageId }, `${effectPrefix}:delete:${messageId}`);
        } else {
          await this.deleteMessage(chatId, messageId);
        }
        deleted += 1;
        this.store.forgetMessage?.(chatId, userId, messageId);
      } catch {
        failed += 1;
      }
    }));
    this.observedUserMessages.delete(key);
    return { attempted: ids.length, deleted, failed };
  }

  async enforceConfirmedScam(chatId, target = {}, sourceMessageIds = [], effectPrefix = '', { joinProtection = false } = {}) {
    if (!target?.id) return { banned: false, reason: 'missing_target_id', attempted: 0, deleted: 0, failed: 0 };
    if (target.is_bot === true || String(target.id) === String(await this.getBotId().catch(() => ''))) {
      return { banned: false, reason: 'protected_bot', attempted: 0, deleted: 0, failed: 0 };
    }
    let protectedAdmin;
    try {
      protectedAdmin = await this.isTelegramChatAdmin(chatId, target.id, { throwOnFailure: true });
    } catch {
      return { banned: false, reason: 'admin_lookup_failed', attempted: 0, deleted: 0, failed: 0 };
    }
    if (protectedAdmin) {
      return { banned: false, reason: 'protected_admin', attempted: 0, deleted: 0, failed: 0 };
    }
    if (!await this.hasBanRights(chatId)) {
      return { banned: false, reason: 'missing_ban_rights', attempted: 0, deleted: 0, failed: 0 };
    }
    if (joinProtection && this.joinAutoRemovalPaused(chatId)) {
      return { banned: false, reason: 'join_auto_removal_paused', attempted: 0, deleted: 0, failed: 0 };
    }
    if (effectPrefix) {
      await this.callEffect('banChatMember', { chat_id: chatId, user_id: target.id }, `${effectPrefix}:ban`);
    } else {
      await this.ban(chatId, target.id);
    }
    this.store.incrementMetric?.('confirmed_scam_bans');
    const deleted = await this.deleteKnownUserMessages(chatId, target.id, sourceMessageIds, effectPrefix);
    this.store.incrementMetric?.('message_delete_attempts', deleted.attempted);
    this.store.incrementMetric?.('messages_deleted', deleted.deleted);
    this.store.incrementMetric?.('message_delete_failures', deleted.failed);
    return { banned: true, reason: 'confirmed_scam', ...deleted };
  }

  conversationContext(message = {}) {
    return (this.conversationHistory.get(this.conversationThreadKey(message)) || [])
      .map((turn) => `${turn.role}: ${turn.text}`)
      .join('\n');
  }

  async call(method, payload, { signal, timeoutMs } = {}) {
    const started = Date.now();
    try {
      const longPollTimeoutMs = method === 'getUpdates'
        ? Math.max(0, Number(payload?.timeout) || 0) * 1000 + POLLING_RESPONSE_MARGIN_MS
        : 0;
      const configuredTimeoutMs = Number(timeoutMs ?? this.config.telegramTimeoutMs) || 30000;
      const requestTimeoutMs = Math.max(configuredTimeoutMs, longPollTimeoutMs);
      const result = await telegram(this.config.telegramToken, method, payload, requestTimeoutMs, signal);
      this.store.incrementMetric?.('telegram_api_calls');
      this.store.incrementMetric?.('telegram_api_latency_ms_total', Date.now() - started);
      return result;
    } catch (error) {
      if (!signal?.aborted) this.store.incrementMetric?.('telegram_api_errors');
      throw error;
    }
  }

  async callEffect(method, payload, effectKey = '') {
    if ((this.currentUpdateId === null && !effectKey) || !this.store.beginEffect) return this.call(method, payload);
    const stablePayload = canonicalJson(payload);
    const semanticKey = effectKey || `${this.currentUpdateId}:${method}:${createHash('sha256').update(stablePayload).digest('hex')}`;
    const key = `telegram:${this.botKey}:${semanticKey}`;
    const canonicalPayload = JSON.parse(stablePayload);
    const existing = this.store.beginEffect(key, method, canonicalPayload, { staleAction: 'uncertain' });
    if (existing.completed) return existing.response;
    if (existing.uncertain) throw new TelegramOutcomeUnknownError(`Telegram effect outcome remains unknown; refusing replay: ${method}`);
    if (existing.inProgress) throw new Error(`Telegram effect already in progress: ${method}`);
    let result;
    try {
      result = await this.call(method, payload);
    } catch (error) {
      if (method === 'editMessageText' && /message is not modified/i.test(error instanceof Error ? error.message : String(error))) {
        result = { message_id: payload.message_id, chat: { id: payload.chat_id }, not_modified: true };
      } else {
        if (error?.telegramOutcomeUnknown) {
          this.store.markEffectUncertain?.(key, error.message);
          this.store.incrementMetric?.('telegram_effects_uncertain');
        }
        else this.store.failEffect(key, error instanceof Error ? error.message : String(error));
        throw error;
      }
    }
    try {
      if (!this.store.completeEffect(key, result)) {
        throw new Error('ledger transition failed');
      }
    } catch (error) {
      try {
        this.store.markEffectUncertain?.(key, `Telegram ${method} succeeded but ledger transition failed: ${error instanceof Error ? error.message : String(error)}`);
        this.store.incrementMetric?.('telegram_effects_uncertain');
      } catch {
        // Preserve original ledger failure; replay remains blocked by running state if uncertainty cannot persist.
      }
      throw new Error(`Telegram effect completed but ledger commit failed for ${method}; refusing replay`, { cause: error });
    }
    return result;
  }

  async send(chatId, text, extra = {}) {
    try {
      const sent = await this.callEffect('sendMessage', { chat_id: chatId, text, ...extra });
      this.rememberBotReply(chatId, sent, text, extra);
      return sent;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (extra.reply_to_message_id && /message to be replied not found/i.test(message)) {
        const { reply_to_message_id, ...fallbackExtra } = extra;
        const sent = await this.callEffect('sendMessage', { chat_id: chatId, text, ...fallbackExtra });
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

  commandResponseOptions(message = {}, extra = {}) {
    const isPrivateChat = message.chat?.type === 'private' || Number(message.chat?.id || 0) > 0;
    return { ...(isPrivateChat && message.message_id ? { reply_to_message_id: message.message_id } : {}), ...extra };
  }

  async sendCleanCommandReply(message = {}, text = '', extra = {}) {
    const sent = await this.sendCommandReply(message.chat.id, text, this.commandResponseOptions(message, extra));
    this.cleanupMenuTrigger(message);
    return sent;
  }

  async sendCleanInteractiveCommandReply(message = {}, text = '', rows = [], extra = {}) {
    const sent = await this.sendInteractiveReply(message.chat.id, text, rows, this.commandResponseOptions(message, extra));
    this.cleanupMenuTrigger(message);
    return sent;
  }

  async menuIntro(message = {}) {
    if (this.llm && this.chatConversationalEnabled(message?.chat?.id)) {
      const reply = await this.generalConversationReply({ ...message, text: message.text || 'Open the Tracabot protection menu.' }).catch(() => '');
      if (reply && reply.length > 5) return reply;
    }
    return 'I’m here to help protect the group. Add TRACaBot as a group admin and keep it running: bans made with normal Telegram admin controls are logged automatically. Use /scan or /report for checks, and /ban or /mute only when you need the bot to act.';
  }

  async sendMenu(message = {}, extra = {}) {
    const chatId = message.chat?.id;
    const requester = message.from?.id || message.from?.username || '';
    const text = await this.menuIntro(message);
    const isPrivateChat = message.chat?.type === 'private' || Number(chatId) > 0;
    const replyContext = isPrivateChat ? { reply_to_message_id: message.message_id } : {};
    const sent = await this.sendInteractiveReply(chatId, text, this.dashboardKeyboard(requester), { ...replyContext, ...extra });
    this.cleanupMenuTrigger(message);
    return sent;
  }

  async editInteractiveMessage(chatId, messageId, text, rows = [], extra = {}) {
    return this.callEffect('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      text,
      ...extra,
      reply_markup: inlineKeyboard(rows)
    });
  }

  async answerCallback(callbackId, text = '', showAlert = false) {
    if (!callbackId) return null;
    return this.call('answerCallbackQuery', { callback_query_id: callbackId, text, show_alert: showAlert }).catch(() => null);
  }

  async sendPersistentCommandReply(chatId, text, extra = {}) {
    return this.send(chatId, text, extra);
  }

  async ban(chatId, userId) {
    return this.callEffect('banChatMember', { chat_id: chatId, user_id: userId });
  }

  async restrict(chatId, userId, untilDate = Math.floor(Date.now() / 1000) + 24 * 60 * 60) {
    return this.callEffect('restrictChatMember', {
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
    return this.callEffect('restrictChatMember', {
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
    return this.callEffect('restrictChatMember', {
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
    return this.callEffect('restrictChatMember', {
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
    if (this.botUsernameCache) return this.botUsernameCache;
    const me = await this.call('getMe', {});
    this.botUsernameCache = normalizeBotUsername(me.username || 'tracethembot');
    return this.botUsernameCache;
  }

  ownBotUsername() {
    return this.botUsernameCache || normalizeBotUsername(this.config.botUsername || '');
  }

  async deleteMessage(chatId, messageId) {
    if (!messageId) return null;
    return this.callEffect('deleteMessage', { chat_id: chatId, message_id: messageId });
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
      return member.status === 'administrator' && member.can_restrict_members === true;
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

  async isTelegramChatAdmin(chatId, userId, { throwOnFailure = false, requireLiveLookup = false } = {}) {
    if (!userId) return false;
    if (!requireLiveLookup) {
      const admins = await this.getChatAdmins(chatId);
      if (admins.some((admin) => String(admin.id) === String(userId))) return true;
    }
    try {
      const member = await this.call('getChatMember', { chat_id: chatId, user_id: userId });
      return ['creator', 'administrator'].includes(member.status);
    } catch (error) {
      if (throwOnFailure) throw error;
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

  chatCampaignPolicyEnabled(chatId, policyId) {
    if (!chatId || !CAMPAIGN_POLICIES.some((policy) => policy.id === policyId)) return false;
    const latest = [...this.store.all()].reverse().find((event) => event.event_type === 'campaign_policy_setting_changed'
      && String(event.chat?.id || '') === String(chatId)
      && event.payload?.campaign_policy_id === policyId);
    return latest?.payload?.enabled === true;
  }

  activeCampaignPolicy(chatId, target) {
    return CAMPAIGN_POLICIES.find((policy) => this.chatCampaignPolicyEnabled(chatId, policy.id)
      && matchKnownCampaignFingerprint(target, policy.patterns));
  }

  campaignSettingsText(chatId) {
    return [
      'Live campaign policies',
      '',
      ...CAMPAIGN_POLICIES.map((policy) => `${policy.label}: ${this.chatCampaignPolicyEnabled(chatId, policy.id) ? 'added (on)' : 'not added (off)'}\n${policy.rule}`),
      '',
      `Global campaign enforcement: ${this.config.knownCampaignAutoBan === false ? 'disabled' : 'enabled'}.`,
      'Explicit opt-in per chat. Only actual chat admins can add/remove policies. Enforcement also requires bot admin and ban permission.'
    ].join('\n');
  }

  campaignSettingsKeyboard(requesterId, chatId) {
    return [
      ...CAMPAIGN_POLICIES.map((policy) => [button(`${this.chatCampaignPolicyEnabled(chatId, policy.id) ? 'Remove' : 'Add'} ${policy.label}`, callbackData('campaign-policy-set', requesterId, policy.id, this.chatCampaignPolicyEnabled(chatId, policy.id) ? 'off' : 'on'))]),
      [button('Settings', callbackData('settings', requesterId))]
    ];
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

  chatPendingReviewNotificationsEnabled(chatId) {
    const key = String(chatId || '');
    const latest = [...this.store.all()].reverse().find((event) => event.event_type === 'pending_review_notification_setting_changed' && String(event.chat?.id || '') === key);
    if (latest) return latest.payload?.enabled !== false;
    return this.config.pendingReviewNotifications !== false;
  }

  chatPendingReviewNotificationIntervalHours(chatId) {
    const key = String(chatId || '');
    const latest = [...this.store.all()].reverse().find((event) => event.event_type === 'pending_review_notification_interval_changed' && String(event.chat?.id || '') === key);
    const value = Number(latest?.payload?.interval_hours || this.config.pendingReviewNotificationIntervalHours || 12);
    return Number.isFinite(value) && value >= 1 && value <= 168 ? value : 12;
  }

  chatPolicyProfile(chatId) {
    const key = String(chatId || '');
    const latest = [...this.store.all()].reverse().find((event) => event.event_type === 'policy_profile_changed' && String(event.chat?.id || '') === key);
    const configured = String(latest?.payload?.profile || this.config.policyId || 'balanced').toLowerCase();
    if (configured.includes('strict')) return 'strict';
    if (configured.includes('monitor')) return 'monitor';
    return 'balanced';
  }

  chatPolicy(chatId) {
    const profile = this.chatPolicyProfile(chatId);
    if (profile === 'strict') {
      return {
        profile,
        warnThreshold: Math.max(40, this.config.warnThreshold - 10),
        restrictThreshold: Math.max(60, this.config.restrictThreshold - 5),
        actionThreshold: Math.max(70, this.config.actionThreshold - 5),
        banThreshold: Math.max(75, this.config.banThreshold - 5)
      };
    }
    if (profile === 'monitor') {
      return {
        profile,
        warnThreshold: Math.min(90, this.config.warnThreshold + 15),
        restrictThreshold: Math.min(95, this.config.restrictThreshold + 15),
        actionThreshold: Math.min(98, this.config.actionThreshold + 10),
        banThreshold: Math.min(99, this.config.banThreshold + 10)
      };
    }
    return {
      profile,
      warnThreshold: this.config.warnThreshold,
      restrictThreshold: this.config.restrictThreshold,
      actionThreshold: this.config.actionThreshold,
      banThreshold: this.config.banThreshold
    };
  }

  reviewEscalationTier(event = {}) {
    const ageHours = Math.max(0, (Date.now() - Date.parse(event.timestamp || new Date().toISOString())) / 3600000);
    const confidence = Number(event.payload?.confidence || event.payload?.current_risk?.confidence || 0);
    const policy = { restrictThreshold: this.config.restrictThreshold, banThreshold: this.config.banThreshold };
    if (event.event_type === 'proactive_cross_group_warning' || confidence >= policy.banThreshold || ageHours >= 24) return 'urgent';
    if (confidence >= policy.restrictThreshold || ageHours >= 12) return 'elevated';
    return 'standard';
  }

  reviewTierRank(event = {}) {
    return { urgent: 3, elevated: 2, standard: 1 }[this.reviewEscalationTier(event)] || 0;
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
    return message.chat?.type === 'private' && this.isBotOwner(actorFromMessage(message));
  }

  async rejectNonOwnerPrivateReport(message) {
    if (message.chat?.type !== 'private' || this.isPrivateOwnerMessage(message)) return false;
    await this.send(message.chat.id, '⚠️ Private reports are restricted to bot owner. Use /report in the group, or ask group admins to review.', { reply_to_message_id: message.message_id, private: true });
    return true;
  }

  commandText(message, command) {
    return boundedText(message.text || '').replace(commandRegex(command, this.ownBotUsername()), '').trim();
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
      'Native admin logging',
      '',
      'Add TRACaBot to the group as an admin and keep it running. When any admin bans a member with normal Telegram controls, TRACaBot records the live ban, the admin actor when Telegram provides it, the target, and the time. No /ban command is required.',
      'Telegram does not give bots access to Recent Actions, admin logs, or bans that happened before installation. Unstated ban reasons are labeled “reason not provided”. A recorded ban is enforcement evidence, not proof of a scam.',
      'When available, TRACaBot also attaches up to 8 recently observed messages from the same user in the same chat (default 60 minutes). They are labeled “recent pre-ban context; causal link unverified” and are never treated as the ban reason or proof of guilt.',
      '',
      'Silent join protection',
      '',
      'No command is required. On a genuine join, TRACaBot checks the exact stable Telegram ID against confirmed shared evidence. Core protection is deterministic and works with no LLM configured. Default is silent observe/log; automatic removal is a separate admin opt-in and requires fresh, unretracted confirmed fraud/scam evidence from a trusted layer. Display names, aliases, admin bans, behavior flags, model confidence, and campaign association cannot authorize removal.',
      '',
      'Ban appeals',
      '',
      'Banned users can start a private chat with TRACaBot and send /appeal. The bot looks up only that Telegram account’s own locally stored ban cases, then asks an admin of the affected group to uphold or overturn. Telegram does not allow bots to send the first private message, so the user must start the chat. A local overturn records a correction and asks Telegram to unban; it never edits the creator-curator global record.',
      '',
      'Commands',
      '',
      '/start - open the TRACaBot Agent menu. In private chat it includes Protection controls, Status, Recent automatic bans, and Appeals for groups where you are a current admin.',
      '/scan - check a user, wallet, link, or replied message for scam risk. Best used as a reply to the exact message or user.',
      '/appeal - private only; list your own ban cases or submit one with /appeal <case> <reason>.',
      '/appeals - private admin review; only current admins of the affected group see pending appeals.',
      '/controls - private only; current-admin keyboard to pause future join removals, resume, and review/override recent automatic join bans.',
      '',
      'Compatibility commands (not required for protection)',
      '',
      '/report - legacy manual queue entry; automatic detection and join protection do not need it.',
      '/ban - optional admin command; normal Telegram admin bans are logged automatically without it.',
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
    const llm = this.llm?.status?.() || { enabled: false, provider: this.config.llmProvider || 'auto', model: this.config.llmModel || '' };
    return [
      '🩺 Tracabot status',
      '',
      'Telegram',
      `• Delete messages: ${canDelete ? '✅ yes' : '❌ no'}`,
      `• Restrict / ban: ${canBan ? '✅ yes' : '❌ no'}`,
      `• Native admin ban log: ${canBan ? '✅ on' : '⚠️ needs bot admin rights'}`,
      `• Automatic evidence sharing: ${this.config.autoPromoteEvidence === false || this.config.dkgWrites === false ? '⚪ local only' : '✅ on'}`,
      '',
      'Protection',
      `• Warn at ${this.config.warnThreshold}%`,
      `• Restrict at ${this.config.restrictThreshold}%`,
      `• Ban at ${this.config.banThreshold}%`,
      `• Silent join lookup: ✅ deterministic${this.config.dkgPseudonymKey ? '' : ' (⚠️ HMAC identity key not configured)'}`,
      `• Join auto-remove: ${this.config.joinAutoRemove === true ? `✅ opt-in (${(this.config.joinAutoRemoveChats || []).length ? `${this.config.joinAutoRemoveChats.length} chat(s)` : 'all chats'}, ${this.config.joinEvidenceMaxAgeDays || 180}d, local review only by default)` : '⚪ off (observe/log only)'}`,
      `• Trusted evidence layers: ${(this.config.joinTrustedLayers || ['local']).join(', ')} (shared/verified graph is flag-only without authenticated approval)`,
      `• Creator-curator: ${this.config.creatorCuratorUrl ? '✅ configured; signed status read required' : '⚪ not configured'}`,
      `• Ban appeals: ✅ private /appeal; group-admin scoped resolution`,
      `• Creator submissions: ${this.config.submitSharedEvidence === true ? '✅ opt-in' : '⚪ off'}`,
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
      `• LLM: ${llm.enabled ? `✅ ${llm.transport}` : '⚪ disabled/not configured'} (${llm.provider || 'auto'}${llm.model ? ` / ${llm.model}` : ''})`,
      `• LLM authority: explanations/classification only; enforcement is deterministic`,
      `• Learning drafts: ${this.config.wmArtifacts === false ? '⚪ off' : '✅ on'}`,
      `• Cross-group alerts: ${this.config.proactiveAlertCrossGroup !== false ? '✅ on' : '⚪ off'}`
    ].join('\n');
  }

  async formatOwnerHealth() {
    const [dkgOk, dkgRuntime, bot] = await Promise.all([
      this.dkgReachable(),
      this.dkg.runtimeStatus(),
      this.call('getMe', {}).catch(() => null)
    ]);
    const pending = this.pendingReviewItems();
    const tiers = pending.reduce((counts, event) => {
      const tier = this.reviewEscalationTier(event);
      counts[tier] = (counts[tier] || 0) + 1;
      return counts;
    }, {});
    const oldest = pending.length ? Math.max(...pending.map((event) => eventAgeMs(event))) : 0;
    const metrics = this.store.metrics?.() || {};
    return [
      '🩺 TRACaBot owner health',
      '',
      `• Telegram: ${bot?.id ? `✅ @${bot.username || 'bot'}` : '❌ unavailable'}`,
      `• Poll offset: ${this.offset}`,
      `• Updates completed/failed: ${metrics.telegram_updates_completed || 0}/${metrics.telegram_updates_failed || 0}`,
      `• Telegram API calls/errors: ${metrics.telegram_api_calls || 0}/${metrics.telegram_api_errors || 0}`,
      `• Telegram uncertain effects: ${metrics.telegram_effects_uncertain || 0}`,
      `• DKG: ${dkgOk && dkgRuntime.ok ? `✅ ${dkgRuntime.dkgReleaseVersion || 'reachable'}` : '❌ unavailable'}`,
      `• Adapter: ${dkgRuntime.adapterVersion || 'unknown'}`,
      `• Reviews: ${pending.length} (${tiers.urgent || 0} urgent, ${tiers.elevated || 0} elevated, ${tiers.standard || 0} standard)`,
      `• Oldest pending: ${oldest ? humanDuration(Math.round(oldest / 1000)) : 'none'}`,
      `• Confirmed bans: ${metrics.confirmed_scam_bans || 0}`,
      `• DKG writes/failures: ${metrics.dkg_write_count || 0}/${metrics.dkg_write_failures || 0}`,
      `• Message deletes: ${metrics.messages_deleted || 0}/${metrics.message_delete_attempts || 0} (${metrics.message_delete_failures || 0} failed)`,
      `• Store: SQLite WAL`
    ].join('\n');
  }

  appealPayload(message = {}, targetEventId = '', reason = '', extra = {}) {
    const receiptId = `appeal-${randomUUID()}`;
    return {
      appeal_receipt_id: receiptId,
      target_event_id: targetEventId,
      source_message_id: message.message_id || '',
      source_reply_message_id: message.reply_to_message?.message_id || '',
      screenshot_file_ids: screenshotFileIds(message),
      appellant: actorFromMessage(message),
      reason,
      provenance: 'telegram_appeal',
      ...extra,
      evidence: [...(extra.evidence || []), `appeal receipt ${receiptId} references event ${targetEventId || 'unknown'}`]
    };
  }

  async record(eventType, message, payload, { writeDkg = null, idempotencyKey = '' } = {}) {
    const communityId = this.config.communityId || String(message.chat?.id || '');
    const decoratedPayload = this.config.testMode
      ? { ...payload, source: payload?.source || 'test-command-loop', test_mode: true }
      : { ...payload };
    decoratedPayload.community_id = decoratedPayload.community_id || communityId;
    decoratedPayload.community_name = decoratedPayload.community_name || this.config.communityName || '';
    decoratedPayload.community_type = decoratedPayload.community_type || this.config.communityType || 'telegram_group';
    decoratedPayload.policy_id = decoratedPayload.policy_id || this.chatPolicyProfile(message.chat?.id);
    decoratedPayload.instance_id = decoratedPayload.instance_id || this.config.instanceId || '';
    if (['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'ban_requested_no_reply', 'ban_requested_no_rights', 'proactive_cross_group_warning'].includes(eventType)) {
      decoratedPayload.target_chat_id = decoratedPayload.target_chat_id || message.chat?.id || '';
      decoratedPayload.target_chat_title = decoratedPayload.target_chat_title || chatLabel(message.chat || {});
      decoratedPayload.target_chat_type = decoratedPayload.target_chat_type || message.chat?.type || '';
      decoratedPayload.source_message_id = decoratedPayload.source_message_id || message.message_id || '';
      decoratedPayload.detected_at = decoratedPayload.detected_at || new Date().toISOString();
      decoratedPayload.evidence_basis = decoratedPayload.evidence_basis || (decoratedPayload.prior_admin_events?.length ? 'prior_admin_action' : 'risk_signal');
    }
    const deterministicBasis = idempotencyKey || (this.currentUpdateId === null ? '' : [
      this.botKey,
      this.currentUpdateId,
      eventType,
      message.chat?.id || '',
      actorFromMessage(message).id || actorFromMessage(message).username || '',
      decoratedPayload.target_event_id || decoratedPayload.report_event_id || decoratedPayload.target_key || '',
      decoratedPayload.artifact_kind || decoratedPayload.review_decision || decoratedPayload.action || ''
    ].join(':'));
    const event = {
      id: deterministicBasis ? `event-${createHash('sha256').update(deterministicBasis).digest('hex').slice(0, 32)}` : randomUUID(),
      event_type: eventType,
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: message.chat,
      user: actorFromMessage(message),
      payload: decoratedPayload
    };
    const policyAssessment = evaluateEvidence(event, {
      history: this.store.all(),
      policy: {
        highConfidenceThreshold: this.config.evidenceHighConfidenceThreshold,
        localConfidenceThreshold: this.config.evidenceLocalConfidenceThreshold,
        minIndependentSignals: this.config.evidenceMinIndependentSignals,
        minIndependentCommunities: this.config.evidenceMinIndependentCommunities,
        promotionThreshold: this.config.evidencePromotionThreshold
      }
    });
    decoratedPayload.claim_level = decoratedPayload.claim_level || policyAssessment.claimLevel;
    decoratedPayload.evidence_fingerprint = decoratedPayload.evidence_fingerprint || policyAssessment.evidenceFingerprint;
    decoratedPayload.evidence_policy_version = decoratedPayload.evidence_policy_version || EVIDENCE_POLICY_VERSION;
    const existingEvent = deterministicBasis ? this.store.all().find((item) => item.id === event.id) : null;
    if (existingEvent) {
      if (['risk_review_needed', 'risk_action_suppressed', 'proactive_cross_group_warning'].includes(eventType)
        && (eventType !== 'proactive_cross_group_warning' || this.config.proactiveAlertCrossGroup !== false)) {
        await this.maybeNotifyPendingReview(existingEvent);
      }
      return existingEvent;
    }
    const shouldWriteDkg = writeDkg ?? (!this.config.testMode && hasEvidenceForDkg(eventType, decoratedPayload));
    if (shouldWriteDkg) {
      const dkgStarted = Date.now();
      try {
        event.dkg = await this.dkg.writeEvent(event);
        const verifiedPublish = event.dkg?.publish;
        const publishSucceeded = verifiedPublish
          && !/^(?:failed|rejected|error)$/i.test(String(verifiedPublish.status || ''))
          && Boolean(verifiedPublish.ual || verifiedPublish.txHash || verifiedPublish.tx_hash);
        if (decoratedPayload.verified_memory_authority && !publishSucceeded) {
          Object.assign(decoratedPayload, {
            admin_verified: false,
            decision_scope: 'local_community',
            trust_basis: 'telegram_local_admin',
            verified_memory_authority: false,
            trac_backed_global_authority: false,
            publish_false_positive: false
          });
        }
        this.store.incrementMetric?.('dkg_write_count');
        this.store.incrementMetric?.('dkg_write_latency_ms_total', Date.now() - dkgStarted);
      } catch (error) {
        if (decoratedPayload.verified_memory_authority) {
          Object.assign(decoratedPayload, {
            admin_verified: false,
            decision_scope: 'local_community',
            trust_basis: 'telegram_local_admin',
            verified_memory_authority: false,
            trac_backed_global_authority: false,
            publish_false_positive: false
          });
        }
        event.dkg_error = error instanceof Error ? error.message : String(error);
        this.store.incrementMetric?.('dkg_write_failures');
      }
    } else {
      event.local_only = true;
    }
    this.store.append(event);
    if (['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'proactive_cross_group_warning', 'review_upheld', 'review_overturned', 'ban_executed', 'review_hidden', 'review_unhidden'].includes(eventType)) {
      this._reviewCache = { pending: null, watches: null, lastUpdate: 0 };
    }
    if (['risk_review_needed', 'risk_action_suppressed', 'proactive_cross_group_warning'].includes(eventType)
      && (eventType !== 'proactive_cross_group_warning' || this.config.proactiveAlertCrossGroup !== false)) {
      await this.maybeNotifyPendingReview(event);
    }
    return event;
  }

  async maybeNotifyPendingReview(event = {}) {
    const chatId = eventChatKey(event);
    if (!chatId || !this.chatPendingReviewNotificationsEnabled(chatId)) return null;
    const intervalMs = this.chatPendingReviewNotificationIntervalHours(chatId) * 60 * 60 * 1000;
    if (this.isReviewHiddenForChat(event, chatId)) return null;
    const cooldownKey = `pending-review-notice:${chatId}`;
    if (this.store.claimCooldown && !this.store.claimCooldown(cooldownKey, intervalMs)) return null;
    const last = this.lastPendingReviewNoticeAt.get(chatId) || 0;
    if (!this.store.claimCooldown && Date.now() - last < intervalMs) return null;
    const count = this.pendingReviewItems({ chatId, scope: 'current' }).length || 1;
    const reservedAt = Date.now();
    this.lastPendingReviewNoticeAt.set(chatId, reservedAt);
    const text = [
      `🛡️ ${count} pending review item${count === 1 ? '' : 's'} for this channel.`,
      `Latest: ${userMention(event.user || event.payload?.target || {})} (${event.payload?.confidence ?? 'n/a'}%).`,
      'Admins: open review queue for evidence and final decision.'
    ].join('\n');
    let sent;
    try {
      const payload = {
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: true,
        reply_markup: inlineKeyboard([
          [button('🚫 Confirm scam', callbackData('review-confirm', 'admin', shortId(event.id))), button('✅ Reject flag', callbackData('review-reject', 'admin', shortId(event.id)))],
          [button('🛡️ Open reviews', callbackData('review-list', 'admin'))]
        ])
      };
      sent = await this.callEffect('sendMessage', payload, `pending-review-notice:${event.id}`);
      this.rememberBotReply(chatId, sent, text, payload);
    } catch (error) {
      if (error?.telegramOutcomeUnknown) this.store.completeCooldown?.(cooldownKey);
      else this.store.releaseCooldown?.(cooldownKey);
      if (this.lastPendingReviewNoticeAt.get(chatId) === reservedAt) {
        if (last) this.lastPendingReviewNoticeAt.set(chatId, last);
        else this.lastPendingReviewNoticeAt.delete(chatId);
      }
      throw error;
    }
    this.store.completeCooldown?.(cooldownKey);
    if (sent?.message_id) this.reviewMessageEvents.set(`${chatId}:${sent.message_id}`, event.id);
    return sent;
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

  resolutionCoversPendingEvent(resolution = {}, event = {}) {
    if (resolution.payload?.target_event_id === event.id || resolution.payload?.report_event_id === event.id) return true;
    if (!resolution.payload?.resolves_target_pending_reviews) return false;
    const batchEventIds = resolution.payload?.review_batch_event_ids;
    if (Array.isArray(batchEventIds)) return batchEventIds.includes(event.id);
    const eventTs = Date.parse(event.timestamp || '');
    const resolutionTs = Date.parse(resolution.timestamp || '');
    if (resolutionTs < eventTs) return false;
    const batchCutoff = Date.parse(resolution.payload?.review_batch_cutoff || '');
    if (Number.isFinite(batchCutoff) && eventTs > batchCutoff) return false;
    const resolutionChat = resolution.payload?.target_chat_id || resolution.payload?.review_chat_id || resolution.chat?.id || '';
    const targetChat = eventChatKey(event);
    if (resolutionChat && targetChat && !sameChat(resolutionChat, targetChat)) return false;
    const reviewed = resolution.payload?.reviewed_target || resolution.user || {};
    const target = event.user || event.payload?.target || {};
    return sameActorTarget(reviewed, target);
  }

  targetResolutionFor(event = {}) {
    const target = event.user || event.payload?.target || {};
    if (!targetIdentityKeys(target).length) return null;
    return this.store.all().find((resolution) => {
      if (!['review_upheld', 'review_overturned', 'ban_executed'].includes(resolution.event_type)) return false;
      return this.resolutionCoversPendingEvent(resolution, event);
    }) || null;
  }

  targetResolutionForObservation(entry = {}) {
    const observedAt = Date.parse(entry.lastSeen || '');
    if (!Number.isFinite(observedAt) || !targetIdentityKeys(entry.user || {}).length) return null;
    return this.store.all().find((resolution) => {
      if (!['review_upheld', 'review_overturned', 'ban_executed'].includes(resolution.event_type)) return false;
      if (Date.parse(resolution.timestamp || '') < observedAt) return false;
      if (['review_upheld', 'review_overturned'].includes(resolution.event_type) && !resolution.payload?.resolves_target_pending_reviews) return false;
      const batchCutoff = Date.parse(resolution.payload?.review_batch_cutoff || '');
      if (Number.isFinite(batchCutoff) && observedAt > batchCutoff) return false;
      const resolutionChat = resolution.payload?.target_chat_id || resolution.payload?.review_chat_id || resolution.chat?.id || '';
      if (!resolutionChat || !entry.chat?.id || !sameChat(resolutionChat, entry.chat.id)) return false;
      const reviewed = resolution.payload?.reviewed_target || resolution.payload?.target || resolution.user || {};
      return sameActorTarget(reviewed, entry.user);
    }) || null;
  }

  legacyTargetResolutionForDuplicate(event = {}, duplicateCount = 0) {
    if (duplicateCount < 2) return null;
    const target = event.user || event.payload?.target || {};
    if (!targetIdentityKeys(target).length) return null;
    return this.store.all().find((resolution) => {
      if (resolution.event_type !== 'review_overturned') return false;
      if (Date.parse(resolution.timestamp || '') < Date.parse(event.timestamp || '')) return false;
      if (resolution.payload?.resolves_target_pending_reviews) return false;
      const reviewed = resolution.payload?.reviewed_target || resolution.user || {};
      return sameActorTarget(reviewed, target);
    }) || null;
  }

  isPendingReviewEvent(event = {}) {
    return Boolean(event?.id && !this.optimisticReviewedEventIds.has(event.id) && ['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'ban_requested_no_reply', 'ban_requested_no_rights', 'proactive_cross_group_warning'].includes(event.event_type) && !this.reviewResolutionFor(event.id) && !this.targetResolutionFor(event));
  }

  reviewHiddenEventForChat(event = {}, chatId = '') {
    const key = chatKey(chatId || eventChatKey(event));
    if (!event?.id || !key) return null;
    return [...this.store.all()].reverse().find((item) => {
      if (!['review_hidden', 'review_unhidden'].includes(item.event_type)) return false;
      if (item.payload?.target_event_id !== event.id) return false;
      return sameChat(item.payload?.review_chat_id || item.chat?.id || '', key);
    }) || null;
  }

  isReviewHiddenForChat(event = {}, chatId = '') {
    return this.reviewHiddenEventForChat(event, chatId)?.event_type === 'review_hidden';
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

  pendingReviewItems(options = {}) {
    const { chatId = '', scope = 'all', allEvents = null, includeHidden = false, hiddenOnly = false } = options || {};
    const now = Date.now();
    const CACHE_TTL = 8000; // 8 seconds — good balance for responsiveness
    const eventsSnapshot = allEvents || this.store.all();
    if (this._reviewCache.pending && (now - this._reviewCache.lastUpdate) < CACHE_TTL) {
      return this.filterPendingReviewItems(this._reviewCache.pending, chatId, scope, eventsSnapshot, { includeHidden, hiddenOnly });
    }

    const pendingTypes = new Set(['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'ban_requested_no_reply', 'ban_requested_no_rights', 'proactive_cross_group_warning']);
    const resolutionTypes = new Set(['review_upheld', 'review_overturned', 'ban_executed']);
    const reviewEvents = eventsSnapshot.filter((event) => pendingTypes.has(event.event_type));

    const candidateCounts = new Map();
    for (const event of reviewEvents) {
      const key = targetIdentityKeys(event.user || event.payload?.target || {})[0] || event.id;
      candidateCounts.set(key, (candidateCounts.get(key) || 0) + 1);
    }

    const directResolutionByEvent = new Map();
    const targetResolutions = [];
    const legacyResolutions = [];
    for (const event of eventsSnapshot) {
      if (!resolutionTypes.has(event.event_type)) continue;
      for (const id of [event.payload?.target_event_id, event.payload?.report_event_id].filter(Boolean)) directResolutionByEvent.set(id, event);
      if (!['review_upheld', 'review_overturned', 'ban_executed'].includes(event.event_type)) continue;
      const reviewed = event.payload?.reviewed_target || event.user || {};
      if (!targetIdentityKeys(reviewed).length) continue;
      if (event.event_type === 'review_overturned' && !event.payload?.resolves_target_pending_reviews) legacyResolutions.push({ event, reviewed, ts: Date.parse(event.timestamp || '') });
      if (event.payload?.resolves_target_pending_reviews) targetResolutions.push({ event, reviewed, ts: Date.parse(event.timestamp || '') });
    }

    const hasTargetResolution = (event) => {
      const target = event.user || event.payload?.target || {};
      if (!targetIdentityKeys(target).length) return false;
      return targetResolutions.some((resolution) => {
        return this.resolutionCoversPendingEvent(resolution.event, event);
      });
    };

    const hasLegacyDuplicateResolution = (event) => {
      const target = event.user || event.payload?.target || {};
      const key = targetIdentityKeys(target)[0] || '';
      if (!key || (candidateCounts.get(key) || 0) < 2) return false;
      const eventTs = Date.parse(event.timestamp || '');
      return legacyResolutions.some((resolution) => sameActorTarget(resolution.reviewed, target) && resolution.ts >= eventTs);
    };

    const items = reviewEvents
      .filter((event) => event?.id && !directResolutionByEvent.has(event.id) && !hasTargetResolution(event) && !hasLegacyDuplicateResolution(event))
      .sort((a, b) => this.reviewTierRank(b) - this.reviewTierRank(a) || Date.parse(a.timestamp) - Date.parse(b.timestamp));

    this._reviewCache.pending = items;
    this._reviewCache.lastUpdate = now;
    return this.filterPendingReviewItems(items, chatId, scope, eventsSnapshot, { includeHidden, hiddenOnly });
  }

  filterPendingReviewItems(items = [], chatId = '', scope = 'all', allEvents = null, visibility = {}) {
    const key = chatKey(chatId);
    const { includeHidden = false, hiddenOnly = false } = visibility || {};
    const eventsSnapshot = allEvents || this.store.all();
    const directResolutionByEvent = new Set();
    const targetResolutions = [];
    for (const event of eventsSnapshot) {
      if (!['review_upheld', 'review_overturned', 'ban_executed'].includes(event.event_type)) continue;
      for (const id of [event.payload?.target_event_id, event.payload?.report_event_id].filter(Boolean)) directResolutionByEvent.add(id);
      const reviewed = event.payload?.reviewed_target || event.user || {};
      if (event.payload?.resolves_target_pending_reviews && targetIdentityKeys(reviewed).length) {
        targetResolutions.push({ event, reviewed, ts: Date.parse(event.timestamp || '') });
      }
    }
    const activeItems = items.filter((event) => {
      if (!event?.id || this.optimisticReviewedEventIds.has(event.id) || directResolutionByEvent.has(event.id)) return false;
      const target = event.user || event.payload?.target || {};
      if (!targetIdentityKeys(target).length) return true;
      return !targetResolutions.some((resolution) => {
        return this.resolutionCoversPendingEvent(resolution.event, event);
      });
    });
    const scopedItems = (!key || scope === 'all') ? activeItems : activeItems.filter((event) => {
      const eventKey = eventChatKey(event);
      if (!eventKey) return scope === 'other';
      return scope === 'other' ? !sameChat(eventKey, key) : sameChat(eventKey, key);
    });
    if (!key || includeHidden) return hiddenOnly ? scopedItems.filter((event) => this.isReviewHiddenForChat(event, key)) : scopedItems;
    return scopedItems.filter((event) => hiddenOnly ? this.isReviewHiddenForChat(event, key) : !this.isReviewHiddenForChat(event, key));
  }

  falsePositiveReviewFor(target = {}, text = '', dkgIntel = {}) {
    if (!targetIdentityKeys(target).length) return null;
    return this.store.all().find((event) => {
      if (event.event_type !== 'review_overturned') return false;
      const reviewed = event.payload?.reviewed_target || {};
      const sameTarget = sameActorTarget(reviewed, target);
      const original = this.findEvent(event.payload?.target_event_id || '');
      const sameOriginalTarget = Boolean(original && sameActorTarget(original.user || original.payload?.target || {}, target));
      if (!sameTarget && !sameOriginalTarget) return false;
      const originalText = [original?.payload?.message_text, original?.payload?.evidence?.join('\n'), original?.text].filter(Boolean).join('\n');
      const originalFingerprint = textFingerprint(originalText);
      const currentFingerprint = textFingerprint(text);
      const sameEvidence = Boolean(originalFingerprint && currentFingerprint && originalFingerprint === currentFingerprint);
      const concreteAdminSafeDecision = Boolean(event.payload?.reviewed_target_key || event.payload?.reviewed_target?.id || event.payload?.reviewed_target?.username);
      if (!sameEvidence && !concreteAdminSafeDecision) return false;
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
    const tier = this.reviewEscalationTier(event);
    const prefix = tier === 'urgent' ? '🔴 URGENT ' : tier === 'elevated' ? '🟠 ELEVATED ' : '🟢 STANDARD ';
    const crossGroup = event.event_type === 'proactive_cross_group_warning' ? 'CROSS-GROUP ' : '';
    return `${index}. ${prefix}${crossGroup}${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''} | ${confidence} | ${shortId(event.id)}\n   ${escapeHtml(this.reviewSummary(event))}`;
  }

  formatWatchlist(filter = '') {
    const restrictions = this.recentRestrictions();
    const reviews = this.pendingReviewItems({ chatId: filter?.chatId || '', scope: filter?.scope || 'all' });
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

  formatReviewPanel(filter = 'flags', chatId = '') {
    if (filter === 'mutes') return this.formatWatchlist('muted');
    if (filter === 'all') return this.formatWatchlist('all');
    if (filter === 'hidden') return this.formatPendingReviews(chatId, { hiddenOnly: true });
    return this.formatPendingReviews(chatId);
  }

  pendingReviewGroups(options = {}) {
    const reviews = this.pendingReviewItems(options);
    const groups = new Map();
    for (const event of reviews) {
      const target = event.user || event.payload?.target || {};
      const key = `${eventChatKey(event) || 'legacy'}:${targetKey(target) || event.id}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(event);
    }
    return [...groups.values()];
  }

  pendingReviewGroupForEvent(event = {}) {
    const target = event.user || event.payload?.target || {};
    const key = targetKey(target);
    if (!key) return event?.id ? [event] : [];
    return this.pendingReviewItems({ chatId: eventChatKey(event), scope: eventChatKey(event) ? 'current' : 'all' }).filter((item) => eventMatchesTarget(item, target));
  }

  formatPendingReviews(chatId = '', options = {}) {
    const allEvents = this.store.all();
    const { hiddenOnly = false } = options || {};
    const reviews = this.pendingReviewItems({ chatId, scope: chatId ? 'current' : 'all', allEvents, hiddenOnly });
    const otherReviews = chatId ? this.pendingReviewItems({ chatId, scope: 'other', allEvents }) : [];
    if (!reviews.length && (hiddenOnly || !otherReviews.length)) return hiddenOnly ? 'No hidden review items for this channel.' : 'No pending review items.';
    if (!reviews.length) return `No pending review items for this channel. ${otherReviews.length} item${otherReviews.length === 1 ? '' : 's'} exist in other channels as context only.`;
    const groups = this.pendingReviewGroups({ chatId, scope: chatId ? 'current' : 'all', allEvents, hiddenOnly });
    const visibleCount = Math.min(groups.length, 5);
    const lines = groups.slice(0, 5).map((events, index) => {
      const suffix = events.length > 1 ? ` (+${events.length - 1} more)` : '';
      return `${this.formatReviewItem(events[0], index + 1)}${suffix}`;
    });
    const queueNote = groups.length > visibleCount ? `Showing the first ${visibleCount} targets. Clear a few and reopen the review panel to continue through the queue.` : 'Tap a button below to open a review item.';
    return [
      `${hiddenOnly ? 'Hidden' : 'Latest pending'} review items for this channel (${reviews.length})`,
      ...lines,
      '',
      queueNote,
      ...(!hiddenOnly && otherReviews.length ? ['', `Other-channel context: ${otherReviews.length} pending item${otherReviews.length === 1 ? '' : 's'} not actionable here.`] : [])
    ].join('\n');
  }

  pendingReviewsKeyboard(requesterId, chatId = '', options = {}) {
    const { hiddenOnly = false } = options || {};
    const groups = this.pendingReviewGroups({ chatId, scope: chatId ? 'current' : 'all', hiddenOnly }).slice(0, 5);
    const rows = groups.flatMap((events, index) => {
      const event = events[0];
      const label = `🔎 ${index + 1}. ${displayName(event.user || event.payload?.target || {})}`.slice(0, 28);
      return [[button(label, callbackData('review-open', requesterId, shortId(event.id)))]];
    });
    rows.push(...this.mainNavKeyboard(requesterId, { includeReview: false }));
    return rows;
  }

  reviewPanelKeyboard(requesterId, filter = 'flags', chatId = '') {
    const rows = [[
      button('🚨 Reviews', callbackData('review-tab', requesterId, 'flags')),
      button('🙈 Hidden', callbackData('review-tab', requesterId, 'hidden')),
      button('🔇 Mutes', callbackData('review-tab', requesterId, 'mutes'))
    ]];
    if (filter === 'flags') rows.push(...this.pendingReviewsKeyboard(requesterId, chatId).filter((row) => row[0]?.callback_data?.includes('review-open')));
    if (filter === 'hidden') rows.push(...this.pendingReviewsKeyboard(requesterId, chatId, { hiddenOnly: true }).filter((row) => row[0]?.callback_data?.includes('review-open')));
    rows.push(...this.mainNavKeyboard(requesterId, { includeReview: false }));
    return rows;
  }

  reviewActionKeyboard(requesterId, eventId) {
    return [
      [
        button('🚫 Confirm scam', callbackData('review-confirm', requesterId, shortId(eventId))),
        button('✅ Reject flag', callbackData('review-reject', requesterId, shortId(eventId)))
      ],
      [button('🙈 Hide here', callbackData('review-hide', requesterId, shortId(eventId)))],
      [button('↩️ Back to queue', callbackData('review-list', requesterId))]
    ];
  }

  hiddenReviewActionKeyboard(requesterId, eventId) {
    return [
      [button('👁️ Unhide here', callbackData('review-unhide', requesterId, shortId(eventId)))],
      [button('↩️ Back to hidden', callbackData('review-tab', requesterId, 'hidden'))]
    ];
  }

  warningActionKeyboard(eventId, target = {}) {
    const id = shortId(eventId);
    const rows = [
      [button('🚫 Ban user', callbackData('warn-ban', 'admin', id)), button('✅ Mark safe', callbackData('warn-safe', 'admin', id))],
      [button('🔎 Review', callbackData('review-open', 'admin', id)), button('✖️ Close', callbackData('close', 'admin'))]
    ];
    if (target.id) rows.unshift([urlButton('👤 Open profile', `tg://user?id=${encodeURIComponent(target.id)}`)]);
    return rows;
  }

  formatPriorCommunityWarning(warningEvent = {}, targetUser = {}) {
    const priorCount = (warningEvent.payload?.prior_admin_events || []).length;
    const riskConf = warningEvent.payload?.current_risk?.confidence || '?';
    const target = targetUser || warningEvent.payload?.target || {};
    return [
      '⚠️ Prior community alert',
      '',
      plainUserLabel(target),
      `Risk: ${escapeHtml(String(riskConf))}%`,
      `Prior reviewed evidence: ${plural(priorCount, 'record')} in TRACaBot context memory.`,
      '',
      'Admins: use /start to review, or choose an action below.'
    ].join('\n');
  }

  async sendPendingReviews(message, extra = {}) {
    const requesterId = message.from?.id || message.from?.username || '';
    const text = this.formatPendingReviews(message.chat?.id);
    const rows = this.pendingReviewsKeyboard(requesterId, message.chat?.id);
    const sent = await this.sendInteractiveReply(message.chat.id, text, rows, { reply_to_message_id: message.message_id, parse_mode: 'HTML', disable_web_page_preview: true, ...extra });
    this.lastPendingReviewsByChat.set(String(message.chat.id), this.pendingReviewGroups({ chatId: message.chat?.id, scope: 'current' }).slice(0, 15));
    return sent;
  }

  formatReviewDetail(event) {
    const target = event.user || event.payload?.target || {};
    const evidence = (event.payload?.evidence || []).slice(0, 5).map((item) => `- ${escapeHtml(item)}`).join('\n') || '- No evidence recorded.';
    const sourceLink = sourceMessageLink(event);
    const dkgRefs = (event.payload?.dkg_evidence || []).slice(0, 3).map((item) => item?.ual || item?.eventId || '').filter(Boolean);
    const sourceLines = [
      sourceLink ? `- <a href="${escapeHtml(sourceLink)}">Source message</a>` : '',
      ...dkgRefs.map((ref) => `- ${escapeHtml(ref)}`),
      event.dkg?.ual ? `- ${escapeHtml(event.dkg.ual)}` : ''
    ].filter(Boolean);
    return [
      `Review ${shortId(event.id)}`,
      `${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}`,
      `Confidence: ${event.payload?.confidence ?? 0}% | Type: ${escapeHtml(event.payload?.scam_type || event.event_type)}`,
      `Priority: ${this.reviewEscalationTier(event).toUpperCase()} | Waiting: ${ageLabel(event.timestamp)}`,
      `Channel: ${escapeHtml(event.payload?.target_chat_title || event.chat?.title || event.payload?.target_chat_id || event.chat?.id || 'unknown')}`,
      '',
      'Evidence:',
      evidence,
      ...(sourceLines.length ? ['', 'Sources:', ...sourceLines] : []),
      '',
      'Choose the final admin decision below.'
    ].join('\n');
  }

  formatWhy(eventId = '', chatId = '') {
    const event = this.findEvent(eventId);
    if (!event || (chatId && !sameChat(eventChatKey(event), chatId))) {
      return `No local tracabot event found for ${eventId} in this chat. Open Stats > Sources for recent DKG receipts.`;
    }
    const risk = event.payload || {};
    const safe = (value = '') => this.redactArtifactText(String(value)).replace(/https?:\/\/\S+/gi, '[url]');
    const evidence = risk.evidence?.length ? risk.evidence.slice(0, 8).map((item) => `- ${safe(item)}`).join('\n') : '- No evidence recorded.';
    const dkgRefs = risk.dkg_evidence?.length ? risk.dkg_evidence.slice(0, 4).map((item) => `- ${safe(item.ual || 'DKG')}${item.eventId ? ` event ${safe(item.eventId)}` : ''}`).join('\n') : '- No DKG source refs on this event.';
    const action = event.event_type;
    const ref = formatDkgReference(event) || event.id;
    const dkg = event.dkg || {};
    const dkgLines = [
      event.local_only ? '- Stored locally only.' : '',
      (event.dkg_error || risk.dkg_error) ? '- DKG write error: present (details redacted).' : '',
      dkg.ual ? `- Shared Memory graph: ${safe(dkg.ual)}` : '',
      dkg.shareOperation ? `- Share operation: ${safe(dkg.shareOperation)}` : '',
      dkg.subject ? `- Subject: ${safe(dkg.subject)}` : '',
      dkg.publish ? `- Context Graph publish: ${safe(dkg.publish.status || 'requested')}` : '',
      dkg.publish_error ? '- Context Graph publish error: present (details redacted).' : '',
      risk.publication_status ? `- Publication status: ${risk.publication_status}` : '',
      risk.lifecycle_stage ? `- Lifecycle stage: ${risk.lifecycle_stage}` : '',
      risk.review_decision ? `- Review decision: ${risk.review_decision}` : '',
      risk.report_decision ? `- Report decision: ${risk.report_decision}` : '',
      risk.campaign_key ? `- Campaign key: ${safe(risk.campaign_key)}` : '',
      risk.evidence_root_ids?.length ? `- Evidence roots: ${risk.evidence_root_ids.slice(0, 6).map(safe).join(', ')}` : ''
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
        'Add TRACaBot as a group admin: normal admin bans are logged automatically. /ban and /mute remain optional bot-driven actions.'
      ].join('\n');
    }

    const lines = ['👮 Enforcement', '', 'Recent actions'];

    for (const ev of enforcementEvents) {
      const target = ev.user || ev.payload?.target || {};
      const name = userMention(target) || target.id || 'unknown';
      const actionType = ev.event_type === 'ban_executed' ? 'BAN' : ev.event_type === 'restrict_executed' ? 'RESTRICT' : 'UPHELD REVIEW';
      const nativeAdmin = ev.payload?.enforcement_observed_from === 'telegram_chat_member';
      const actor = ev.payload?.performed_by?.username ? `@${String(ev.payload.performed_by.username).replace(/^@/, '')}` : '';
      const reason = ev.payload?.reason_provided === false
        ? 'reason not provided'
        : (ev.payload?.reason || ev.payload?.evidence?.[0] || 'admin action').slice(0, 120);
      const contextCategory = ev.payload?.ban_context?.category || ev.payload?.context_category || '';
      const contextNote = nativeAdmin && contextCategory && contextCategory !== 'unknown'
        ? `context ${contextCategory} (unverified)`
        : '';

      const summary = [nativeAdmin ? 'native admin' : '', actor, reason, contextNote].filter(Boolean).join(' · ');

      const time = ageLabel(ev.timestamp);
      lines.push(`• ${actionType} ${name}`);
      lines.push(`  ${escapeHtml(summary)} · ${time}`);
    }

    lines.push('', 'Use Reviews to handle pending items. Event IDs stay in Sources for admins who need receipts.');
    return lines.join('\n');
  }

  statsKeyboard(requesterId) {
    return [
      [button('📎 Sources', callbackData('stats-sources', requesterId)), button('🧬 Campaigns', callbackData('campaigns', requesterId)), button('👮 Admin log', callbackData('banlist', requesterId))],
      ...this.mainNavKeyboard(requesterId)
    ];
  }

  banlistKeyboard(requesterId) {
    return [
      [button('🛡️ Pending reviews', callbackData('review-list', requesterId)), button('🔇 Mutes', callbackData('review-tab', requesterId, 'mutes'))],
      ...this.mainNavKeyboard(requesterId, { includeReview: false })
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

  dashboardKeyboard(requesterId, { includeControls = false } = {}) {
    const rows = [
      [button('📊 Stats', callbackData('stats', requesterId)), button('🛡️ Reviews', callbackData('review-list', requesterId))],
      [button('❔ Help', callbackData('help', requesterId)), button('🧾 Explain event', callbackData('why', requesterId))],
      [button('👮 Admin log', callbackData('banlist', requesterId)), button('⚙️ Settings', callbackData('settings', requesterId))]
    ];
    if (includeControls) {
      rows.unshift(
        [button('🛡️ Protection controls', callbackData('controls', requesterId)), button('🩺 Status', callbackData('controls-status', requesterId))],
        [button('🚨 Recent automatic bans', callbackData('controls-recent', requesterId)), button('📣 Appeals', callbackData('appeals', requesterId))]
      );
    }
    rows.push([button('✖️ Close', callbackData('close', requesterId))]);
    return rows;
  }

  settingsText(chatId) {
    const challengeOn = this.chatJoinChallengeEnabled(chatId);
    const languageOn = this.chatConversationalEnabled(chatId);
    const reviewNoticesOn = this.chatPendingReviewNotificationsEnabled(chatId);
    const reviewNoticeHours = this.chatPendingReviewNotificationIntervalHours(chatId);
    const policy = this.chatPolicyProfile(chatId);
    return [
      '⚙️ Tracabot settings',
      '',
      `🚪 Join challenge: ${challengeOn ? '✅ on' : '⚪ off'}`,
      `🧠 Natural language: ${languageOn ? '✅ on' : '⚪ off'}`,
      `🛡️ Review notifications: ${reviewNoticesOn ? '✅ on' : '⚪ off'}`,
      `⏱️ Review notification interval: ${reviewNoticeHours}h`,
      `🎚️ Protection profile: ${policy}`,
      `Campaign policies: ${CAMPAIGN_POLICIES.filter((item) => this.chatCampaignPolicyEnabled(chatId, item.id)).map((item) => item.label).join(', ') || 'none (opt-in)'}`,
      '',
      'Tap a toggle below to switch the setting for this chat.'
    ].join('\n');
  }

  settingsKeyboard(requesterId, chatId = '') {
    const challengeOn = this.chatJoinChallengeEnabled(chatId);
    const languageOn = this.chatConversationalEnabled(chatId);
    const reviewNoticesOn = this.chatPendingReviewNotificationsEnabled(chatId);
    const reviewNoticeHours = this.chatPendingReviewNotificationIntervalHours(chatId);
    const nextHours = reviewNoticeHours === 6 ? 12 : reviewNoticeHours === 12 ? 24 : 6;
    const policy = this.chatPolicyProfile(chatId);
    const nextPolicy = policy === 'balanced' ? 'strict' : policy === 'strict' ? 'monitor' : 'balanced';
    return [
      [button(`${challengeOn ? '✅' : '⚪'} Join challenge`, callbackData('challenge-set', requesterId, challengeOn ? 'off' : 'on')), button(`${languageOn ? '✅' : '⚪'} Natural language`, callbackData('conversation-set', requesterId, languageOn ? 'off' : 'on'))],
      [button(`${reviewNoticesOn ? '✅' : '⚪'} Review notices`, callbackData('review-notice-set', requesterId, reviewNoticesOn ? 'off' : 'on')), button(`⏱️ ${reviewNoticeHours}h`, callbackData('review-notice-interval', requesterId, String(nextHours)))],
      [button(`🎚️ ${policy}`, callbackData('policy-profile', requesterId, nextPolicy))],
      [button('Campaign policies', callbackData('campaign-settings', requesterId))],
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
      .filter((item) => item.events.length >= 2 && item.affectedCommunities.length >= 2)
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
      ? `${reviews.length} admin reviews waiting across local memory. Open Reviews for this channel queue.`
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
      const event = await this.record('appeal_submitted', message, this.appealPayload(message, reviewedEvent.id, reason, {
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        implicit_detection: true,
        detection_method: 'numbered_review_list_reply',
        evidence: [`non-admin review-list reply logged as appeal for ${reviewedEvent.id}: ${reason}`]
      }));
      await this.sendCommandReply(message.chat.id, `📝 Appeal logged for ${userMention(reviewedTarget)}. Receipt: ${escapeHtml(event.payload.appeal_receipt_id)}. Admins can confirm or reject the scam flag.`, { reply_to_message_id: message.message_id, parse_mode: 'HTML' });
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

    let targetEvents = selectedGroup?.length ? selectedGroup : target ? this.pendingReviewItems({ chatId: message.chat?.id, scope: 'current' }).filter((event) => eventMatchesTarget(event, target)) : [];

    if (extraEvent && !targetEvents.some(e => e.id === extraEvent.id)) {
      targetEvents = [extraEvent, ...targetEvents];
    }

    if (!targetEvents.length) return false;
    const reason = messageText(message).replace(/@(?:tracabot|tracethembot)\b/ig, '').trim() || 'natural-language false positive review';
    const { reviewed, artifactWrites } = await this.recordReviewDecisionForEvents(message, targetEvents, 'reject', reason, { target, evidencePrefix: 'natural language admin rejected scam flag' });
    const displayTarget = reviewed[0]?.user || reviewed[0]?.payload?.target || target;
    await this.sendCommandReply(message.chat.id, `✅ Marked ${userMention(displayTarget)} as false positive and cleared ${reviewed.length} pending review${reviewed.length === 1 ? '' : 's'}.`, { reply_to_message_id: message.message_id, parse_mode: 'HTML' });
    for (const { reviewedEvent, event } of artifactWrites) {
      this.recordConversationArtifact(message, { risk: { confidence: 80, local_confidence: 80, scam_type: 'false_positive', evidence: [`false positive correction for ${reviewedEvent.id}: ${reason}`] }, text: reason, artifactKind: 'false_positive_signal', conversationRole: 'moderator', sourceEventIds: [reviewedEvent.id, event.id], operatorNote: reason, forceDkg: true })
        .catch((error) => console.error(`False positive artifact write failed after review ${event.id}: ${error instanceof Error ? error.message : String(error)}`));
    }
    return true;
  }

  async recordReviewDecisionForEvents(message, events = [], decision = 'reject', reason = '', { target = null, evidencePrefix = 'admin reviewed scam flag', extraPayload = {}, reviewChatId = '', idempotencyKey = '', repairBatch = false } = {}) {
    const unique = new Map();
    for (const event of events) {
      if (event?.id && (repairBatch || this.isPendingReviewEvent(event))) unique.set(event.id, event);
    }
    const reviewer = actorFromMessage(message);
    const reviewEventType = decision === 'reject' ? 'review_overturned' : 'review_upheld';
    const reviewDecision = decision === 'reject' ? 'reject' : 'confirm';
    const reviewBatchEventIds = Array.isArray(extraPayload.review_batch_event_ids) && extraPayload.review_batch_event_ids.length
      ? [...new Set(extraPayload.review_batch_event_ids)].sort()
      : [...unique.keys()].sort();
    const reviewBatchCutoff = extraPayload.review_batch_cutoff || new Date().toISOString();
    const artifactWrites = await Promise.all([...unique.values()].map(async (reviewedEvent) => {
      const reviewedTarget = reviewedEvent?.payload?.reviewed_target || reviewedEvent?.user || reviewedEvent?.payload?.target || target || {};
      const targetChatId = eventChatKey(reviewedEvent);
      const actualReviewChatId = chatKey(reviewChatId || message.chat?.id || '');
      const sameChannelReview = !targetChatId || !actualReviewChatId || sameChat(targetChatId, actualReviewChatId);
      const event = await this.record(reviewEventType, message, {
        target_event_id: reviewedEvent.id,
        review_decision: reviewDecision,
        reason,
        reviewer,
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        target_chat_id: targetChatId,
        target_chat_title: reviewedEvent.payload?.target_chat_title || reviewedEvent.chat?.title || '',
        target_chat_type: reviewedEvent.payload?.target_chat_type || reviewedEvent.chat?.type || '',
        review_chat_id: actualReviewChatId,
        review_chat_title: message.chat?.title || '',
        review_scope: sameChannelReview ? 'same_channel' : 'cross_channel',
        review_jurisdiction: sameChannelReview ? 'local_channel' : 'context_only',
        review_weight: sameChannelReview ? 1 : 0.5,
        decision_threshold: sameChannelReview ? 1 : 2,
        local_approval: sameChannelReview && decision !== 'reject',
        approval_source: 'telegram_admin_review',
        ...this.reviewTrustPayload(reviewer),
        ...extraPayload,
        review_batch_event_ids: reviewBatchEventIds,
        review_batch_cutoff: reviewBatchCutoff,
        false_positive_reason: decision === 'reject' ? reason : '',
        resolves_target_pending_reviews: sameChannelReview,
        evidence: [`${evidencePrefix} ${reviewedEvent.id}: ${reason}`]
      }, { idempotencyKey: idempotencyKey ? `${idempotencyKey}:${reviewedEvent.id}` : '' });
      return { reviewedEvent, event };
    }));
    return { reviewed: [...unique.values()], artifactWrites };
  }

  recordReviewDecisionInBackground(message, events = [], decision = 'reject', reason = '', options = {}) {
    const eventIds = [...new Set(events.filter((event) => event?.id && this.isPendingReviewEvent(event)).map((event) => event.id))];
    const selectedEvents = events.filter((event) => eventIds.includes(event?.id));
    const expectedCount = eventIds.length;
    this._reviewCache = { pending: null, watches: null, lastUpdate: 0 };
    const write = this.recordReviewDecisionForEvents(message, selectedEvents, decision, reason, options);
    for (const id of eventIds) this.optimisticReviewedEventIds.add(id);
    write
      .then(() => { this._reviewCache = { pending: null, watches: null, lastUpdate: 0 }; })
      .catch((error) => {
        for (const id of eventIds) this.optimisticReviewedEventIds.delete(id);
        this._reviewCache = { pending: null, watches: null, lastUpdate: 0 };
        console.error(`Review evidence write failed for ${expectedCount || 'unknown'} item(s): ${error instanceof Error ? error.message : String(error)}`);
      });
    return expectedCount;
  }

  async recordBanEvidenceInBackground(message, target, risk = {}, reason = 'admin requested ban', extra = {}) {
    const payload = {
      ...risk,
      reason,
      reason_provided: extra.reasonProvided === true,
      consent_to_share: this.config.autoPromoteEvidence !== false && this.config.dkgWrites !== false,
      enforcement_action: 'ban',
      enforcement_observed_from: extra.observedFrom || (extra.source === 'manual /ban command' ? 'telegram_bot_command' : 'automated_enforcement'),
      performed_by: extra.performedBy || null,
      source: extra.source || 'admin_ban_action',
      replied_message_id: extra.repliedMessageId || '',
      replied_message_deleted: Boolean(extra.repliedMessageDeleted),
      replied_message_delete_error: extra.repliedMessageDeleteError || '',
      deleted_message_count: Number(extra.deletedMessageCount || 0),
      delete_attempt_count: Number(extra.deleteAttemptCount || 0),
      confidence: Math.max(Number(risk.confidence || 0), this.config.actionThreshold || 85),
      admin_verified: extra.adminVerified ?? true,
      scam_type: risk.scam_type || 'admin_action',
      evidence: [...(risk.evidence || []), reason, extra.sangmataEvidence || '', extra.deletedMessageCount ? `${extra.deletedMessageCount} message${extra.deletedMessageCount === 1 ? '' : 's'} deleted during ban cleanup` : extra.repliedMessageId ? 'replied scam message deletion unavailable' : '', extra.source || 'admin ban action'].filter(Boolean)
    };
    const event = await this.record('ban_executed', { ...message, from: target }, payload, {
      writeDkg: false,
      idempotencyKey: extra.idempotencyKey || ''
    });
    Promise.resolve()
      .then(async () => {
        if (this.config.autoPromoteEvidence !== false && this.config.dkgWrites !== false && !this.config.testMode && hasEvidenceForDkg('ban_executed', payload)) {
          const dkgStarted = Date.now();
          try {
            await this.dkg.writeEvent(event);
            this.store.incrementMetric?.('dkg_write_count');
            this.store.incrementMetric?.('dkg_write_latency_ms_total', Date.now() - dkgStarted);
          } catch (error) {
            this.store.incrementMetric?.('dkg_write_failures');
            console.error(`Ban evidence DKG write failed for ${target?.id || target?.username || 'target'}: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
        await this.maybeRecordCampaign({ ...message, from: target, text: reason }, risk);
      })
      .catch((error) => console.error(`Ban evidence background work failed for ${target?.id || target?.username || 'target'}: ${error instanceof Error ? error.message : String(error)}`));
    return event;
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
    return `commit:${createHash('sha256').update(basis).digest('hex').slice(0, 24)}`;
  }

  async recordConversationArtifact(message, { risk = {}, text = '', artifactKind = 'conversation_artifact', conversationRole = 'observer', sourceEventIds = [], operatorNote = '', forceDkg = false } = {}) {
    if (this.config.wmArtifacts === false) return null;
    const rawText = boundedText(text || message.text || '', this.config.wmArtifactMaxTextChars || 700);
    // Skip ordinary conversation before allocating DKG Working Memory.
    const domains = risk.domains?.length ? risk.domains : extractDomains(rawText);
    const wallets = risk.wallets?.length ? risk.wallets : extractWallets(rawText);
    const patterns = risk.patterns?.length ? risk.patterns : extractPatterns(rawText);
    const quality = this.artifactQuality({ risk: { ...risk, domains, wallets, patterns }, text: rawText, artifactKind });
    const confidence = Number(risk.local_confidence || risk.confidence || 0);
    const stageCandidate = forceDkg || (artifactKind !== 'benign_conversation_flow' && (
      confidence >= 40 || domains.length > 0 || wallets.length > 0 || patterns.length > 0
      || /\b(?:phish|airdrop|verify wallet|fake support|gambling)\b/i.test(rawText)
    ));
    const useful = forceDkg || quality >= 40 || confidence >= (this.config.wmArtifactMinConfidence || 40) || domains.length || wallets.length || patterns.length;
    if (!useful) return null;
    const commitStamped = forceDkg;
    const commitReceiptId = commitStamped ? this.commitReceiptId({ artifactKind, quality, risk, sourceEventIds, text: rawText }) : '';
    const normalized = this.redactArtifactText(rawText).toLowerCase().replace(/https?:\/\/\S+/g, '[url]').replace(/\s+/g, ' ').trim();
    const event = await this.record('conversation_artifact', message, {
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
      source_message_id: message.message_id || '',
      expires_at: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(),
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
    if (stageCandidate && !commitStamped && !this.config.testMode && this.config.dkgWrites !== false && typeof this.dkg.stageConversationArtifact === 'function') {
      try {
        event.wm = await this.dkg.stageConversationArtifact(event);
      } catch (error) {
        event.wm_error = error instanceof Error ? error.message : String(error);
      }
    }
    return event;
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
      else await this.sendInteractiveReply(chatId, this.formatReviewPanel('mutes', chatId), this.reviewPanelKeyboard(message.from?.id || message.from?.username || '', 'mutes', chatId), { ...replyOptions, parse_mode: 'HTML', disable_web_page_preview: true });
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
        const action = AGENT_ACTIONS.has(String(parsed.action || '')) ? String(parsed.action) : 'general_on_topic';
        return {
          action,
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
      const targetEvents = this.pendingReviewItems({ chatId, scope: 'current' }).filter((event) => eventMatchesTarget(event, reviewedTarget));
      if (targetEvent && !targetEvents.some((event) => event.id === targetEvent.id)) targetEvents.unshift(targetEvent);
      const { artifactWrites } = await this.recordReviewDecisionForEvents(message, targetEvents, classified.decision, reason, {
        target: reviewedTarget,
        reviewChatId: chatId,
        evidencePrefix: `LLM classified admin alert reply as ${classified.decision}`,
        extraPayload: {
          implicit_detection: true,
          detection_method: 'llm_alert_reply_classifier',
          llm_intent: classified.intent,
          llm_confidence: classified.confidence,
          original_flag_event: targetEvent.id
        }
      });
      if (classified.decision === 'reject') {
        for (const { reviewedEvent, event } of artifactWrites) {
          this.recordConversationArtifact(message, { risk: { confidence: 80, local_confidence: 80, scam_type: 'false_positive', evidence: [`false positive correction for ${reviewedEvent.id}: ${reason}`] }, text: reason, artifactKind: 'false_positive_signal', conversationRole: 'moderator', sourceEventIds: [reviewedEvent.id, event.id], operatorNote: reason, forceDkg: true })
            .catch((error) => console.error(`False positive artifact write failed after alert reply ${event.id}: ${error instanceof Error ? error.message : String(error)}`));
        }
      }
      const verb = classified.decision === 'reject' ? 'Rejected' : 'Confirmed';
      const suffix = classified.user_reply ? escapeHtml(classified.user_reply) : `${verb} the scam flag for ${userMention(reviewedTarget)}.`;
      await this.sendCommandReply(chatId, `✅ ${suffix}`, { ...replyOptions, parse_mode: 'HTML' });
      return true;
    }

    if (trusted && classified.intent === 'admin_review' && classified.decision && !explicitAdminDecision) {
      await this.sendEphemeral(chatId, 'I need an explicit verdict before writing review memory. Reply “confirm scam” or “reject flag” to this alert, or open Reviews from /start.', replyOptions);
      return true;
    }

    if (!trusted && (classified.intent === 'appeal' || classified.decision === 'reject')) {
      const event = await this.record('appeal_submitted', message, this.appealPayload(message, targetEvent.id, reason, {
        reviewed_target: reviewedTarget,
        reviewed_target_key: targetKey(reviewedTarget),
        implicit_detection: true,
        detection_method: 'llm_alert_reply_classifier',
        llm_intent: classified.intent,
        llm_confidence: classified.confidence,
        original_flag_event: targetEvent.id,
        evidence: [`LLM classified non-admin alert reply as appeal for ${targetEvent.id}: ${reason}`]
      }));
      await this.sendCommandReply(chatId, classified.user_reply ? `${escapeHtml(classified.user_reply)}\nReceipt: ${escapeHtml(event.payload.appeal_receipt_id)}` : `📝 Appeal logged for ${userMention(reviewedTarget)}. Receipt: ${escapeHtml(event.payload.appeal_receipt_id)}. Admins can confirm or reject the scam flag.`, { ...replyOptions, parse_mode: 'HTML' });
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
        await this.sendInteractiveReply(chatId, this.formatReviewPanel(filter, chatId), this.reviewPanelKeyboard(message.from?.id || message.from?.username || '', filter, chatId), { ...replyOptions, parse_mode: 'HTML', disable_web_page_preview: true });
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
      if (!trusted && !await this.isTrustedModerator(message)) {
        await this.sendInteractiveReply(chatId, '⚠️ Event explanations are restricted to configured admins or Telegram chat admins.', this.mainNavKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
        return { handled: true, denied: true };
      }
      const eventId = parameters.event_id || parameters.eventId || '';
      const svc = getSkillService();
      if (svc && eventId) {
        svc.explainEvent({ eventId, chatId });
      }
      await this.sendInteractiveReply(chatId, this.formatWhy(eventId, chatId), this.mainNavKeyboard(message.from?.id || message.from?.username || ''), replyOptions);
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
        const event = await this.record('appeal_submitted', message, this.appealPayload(message, targetEventId, reason, {
          implicit_detection: true,
          detection_method: 'llm_context_reply_to_flag',
          original_flag_event: targetEventId
        }));
        await this.sendEphemeral(chatId, `Appeal recorded for event ${shortId(targetEventId)}. Receipt: ${event.payload.appeal_receipt_id}. Admins will review.`, replyOptions);
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
      const reviewedTarget = targetEvent.user || targetEvent.payload?.target || {};
      const targetEvents = this.pendingReviewItems({ chatId, scope: 'current' }).filter((event) => eventMatchesTarget(event, reviewedTarget));
      if (!targetEvents.some((event) => event.id === targetEvent.id)) targetEvents.unshift(targetEvent);
      const { reviewed, artifactWrites } = await this.recordReviewDecisionForEvents(message, targetEvents, decision, reason, {
        target: reviewedTarget,
        reviewChatId: chatId,
        evidencePrefix: 'LLM context admin review',
        extraPayload: {
          implicit_detection: true,
          detection_method: 'llm_context_after_flag',
          moderator: actorFromMessage(message)
        }
      });
      if (decision === 'reject') {
        for (const { reviewedEvent, event } of artifactWrites) {
          this.recordConversationArtifact(message, { risk: { confidence: 80, local_confidence: 80, scam_type: 'false_positive', evidence: [`false positive correction for ${reviewedEvent.id}: ${reason}`] }, text: reason, artifactKind: 'false_positive_signal', conversationRole: 'moderator', sourceEventIds: [reviewedEvent.id, event.id], operatorNote: reason, forceDkg: true })
            .catch((error) => console.error(`False positive artifact write failed after LLM review ${event.id}: ${error instanceof Error ? error.message : String(error)}`));
        }
      }

      const msg = decision === 'reject'
        ? `Rejected the scam flag for ${shortId(eventId)} and cleared ${reviewed.length} pending review${reviewed.length === 1 ? '' : 's'}. Correction recorded.`
        : `Confirmed the scam flag for ${shortId(eventId)} and cleared ${reviewed.length} pending review${reviewed.length === 1 ? '' : 's'}.`;
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

  knownCampaignPatterns() {
    const configured = (this.config.knownCampaignPatterns || []).map(normalizeCampaignLabel).filter(Boolean);
    return [...new Set([...DEFAULT_KNOWN_CAMPAIGN_PATTERNS, ...configured])];
  }

  /**
   * Count prior ban_executed roots that share this target's id or campaign-style aliases
   * (e.g. repeated "BC GAME" renames with different Telegram IDs).
   */
  localBanRootsForTarget(target = {}) {
    const id = target?.id ? String(target.id) : '';
    const patterns = this.knownCampaignPatterns();
    const campaignFingerprint = matchKnownCampaignFingerprint(target, patterns);
    const events = this.store.all().filter((event) => event.event_type === 'ban_executed'
      && event.payload?.campaign_root_eligible !== false);
    const matched = [];
    for (const event of events) {
      const user = event.user || event.payload?.target || {};
      const eventId = user.id ? String(user.id) : '';
      if (id && eventId && id === eventId) {
        matched.push(event);
        continue;
      }
      if (!campaignFingerprint) continue;
      if (event.payload?.admin_verified !== true) continue;
      const eventFingerprint = matchKnownCampaignFingerprint({
        ...user,
        label: user.label || event.payload?.campaign_label || event.payload?.campaign_key || ''
      }, patterns);
      if (eventFingerprint?.pattern === campaignFingerprint.pattern) {
        matched.push(event);
      }
    }
    return matched;
  }

  priorIdentityForTarget(chat = {}, target = {}) {
    if (!chat?.id || !target?.id) return null;
    const current = new Set(actorAliases(target).map(normalizeCampaignLabel).filter(Boolean));
    const events = this.store.all().toReversed();
    for (const event of events) {
      if (String(event.chat?.id || '') !== String(chat.id)) continue;
      if (!String(event.event_type || '').startsWith('join_challenge_')) continue;
      const user = event.user || event.payload?.target || {};
      if (String(user.id || '') !== String(target.id)) continue;
      const labels = [
        [user.first_name, user.last_name].filter(Boolean).join(' '),
        user.username,
        user.label
      ].filter(Boolean);
      const priorLabel = labels.find((label) => {
        const normalized = normalizeCampaignLabel(label);
        return normalized && !current.has(normalized);
      });
      if (priorLabel) return { user, label: priorLabel, eventId: event.id };
    }
    return null;
  }

  async assess(message, targetUser = actorFromMessage(message), text = message.text || '') {
    const bounded = boundedText(text);
    const policy = this.chatPolicy(message.chat?.id);
    this.rememberUser(message.chat, targetUser, bounded);
    const aliases = actorAliases(targetUser);
    const campaignFingerprint = matchKnownCampaignFingerprint(targetUser, this.knownCampaignPatterns());
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: targetUser.username, userId: targetUser.id, aliases, text: bounded });

    // Phase 4: Check for prior high-severity admin actions on this actor across communities
    const adminHistory = (typeof this.dkg.queryAdminHistoryForActor === 'function')
      ? await this.dkg.queryAdminHistoryForActor({
          userId: targetUser.id,
          username: targetUser.username,
          aliases
        }).catch(() => ({ hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] }))
      : { hasPriorAdminAction: false, hasPriorFalsePositive: false, events: [], falsePositiveEvents: [] };
    const campaignHistory = campaignFingerprint && typeof this.dkg.queryCampaignModerationRoots === 'function'
      ? await this.dkg.queryCampaignModerationRoots({
          fingerprints: [campaignFingerprint.pattern, campaignFingerprint.matchedLabel]
        }).catch(() => ({ events: [] }))
      : { events: [] };

    const graphFalsePositiveReview = adminHistory.hasPriorFalsePositive ? { id: adminHistory.falsePositiveEvents?.[0]?.eventId || 'context-graph-false-positive' } : null;
    const localFalsePositiveReview = this.falsePositiveReviewFor(targetUser, bounded, dkgIntel);

    if (!graphFalsePositiveReview && !localFalsePositiveReview && campaignHistory.events?.length) {
      dkgIntel.evidence = dkgIntel.evidence || [];
      const existingEventIds = new Set(dkgIntel.evidence.map((item) => item?.eventId).filter(Boolean));
      for (const event of campaignHistory.events) {
        if (existingEventIds.has(event.eventId)) continue;
        dkgIntel.evidence.push(event);
        existingEventIds.add(event.eventId);
      }
      dkgIntel.riskScore = Math.max(
        Number(dkgIntel.riskScore || 0),
        ...campaignHistory.events.map((event) => Number(event.confidence || 0))
      );
    }

    if (!graphFalsePositiveReview && !localFalsePositiveReview && adminHistory.hasPriorAdminAction) {
      dkgIntel.evidence = dkgIntel.evidence || [];
      dkgIntel.evidence.push('Prior admin action/sentence found in Tracabot Context Graph for this actor');
      dkgIntel.riskScore = Math.max(dkgIntel.riskScore || 0, 75);

      // Create a real proactive cross-group alert when risk is meaningful
      const currentRisk = combineRisk({ analysis: { confidence: 0 }, dkgIntel, threshold: policy.actionThreshold });
      if (currentRisk.confidence >= policy.warnThreshold) {
        const existingPriorAdminAlert = [...this.store.all()].reverse().find((item) =>
          item.event_type === 'proactive_cross_group_warning'
          && sameChat(eventChatKey(item), message.chat?.id)
          && eventMatchesTarget(item, targetUser)
          && this.isPendingReviewEvent(item)
        );
        if (!existingPriorAdminAlert) {
          await this.record('proactive_cross_group_warning', message, {
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
        }

      }
    }
    const adminUsernames = (await this.adminIdentities(message.chat.id)).filter((id) => !/^\d+$/.test(id));
    const renameCopycat = this.adminRenameCopycat(message.chat, targetUser, adminUsernames);
    const falsePositiveReview = localFalsePositiveReview || graphFalsePositiveReview;
    const effectiveIntel = falsePositiveReview ? { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: [], evidence: [], artifactEvidence: [] } : dkgIntel;
    const analysis = this.analyzer({ text: bounded, user: { ...targetUser, adminUsernames, adminRenameCopycat: Boolean(renameCopycat) }, globalIntel: effectiveIntel });
    if (renameCopycat) {
      analysis.confidence = Math.max(analysis.confidence || 0, policy.actionThreshold);
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
    if (campaignFingerprint && !falsePositiveReview) {
      analysis.confidence = Math.max(analysis.confidence || 0, policy.restrictThreshold);
      analysis.is_scam = true;
      analysis.scam_type = analysis.scam_type && analysis.scam_type !== 'unknown' ? analysis.scam_type : 'known_campaign';
      analysis.evidence = [
        ...(analysis.evidence || []),
        `Known scam campaign fingerprint: ${campaignFingerprint.pattern}`
      ];
    }
    if (targetUser.sangmata?.evidence) {
      analysis.evidence = [...(analysis.evidence || []), targetUser.sangmata.evidence];
    }
    if (targetUser.identityChange?.evidence) {
      analysis.evidence = [...(analysis.evidence || []), targetUser.identityChange.evidence];
    }
    const risk = combineRisk({ analysis, dkgIntel: effectiveIntel, threshold: policy.actionThreshold });
    const localBanRoots = this.localBanRootsForTarget(targetUser);
    const dkgBanRootIds = new Set(
      [...(adminHistory.events || []), ...(campaignHistory.events || [])]
        .filter((event) => event.eventType === 'ban_executed' || event.eventType === 'review_upheld')
        .map((event) => event.eventId)
        .filter(Boolean)
    );
    risk.known_campaign_fingerprint = campaignFingerprint || null;
    risk.local_ban_roots = localBanRoots.length;
    risk.dkg_ban_roots = dkgBanRootIds.size;
    risk.dkg_campaign_roots = campaignHistory.events || [];
    risk.dkg_exact_actor_roots = adminHistory.hasPriorFalsePositive ? [] : (adminHistory.events || []).filter((event) => event.exactActorMatch === true
      && event.trustLayer !== 'shared-working-memory'
      && (event.eventType === 'review_upheld' || (event.eventType === 'fraud_finding' && event.adminVerified === true)));
    risk.dkg_confirmed_actor_roots = risk.dkg_exact_actor_roots;
    risk.campaign_key = risk.campaign_key || (campaignFingerprint ? `alias:${campaignFingerprint.pattern}` : '');
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
      dkg_campaign_roots: [],
      known_campaign_fingerprint: null,
      evidence: [...(risk.evidence || []), `admin false-positive review ${falsePositiveReview.id} suppresses autonomous enforcement`]
    };
  }

  /**
   * Proactively process SangMata rename alerts from group polling (getUpdates).
   * Clear known campaigns (e.g. BC GAME) with prior ban roots auto-ban + channel notice.
   * @returns {Promise<boolean>} true if message was handled as SangMata
   */
  async handleSangMataMessage(message) {
    if (message.chat?.type === 'private') return false;
    const text = messageText(message) || message.text || '';
    const target = sangmataTargetFromText(text);
    if (!target?.id) return false;

    const from = message.from || {};
    const fromSangMataBot = isSangMataBotUser(from);
    if (!fromSangMataBot) return false;
    return this.handleKnownCampaignIdentityChange(message, target, {
      source: 'sangmata',
      sourceId: message.message_id || '',
      sourceEvidence: target.sangmata?.evidence || ''
    });
  }

  async handleKnownCampaignIdentityChange(message, target, {
    source = 'identity_change',
    sourceId = '',
    sourceEvidence = ''
  } = {}) {
    const text = messageText(message) || message.text || '';
    const sourceLabel = source === 'sangmata' ? 'SangMata rename' : 'Telegram identity change';
    const checkEventType = source === 'sangmata' ? 'sangmata_campaign_check' : 'identity_campaign_check';

    const chatId = message.chat.id;
    const idempotencyKey = `known-campaign-identity:${source}:${chatId}:${sourceId}:${target.id}`;
    const already = this.store.all().some((event) => (
      ['ban_executed', 'risk_review_needed', 'risk_action_suppressed', checkEventType].includes(event.event_type)
      && event.payload?.identity_source_id
      && String(event.payload.identity_source_id) === String(sourceId)
      && String(event.chat?.id || '') === String(chatId)
      && String(event.user?.id || event.payload?.target?.id || '') === String(target.id)
    ));
    if (already) return true;

    const targetText = [
      text,
      target.sangmata?.oldName || '',
      target.sangmata?.newName || '',
      target.identityChange?.oldName || '',
      target.identityChange?.newName || '',
      target.sangmata?.evidence || '',
      target.identityChange?.evidence || ''
    ].filter(Boolean).join('\n');
    const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
    const policy = this.chatPolicy(chatId);
    const eligibility = evaluateKnownCampaignAutoBan({
      target,
      risk,
      patterns: this.knownCampaignPatterns(),
      localBanRoots: Number(risk.local_ban_roots || 0),
      dkgBanRoots: Number(risk.dkg_ban_roots || 0),
      minBanRoots: this.config.knownCampaignMinBanRoots || 2,
      enabled: this.config.knownCampaignAutoBan !== false,
      banThreshold: policy.banThreshold
    });
    const localDecision = this.localProtectionDecision(target, chatId);
    const confirmed = {
      eligible: localDecision.action === 'remove',
      reason: localDecision.reason,
      roots: localDecision.roots || []
    };
    const campaignPolicy = this.activeCampaignPolicy(chatId, target);
    if (this.config.knownCampaignAutoBan === false || !campaignPolicy) confirmed.eligible = false;
    if (confirmed.eligible && risk.recommended_action !== 'ignore') {
      eligibility.eligible = true;
      eligibility.reason = confirmed.reason;
      eligibility.banRoots = confirmed.roots.length;
      eligibility.campaignLabel = eligibility.campaignLabel || target.first_name || target.username || 'confirmed actor';
    }
    // Local ban counts and name-only matches cannot authorize cross-group bans.
    eligibility.eligible = confirmed.eligible && (eligibility.eligible || confirmed.reason === 'previous_admin_ban_same_actor');
    if (!confirmed.eligible && eligibility.reason !== 'no_campaign_fingerprint' && eligibility.reason !== 'false_positive_suppressed') eligibility.reason = confirmed.reason;
    if (!CAMPAIGN_POLICIES.some((item) => this.chatCampaignPolicyEnabled(chatId, item.id))) eligibility.reason = 'chat_campaign_policy_not_enabled';
    if (this.config.knownCampaignAutoBan === false) eligibility.reason = 'known_campaign_auto_ban_disabled';

    if (!eligibility.eligible) {
      await this.record(checkEventType, { ...message, from: target }, {
        ...risk,
        target,
        target_key: targetKey(target),
        identity_source: source,
        identity_source_id: sourceId,
        sangmata_source_message_id: source === 'sangmata' ? sourceId : '',
        sangmata: target.sangmata,
        auto_ban_eligible: false,
        auto_ban_reason: eligibility.reason,
        recommended_action: risk.confidence >= policy.warnThreshold ? 'admin_review' : 'monitor',
        evidence: [
          ...(risk.evidence || []),
          sourceEvidence,
          `${sourceLabel} observed; auto-ban not taken (${eligibility.reason})`
        ].filter(Boolean)
      }, { writeDkg: false, idempotencyKey: `${idempotencyKey}:check` });
      if (risk.confidence >= policy.restrictThreshold) {
        await this.applyRiskAction({ ...message, from: target, text: targetText }, {
          ...risk,
          evidence: [...(risk.evidence || []), `${sourceLabel} held for admin review`]
        });
      }
      return true;
    }

    const enforcement = await this.enforceConfirmedScam(
      chatId,
      target,
      [message.message_id].filter(Boolean),
      idempotencyKey
    );
    if (!enforcement.banned) {
      await this.record('risk_action_suppressed', { ...message, from: target }, {
        ...risk,
        target,
        target_key: targetKey(target),
        identity_source: source,
        identity_source_id: sourceId,
        sangmata_source_message_id: source === 'sangmata' ? sourceId : '',
        recommended_action: 'admin_review',
        auto_ban_reason: eligibility.reason,
        suppression_reason: enforcement.reason,
        evidence: [
          ...(risk.evidence || []),
          sourceEvidence,
          `Known campaign auto-ban suppressed: ${enforcement.reason}`
        ].filter(Boolean)
      }, { writeDkg: false, idempotencyKey: `${idempotencyKey}:suppressed` });
      return true;
    }

    const campaignLabel = eligibility.campaignLabel || target.sangmata?.newName || 'known campaign';
    const publicLabel = plainUserLabel(target);
    await this.recordBanEvidenceInBackground(
      { ...message, from: target, text: targetText },
      target,
      {
        ...risk,
        confidence: Math.max(Number(risk.confidence || 0), policy.banThreshold),
        scam_type: risk.scam_type || 'known_campaign',
        recommended_action: 'ban',
        known_campaign_auto_ban: true,
        campaign_key: risk.campaign_key || `alias:${eligibility.fingerprint?.pattern || campaignLabel}`,
        local_ban_roots: risk.local_ban_roots,
        dkg_ban_roots: risk.dkg_ban_roots,
        identity_source: source,
        identity_source_id: sourceId,
        sangmata_source_message_id: source === 'sangmata' ? sourceId : '',
        auto_ban_reason: eligibility.reason,
        ban_roots: eligibility.banRoots,
        campaign_label: campaignLabel
      },
      `auto-ban known campaign (${campaignLabel}) after ${sourceLabel.toLowerCase()}`,
      {
        source: 'known_campaign_auto_ban',
        adminVerified: false,
        sangmataEvidence: source === 'sangmata' ? sourceEvidence : '',
        deletedMessageCount: enforcement.deleted || 0,
        deleteAttemptCount: enforcement.attempted || 0,
        repliedMessageId: message.message_id || '',
        idempotencyKey: `${idempotencyKey}:ban`
      }
    );
    await this.record(checkEventType, { ...message, from: target }, {
      target,
      target_key: targetKey(target),
      identity_source: source,
      identity_source_id: sourceId,
      sangmata_source_message_id: source === 'sangmata' ? sourceId : '',
      auto_ban_eligible: true,
      auto_ban_reason: eligibility.reason,
      ban_roots: eligibility.banRoots,
      campaign_label: campaignLabel,
      evidence: [sourceEvidence, `Known campaign auto-ban executed for ${campaignLabel}`].filter(Boolean)
    }, { writeDkg: false, idempotencyKey: `${idempotencyKey}:done` });

    const notice = [
      `TRACaBot removed ${publicLabel} — matches repeated ${campaignLabel}–style scam campaign with prior ban evidence.`,
      'Admins can reverse via Reviews in /start if needed.'
    ].join(' ');
    await this.send(chatId, notice, { reply_to_message_id: message.message_id || undefined }).catch(() => null);
    this.store.incrementMetric?.('known_campaign_auto_bans');
    return true;
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

  async maybeAutoBanConfirmedActor(message, target, risk) {
    if (this.config.knownCampaignAutoBan === false || !target?.id || target.is_bot === true || risk.recommended_action === 'ignore'
      || !this.activeCampaignPolicy(message.chat?.id, target)) return false;
    const decision = this.localProtectionDecision(target, message.chat?.id);
    if (decision.action !== 'remove') return false;
    const effectKey = `confirmed-actor:${message.chat.id}:${target.id}:${message.message_id || 'message'}`;
    const result = await this.enforceConfirmedScam(message.chat.id, target, [message.message_id].filter(Boolean), effectKey);
    if (!result.banned) return false;
    await this.record('ban_executed', { ...message, from: target }, {
      ...risk, target, target_key: targetKey(target), admin_verified: false,
      source: 'confirmed_campaign_auto_ban', auto_ban_reason: decision.reason,
      evidence_root_ids: decision.roots, confidence: 100,
      evidence: [...(risk.evidence || []), `Auto-ban based on active same-chat local admin review roots: ${decision.roots.join(', ')}`]
    }, { writeDkg: this.config.autoPromoteEvidence !== false && this.config.dkgWrites !== false, idempotencyKey: `${effectKey}:evidence` });
    return true;
  }

  async applyRiskAction(message, risk) {
    const policy = this.chatPolicy(message.chat?.id);
    const check = await this.record('risk_check', message, risk);
    if (risk.confidence < policy.warnThreshold) return check;
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
        evidence: [...risk.evidence, actor.is_bot === true ? 'auto-action suppressed for Telegram bot account' : 'auto-action suppressed for Telegram chat admin', 'queued for admin review without channel alert']
      }, { writeDkg: false });
      return review;
    }

    // Auto-delete of user messages disabled during testing period (except join challenges)
    const deletedMessage = false;
    const finding = risk.confidence >= policy.actionThreshold ? await this.publishHighConfidenceFinding(message, {
      ...risk,
      recommended_action: 'admin_review',
      evidence: [...risk.evidence, 'triggering message removal disabled during testing', 'auto ban/restrict disabled for message classifier decisions; admin review required']
    }) : null;
    const review = await this.record('risk_review_needed', message, {
      ...risk,
      recommended_action: 'admin_review',
      finding_event_id: finding?.id || '',
      evidence: [...risk.evidence, 'triggering message removal disabled during testing', 'auto ban/restrict disabled for message classifier decisions; admin review required', 'queued for admin review without channel alert']
    }, { writeDkg: false });
    return review;
  }

  async handleMuteCommand(message) {
    const chatId = message.chat.id;
    if (!await this.isTrustedModerator(message)) {
      await this.sendCleanCommandReply(message, '⚠️ /mute is restricted to configured admins or Telegram chat admins.');
      return;
    }
    if (!await this.hasRestrictRights(chatId)) {
      await this.sendCleanCommandReply(message, 'I can advise and log, but I need Telegram admin restrict rights before I can mute users in this group.');
      return;
    }
    const argText = this.commandText(message, 'mute');
    const { target } = this.resolveCommandTarget(message, 'mute');
    const replyUser = target?.id ? target : message.reply_to_message?.from;
    if (!replyUser?.id) {
      await this.sendCleanCommandReply(message, 'Reply to the user you want muted, mention them after /mute, or use a Telegram ID. Example: /mute 5 minutes.');
      return;
    }
    if (replyUser.is_bot === true || await this.isTelegramChatAdmin(chatId, replyUser.id)) {
      await this.sendCleanCommandReply(message, 'I will not mute bot accounts or Telegram chat admins.');
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
    await this.sendCleanCommandReply(message, `🔇 Muted ${userMention(replyUser)} for ${humanDuration(seconds)}. Event: ${event.id}.`, { parse_mode: 'HTML' });
  }

  appealCaseRef(ban = {}) {
    return `case-${createHash('sha256').update(`ban:${ban.id || ''}`).digest('hex').slice(0, 10)}`;
  }

  appealRef(receiptId = '') {
    return `ap-${createHash('sha256').update(String(receiptId)).digest('hex').slice(0, 10)}`;
  }

  banEventTargets(ban = {}, userId = '') {
    const target = ban.payload?.target || ban.user || {};
    const key = String(ban.payload?.target_key || '');
    return String(target.id || '') === String(userId) || key === `id:${userId}`;
  }

  eventTimeMs(event = {}) {
    const parsed = Date.parse(event.payload?.occurred_at || event.timestamp || '');
    return Number.isFinite(parsed) ? parsed : 0;
  }

  newerIndependentBanFor({ ban = {}, userId = '', chatId = '' } = {}) {
    const targetId = String(userId || ban.payload?.target?.id || ban.user?.id || '');
    const caseChatId = String(chatId || ban.chat?.id || ban.payload?.target_chat_id || '');
    const caseTime = this.eventTimeMs(ban);
    if (!targetId || !caseChatId || !caseTime) return null;
    return this.store.all().find((event) => {
      if (event.event_type !== 'ban_executed') return false;
      if (String(event.id || '') === String(ban.id || '')) return false;
      if (event.payload?.provenance === 'automatic_evidence_policy') return false;
      if (ban.id && String(event.payload?.source_event_id || '') === String(ban.id)) return false;
      if (!this.banEventTargets(event, targetId)) return false;
      const eventChatId = event.payload?.target_chat_id || event.chat?.id || '';
      if (!sameChat(eventChatId, caseChatId)) return false;
      return this.eventTimeMs(event) > caseTime;
    }) || null;
  }

  appealResolutionFor(banId = '') {
    return [...this.store.all()].reverse().find((event) => event.event_type === 'appeal_resolved'
      && String(event.payload?.ban_event_id || '') === String(banId || '')) || null;
  }

  appealCasesForUser(userId = '') {
    const id = String(userId || '');
    if (!id) return [];
    const resolutions = new Map();
    for (const event of this.store.all()) {
      if (event.event_type === 'appeal_resolved' && event.payload?.ban_event_id) {
        resolutions.set(String(event.payload.ban_event_id), event);
      }
    }
    return this.store.all()
      .filter((event) => event.event_type === 'ban_executed'
        && event.payload?.provenance !== 'automatic_evidence_policy'
        && this.banEventTargets(event, id))
      .sort((a, b) => Date.parse(b.timestamp || '') - Date.parse(a.timestamp || ''))
      .slice(0, 10)
      .map((ban) => {
        const resolution = resolutions.get(String(ban.id)) || null;
        return {
          ban,
          caseRef: this.appealCaseRef(ban),
          createdAt: ban.timestamp || '',
          status: resolution ? String(resolution.payload?.status || resolution.payload?.decision || 'resolved') : 'banned'
        };
      });
  }

  pendingAppeals(chatId = '') {
    const events = this.store.all();
    const resolved = new Set(events
      .filter((event) => event.event_type === 'appeal_resolved' && event.payload?.appeal_ref)
      .map((event) => String(event.payload.appeal_ref)));
    return events
      .filter((event) => event.event_type === 'appeal_submitted' && event.payload?.appeal_ref && !resolved.has(String(event.payload.appeal_ref)))
      .filter((event) => !chatId || sameChat(event.payload?.target_chat_id, chatId))
      .sort((a, b) => Date.parse(a.timestamp || '') - Date.parse(b.timestamp || ''))
      .slice(0, 20);
  }

  appealById(appealRef = '') {
    return this.store.all().find((event) => event.event_type === 'appeal_submitted'
      && String(event.payload?.appeal_ref || '') === String(appealRef || '')) || null;
  }

  isAppealAdminForChat(userId = '', chatId = '') {
    if (!userId || !chatId) return Promise.resolve(false);
    // Only a current Telegram administrator of the affected group can resolve
    // an appeal. Configured bot owners do not inherit group jurisdiction.
    return this.isTelegramChatAdmin(chatId, userId, { requireLiveLookup: true, throwOnFailure: true })
      .catch(() => false);
  }

  joinAutoRemovalPaused(chatId = '') {
    const id = String(chatId || '');
    if (!id) return false;
    const row = [...this.store.all()].reverse().find((event) => event.event_type === 'join_auto_removal_setting_changed'
      && sameChat(event.chat?.id || event.payload?.target_chat_id, id));
    return row?.payload?.paused === true;
  }

  async setJoinAutoRemovalPaused(chat = {}, paused = false, actor = {}, source = 'controls') {
    const chatId = String(chat.id || chat.chat_id || '');
    if (!chatId) throw new Error('missing chat for join auto-removal setting');
    const next = paused === true;
    if (this.joinAutoRemovalPaused(chatId) === next) return { paused: next, changed: false };
    const event = await this.record('join_auto_removal_setting_changed', {
      chat: { id: chatId, type: chat.type || 'supergroup', title: chat.title || '' },
      from: actor,
      message_id: chat.message_id
    }, {
      paused: next,
      moderator: actor,
      source,
      target_chat_id: chatId,
      evidence: [next
        ? 'Current group admin paused future automatic join removals; evidence capture and sharing remain active.'
        : 'Current group admin resumed future automatic join removals; configured policy still controls enforcement.']
    }, { writeDkg: false, idempotencyKey: `join-auto-removal-setting:${chatId}:${next}:${actor.id || actor.username || ''}:${this.currentUpdateId || Date.now()}` });
    return { paused: next, changed: true, event };
  }

  controlGroupCandidates() {
    const candidates = new Map();
    const remember = (id, title = '', lastAt = 0) => {
      const key = String(id || '');
      if (!/^-\d{1,24}$/.test(key)) return;
      const existing = candidates.get(key) || { id: key, title: '', lastAt: 0 };
      candidates.set(key, {
        id: key,
        title: existing.title || String(title || '').slice(0, 80),
        lastAt: Math.max(existing.lastAt, Number(lastAt) || 0)
      });
    };
    for (const event of this.store.all()) {
      const id = event.chat?.id || event.payload?.target_chat_id;
      remember(id, event.chat?.title || event.payload?.target_chat_title || '', Date.parse(event.timestamp || '') || 0);
    }
    for (const chat of this.seenChats.values()) remember(chat.id, chat.title || '', Date.now());
    return [...candidates.values()].sort((a, b) => b.lastAt - a.lastAt).slice(0, 20);
  }

  async controlGroupsForAdmin(userId = '') {
    const groups = [];
    for (const candidate of this.controlGroupCandidates()) {
      if (await this.isAppealAdminForChat(userId, candidate.id)) groups.push(candidate);
    }
    return groups;
  }

  isAutomaticJoinBan(event = {}) {
    return event.event_type === 'ban_executed'
      && (event.payload?.source === 'silent_join_protection'
        || event.payload?.enforcement_observed_from === 'tracabot_join_protection');
  }

  autoBanOverturned(banId = '') {
    return this.store.all().some((event) => (event.event_type === 'review_overturned'
      && String(event.payload?.target_event_id || '') === String(banId || ''))
      || (event.event_type === 'auto_ban_override'
        && String(event.payload?.ban_event_id || '') === String(banId || '')
        && ['unban_completed', 'overturned', 'unban_pending', 'overturned_unban_pending'].includes(String(event.payload?.status || ''))));
  }

  autoBanOverrideRecord(banId = '') {
    return [...this.store.all()].reverse().find((event) => event.event_type === 'auto_ban_override'
      && String(event.payload?.ban_event_id || '') === String(banId || '')) || null;
  }

  autoBanNeedsRetry(banId = '') {
    const status = String(this.autoBanOverrideRecord(banId)?.payload?.status || '');
    return status === 'unban_pending' || status === 'overturned_unban_pending';
  }

  recentAutoBansForChat(chatId = '', limit = 3) {
    return [...this.store.all()]
      .filter((event) => this.isAutomaticJoinBan(event) && sameChat(event.chat?.id, chatId) && (!this.autoBanOverturned(event.id) || this.autoBanNeedsRetry(event.id)))
      .sort((a, b) => Date.parse(b.timestamp || '') - Date.parse(a.timestamp || ''))
      .slice(0, limit);
  }

  controlFooterRows(userId = '', current = '') {
    const nav = [
      ['🛡️ Protection controls', 'controls', 'controls'],
      ['🩺 Status', 'controls-status', 'status'],
      ['🚨 Recent automatic bans', 'controls-recent', 'recent'],
      ['📣 Appeals', 'appeals', 'appeals']
    ].filter((item) => item[2] !== current);
    const rows = [];
    for (let index = 0; index < nav.length; index += 2) {
      rows.push(nav.slice(index, index + 2).map(([label, action]) => button(label, callbackData(action, userId))));
    }
    const refreshAction = current === 'status' ? 'controls-status'
      : current === 'recent' ? 'controls-recent'
        : current === 'appeals' ? 'appeals' : 'controls-refresh';
    rows.push([button('🔄 Refresh', callbackData(refreshAction, userId)), button('✖️ Close', callbackData('close', userId))]);
    return rows;
  }

  async controlsView(userId = '') {
    const groups = await this.controlGroupsForAdmin(userId);
    const rows = [];
    const lines = [
      '🛡️ Protection controls',
      '',
      'Only current Telegram admins of the affected group can pause removals or review auto-bans. Bot owners do not bypass group administration.',
      'Pausing stops future automatic join removals only. Evidence capture and sharing continue. Resume cannot enable a policy configured off.',
      ''
    ];
    if (!groups.length) {
      lines.push('No groups were found where you are a current Telegram admin.');
      rows.push(...this.controlFooterRows(userId, 'controls'));
      return { text: lines.join('\n'), rows, groups };
    }
    const recent = [];
    for (const group of groups) {
      const paused = this.joinAutoRemovalPaused(group.id);
      const policyEnabled = this.config.joinAutoRemove === true;
      const allowedChats = this.config.joinAutoRemoveChats || [];
      const chatAllowed = !allowedChats.length || allowedChats.map(String).includes(group.id);
      const state = paused ? '⏸️ Paused by admin' : (policyEnabled && chatAllowed ? '▶️ Running' : '⚪ Configured off');
      lines.push(`• ${group.title || group.id} — ${state}`);
      rows.push([button(`${paused ? '▶️ Resume' : '⏸️ Pause'} future join removals · ${(group.title || group.id).slice(0, 24)}`, callbackData('controls-join-toggle', userId, group.id, paused ? 'off' : 'on'))]);
      for (const ban of this.recentAutoBansForChat(group.id, 3)) recent.push({ ban, group });
    }
    recent.sort((a, b) => Date.parse(b.ban.timestamp || '') - Date.parse(a.ban.timestamp || ''));
    if (recent.length) {
      lines.push('', 'Recent automatic join bans');
      for (const { ban, group } of recent.slice(0, 8)) {
        const target = ban.payload?.target || ban.user || {};
        lines.push(`• ${displayName(target) || target.id || 'target'} · ${ageLabel(ban.timestamp)} · ${group.title || group.id}`);
        rows.push([button(`Review auto-ban · ${(displayName(target) || target.id || 'target').slice(0, 24)}`, callbackData('controls-ban-open', userId, shortId(ban.id)))]);
      }
    } else {
      lines.push('', 'No recent automatic join bans need review.');
    }
    rows.push(...this.controlFooterRows(userId, 'controls'));
    return { text: lines.join('\n'), rows, groups };
  }

  async protectionStatusView(userId = '') {
    const groups = await this.controlGroupsForAdmin(userId);
    const lines = [
      '🩺 Protection status',
      '',
      'Live current-admin scope only. Bot owners without group admin status see nothing here.',
      ''
    ];
    if (!groups.length) {
      lines.push('No groups were found where you are a current Telegram admin.');
      return { text: lines.join('\n'), rows: this.controlFooterRows(userId, 'status'), groups };
    }
    const trustedLayers = (this.config.joinTrustedLayers || ['local']).join(', ');
    for (const group of groups) {
      const paused = this.joinAutoRemovalPaused(group.id);
      const policyEnabled = this.config.joinAutoRemove === true;
      const allowedChats = this.config.joinAutoRemoveChats || [];
      const chatAllowed = !allowedChats.length || allowedChats.map(String).includes(group.id);
      const [canBan, canDelete] = await Promise.all([
        this.hasBanRights(group.id).catch(() => false),
        this.hasDeleteRights(group.id).catch(() => false)
      ]);
      const state = paused ? '⏸️ Paused by admin' : (policyEnabled && chatAllowed ? '▶️ Running' : '⚪ Configured off');
      lines.push(`• ${group.title || group.id} — ${state}`);
      lines.push(`  Auto-remove config: ${policyEnabled ? (chatAllowed ? 'on for this group' : 'off for this group') : 'off'}; trusted layers: ${trustedLayers}`);
      lines.push(`  Bot rights: ban ${canBan ? '✅' : '❌'}, delete ${canDelete ? '✅' : '❌'}; pause is separate from unban`);
    }
    return { text: lines.join('\n'), rows: this.controlFooterRows(userId, 'status'), groups };
  }

  async recentAutoBansView(userId = '') {
    const groups = await this.controlGroupsForAdmin(userId);
    const recent = [];
    for (const group of groups) {
      for (const ban of this.recentAutoBansForChat(group.id, 5)) recent.push({ ban, group });
    }
    recent.sort((a, b) => Date.parse(b.ban.timestamp || '') - Date.parse(a.ban.timestamp || ''));
    const lines = [
      '🚨 Recent automatic join bans',
      '',
      'Only bans from groups where you are a current Telegram admin are shown.',
      ''
    ];
    const rows = [];
    if (!recent.length) {
      lines.push('No recent automatic join bans need review.');
    } else {
      for (const { ban, group } of recent.slice(0, 10)) {
        const target = ban.payload?.target || ban.user || {};
        lines.push(`• ${displayName(target) || target.id || 'target'} · ${ageLabel(ban.timestamp)} · ${group.title || group.id}`);
        rows.push([button(`Review auto-ban · ${(displayName(target) || target.id || 'target').slice(0, 24)}`, callbackData('controls-ban-open', userId, shortId(ban.id)))]);
      }
      lines.push('', 'Select one to review. Override / allow return is an admin action and does not need a member appeal.');
    }
    rows.push(...this.controlFooterRows(userId, 'recent'));
    return { text: lines.join('\n'), rows, groups };
  }

  async handleControlsCommand(message = {}) {
    const isPrivate = message.chat?.type === 'private' || Number(message.chat?.id || 0) > 0;
    if (!isPrivate) {
      await this.sendCleanCommandReply(message, 'Protection controls are private. Open a private chat with this bot and send /controls.');
      return;
    }
    const view = await this.controlsView(message.from?.id || message.from?.username || '');
    await this.sendInteractiveReply(message.chat.id, view.text, view.rows, { reply_to_message_id: message.message_id });
  }

  async showAutoBanControl(shortEventId = '', admin = {}, sourceChat = {}) {
    const ban = this.findEvent(shortEventId);
    if (!ban || !this.isAutomaticJoinBan(ban)) return { ok: false, error: 'auto_ban_not_found' };
    const chatId = String(ban.chat?.id || ban.payload?.target_chat_id || '');
    if (!await this.isAppealAdminForChat(admin.id, chatId)) return { ok: false, error: 'not_chat_admin' };
    const target = ban.payload?.target || ban.user || {};
    const latestOverride = this.autoBanOverrideRecord(ban.id);
    const correction = this.store.all().find((event) => event.event_type === 'review_overturned'
      && String(event.payload?.target_event_id || '') === String(ban.id));
    const overridden = Boolean(correction || latestOverride);
    const unbanPending = latestOverride?.payload?.status === 'unban_pending' || latestOverride?.payload?.status === 'overturned_unban_pending';
    const status = unbanPending ? 'local override recorded; Telegram unban pending'
      : overridden ? 'local override already recorded' : 'active automatic removal';
    const text = [
      '🛡️ Automatic join ban',
      '',
      `Target: ${displayName(target) || target.id || 'unknown'}`,
      `Group: ${ban.chat?.title || chatId}`,
      `When: ${ageLabel(ban.timestamp)}`,
      `Status: ${status}`,
      '',
      'Override records a group-scoped local correction and requests an idempotent Telegram unban. It does not revoke a creator-curator global record.',
      'If you pause future removals, that is separate from whether this user was actually unbanned.'
    ].join('\n');
    const rows = unbanPending
      ? [
        [button('🔁 Retry unban', callbackData('controls-ban-retry', admin.id || 'admin', shortId(ban.id)))],
        [button('↩️ Back', callbackData('controls-recent', admin.id || 'admin')), button('✖️ Close', callbackData('close', admin.id || 'admin'))]
      ]
      : overridden
        ? [[button('🔄 Refresh controls', callbackData('controls-refresh', admin.id || 'admin')), button('✖️ Close', callbackData('close', admin.id || 'admin'))]]
        : [
          [button('Override / allow return', callbackData('controls-ban-confirm', admin.id || 'admin', shortId(ban.id)))],
          [button('↩️ Back', callbackData('controls-refresh', admin.id || 'admin')), button('✖️ Close', callbackData('close', admin.id || 'admin'))]
        ];
    return { ok: true, text, rows, ban, target, chatId, overridden, unbanPending };
  }

  async overrideAutomaticBan({ ban = null, admin = {}, sourceChat = {}, reason = '' } = {}) {
    if (!ban || !this.isAutomaticJoinBan(ban)) return { ok: false, error: 'auto_ban_not_found' };
    const chatId = String(ban.chat?.id || ban.payload?.target_chat_id || '');
    if (!chatId) return { ok: false, error: 'ban_chat_unavailable' };
    if (!await this.isAppealAdminForChat(admin.id, chatId)) return { ok: false, error: 'not_chat_admin' };
    const existing = this.store.all().find((event) => event.event_type === 'review_overturned'
      && String(event.payload?.target_event_id || '') === String(ban.id))
      || this.autoBanOverrideRecord(ban.id)
      || this.store.all().find((event) => event.event_type === 'auto_ban_override' && event.payload?.ban_event_id === ban.id);
    if (existing) {
      const latestOverride = this.autoBanOverrideRecord(ban.id);
      return {
        ok: true,
        already: true,
        correction: existing,
        ban,
        unbanPending: latestOverride?.payload?.status === 'unban_pending'
          || latestOverride?.payload?.status === 'overturned_unban_pending'
      };
    }
    const target = ban.payload?.target || ban.user || {};
    if (!target.id) return { ok: false, error: 'missing_target' };
    const source = 'telegram_admin_auto_ban_override';
    const resolutionChat = { id: sourceChat.id || `auto:${ban.id}`, type: sourceChat.type || 'private', title: sourceChat.title || 'auto-ban override' };
    const adminMessage = { chat: resolutionChat, from: admin, message_id: sourceChat.message_id };
    const resolutionReason = boundedText(reason || 'current group admin overrode an automatic join removal', 500);
    const correction = await this.record('review_overturned', {
      chat: ban.chat || { id: chatId, type: 'supergroup' },
      from: admin,
      date: Math.floor(Date.now() / 1000)
    }, {
      target_event_id: ban.id,
      evidence_root_ids: this.localProtectionLineage(ban),
      review_decision: 'reject',
      reviewed_target: target,
      reviewed_target_key: `id:${target.id}`,
      target_chat_id: chatId,
      target_chat_title: ban.chat?.title || '',
      target_chat_type: ban.chat?.type || 'supergroup',
      review_chat_id: resolutionChat.id,
      review_scope: 'same_channel',
      review_jurisdiction: 'local_channel',
      review_weight: 1,
      local_approval: false,
      correction_source: source,
      local_override: true,
      creator_global_record_unchanged: true,
      reason: resolutionReason,
      reviewer: admin,
      moderator: admin,
      admin_verified: true,
      retracted: true,
      evidence: [`Current group admin overrode automatic join ban ${ban.id}: ${resolutionReason}`]
    }, { writeDkg: false, idempotencyKey: `auto-ban-override:${ban.id}` });
    await this.record('creator_reconsideration_requested', adminMessage, {
      target,
      target_key: `id:${target.id}`,
      ban_event_id: ban.id,
      status: 'pending_creator_review',
      local_only: true,
      consent_to_share: false,
      evidence: ['Automatic join ban local override queued for creator-curator reconsideration; no global record was revoked locally.']
    }, { writeDkg: false, idempotencyKey: `auto-ban-reconsider:${ban.id}` });
    const unban = await this.unbanForAppeal(chatId, target.id, `auto-ban-override:${ban.id}`, adminMessage, { reconcileFirst: true });
    const resolution = await this.record('auto_ban_override', adminMessage, {
      ban_event_id: ban.id,
      target,
      target_key: `id:${target.id}`,
      target_chat_id: chatId,
      decision: 'overturn',
      status: unban.ok ? 'unban_completed' : 'unban_pending',
      unban_ok: unban.ok === true,
      unban_attempts: unban.attempts || 0,
      unban_error: unban.error ? String(unban.error).slice(0, 240) : '',
      correction_event_id: correction.id,
      moderator: admin,
      creator_global_record_unchanged: true,
      evidence: [unban.ok
        ? 'Local correction recorded and Telegram unban completed. Unban only permits return; it cannot add a user.'
        : 'Local correction recorded but Telegram unban did not complete; admins still see failure state.']
    }, { writeDkg: false, idempotencyKey: `auto-ban-override-result:${ban.id}` });
    return { ok: true, already: false, correction, resolution, unban, ban, target, chatId };
  }

  async retryAutomaticBanOverride({ ban = null, admin = {}, sourceChat = {}, requestId = '' } = {}) {
    if (!ban || !this.isAutomaticJoinBan(ban)) return { ok: false, error: 'auto_ban_not_found' };
    const chatId = String(ban.chat?.id || ban.payload?.target_chat_id || '');
    if (!chatId) return { ok: false, error: 'ban_chat_unavailable' };
    if (!await this.isAppealAdminForChat(admin.id, chatId)) return { ok: false, error: 'not_chat_admin' };
    const correction = this.store.all().find((event) => event.event_type === 'review_overturned'
      && String(event.payload?.target_event_id || '') === String(ban.id));
    if (!correction) return { ok: false, error: 'override_not_found' };
    const target = ban.payload?.target || ban.user || {};
    if (!target.id) return { ok: false, error: 'missing_target' };
    const newerBan = this.newerIndependentBanFor({ ban, userId: target.id, chatId });
    if (newerBan) {
      return { ok: false, error: 'ban_superseded', newer_ban_event_id: newerBan.id, ban };
    }
    const resolutionChat = { id: sourceChat.id || `auto:${ban.id}`, type: sourceChat.type || 'private', title: sourceChat.title || 'auto-ban override retry' };
    const adminMessage = { chat: resolutionChat, from: admin, message_id: sourceChat.message_id };
    const unban = await this.unbanForAppeal(chatId, target.id, `auto-ban-override:${ban.id}`, adminMessage, { reconcileFirst: true });
    const priorRetries = this.store.all().filter((event) => event.event_type === 'auto_ban_override'
      && String(event.payload?.ban_event_id || '') === String(ban.id)).length;
    const retryKey = requestId
      ? `auto-ban-override-retry:${ban.id}:${requestId}`
      : `auto-ban-override-retry:${ban.id}:${priorRetries}:${unban.ok ? 'ok' : 'pending'}`;
    const resolution = await this.record('auto_ban_override', adminMessage, {
      ban_event_id: ban.id,
      target,
      target_key: `id:${target.id}`,
      target_chat_id: chatId,
      decision: 'overturn',
      status: unban.ok ? 'unban_completed' : 'unban_pending',
      unban_ok: unban.ok === true,
      unban_attempts: unban.attempts || 0,
      unban_error: unban.error ? String(unban.error).slice(0, 240) : '',
      correction_event_id: correction.id,
      moderator: admin,
      retry: true,
      creator_global_record_unchanged: true,
      evidence: [unban.ok
        ? 'Safe unban retry completed after a local auto-ban correction; unban only permits return.'
        : 'Safe unban retry did not complete; the local correction remains and the failure is still visible to admins.']
    }, { writeDkg: false, idempotencyKey: retryKey });
    return { ok: true, already: false, correction, resolution, unban, ban, target, chatId };
  }

  appealStatusLine(item = {}) {
    const age = ageLabel(item.createdAt);
    return `• ${item.caseRef} · ${age} · ${item.status}`;
  }

  async handleAppealCommand(message) {
    const userId = String(message.from?.id || '');
    const isPrivate = message.chat?.type === 'private' || Number(message.chat?.id || 0) > 0;
    if (!userId) return;
    if (!isPrivate) {
      const username = this.ownBotUsername() || await this.botUsername().catch(() => '');
      const link = username ? `https://t.me/${username}` : '';
      await this.sendCleanCommandReply(message, [
        'Appeals are handled in a private chat so other members do not see your case.',
        link ? `Open ${link} and send /appeal there.` : 'Open a private chat with this bot and send /appeal there.',
        'Telegram only lets the bot message you privately after you start it. Your ban case is stored locally from the group action, so you can start the private chat later.'
      ].join('\n'), { disable_web_page_preview: true });
      return;
    }
    const arg = this.commandText(message, 'appeal');
    const cases = this.appealCasesForUser(userId);
    if (!cases.length) {
      await this.sendCleanCommandReply(message, [
        'No locally stored ban case is linked to this Telegram account.',
        'If you were banned, start this private chat and send /appeal after the group action is recorded. The bot cannot message you first, but it can look up your own case when you arrive here.',
        'Include the case code and a short reason: /appeal case-abc123 I believe this was a mistake.'
      ].join('\n'));
      return;
    }
    const [selector = '', ...reasonParts] = arg.split(/\s+/).filter(Boolean);
    const reason = reasonParts.join(' ').replace(/\s+/g, ' ').trim();
    if (!selector) {
      await this.sendCleanCommandReply(message, [
        'Your local ban case(s):',
        ...cases.map(this.appealStatusLine.bind(this)),
        '',
        'To appeal one case, send: /appeal <case code> <short reason>',
        'Example: /appeal ' + cases[0].caseRef + ' I believe this was a false positive.',
        'Only you and authorized admins for the affected group can see the case details.'
      ].join('\n'));
      return;
    }
    const numeric = /^\d{1,2}$/.test(selector) ? Number(selector) - 1 : -1;
    const selected = numeric >= 0 ? cases[numeric] : cases.find((item) => item.caseRef === selector || String(item.ban.id).startsWith(selector));
    if (!selected) {
      await this.sendCleanCommandReply(message, 'That case code does not match a ban stored for this Telegram account. Send /appeal to list your own cases.');
      return;
    }
    if (selected.status === 'overturned' || selected.status === 'overturned_unban_pending') {
      await this.sendCleanCommandReply(message, `Case ${selected.caseRef} was already overturned. A local unban was requested; if you still cannot return, ask a group admin because Telegram may have restricted the account separately.`);
      return;
    }
    if (selected.status === 'upheld') {
      await this.sendCleanCommandReply(message, `Case ${selected.caseRef} was finally upheld by the group admin. Re-appealing the same local ban is not accepted. Ask the group admin to reopen it with new evidence.`);
      return;
    }
    if (reason.length < 10 || reason.length > (this.config.appealMaxReasonChars || 500)) {
      await this.sendCleanCommandReply(message, `Add a short reason (10-${this.config.appealMaxReasonChars || 500} characters) after the case code.`);
      return;
    }
    const now = Date.now();
    const dedupMs = (this.config.appealDedupHours || 24) * 60 * 60 * 1000;
    const open = this.store.all().some((event) => event.event_type === 'appeal_submitted'
      && event.payload?.appealant_id === userId
      && String(event.payload?.ban_event_id || '') === String(selected.ban.id)
      && now - Date.parse(event.timestamp || '') < dedupMs
      && !this.appealResolutionFor(selected.ban.id));
    if (open) {
      await this.sendCleanCommandReply(message, `An appeal for ${selected.caseRef} is already pending. Admins will review it; duplicate submissions are not stored.`);
      return;
    }
    const perHour = this.store.all().filter((event) => event.event_type === 'appeal_submitted'
      && event.payload?.appealant_id === userId
      && now - Date.parse(event.timestamp || '') < 60 * 60 * 1000).length;
    if (perHour >= (this.config.appealMaxPerHour || 3)) {
      await this.sendCleanCommandReply(message, 'Too many appeals in the last hour. Try again later.');
      return;
    }
    const receiptId = `appeal-${randomUUID()}`;
    const appealRef = this.appealRef(receiptId);
    const banChat = selected.ban.chat || {};
    const event = await this.record('appeal_submitted', {
      chat: { id: message.chat.id, type: 'private' },
      from: message.from,
      message_id: message.message_id
    }, {
      appeal_receipt_id: receiptId,
      appeal_ref: appealRef,
      ban_event_id: selected.ban.id,
      case_ref: selected.caseRef,
      appealant_id: userId,
      target: { id: userId },
      target_key: `id:${userId}`,
      target_chat_id: String(banChat.id || selected.ban.payload?.target_chat_id || ''),
      target_chat_type: String(banChat.type || selected.ban.payload?.target_chat_type || ''),
      reason: boundedText(reason, this.config.appealMaxReasonChars || 500),
      provenance: 'telegram_private_appeal',
      status: 'pending',
      consent_to_share: false,
      local_only: true,
      evidence: [`Private appeal submitted for own local ban case ${selected.caseRef}; no group broadcast.`]
    }, { writeDkg: false, idempotencyKey: `appeal-submit:${selected.ban.id}:${message.message_id || this.currentUpdateId || receiptId}` });
    await this.notifyAppealAdmins(event);
    await this.sendCleanCommandReply(message, [
      `Appeal received for ${selected.caseRef}. Receipt: ${appealRef}.`,
      'Admins for the affected group can review it. If they overturn the ban, the bot asks Telegram to lift it. Telegram permission or API failures are retried and shown to admins.',
      'A local admin override does not change a creator-curator global record; a curator reconsideration request is queued locally.'
    ].join('\n'));
  }

  async notifyAppealAdmins(appeal = {}) {
    const chatId = String(appeal.payload?.target_chat_id || '');
    if (!chatId) return;
    const recipients = new Set();
    try {
      const members = await this.call('getChatAdministrators', { chat_id: chatId });
      for (const member of members || []) {
        if (member?.user?.id && member.user.is_bot !== true) recipients.add(String(member.user.id));
      }
    } catch {
      // Fail closed: no unrelated owner or cached recipient gets appeal details.
      return;
    }
    const text = [
      '📣 New private ban appeal',
      `Case: ${appeal.payload?.case_ref || 'unknown'} · Ref: ${appeal.payload?.appeal_ref || 'unknown'}`,
      `Reason: ${String(appeal.payload?.reason || '').slice(0, 400)}`,
      'Only admins for the affected group can resolve this. The creator-curator global record is unchanged by a local decision.'
    ].join('\n');
    const keyboard = inlineKeyboard([[
      button('✅ Uphold ban', callbackData('appeal-uphold', 'admin', appeal.payload?.appeal_ref || '')),
      button('↩️ Overturn', callbackData('appeal-overturn', 'admin', appeal.payload?.appeal_ref || ''))
    ]]);
    for (const recipient of recipients) {
      // Telegram blocks bot-initiated DMs until the admin starts the bot. A
      // failed notice is expected and never changes the appeal state.
      this.send(recipient, text, { reply_markup: keyboard }).catch(() => null);
    }
  }

  async appealsView(userId = '') {
    const appeals = this.pendingAppeals('');
    const visible = [];
    for (const appeal of appeals) {
      if (await this.isAppealAdminForChat(userId, appeal.payload?.target_chat_id)) visible.push(appeal);
    }
    if (!visible.length) {
      return {
        text: 'No pending appeals are available to you. Appeals appear after a banned user starts a private chat and submits /appeal.',
        rows: this.controlFooterRows(userId, 'appeals'),
        appeals: []
      };
    }
    const lines = ['📣 Pending private ban appeals', ''];
    const rows = [];
    for (const appeal of visible.slice(0, 8)) {
      lines.push(`• ${appeal.payload?.case_ref || 'case'} · ${ageLabel(appeal.timestamp)} · ${String(appeal.payload?.reason || '').slice(0, 180)}`);
      rows.push([
        button('✅ Uphold', callbackData('appeal-uphold', 'admin', appeal.payload?.appeal_ref || '')),
        button('↩️ Overturn', callbackData('appeal-overturn', 'admin', appeal.payload?.appeal_ref || ''))
      ]);
    }
    lines.push('', 'Uphold keeps the local ban. Overturn records a local correction and asks Telegram to lift the ban. A local decision never rewrites the creator-curator global record.');
    rows.push(...this.controlFooterRows(userId, 'appeals'));
    return { text: lines.join('\n'), rows, appeals: visible };
  }

  async handleAppealsCommand(message) {
    const fromId = String(message.from?.id || '');
    const isPrivate = message.chat?.type === 'private' || Number(message.chat?.id || 0) > 0;
    const chatId = String(message.chat?.id || '');
    if (!isPrivate) {
      if (!await this.isTelegramChatAdmin(chatId, fromId, { requireLiveLookup: true, throwOnFailure: true }).catch(() => false)) {
        await this.sendCleanCommandReply(message, 'Appeal review is restricted to actual admins of this group.');
        return;
      }
      await this.sendCleanCommandReply(message, 'Private appeal details are not posted in the group. Open a private chat with this bot and send /appeals to review pending cases for groups you moderate.');
      return;
    }
    const view = await this.appealsView(fromId);
    await this.sendInteractiveReply(message.chat.id, view.text, view.rows, { reply_to_message_id: message.message_id });
  }

  async resolveAppeal({ appealRef = '', admin = {}, decision = 'uphold', reason = '', sourceChat = {} } = {}) {
    const appeal = this.appealById(appealRef);
    if (!appeal) return { ok: false, error: 'appeal_not_found' };
    if (this.appealResolutionFor(appeal.payload?.ban_event_id)) return { ok: false, error: 'appeal_already_resolved' };
    const ban = this.store.all().find((event) => event.id === appeal.payload?.ban_event_id);
    if (!ban) return { ok: false, error: 'ban_not_found' };
    const banChatId = String(ban.chat?.id || appeal.payload?.target_chat_id || '');
    if (!banChatId) return { ok: false, error: 'ban_chat_unavailable' };
    if (!await this.isAppealAdminForChat(admin.id, banChatId)) return { ok: false, error: 'not_chat_admin' };
    const resolution = decision === 'overturn' ? 'overturn' : 'uphold';
    const resolutionReason = boundedText(reason || (resolution === 'overturn' ? 'group admin overturned the ban from a private appeal' : 'group admin upheld the ban from a private appeal'), 500);
    const resolutionChat = { id: sourceChat.id || `appeal:${appealRef}`, type: sourceChat.type || 'private', title: sourceChat.title || 'appeal review' };
    const adminMessage = { chat: resolutionChat, from: admin, message_id: sourceChat.message_id };
    let unban = null;
    if (resolution === 'overturn') {
      const correction = await this.record('review_overturned', {
        chat: ban.chat || { id: banChatId, type: appeal.payload?.target_chat_type || 'supergroup' },
        from: admin,
        date: Math.floor(Date.now() / 1000)
      }, {
        target_event_id: ban.id,
        evidence_root_ids: this.localProtectionLineage(ban),
        review_decision: 'reject',
        reviewed_target: ban.payload?.target || ban.user || { id: appeal.payload?.appealant_id },
        reviewed_target_key: `id:${appeal.payload?.appealant_id || ''}`,
        target_chat_id: banChatId,
        target_chat_title: ban.chat?.title || '',
        target_chat_type: ban.chat?.type || 'supergroup',
        review_chat_id: resolutionChat.id,
        review_scope: 'same_channel',
        review_jurisdiction: 'local_channel',
        review_weight: 1,
        local_approval: false,
        correction_source: 'telegram_private_appeal_overturn',
        appeal_ref: appealRef,
        appeal_receipt_id: appeal.payload?.appeal_receipt_id || '',
        local_override: true,
        creator_global_record_unchanged: true,
        reason: resolutionReason,
        reviewer: admin,
        admin_verified: true,
        retracted: true,
        evidence: [`Group admin overturned local ban ${ban.id} from private appeal ${appealRef}: ${resolutionReason}`]
      }, { writeDkg: false, idempotencyKey: `appeal-overturn:${appealRef}` });
      await this.record('creator_reconsideration_requested', adminMessage, {
        target: { id: appeal.payload?.appealant_id },
        target_key: `id:${appeal.payload?.appealant_id || ''}`,
        ban_event_id: ban.id,
        appeal_ref: appealRef,
        status: 'pending_creator_review',
        local_only: true,
        consent_to_share: false,
        evidence: ['Local appeal correction is queued for creator-curator reconsideration; no global record was revoked locally.']
      }, { writeDkg: false, idempotencyKey: `appeal-reconsider:${appealRef}` });
      unban = await this.unbanForAppeal(banChatId, appeal.payload?.appealant_id, appealRef, adminMessage);
      await this.record('appeal_resolved', adminMessage, {
        appeal_ref: appealRef,
        appeal_receipt_id: appeal.payload?.appeal_receipt_id || '',
        ban_event_id: ban.id,
        case_ref: appeal.payload?.case_ref || '',
        target: { id: appeal.payload?.appealant_id },
        target_key: `id:${appeal.payload?.appealant_id || ''}`,
        target_chat_id: banChatId,
        decision: 'overturn',
        status: unban?.ok ? 'overturned' : 'overturned_unban_pending',
        correction_event_id: correction.id,
        unban_ok: unban?.ok === true,
        unban_attempts: unban?.attempts || 0,
        unban_error: unban?.error ? String(unban.error).slice(0, 240) : '',
        creator_global_record_unchanged: true,
        moderator: admin,
        reason: resolutionReason,
        evidence: [`Appeal ${appealRef} overturned locally; creator global record untouched.`]
      }, { writeDkg: false, idempotencyKey: `appeal-resolved:${appealRef}` });
    } else {
      await this.record('appeal_resolved', adminMessage, {
        appeal_ref: appealRef,
        appeal_receipt_id: appeal.payload?.appeal_receipt_id || '',
        ban_event_id: ban.id,
        case_ref: appeal.payload?.case_ref || '',
        target: { id: appeal.payload?.appealant_id },
        target_key: `id:${appeal.payload?.appealant_id || ''}`,
        target_chat_id: banChatId,
        decision: 'uphold',
        status: 'upheld',
        creator_global_record_unchanged: true,
        moderator: admin,
        reason: resolutionReason,
        evidence: [`Appeal ${appealRef} upheld locally; creator global record untouched.`]
      }, { writeDkg: false, idempotencyKey: `appeal-resolved:${appealRef}` });
    }
    const userText = resolution === 'overturn'
      ? (unban?.ok
        ? 'Your appeal was upheld. A local admin overturned the ban and Telegram was asked to lift it. You can try to return to the group. Telegram permissions can still block re-entry.'
        : `Your appeal was upheld. A local admin overturned the ban, but Telegram unban did not succeed after ${unban?.attempts || 0} attempt(s). The failure is visible to admins; ask them to retry.`)
      : 'Your appeal was reviewed. The local ban was upheld.';
    this.send(appeal.payload?.appealant_id, userText).catch(() => null);
    return { ok: true, decision: resolution, unban, appeal, ban };
  }

  async retryAppealUnban(appealRef = '', admin = {}, sourceChat = {}) {
    const appeal = this.appealById(appealRef);
    if (!appeal) return { ok: false, error: 'appeal_not_found' };
    const resolution = this.appealResolutionFor(appeal.payload?.ban_event_id);
    if (!resolution || resolution.payload?.decision !== 'overturn') return { ok: false, error: 'appeal_not_overturned' };
    const banChatId = String(resolution.payload?.target_chat_id || appeal.payload?.target_chat_id || '');
    if (!await this.isAppealAdminForChat(admin.id, banChatId)) return { ok: false, error: 'not_chat_admin' };
    const caseBan = this.findEvent(appeal.payload?.ban_event_id) || {
      id: appeal.payload?.ban_event_id || '',
      timestamp: appeal.timestamp || '',
      chat: { id: banChatId },
      payload: {
        target: { id: appeal.payload?.appealant_id },
        target_chat_id: banChatId
      }
    };
    const newerBan = this.newerIndependentBanFor({
      ban: caseBan,
      userId: appeal.payload?.appealant_id,
      chatId: banChatId
    });
    if (newerBan) {
      return { ok: false, error: 'ban_superseded', newer_ban_event_id: newerBan.id, ban: caseBan };
    }
    const adminMessage = { chat: sourceChat, from: admin, message_id: sourceChat.message_id };
    const unban = await this.unbanForAppeal(banChatId, appeal.payload?.appealant_id, appealRef, adminMessage, { reconcileFirst: true });
    await this.record('appeal_unban_retry_result', adminMessage, {
      appeal_ref: appealRef,
      target: { id: appeal.payload?.appealant_id },
      target_chat_id: banChatId,
      ok: unban.ok,
      attempts: unban.attempts,
      error: unban.error ? String(unban.error).slice(0, 240) : '',
      evidence: ['Admin requested a manual retry of the idempotent Telegram unban.']
    }, { writeDkg: false, idempotencyKey: `appeal-unban-retry-result:${appealRef}:${Date.now()}` });
    return { ok: unban.ok, unban, error: unban.ok ? '' : 'unban_failed' };
  }

  async unbanForAppeal(chatId = '', userId = '', appealRef = '', adminMessage = {}, { reconcileFirst = false } = {}) {
    if (!chatId || !userId) return { ok: false, attempts: 0, error: 'missing_target' };
    if (!await this.hasBanRights(chatId)) {
      await this.record('appeal_unban_failed', adminMessage, {
        appeal_ref: appealRef,
        target: { id: userId },
        target_chat_id: chatId,
        attempt: 0,
        error: 'missing_ban_rights',
        evidence: ['Appeal overturn recorded; Telegram unban could not run because the bot lacks ban rights.']
      }, { writeDkg: false, idempotencyKey: `appeal-unban-missing-rights:${appealRef}` });
      return { ok: false, attempts: 0, error: 'missing_ban_rights' };
    }
    const reconcile = async () => {
      try {
        const member = await this.call('getChatMember', { chat_id: chatId, user_id: Number(userId) || userId });
        // Telegram reports a still-banned user as "kicked". Any other state
        // means the idempotent unban already took effect or is unnecessary.
        return member && member.status !== 'kicked' ? { ok: true } : { ok: false };
      } catch {
        return { ok: false, unknown: true };
      }
    };
    if (reconcileFirst) {
      const current = await reconcile();
      if (current.ok) {
        await this.record('appeal_unban_completed', adminMessage, {
          appeal_ref: appealRef,
          target: { id: userId },
          target_chat_id: chatId,
          attempts: 0,
          reconciled: true,
          evidence: ['Telegram member state already permitted return; no duplicate unban call was made.']
        }, { writeDkg: false, idempotencyKey: `appeal-unban-reconciled:${appealRef}` });
        return { ok: true, attempts: 0, reconciled: true };
      }
    }
    let lastError = '';
    const runId = randomUUID();
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      if (attempt > 1) {
        const current = await reconcile();
        if (current.ok) {
          await this.record('appeal_unban_completed', adminMessage, {
            appeal_ref: appealRef,
            target: { id: userId },
            target_chat_id: chatId,
            attempts: attempt - 1,
            reconciled: true,
            evidence: ['A retry reconciled the current Telegram member state; no duplicate unban call was made.']
          }, { writeDkg: false, idempotencyKey: `appeal-unban-reconciled:${appealRef}` });
          return { ok: true, attempts: attempt - 1, reconciled: true };
        }
      }
      try {
        // A distinct key per attempt is required after an uncertain timeout:
        // the previous effect may still be unresolved, but unban is idempotent
        // and only permits return. It cannot add a user.
        await this.callEffect('unbanChatMember', { chat_id: chatId, user_id: Number(userId) || userId, only_if_banned: true }, `appeal-unban:${appealRef}:${runId}:${attempt}`);
        await this.record('appeal_unban_completed', adminMessage, {
          appeal_ref: appealRef,
          target: { id: userId },
          target_chat_id: chatId,
          attempts: attempt,
          run_id: runId,
          evidence: ['Telegram unban succeeded. Unban can only permit return; it cannot add a user back.']
        }, { writeDkg: false, idempotencyKey: `appeal-unban-completed:${appealRef}:${runId}:${attempt}` });
        return { ok: true, attempts: attempt };
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        await this.record('appeal_unban_failed', adminMessage, {
          appeal_ref: appealRef,
          target: { id: userId },
          target_chat_id: chatId,
          attempt,
          run_id: runId,
          outcome_unknown: error?.telegramOutcomeUnknown === true,
          error: String(lastError).slice(0, 240),
          evidence: [`Telegram unban attempt ${attempt} failed; visible to admins and safe to retry.`]
        }, { writeDkg: false, idempotencyKey: `appeal-unban-failed:${appealRef}:${runId}:${attempt}` });
      }
    }
    return { ok: false, attempts: 3, error: lastError || 'unban_failed' };
  }

  async handleCommand(message) {
    const text = message.text || '';
    const chatId = message.chat.id;
    const botUsername = this.ownBotUsername() || await this.botUsername().catch(() => '');
    if (isCommand(text, 'start', botUsername)) {
      const isPrivateChat = message.chat?.type === 'private' || Number(chatId) > 0;
      const replyContext = isPrivateChat ? { reply_to_message_id: message.message_id } : {};
      const helpText = isPrivateChat
        ? [this.formatHelp(), '', 'Banned from a group that uses TRACaBot? Send /appeal here to list your own locally stored ban cases. Telegram only lets the bot message you after you start this private chat; the bot cannot send the first DM.', 'Group admins: use Protection controls, Status, Recent automatic bans, or Appeals below. Only current admins of the affected group see its details; bot owners do not bypass group administration.'].join('\n')
        : this.formatHelp();
      await this.sendInteractiveReply(chatId, helpText, this.dashboardKeyboard(message.from?.id || message.from?.username || '', { includeControls: isPrivateChat }), replyContext);
      this.cleanupMenuTrigger(message);
      return;
    }
    if (isCommand(text, 'health', botUsername)) {
      if (!this.isPrivateOwnerMessage(message)) {
        await this.sendCleanCommandReply(message, '⚠️ /health is available only to configured bot owners in private chat.');
        return;
      }
      await this.sendCleanCommandReply(message, await this.formatOwnerHealth());
      return;
    }
    if (isCommand(text, 'appeal', botUsername)) {
      await this.handleAppealCommand(message);
      return;
    }
    if (isCommand(text, 'controls', botUsername)) {
      await this.handleControlsCommand(message);
      return;
    }
    if (isCommand(text, 'appeals', botUsername)) {
      await this.handleAppealsCommand(message);
      return;
    }
    if (isCommand(text, 'appeal_retry', botUsername)) {
      const ref = text.replace(commandRegex('appeal_retry', botUsername), '').trim().split(/\s+/)[0] || '';
      if (!ref) {
        await this.sendCleanCommandReply(message, 'Usage: /appeal_retry <appeal ref>');
        return;
      }
      const result = await this.retryAppealUnban(ref, actorFromMessage(message), message.chat || {});
      await this.sendCleanCommandReply(message, result.ok
        ? '✅ Telegram unban retry completed.'
        : (result.error === 'not_chat_admin'
          ? 'Only an actual admin of the affected group can retry this unban.'
          : result.error === 'ban_superseded'
            ? 'A newer ban for this user in this group supersedes this retry. Review the newer case instead.'
            : 'Unban retry did not succeed; failure remains visible to admins.'));
      return;
    }
    if (isCommand(text, 'appeal_uphold', botUsername) || isCommand(text, 'appeal_overturn', botUsername)) {
      const decision = isCommand(text, 'appeal_overturn', botUsername) ? 'overturn' : 'uphold';
      const args = text.replace(commandRegex(decision === 'overturn' ? 'appeal_overturn' : 'appeal_uphold', botUsername), '').trim();
      const [ref = '', ...reasonParts] = args.split(/\s+/).filter(Boolean);
      if (!ref) {
        await this.sendCleanCommandReply(message, `Usage: /appeal_${decision} <appeal ref> [reason]`);
        return;
      }
      const result = await this.resolveAppeal({ appealRef: ref, admin: actorFromMessage(message), decision, reason: reasonParts.join(' '), sourceChat: message.chat || {} });
      const messages = {
        appeal_not_found: 'Appeal not found.',
        appeal_already_resolved: 'That appeal is already resolved.',
        ban_not_found: 'The local ban record is unavailable.',
        ban_chat_unavailable: 'The affected group is unavailable.',
        not_chat_admin: 'Only an actual admin of the affected group can resolve this appeal.'
      };
      await this.sendCleanCommandReply(message, result.ok
        ? (decision === 'overturn'
          ? (result.unban?.ok ? '✅ Appeal overturned and Telegram unban completed.' : `⚠️ Appeal overturned locally, but Telegram unban failed after ${result.unban?.attempts || 0} attempt(s). Admins can retry.`)
          : '✅ Appeal reviewed and the local ban upheld.')
        : (messages[result.error] || 'Appeal could not be resolved.'));
      return;
    }
    if (isCommand(text, 'scan', botUsername)) {
      if (await this.rejectNonOwnerPrivateReport(message)) return;
      const { target, text: targetText } = this.resolveCommandTarget(message, 'scan');
      const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      await this.recordConversationArtifact({ ...message, from: target }, { risk, text: targetText || message.text, artifactKind: 'safety_question', conversationRole: 'questioner', sourceEventIds: [event.id] });
      const finding = risk.confidence >= 80 ? await this.publishHighConfidenceFinding({ ...message, from: target, text: targetText }, risk) : null;
      await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, risk);
      await this.sendCleanInteractiveCommandReply(message, formatScanReply({ target, risk, eventId: event.id, findingId: finding?.id }), this.scanKeyboard(message.from?.id || message.from?.username || '', target, event.id));
      return;
    }

    if (isCommand(text, 'report', botUsername)) {
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
        await this.sendCleanCommandReply(message, formatReportReply(event, reportDecision));
        return;
      }
      const event = await this.record('report_review_needed', { ...message, from: target }, reportPayload, { writeDkg: false });
      await this.maybeRecordCampaign({ ...message, from: target, text: targetText }, reportPayload);
      await this.recordConversationArtifact({ ...message, from: target }, { risk: reportPayload, text: targetText || evidenceText(message), artifactKind: 'report_review_observation', conversationRole: 'reporter', sourceEventIds: [event.id] });
      await this.sendCleanCommandReply(message, formatReportReply(event, reportDecision));
      return;
    }
    if (isCommand(text, 'mute', botUsername)) {
      await this.handleMuteCommand(message);
      return;
    }
    if (isCommand(text, 'ban', botUsername)) {
      const { target, text: targetText } = this.resolveCommandTarget(message, 'ban');
      const replyUser = target?.id ? target : message.reply_to_message?.from;
      if (!await this.isTrustedModerator(message)) {
        const event = await this.record('ban_rejected_unauthorized', { ...message, from: target }, {
          reason: 'manual /ban rejected because requester is not a configured admin or Telegram chat admin',
          requester: actorFromMessage(message),
          evidence: ['manual /ban requires trusted moderator privileges']
        }, { writeDkg: false });
        await this.sendCleanCommandReply(message, `⚠️ /ban is restricted to configured admins or Telegram chat admins. Request logged locally as ${event.id}.`);
        return;
      }
      if (!replyUser?.id) {
        const risk = await this.assess({ ...message, from: target, text: targetText }, target, targetText);
        const event = await this.record('ban_requested_no_reply', { ...message, from: target }, {
          ...risk,
          evidence: [...risk.evidence, 'manual /ban requested without a replied Telegram user ID']
        });
        await this.sendCleanCommandReply(message, `⚠️ I can scan or report ${target.label || target.username || 'that target'}, but Telegram needs you to reply to the exact user's message before I can ban them. I saved the evidence for admin review.`);
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
      const effectPrefix = `manual-ban:${chatId}:${message.message_id}:${replyUser.id}`;
      await this.callEffect('banChatMember', { chat_id: chatId, user_id: replyUser.id }, `${effectPrefix}:ban`);
      const repliedMessageId = String(message.reply_to_message?.from?.id || '') === String(replyUser.id || '') ? message.reply_to_message?.message_id : '';
      const deletedMessages = await this.deleteKnownUserMessages(chatId, replyUser.id, [repliedMessageId], effectPrefix);
      const repliedMessageDeleted = Boolean(repliedMessageId && deletedMessages.deleted > 0);
      const repliedMessageDeleteError = deletedMessages.failed ? `${deletedMessages.failed} message delete attempt${deletedMessages.failed === 1 ? '' : 's'} failed` : '';
      const deletionNote = replyUser.sangmata ? '' : deletedMessages.deleted ? ` Removed ${deletedMessages.deleted} message${deletedMessages.deleted === 1 ? '' : 's'}.` : '';
      await this.recordBanEvidenceInBackground(message, replyUser, risk, reason, {
        repliedMessageId: repliedMessageId || '',
        repliedMessageDeleted,
        repliedMessageDeleteError,
        deletedMessageCount: deletedMessages.deleted,
        deleteAttemptCount: deletedMessages.attempted,
        sangmataEvidence: replyUser.sangmata?.evidence || '',
        source: 'manual /ban command',
        performedBy: { id: message.from?.id, username: message.from?.username || '', is_bot: message.from?.is_bot === true },
        reasonProvided: reason !== 'admin requested ban'
      });
      await this.sendCleanCommandReply(message, `${formatBanReply(replyUser, '')}${deletionNote}`);
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
    const memoryCard = this.selectMemoryCardChallenge(chatId, member);
    if (memoryCard) {
      return [
        '🛡️ TRACaBot Memory Check',
        '',
        `${userMention(member)}, quick anti-bot check before posting.`,
        '',
        'TRACaBot uses shared agent memory to remember scam signals across communities.',
        '',
        'Open DM and answer one memory question to unlock.',
        `Time limit: ${ttl}s.`
      ].join('\n');
    }
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

  joinChallengeKeyboard(chatId, member, challenge) {
    if (challenge?.mode !== 'memory-card') return null;
    const username = this.botUsernameCache || 'tracethembot';
    return inlineKeyboard([
      [urlButton('🧠 Answer in DM', `https://t.me/${username}?start=${verifyStartPayload(chatId, member.id)}`)],
      [button('❔ What is memory?', callbackData('join-info', String(member.id)))]
    ]);
  }

  memoryCardText(card) {
    const rows = [
      '🧠 Memory Check',
      '',
      'TRACaBot memory stores reusable safety records that agents can recognize across communities.',
      '',
      'Memory card:'
    ];
    if (card.memoryId && card.field !== 'ID') rows.push(`ID: ${card.memoryId}`);
    if (card.field && card.value) rows.push(`${card.field}: ${card.value}`);
    if (card.signal) rows.push(`Signal: ${card.signal}`);
    if (card.alert) rows.push(`Alert: ${card.alert}`);
    if (card.use) rows.push(`Use: ${card.use}`);
    rows.push('', card.question);
    return rows.join('\n');
  }

  memoryCardKeyboard(chatId, userId, card) {
    return inlineKeyboard(card.options.map((option, index) => [button(option, callbackData('join-answer', chatId, userId, card.id, index))]));
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
    const expiresAt = Date.now() + (this.config.joinChallengeTtlSeconds ?? 60) * 1000;
    const key = this.challengeKey(chatId, member.id);
    const memoryCard = this.selectMemoryCardChallenge(chatId, member);
    const qa = memoryCard ? null : this.selectJoinChallengeQa(chatId, member);
    const challenge = { chat: message.chat, user: member, startedAt: Date.now(), expiresAt, messageId: '', attempts: 0, mode: memoryCard ? 'memory-card' : (qa ? 'qa' : 'ual'), qa, memoryCard, restricted: false };
    this.joinChallenges.set(key, challenge);
    this.scheduleJoinChallengeExpiry(key, challenge);
    let restricted = false;
    try {
      await this.restrict(chatId, member.id, Math.floor(expiresAt / 1000));
      restricted = true;
      challenge.restricted = true;
      const username = await this.botUsername().catch(() => 'tracethembot');
      this.botUsernameCache = username;
      const sent = await this.send(chatId, await this.challengeText(chatId, member), { parse_mode: 'HTML', disable_web_page_preview: true, reply_markup: this.joinChallengeKeyboard(chatId, member, challenge) });
      challenge.messageId = sent?.message_id || '';
    } catch (error) {
      this.joinChallenges.delete(key);
      this.clearJoinChallengeTimer(key);
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
      challenge_type: challenge.mode === 'memory-card' ? 'memory_card' : (qa ? 'dkg_asset_qa' : 'dkg_ual'),
      challenge_id: memoryCard?.id || qa?.id || '',
      ttl_seconds: this.config.joinChallengeTtlSeconds || 60,
      restricted_text_only: restricted,
      evidence: [challenge.mode === 'memory-card' ? 'new user asked to answer a TRACaBot memory-card challenge' : (qa ? 'new user asked to answer a DKG Knowledge Asset question' : 'new user asked to verify with a DKG Knowledge Asset UAL')]
    }, { writeDkg: false });
  }

  clearJoinChallengeTimer(key) {
    const timer = this.joinChallengeTimers.get(key);
    if (timer) clearTimeout(timer);
    this.joinChallengeTimers.delete(key);
  }

  scheduleJoinChallengeExpiry(key, challenge) {
    this.clearJoinChallengeTimer(key);
    const delay = Math.max(0, challenge.expiresAt - Date.now());
    const graceMs = Math.min(250, Math.max(10, delay * 0.1));
    const timer = setTimeout(() => {
      this.expireJoinChallenges().catch((error) => console.error(error instanceof Error ? error.message : String(error)));
    }, delay + graceMs);
    timer.unref?.();
    this.joinChallengeTimers.set(key, timer);
  }

  async deleteJoinChallengePrompt(challenge) {
    if (!challenge?.messageId || !challenge.chat?.id) return false;
    if (!await this.hasDeleteRights(challenge.chat.id)) return false;
    await this.deleteMessage(challenge.chat.id, challenge.messageId).catch(() => null);
    return true;
  }

  selectJoinChallengeQa(chatId, member = {}) {
    if (this.config.joinChallengeMode !== 'qa') return null;
    if (!this.config.joinChallengeAssetUrl || !Array.isArray(this.config.joinChallengeQaBank) || this.config.joinChallengeQaBank.length === 0) return null;
    const bucket = Math.floor(Date.now() / Math.max(1, (this.config.joinChallengeTtlSeconds || 60) * 1000));
    const seed = `${chatId}:${member.id}:${bucket}`;
    let hash = 0;
    for (const char of seed) hash = ((hash * 31) + char.charCodeAt(0)) >>> 0;
    const entry = this.config.joinChallengeQaBank[hash % this.config.joinChallengeQaBank.length];
    return { ...entry, assetUrl: this.config.joinChallengeAssetUrl };
  }

  selectMemoryCardChallenge(chatId, member = {}) {
    if (this.config.joinChallengeMode !== 'memory-card') return null;
    const bucket = Math.floor(Date.now() / Math.max(1, (this.config.joinChallengeTtlSeconds || 60) * 1000));
    const seed = `${chatId}:${member.id}:${bucket}`;
    let hash = 0;
    for (const char of seed) hash = ((hash * 31) + char.charCodeAt(0)) >>> 0;
    const template = MEMORY_CARD_CHALLENGES[hash % MEMORY_CARD_CHALLENGES.length];
    return { ...template, options: [...template.options] };
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
    if (challenge.mode === 'memory-card') {
      await this.send(message.chat.id, this.memoryCardText(challenge.memoryCard), { private: true, reply_markup: this.memoryCardKeyboard(payload.chatId, payload.userId, challenge.memoryCard) });
    } else if (challenge.mode === 'qa') {
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
    const key = this.challengeKey(chatId, challenge.user.id);
    this.joinChallenges.delete(key);
    this.clearJoinChallengeTimer(key);
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
    await this.deleteJoinChallengePrompt(challenge);
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
        challenge_type: challenge.mode === 'memory-card' ? 'memory_card' : (challenge.mode === 'qa' ? 'dkg_asset_qa' : 'dkg_ual'),
        challenge_id: challenge.memoryCard?.id || challenge.qa?.id || '',
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
    if (challenge.mode === 'memory-card') {
      const selected = this.resolveMemoryCardAnswer(challenge.memoryCard, text);
      return this.handleMemoryCardAnswer({ id: '', from: message.from, message: { chat: { id: replyChatId, type: 'private' }, message_id: message.message_id } }, challenge, selected, options);
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

  resolveMemoryCardAnswer(card, text = '') {
    const value = String(text || '').trim();
    const letter = value.match(/^[abc]$/i)?.[0]?.toLowerCase();
    if (letter) return letter.charCodeAt(0) - 97;
    const normalized = normalizeChallengeAnswer(value);
    return (card?.options || []).findIndex((option) => normalizeChallengeAnswer(option) === normalized);
  }

  async handleMemoryCardAnswer(query, challenge, selectedIndex, options = {}) {
    const card = challenge.memoryCard || {};
    const sourceChatId = options.sourceChatId || query.message?.chat?.id || query.from?.id;
    const message = { chat: challenge.chat, from: challenge.user, message_id: query.message?.message_id, text: card.options?.[selectedIndex] || '' };
    if (selectedIndex === card.answerIndex) {
      if (query.id) await this.answerCallback(query.id, 'Correct. Unlocking...').catch(() => null);
      if (query.message?.chat?.id && query.message?.message_id) await this.editInteractiveMessage(query.message.chat.id, query.message.message_id, `✅ Correct.\n\n${card.explanation || 'That is the reusable memory detail TRACaBot can carry across communities.'}`, [], { disable_web_page_preview: true }).catch(() => null);
      return this.completeJoinChallenge(message, challenge, { ...options, dm: true, sourceChatId }, { answer: card.options[selectedIndex], validationReason: 'memory_card_answer_match' });
    }

    challenge.attempts += 1;
    await this.record('join_challenge_bad_attempt', message, {
      target: challenge.user,
      target_key: targetKey(challenge.user),
      alias_keys: challengeAliasSignals(challenge.user),
      attempts: challenge.attempts,
      challenge_type: 'memory_card',
      challenge_id: card.id || '',
      selected_answer: card.options?.[selectedIndex] || '',
      verification_channel: 'dm',
      evidence: ['pending join challenge user selected an incorrect TRACaBot memory-card answer']
    }, { writeDkg: false });
    if (await this.maybeFailJoinChallenge(message, challenge, { ...options, dm: true, sourceChatId })) return true;
    const reply = `Not quite. Look for the answer that matches the memory card.\n\n${this.memoryCardText(card)}`;
    if (query.id) await this.answerCallback(query.id, 'Not quite. Try again.').catch(() => null);
    if (query.message?.chat?.id && query.message?.message_id) await this.editInteractiveMessage(query.message.chat.id, query.message.message_id, reply, this.memoryCardKeyboard(challenge.chat.id, challenge.user.id, card), { disable_web_page_preview: true }).catch(() => null);
    else if (sourceChatId) await this.send(sourceChatId, reply, { private: true, reply_markup: this.memoryCardKeyboard(challenge.chat.id, challenge.user.id, card) }).catch(() => null);
    return true;
  }

  async completeJoinChallenge(message, challenge, options = {}, result = {}) {
    const chatId = message.chat.id;
    const replyChatId = options.sourceChatId || chatId;
    const key = this.challengeKey(chatId, message.from.id);
    this.joinChallenges.delete(key);
    this.clearJoinChallengeTimer(key);
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
      challenge_type: challenge.mode === 'memory-card' ? 'memory_card' : (challenge.mode === 'qa' ? 'dkg_asset_qa' : 'dkg_ual'),
      challenge_id: challenge.memoryCard?.id || challenge.qa?.id || '',
      verification_channel: options.dm ? 'dm' : 'group',
      evidence: [challenge.mode === 'memory-card' ? 'new user answered the TRACaBot memory-card challenge' : (challenge.mode === 'qa' ? 'new user answered the DKG Knowledge Asset challenge' : 'new user completed DKG Knowledge Asset UAL verification')]
    }, { writeDkg: false });
    if (options.dm) {
      const accessLink = await this.groupAccessLink(challenge.chat);
      const accessText = accessLink ? `\n\nReturn to the community: ${accessLink}` : '';
      const ualEducation = challenge.mode === 'ual' ? `\n\n${this.ualChallengeEducationText()}` : '';
      const memoryEducation = challenge.mode === 'memory-card' ? '\n\nTRACaBot memory helps communities and agents reuse safety signals instead of starting from zero each time.' : '';
      await this.send(replyChatId, `✅ You’re in.${memoryEducation}${ualEducation}${accessText}`, { disable_web_page_preview: true });
    }
    const successText = `✅ Memory-verified: ${userMention(message.from)}\n\nYou are now protected by TRACaBot shared memory against repeat scams and impersonators.`;
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
    if (parsed.action === 'join-info') {
      await this.answerCallback(query.id, 'TRACaBot memory is reusable safety context agents can carry across communities.', true);
      return true;
    }
    if (parsed.action === 'join-answer') {
      const [challengeChatId, userId, cardId, selectedRaw] = parsed.parts;
      if (String(from.id || '') !== String(userId || '')) {
        await this.answerCallback(query.id, 'This challenge belongs to another user.');
        return true;
      }
      const challenge = this.joinChallenges.get(this.challengeKey(challengeChatId, userId));
      if (!challenge || challenge.mode !== 'memory-card' || challenge.memoryCard?.id !== cardId) {
        await this.answerCallback(query.id, 'Challenge expired. Ask an admin to restart verification.');
        return true;
      }
      return this.handleMemoryCardAnswer(query, challenge, Number(selectedRaw), { dm: true, sourceChatId: chatId });
    }
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
    if (parsed.action === 'appeal-uphold' || parsed.action === 'appeal-overturn') {
      const appealRef = parsed.parts[1] || '';
      const decision = parsed.action === 'appeal-overturn' ? 'overturn' : 'uphold';
      const result = await this.resolveAppeal({ appealRef, admin: from, decision, sourceChat: message.chat || {} });
      const messages = {
        appeal_not_found: 'Appeal not found.',
        appeal_already_resolved: 'That appeal is already resolved.',
        ban_not_found: 'The local ban record is unavailable.',
        ban_chat_unavailable: 'The affected group is unavailable.',
        not_chat_admin: 'Only an actual admin of the affected group can resolve this appeal.'
      };
      const text = result.ok
        ? (decision === 'overturn'
          ? (result.unban?.ok
            ? '✅ Appeal overturned. Telegram unban completed; the user may return if no other restriction applies. Creator global record unchanged.'
            : `⚠️ Appeal overturned locally, but Telegram unban failed after ${result.unban?.attempts || 0} attempt(s). Failure is recorded for admins. Creator global record unchanged.`)
          : '✅ Appeal reviewed. Local ban upheld. Creator global record unchanged.')
        : (messages[result.error] || 'Appeal could not be resolved.');
      await this.editInteractiveMessage(chatId, message.message_id, text, [[button('✖️ Close', callbackData('close', requester || 'admin'))]]).catch(() => null);
      await this.answerCallback(query.id, result.ok ? 'Appeal resolved' : text, !result.ok);
      return true;
    }
    const adminWideAction = parsed.action.startsWith('review-') || parsed.action.startsWith('warn-');
    if (requester && String(from.id || from.username || '') !== String(requester) && !(trusted && adminWideAction)) {
      await this.answerCallback(query.id, 'Open your own panel to use these buttons.');
      return true;
    }
    if (!trusted && adminWideAction) {
      await this.answerCallback(query.id, 'Admin only');
      return true;
    }
    const controlAction = ['controls', 'controls-refresh', 'controls-status', 'controls-recent', 'controls-join-toggle', 'controls-ban-open', 'controls-ban-confirm', 'controls-ban-retry', 'appeals'].includes(parsed.action);
    if (controlAction) {
      const isPrivate = message.chat?.type === 'private' || Number(chatId) > 0;
      if (!isPrivate) {
        await this.answerCallback(query.id, 'Use /controls in a private chat.');
        return true;
      }
      const render = async () => {
        const view = await this.controlsView(from.id || from.username || '');
        await this.editInteractiveMessage(chatId, message.message_id, view.text, view.rows);
      };
      if (parsed.action === 'controls' || parsed.action === 'controls-refresh') {
        await this.answerCallback(query.id);
        await render();
        return true;
      }
      if (parsed.action === 'controls-status' || parsed.action === 'controls-recent' || parsed.action === 'appeals') {
        const view = parsed.action === 'controls-status'
          ? await this.protectionStatusView(from.id || from.username || '')
          : parsed.action === 'controls-recent'
            ? await this.recentAutoBansView(from.id || from.username || '')
            : await this.appealsView(from.id || from.username || '');
        await this.answerCallback(query.id);
        await this.editInteractiveMessage(chatId, message.message_id, view.text, view.rows);
        return true;
      }
      if (parsed.action === 'controls-join-toggle') {
        const targetChatId = parsed.parts[1] || '';
        const nextPaused = parsed.parts[2] === 'on';
        if (!await this.isAppealAdminForChat(from.id, targetChatId)) {
          await this.answerCallback(query.id, 'Only a current admin of that group can change this.', true);
          return true;
        }
        const group = this.controlGroupCandidates().find((item) => item.id === String(targetChatId)) || {};
        await this.setJoinAutoRemovalPaused({ id: targetChatId, type: 'supergroup', title: group.title || '' }, nextPaused, from, 'private controls');
        await this.answerCallback(query.id, nextPaused ? 'Paused future join removals. Evidence capture continues.' : 'Resumed future join removals. Configured policy still applies.');
        await render();
        return true;
      }
      if (parsed.action === 'controls-ban-open') {
        const view = await this.showAutoBanControl(eventId, from, message.chat || {});
        if (!view.ok) {
          await this.answerCallback(query.id, view.error === 'not_chat_admin' ? 'Only a current admin of the affected group can review this ban.' : 'Automatic join ban not found.', true);
          return true;
        }
        await this.answerCallback(query.id);
        await this.editInteractiveMessage(chatId, message.message_id, view.text, view.rows);
        return true;
      }
      if (parsed.action === 'controls-ban-confirm') {
        const ban = this.findEvent(eventId);
        const result = await this.overrideAutomaticBan({ ban, admin: from, sourceChat: message.chat || {} });
        if (!result.ok) {
          const messageText = result.error === 'not_chat_admin'
            ? 'Only a current admin of the affected group can override this ban.'
            : 'Automatic join ban could not be overridden.';
          await this.answerCallback(query.id, messageText, true);
          return true;
        }
        const text = result.already
          ? (result.unbanPending
            ? 'A local override is already recorded, but Telegram unban is still pending. Use Retry unban from the case view.'
            : 'A local override is already recorded for this automatic join ban. Refresh controls to see current state.')
          : (result.unban?.ok
            ? '✅ Override recorded and Telegram unban completed. The user may return if no other restriction applies. This is separate from pausing future join removals.'
            : `⚠️ Override recorded locally, but Telegram unban did not complete after ${result.unban?.attempts || 0} attempt(s). Future pause state is separate; admins still see the failure.`);
        const retryAvailable = result.unbanPending === true || (result.unban && result.unban.ok === false);
        const rows = retryAvailable
          ? [
            [button('🔁 Retry unban', callbackData('controls-ban-retry', from.id || from.username || 'admin', shortId(eventId)))],
            [button('🔄 Refresh controls', callbackData('controls-refresh', from.id || from.username || 'admin')), button('✖️ Close', callbackData('close', from.id || from.username || 'admin'))]
          ]
          : [[button('🔄 Refresh controls', callbackData('controls-refresh', from.id || from.username || 'admin')), button('✖️ Close', callbackData('close', from.id || from.username || 'admin'))]];
        await this.editInteractiveMessage(chatId, message.message_id, text, rows).catch(() => null);
        await this.answerCallback(query.id, result.unban?.ok ? 'Unban completed' : (result.unbanPending ? 'Unban retry available' : 'Override recorded'));
        return true;
      }
      if (parsed.action === 'controls-ban-retry') {
        const ban = this.findEvent(eventId);
        const result = await this.retryAutomaticBanOverride({ ban, admin: from, sourceChat: message.chat || {}, requestId: query.id });
        if (!result.ok) {
          const messageText = result.error === 'not_chat_admin'
            ? 'Only a current admin of the affected group can retry this unban.'
            : result.error === 'override_not_found'
              ? 'Record the local override before retrying the unban.'
              : result.error === 'ban_superseded'
                ? 'A newer ban for this user in this group supersedes this retry. Review the newer case instead.'
                : 'Automatic join ban unban retry could not run.';
          await this.answerCallback(query.id, messageText, true);
          return true;
        }
        const text = result.unban?.ok
          ? '✅ Telegram unban retry completed. The local correction and creator global record are unchanged.'
          : `⚠️ Telegram unban retry did not complete after ${result.unban?.attempts || 0} attempt(s). The local correction remains and admins still see the failure.`;
        await this.editInteractiveMessage(chatId, message.message_id, text, [
          [button('🛡️ Protection controls', callbackData('controls', from.id || from.username || 'admin')), button('🚨 Recent automatic bans', callbackData('controls-recent', from.id || from.username || 'admin'))],
          [button('✖️ Close', callbackData('close', from.id || from.username || 'admin'))]
        ]).catch(() => null);
        await this.answerCallback(query.id, result.unban?.ok ? 'Unban completed' : 'Unban still pending');
        return true;
      }
    }
    const deferredReviewDecision = parsed.action === 'review-confirm' || parsed.action === 'review-reject';
    if (!deferredReviewDecision) await this.answerCallback(query.id);

    if (parsed.action === 'dashboard') {
      await this.editInteractiveMessage(chatId, message.message_id, this.formatHelp(), this.dashboardKeyboard(requester, { includeControls: message.chat?.type === 'private' }));
      return true;
    }

    if (parsed.action === 'campaign-settings' || parsed.action === 'campaign-policy-set') {
      if (!['group', 'supergroup', 'channel'].includes(message.chat?.type)
        || !await this.isTelegramChatAdmin(chatId, from.id, { requireLiveLookup: true }).catch(() => false)) {
        await this.answerCallback(query.id, 'Actual chat admin required');
        return true;
      }
      if (parsed.action === 'campaign-policy-set') {
        const policyId = parsed.parts[1];
        const value = parsed.parts[2];
        if (!CAMPAIGN_POLICIES.some((policy) => policy.id === policyId) || !['on', 'off'].includes(value)) {
          await this.answerCallback(query.id, 'Unknown campaign policy or setting');
          return true;
        }
        await this.record('campaign_policy_setting_changed', callbackMessage, {
          campaign_policy_id: policyId, enabled: value === 'on', moderator: from,
          evidence: [`chat admin set campaign policy ${policyId} ${value}`]
        }, { writeDkg: false });
      }
      await this.editInteractiveMessage(chatId, message.message_id, this.campaignSettingsText(chatId), this.campaignSettingsKeyboard(requester, chatId));
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
      await this.editInteractiveMessage(chatId, message.message_id, this.formatReviewPanel('flags', chatId), this.reviewPanelKeyboard(requester, 'flags', chatId), { parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (parsed.action === 'review-tab') {
      if (!trusted) {
        await this.answerCallback(query.id, 'Admin only');
        return true;
      }
      const filter = parsed.parts[1] || 'flags';
      await this.editInteractiveMessage(chatId, message.message_id, this.formatReviewPanel(filter, chatId), this.reviewPanelKeyboard(requester, filter, chatId), { parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (['stats', 'stats-sources', 'campaigns', 'banlist', 'status', 'challenge-set', 'conversation-set', 'review-notice-set', 'review-notice-interval', 'policy-profile', 'help', 'help-scan', 'why'].includes(parsed.action)) {
      if (requester && String(from.id || from.username || '') !== String(requester)) {
        await this.answerCallback(query.id, 'Open your own panel to use these buttons.');
        return true;
      }
      if (parsed.action === 'stats' || parsed.action === 'stats-sources') {
        await this.editInteractiveMessage(chatId, message.message_id, '📊 Loading stats...', this.statsKeyboard(requester)).catch(() => null);
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
        await this.editInteractiveMessage(chatId, message.message_id, '👮 Loading enforcement status...', this.banlistKeyboard(requester), { parse_mode: 'HTML', disable_web_page_preview: true }).catch(() => null);
        await this.editInteractiveMessage(chatId, message.message_id, await this.formatBanlist(), this.banlistKeyboard(requester), { parse_mode: 'HTML', disable_web_page_preview: true });
        return true;
      }
      if (parsed.action === 'status') {
        if (!trusted) {
          await this.answerCallback(query.id, 'Admin only');
          return true;
        }
        await this.editInteractiveMessage(chatId, message.message_id, '🩺 Checking status...', this.settingsKeyboard(requester, chatId)).catch(() => null);
        await this.editInteractiveMessage(chatId, message.message_id, await this.formatStatus(callbackMessage), this.settingsKeyboard(requester, chatId));
        return true;
      }
      if (parsed.action === 'challenge-set' || parsed.action === 'conversation-set' || parsed.action === 'review-notice-set' || parsed.action === 'review-notice-interval' || parsed.action === 'policy-profile') {
        if (!trusted) {
          await this.answerCallback(query.id, 'Admin only');
          return true;
        }
        const value = parsed.parts[1] || 'status';
        if (parsed.action === 'policy-profile') {
          if (['strict', 'balanced', 'monitor'].includes(value)) {
            await this.record('policy_profile_changed', callbackMessage, { profile: value, moderator: from, evidence: [`admin set channel protection profile to ${value}`] }, { writeDkg: false });
          }
        } else if (parsed.action === 'review-notice-interval') {
          const intervalHours = Number(value);
          if ([6, 12, 24].includes(intervalHours)) {
            await this.record('pending_review_notification_interval_changed', callbackMessage, { interval_hours: intervalHours, moderator: from, evidence: [`admin set pending review notification interval to ${intervalHours}h`] }, { writeDkg: false });
          }
        } else {
          const setting = parsed.action === 'challenge-set' ? 'join_challenge_setting_changed' : parsed.action === 'conversation-set' ? 'conversational_setting_changed' : 'pending_review_notification_setting_changed';
          const label = parsed.action === 'challenge-set' ? 'new-user join challenge' : parsed.action === 'conversation-set' ? 'conversation mode' : 'pending review notifications';
          if (value === 'on' || value === 'off') {
            await this.record(setting, callbackMessage, { enabled: value === 'on', moderator: from, evidence: [`admin turned ${label} ${value}`] }, { writeDkg: false });
          }
        }
        await this.editInteractiveMessage(chatId, message.message_id, this.settingsText(chatId), this.settingsKeyboard(requester, chatId));
        return true;
      }
      if (parsed.action === 'help' || parsed.action === 'help-scan') {
        await this.editInteractiveMessage(chatId, message.message_id, this.formatMenuHelp(), this.mainNavKeyboard(requester));
        return true;
      }
      if (parsed.action === 'why') {
        if (!trusted) {
          await this.answerCallback(query.id, 'Admin only');
          return true;
        }
        await this.editInteractiveMessage(chatId, message.message_id, this.formatWhy(parsed.parts[1] || '', chatId), this.statsKeyboard(requester));
        return true;
      }
    }
    if (parsed.action === 'review-open') {
      const event = this.findEvent(eventId);
      if (!event) {
        await this.answerCallback(query.id, 'Review item not found');
        return true;
      }
      if (!eventChatKey(event)) {
        await this.answerCallback(query.id, 'Review channel unavailable');
        return true;
      }
      if (!sameChat(eventChatKey(event), chatId)) {
        await this.answerCallback(query.id, 'Review belongs to another channel');
        return true;
      }
      if (!this.isPendingReviewEvent(event)) {
        await this.answerCallback(query.id, 'Already reviewed or expired');
        return true;
      }
      const hidden = this.isReviewHiddenForChat(event, chatId);
      await this.editInteractiveMessage(chatId, message.message_id, this.formatReviewDetail(event), hidden ? this.hiddenReviewActionKeyboard(requester, event.id) : this.reviewActionKeyboard(requester, event.id), { parse_mode: 'HTML', disable_web_page_preview: true });
      return true;
    }
    if (parsed.action === 'review-hide' || parsed.action === 'review-unhide') {
      const event = this.findEvent(eventId);
      if (!event) {
        await this.answerCallback(query.id, 'Review item not found');
        return true;
      }
      if (!eventChatKey(event)) {
        await this.answerCallback(query.id, 'Review channel unavailable');
        return true;
      }
      if (!sameChat(eventChatKey(event), chatId)) {
        await this.answerCallback(query.id, 'Review belongs to another channel');
        return true;
      }
      if (!this.isPendingReviewEvent(event)) {
        await this.answerCallback(query.id, 'Already reviewed or expired');
        return true;
      }
      const hidden = parsed.action === 'review-hide';
      const target = event.user || event.payload?.target || {};
      await this.record(hidden ? 'review_hidden' : 'review_unhidden', callbackMessage, {
        target_event_id: event.id,
        reviewed_target: target,
        review_chat_id: chatId,
        moderator: from,
        evidence: [`admin ${hidden ? 'hid' : 'unhid'} review ${shortId(event.id)} in this channel`]
      }, { writeDkg: false });
      await this.editInteractiveMessage(
        chatId,
        message.message_id,
        hidden ? `🙈 Hidden here. This review will not notify this channel. Use Hidden to unhide it later.` : `👁️ Unhidden here. This review is back in this channel queue.`,
        [[button(hidden ? '🙈 Hidden reviews' : '↩️ Back to queue', callbackData('review-tab', requester, hidden ? 'hidden' : 'flags')), button('✖️ Close', callbackData('close', requester))]],
        { parse_mode: 'HTML' }
      );
      return true;
    }
    if (parsed.action === 'review-confirm' || parsed.action === 'review-reject') {
      const event = this.findEvent(eventId);
      if (!event) {
        await this.answerCallback(query.id, 'Review item not found');
        return true;
      }
      const finalDecision = parsed.action === 'review-confirm' ? 'confirm' : 'reject';
      const target = event.user || event.payload?.target || {};
      if (!eventChatKey(event)) {
        await this.answerCallback(query.id, 'Review channel unavailable');
        return true;
      }
      if (eventChatKey(event) && !sameChat(eventChatKey(event), chatId)) {
        await this.answerCallback(query.id, 'Review belongs to another channel');
        return true;
      }
      const priorBatchDecision = [...this.store.all()].reverse().find((item) =>
        ['review_upheld', 'review_overturned'].includes(item.event_type)
        && item.payload?.review_decision_key
        && Array.isArray(item.payload?.review_batch_event_ids)
        && item.payload.review_batch_event_ids.includes(event.id)
      );
      if (priorBatchDecision) {
        const priorPayload = priorBatchDecision.payload || {};
        const priorDecision = priorPayload.review_decision === 'reject' ? 'reject' : 'confirm';
        const batchEventIds = priorPayload.review_batch_event_ids;
        const repairClaim = this.store.beginEffect?.(priorPayload.review_decision_key, 'review-decision', { chatId, target: targetKey(target) });
        if (repairClaim?.completed || repairClaim?.inProgress || repairClaim?.uncertain) {
          const status = repairClaim.completed
            ? 'Already reviewed'
            : repairClaim.uncertain
              ? 'Prior review outcome unknown; manual verification required'
              : 'Review decision in progress';
          await this.answerCallback(query.id, status);
          return true;
        }
        try {
          const recordedBatchEventIds = new Set(this.store.all()
            .filter((item) => ['review_upheld', 'review_overturned'].includes(item.event_type) && item.payload?.review_decision_key === priorPayload.review_decision_key)
            .map((item) => item.payload?.target_event_id)
            .filter(Boolean));
          const missingBatchEvents = batchEventIds
            .filter((id) => !recordedBatchEventIds.has(id))
            .map((id) => this.store.all().find((item) => item.id === id))
            .filter(Boolean);
          if (missingBatchEvents.length) {
            const repairMessage = { ...callbackMessage, from: priorPayload.reviewer || priorBatchDecision.user || from };
            await this.recordReviewDecisionForEvents(
              repairMessage,
              missingBatchEvents,
              priorDecision,
              priorPayload.reason || (priorDecision === 'confirm' ? 'admin confirmed scam flag' : 'admin rejected scam flag as false positive'),
              {
                target: priorPayload.reviewed_target || target,
                reviewChatId: priorPayload.review_chat_id || chatId,
                extraPayload: {
                  review_batch_id: priorPayload.review_batch_id,
                  review_decision_key: priorPayload.review_decision_key,
                  review_batch_event_ids: batchEventIds,
                  review_batch_cutoff: priorPayload.review_batch_cutoff,
                  enforcement_banned: priorPayload.enforcement_banned,
                  enforcement_reason: priorPayload.enforcement_reason,
                  delete_attempt_count: priorPayload.delete_attempt_count,
                  deleted_message_count: priorPayload.deleted_message_count,
                  delete_failure_count: priorPayload.delete_failure_count
                },
                evidencePrefix: `recovered admin callback ${priorDecision === 'confirm' ? 'confirmed scam flag' : 'rejected scam flag'}`,
                idempotencyKey: priorPayload.review_decision_key,
                repairBatch: true
              }
            );
          }
          const banEvidenceExists = this.store.all().some((item) =>
            item.event_type === 'ban_executed'
            && (item.payload?.review_decision_key === priorPayload.review_decision_key
              || (priorPayload.review_batch_id && item.payload?.review_batch_id === priorPayload.review_batch_id))
          );
          if (priorDecision === 'confirm' && priorPayload.enforcement_banned && !banEvidenceExists) {
            const reviewedTarget = priorPayload.reviewed_target || target;
            await this.record('ban_executed', { ...callbackMessage, from: reviewedTarget }, {
              target: reviewedTarget,
              target_key: targetKey(reviewedTarget),
              moderator: priorPayload.reviewer || priorBatchDecision.user || from,
              admin_verified: true,
              target_event_id: priorPayload.target_event_id || batchEventIds[0],
              target_chat_id: priorPayload.target_chat_id || chatId,
              review_batch_id: priorPayload.review_batch_id,
              review_decision_key: priorPayload.review_decision_key,
              review_batch_event_ids: batchEventIds,
              review_batch_cutoff: priorPayload.review_batch_cutoff,
              reason: priorPayload.reason || 'admin confirmed scam flag',
              deleted_message_count: priorPayload.deleted_message_count,
              delete_attempt_count: priorPayload.delete_attempt_count,
              delete_failure_count: priorPayload.delete_failure_count,
              evidence: [`recovered ban evidence for review batch ${priorPayload.review_batch_id || priorPayload.review_decision_key}`]
            }, { idempotencyKey: `${priorPayload.review_decision_key}:ban` });
          }
          this.store.completeEffect?.(priorPayload.review_decision_key, { decision: priorDecision, reviewed: batchEventIds.length });
        } catch (error) {
          this.store.failEffect?.(priorPayload.review_decision_key, error instanceof Error ? error.message : String(error));
          throw error;
        }
        await this.answerCallback(query.id, priorDecision === finalDecision ? 'Already reviewed' : `Already reviewed as ${priorDecision === 'confirm' ? 'scam' : 'false positive'}`);
        return true;
      }
      if (!this.isPendingReviewEvent(event)) {
        const recordedDecision = this.store.all().find((item) =>
          ['review_upheld', 'review_overturned'].includes(item.event_type)
          && item.payload?.target_event_id === event.id
          && item.payload?.review_decision === finalDecision
        );
        if (recordedDecision?.payload?.review_decision_key) this.store.completeEffect?.(recordedDecision.payload.review_decision_key, { decision: finalDecision, reviewed: 1 }, { allowUncertain: true });
        await this.answerCallback(query.id, 'Already reviewed or expired');
        return true;
      }
      const reason = finalDecision === 'confirm' ? 'admin confirmed scam flag' : 'admin rejected scam flag as false positive';
      const events = this.pendingReviewGroupForEvent(event);
      const reviewBatchEventIds = events.map((item) => item.id).sort();
      const reviewBatchId = createHash('sha256').update(`${eventChatKey(event) || chatId}:${targetKey(target) || event.id}:${reviewBatchEventIds.join(',')}`).digest('hex').slice(0, 24);
      const decisionKey = `review:v2:${chatId}:${reviewBatchId}:decision`;
      const reviewBatchCutoff = new Date().toISOString();
      const decisionClaim = this.store.beginEffect?.(decisionKey, 'review-decision', { chatId, target: targetKey(target) });
      if (decisionClaim?.completed || decisionClaim?.inProgress || decisionClaim?.uncertain) {
        const status = decisionClaim.completed
          ? 'Already reviewed'
          : decisionClaim.uncertain
            ? 'Prior review outcome unknown; manual verification required'
            : 'Review decision in progress';
        await this.answerCallback(query.id, status);
        return true;
      }
      await this.answerCallback(query.id, finalDecision === 'confirm' ? 'Confirming scam...' : 'Rejecting flag...');
      this.store.incrementMetric?.(finalDecision === 'confirm' ? 'reviews_confirmed' : 'reviews_rejected');
      let enforcement;
      let reviewed;
      try {
        const enforcementKey = `review:v2:${chatId}:${reviewBatchId}:confirm`;
        enforcement = finalDecision === 'confirm'
          ? await this.enforceConfirmedScam(chatId, target, events.map((item) => item.payload?.source_message_id), enforcementKey)
          : { banned: false, reason: 'flag_rejected', attempted: 0, deleted: 0, failed: 0 };
        ({ reviewed } = await this.recordReviewDecisionForEvents(callbackMessage, events, finalDecision, reason, {
          target,
          reviewChatId: chatId,
          extraPayload: {
            review_batch_id: reviewBatchId,
            review_decision_key: decisionKey,
            review_batch_cutoff: reviewBatchCutoff,
            enforcement_banned: enforcement.banned,
            enforcement_reason: enforcement.reason,
            delete_attempt_count: enforcement.attempted,
            deleted_message_count: enforcement.deleted,
            delete_failure_count: enforcement.failed
          },
          evidencePrefix: `admin callback ${finalDecision === 'confirm' ? 'confirmed scam flag' : 'rejected scam flag'}`,
          idempotencyKey: decisionKey
        }));
        if (finalDecision === 'confirm' && enforcement.banned) {
          await this.record('ban_executed', { ...callbackMessage, from: target }, {
            target,
            target_key: targetKey(target),
            moderator: from,
            admin_verified: true,
            target_event_id: event.id,
            target_chat_id: chatId,
            review_batch_id: reviewBatchId,
            review_decision_key: decisionKey,
            review_batch_event_ids: reviewBatchEventIds,
            review_batch_cutoff: reviewBatchCutoff,
            reason,
            deleted_message_count: enforcement.deleted,
            delete_attempt_count: enforcement.attempted,
            delete_failure_count: enforcement.failed,
            evidence: [`admin confirmed review ${event.id}; user banned and ${enforcement.deleted}/${enforcement.attempted} known messages deleted`]
          }, { idempotencyKey: `${decisionKey}:ban` });
        }
        this.store.completeEffect?.(decisionKey, { decision: finalDecision, reviewed: reviewed.length });
      } catch (error) {
        this.store.failEffect?.(decisionKey, error instanceof Error ? error.message : String(error));
        throw error;
      }
      const reviewedCount = reviewed.length;
      const cleared = reviewedCount > 1 ? `\nCleared ${reviewedCount} pending reviews for ${userMention(target)}.` : '';
      const enforcementLine = finalDecision === 'confirm'
        ? enforcement.banned
          ? `\nBanned ${userMention(target)} and deleted ${enforcement.deleted}/${enforcement.attempted} known messages.`
          : `\nEnforcement not applied: ${escapeHtml(enforcement.reason.replaceAll('_', ' '))}.`
        : '';
      await this.editInteractiveMessage(chatId, message.message_id, `${finalDecision === 'confirm' ? '🚫 Confirmed scam.' : '✅ Rejected flag as false positive.'}${enforcementLine}${cleared}\n\nSaving evidence to TRACaBot context memory.`, [[button('↩️ Back to queue', callbackData('review-list', requester)), button('✖️ Close', callbackData('close', requester))]], { parse_mode: 'HTML' });
      return true;
    }
    if (parsed.action === 'warn-ban' || parsed.action === 'warn-safe') {
      const event = this.findEvent(eventId);
      if (!event) {
        await this.answerCallback(query.id, 'Warning not found');
        return true;
      }
      if (!eventChatKey(event)) {
        await this.answerCallback(query.id, 'Warning channel unavailable');
        return true;
      }
      if (!sameChat(eventChatKey(event), chatId)) {
        await this.answerCallback(query.id, 'Warning belongs to another channel');
        return true;
      }
      if (!this.isPendingReviewEvent(event)) {
        await this.answerCallback(query.id, 'Already reviewed or expired');
        return true;
      }
      const target = event.user || event.payload?.target || {};
      if (parsed.action === 'warn-safe') {
        const reason = 'admin marked prior-community warning as safe';
        const events = this.pendingReviewItems({ chatId, scope: 'current' }).filter((item) => eventMatchesTarget(item, target));
        const reviewedCount = this.recordReviewDecisionInBackground(callbackMessage, events, 'reject', reason, { target, reviewChatId: chatId, evidencePrefix: 'admin callback marked warning safe' });
        await this.editInteractiveMessage(chatId, message.message_id, `✅ Marked ${userMention(target)} as safe.\n\nCleared ${reviewedCount} pending review${reviewedCount === 1 ? '' : 's'}. Saving evidence to TRACaBot context memory.`, [[button('↩️ Back to queue', callbackData('review-list', requester)), button('✖️ Close', callbackData('close', requester))]], { parse_mode: 'HTML' });
        return true;
      }
      const enforcement = await this.enforceConfirmedScam(chatId, target, [event.payload?.source_message_id]);
      if (!enforcement.banned) {
        await this.answerCallback(query.id, `Enforcement not applied: ${enforcement.reason.replaceAll('_', ' ')}`);
        return true;
      }
      const reason = 'admin banned from prior-community warning';
      const risk = event.payload?.current_risk || event.payload || {};
      await this.recordBanEvidenceInBackground(callbackMessage, target, risk, reason, {
        source: 'prior-community warning ban button',
        idempotencyKey: `warning-ban:${chatId}:${event.id}`
      });
      await this.editInteractiveMessage(chatId, message.message_id, `${formatBanReply(target, '')}\nDeleted ${enforcement.deleted}/${enforcement.attempted} known messages.\n\nEvidence is being saved to TRACaBot context memory.`, [[button('↩️ Back to queue', callbackData('review-list', requester)), button('✖️ Close', callbackData('close', requester))]], { parse_mode: 'HTML' });
      return true;
    }
    return false;
  }

  async handleMessage(message) {
    this.rememberSeenChat(message.chat || {});
    this.rememberUserMessage(message);
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
    // Poll group SangMata rename alerts (getUpdates) → known-campaign auto-ban when clear
    if (await this.handleSangMataMessage(message)) return;
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
    const policy = this.chatPolicy(message.chat?.id);
    const risk = await this.assess({ ...message, text: fullMessageText }, user, fullMessageText);
    const passiveLowRisk = !this.isDirectlyAddressed(message) && risk.confidence < policy.warnThreshold;
    if (risk.confidence < policy.actionThreshold) {
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

      if (!passiveLowRisk) await this.recordConversationArtifact(message, {
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
    if (risk.confidence >= policy.warnThreshold) {
      await this.record('scam_detection', message, risk);
      await this.recordChannelObservation(message, risk);
      await this.maybeRecordCampaign(message, risk);
    }
      if (risk.confidence >= policy.restrictThreshold) {
        if (await this.maybeAutoBanConfirmedActor(message, user, risk)) return;
        await this.applyRiskAction(message, risk);
      return;
    }
  }

  membershipEpisodeKey(chatId = '', userId = '') {
    return `${chatId}:${userId}`;
  }

  membershipNotification({ messageId = '', eventDate = '', updateId = '' } = {}) {
    const eventMs = Number(eventDate);
    const update = Number(updateId);
    return {
      message_id: messageId ? String(messageId) : '',
      event_ms: Number.isFinite(eventMs) && eventMs > 0 ? eventMs * 1000 : 0,
      update_id: Number.isFinite(update) && update > 0 ? update : 0
    };
  }

  membershipBoundary(open, seen, notification = {}) {
    const boundaries = [open, ...seen, notification].filter(Boolean).map((item) => item.payload || item);
    return {
      event_ms: Math.max(0, ...boundaries.map((item) => Number(item.last_event_ms || item.event_ms || 0))),
      update_id: Math.max(0, ...boundaries.map((item) => Number(item.last_update_id || item.update_id || 0))),
      message_id: String(boundaries.map((item) => item.last_message_id || item.message_id || '').filter(Boolean).sort().at(-1) || '')
    };
  }

  isReplayJoin(closed = null, notification = {}) {
    if (!closed) return false;
    const boundaryEventMs = Number(closed.payload?.boundary_event_ms || 0);
    const notificationEventMs = Number(notification.event_ms || 0);
    // Closure boundaries are strict. Same-second notifications remain ambiguous
    // even if they carry a newer update/message identity; missing comparable
    // event time also fails closed.
    if (!boundaryEventMs || !notificationEventMs) return true;
    return notificationEventMs <= boundaryEventMs;
  }

  openMembershipEpisode(chatId = '', userId = '', notification = {}) {
    const key = this.membershipEpisodeKey(chatId, userId);
    const notice = this.membershipNotification(notification);
    let open = null;
    let closed = null;
    const seen = [];
    const history = this.store.all()
      .filter((event) => ['membership_episode_opened', 'membership_episode_closed', 'membership_episode_seen'].includes(event.event_type)
        && event.payload?.membership_key === key)
      .sort((a, b) => Date.parse(a.timestamp || '') - Date.parse(b.timestamp || ''));
    for (const event of history) {
      if (event.event_type === 'membership_episode_opened') {
        open = event;
        closed = null;
      } else if (event.event_type === 'membership_episode_closed') {
        if (open && event.payload?.episode_id === open.payload?.episode_id) {
          closed = event;
          open = null;
        }
      } else if (open && event.payload?.episode_id === open.payload?.episode_id) {
        seen.push(event);
      }
    }
    if (open && Date.now() - Date.parse(open.timestamp || '') <= MEMBERSHIP_EPISODE_DEDUPE_MS) {
      if (notice.event_ms || notice.update_id || notice.message_id) {
        this.store.append({
          id: `membership-seen:${open.payload.episode_id}:${notice.event_ms || 0}:${notice.update_id || 0}:${notice.message_id || ''}`,
          event_type: 'membership_episode_seen',
          timestamp: new Date().toISOString(),
          local_only: true,
          chat: { id: chatId },
          user: { id: userId },
          payload: { membership_key: key, episode_id: open.payload.episode_id, ...notice }
        });
      }
      return { episodeId: open.payload.episode_id, replay: false };
    }
    if (open) {
      this.closeMembershipEpisode(chatId, userId);
      closed = this.store.all().filter((event) => event.event_type === 'membership_episode_closed'
        && event.payload?.membership_key === key).at(-1) || null;
    }
    if (this.isReplayJoin(closed, notice)) {
      return { episodeId: closed?.payload?.episode_id || '', replay: true };
    }
    const episodeId = `episode-${randomUUID()}`;
    this.store.append({
      id: `membership-open:${episodeId}`,
      event_type: 'membership_episode_opened',
      timestamp: new Date().toISOString(),
      local_only: true,
      chat: { id: chatId },
      user: { id: userId },
      payload: {
        membership_key: key,
        episode_id: episodeId,
        last_event_ms: notice.event_ms,
        last_update_id: notice.update_id,
        last_message_id: notice.message_id,
        evidence: ['Membership episode opened for a genuine join; service-message and chat_member notifications share this episode.']
      }
    });
    return { episodeId, replay: false };
  }

  closeMembershipEpisode(chatId = '', userId = '', notification = {}) {
    const key = this.membershipEpisodeKey(chatId, userId);
    const notice = this.membershipNotification(notification);
    let open = null;
    const seen = [];
    const history = this.store.all()
      .filter((event) => ['membership_episode_opened', 'membership_episode_closed', 'membership_episode_seen'].includes(event.event_type)
        && event.payload?.membership_key === key)
      .sort((a, b) => Date.parse(a.timestamp || '') - Date.parse(b.timestamp || ''));
    for (const event of history) {
      if (event.event_type === 'membership_episode_opened') {
        open = event;
      } else if (event.event_type === 'membership_episode_closed') {
        if (open && event.payload?.episode_id === open.payload?.episode_id) open = null;
      } else if (open && event.payload?.episode_id === open.payload?.episode_id) {
        seen.push(event);
      }
    }
    if (!open) return null;
    const episodeId = open.payload.episode_id;
    const boundary = this.membershipBoundary(open, seen, notice);
    this.store.append({
      id: `membership-close:${episodeId}`,
      event_type: 'membership_episode_closed',
      timestamp: new Date().toISOString(),
      local_only: true,
      chat: { id: chatId },
      user: { id: userId },
      payload: {
        membership_key: key,
        episode_id: episodeId,
        boundary_event_ms: boundary.event_ms,
        boundary_update_id: boundary.update_id,
        boundary_message_id: boundary.message_id,
        evidence: ['Membership episode closed on departure; a later genuine join gets a new episode. Older notifications are replayed, not reopened.']
      }
    });
    return episodeId;
  }

  localProtectionLineage(event = {}, all = this.store.all()) {
    const roots = new Set();
    const seen = new Set();
    const visit = (item, depth = 0) => {
      if (!item || depth > 6) return;
      const itemId = String(item.id || '');
      if (itemId && seen.has(itemId)) return;
      if (itemId) seen.add(itemId);
      const resolved = itemId ? resolveReviewTarget(all, itemId) : { ok: false };
      const finding = resolved.ok ? resolved.finding : item;
      const candidates = new Set([String(finding.id || '')]);
      for (const payload of [item.payload || {}, finding.payload || {}]) {
        for (const value of [payload.target_event_id, payload.source_event_id]) {
          if (value) candidates.add(String(value));
        }
        for (const value of [...(payload.evidence_root_ids || []), ...(payload.related_event_ids || [])]) {
          if (value) candidates.add(String(value));
        }
      }
      for (const candidate of candidates) {
        if (!candidate) continue;
        roots.add(candidate);
        if (candidate !== itemId && candidate !== String(finding.id || '')) {
          const next = all.find((entry) => String(entry.id || '') === candidate);
          if (next) visit(next, depth + 1);
        }
      }
    };
    visit(event);
    return [...roots].slice(0, 50);
  }

  localProtectionEvidence(target = {}, chatId = '') {
    const targetId = String(target.id || '');
    if (!targetId) return { evidence: [], complete: true };
    const all = this.store.all();
    const exact = (event = {}) => {
      const subject = event.payload?.reviewed_target || event.payload?.target || {};
      const key = String(event.payload?.reviewed_target_key || event.payload?.target_key || '');
      return String(subject.id || '') === targetId || key === `id:${targetId}`;
    };
    const referenced = (event = {}) => {
      const id = String(event.payload?.target_event_id || '');
      return id ? all.find((item) => item.id === id) || null : null;
    };
    const created = (event = {}) => String(event.payload?.occurred_at || event.timestamp || '');
    const rows = all
      .filter((event) => exact(event))
      .filter((event) => !chatId || sameChat(eventChatKey(event), chatId))
      .filter((event) => ['review_upheld', 'review_overturned'].includes(event.event_type));
    return {
      complete: rows.length < 200,
      evidence: rows.slice(-200).map((event) => {
        const parent = referenced(event);
        const resolvedParent = parent ? resolveReviewTarget(all, parent.id) : { ok: false };
        const reviewedKey = String(event.payload?.reviewed_target_key || '');
        const targetChat = String(event.payload?.target_chat_id || '');
        const targetChatMatches = Boolean(targetChat) && resolvedParent.ok && sameChat(targetChat, resolvedParent.targetChatId);
        const approved = event.event_type === 'review_upheld'
          && event.payload?.local_approval === true
          && resolvedParent.ok
          && resolvedParent.subjectKey === reviewedKey
          && targetChatMatches
          && ['telegram_admin_review', 'authorized_skill_review'].includes(String(event.payload?.approval_source || ''));
        const lineageRoots = this.localProtectionLineage(event, all);
        const underlyingId = resolvedParent.ok ? String(resolvedParent.finding.id || '') : String(event.payload?.target_event_id || '');
        return {
          eventId: event.id,
          eventType: event.event_type,
          claimLevel: event.event_type === 'review_overturned' ? 'retracted' : 'confirmed_scam',
          confidence: Number(event.payload?.confidence || 0),
          created: created(event),
          adminVerified: event.event_type === 'review_upheld',
          exactActorMatch: true,
          trustLayer: 'local',
          source: 'local_admin_review',
          communityId: String(event.payload?.community_id || event.chat?.id || ''),
          targetEventId: underlyingId,
          sourceEventId: underlyingId,
          evidenceRootIds: lineageRoots,
          publisherApprovalVerified: false,
          localApproval: approved,
          approvalSource: String(event.payload?.approval_source || ''),
          retracted: event.event_type === 'review_overturned'
        };
      })
    };
  }

  localProtectionDecision(target = {}, chatId = '') {
    const local = this.localProtectionEvidence(target, chatId);
    return evaluateJoinProtection({
      target,
      evidence: local.evidence,
      chatId,
      policy: {
        autoRemove: true,
        allowedChatIds: [],
        maxAgeDays: this.config.joinEvidenceMaxAgeDays || 180,
        minRoots: this.config.joinMinConfirmedRoots || 1,
        trustedLayers: ['local'],
        trustedSources: [],
        evidenceComplete: local.complete
      }
    });
  }

  localProtectionOverride(target = {}, chatId = '') {
    const targetId = String(target.id || '');
    if (!targetId || !chatId) return null;
    const all = this.store.all();
    const exact = (event = {}) => {
      const subject = event.payload?.reviewed_target || event.payload?.target || event.user || {};
      return String(subject.id || '') === targetId || event.payload?.reviewed_target_key === `id:${targetId}`;
    };
    const rows = all
      .filter((event) => exact(event) && sameChat(eventChatKey(event), chatId))
      // Both private appeal overturn and native admin unban are group-scoped
      // local corrections. They never revoke a creator global attestation.
      .filter((event) => event.event_type === 'appeal_resolved'
        || (event.event_type === 'review_overturned' && ['telegram_private_appeal_overturn', 'native_chat_member_unban', 'telegram_admin_auto_ban_override'].includes(String(event.payload?.correction_source || '')))
        || event.event_type === 'review_upheld')
      .sort((a, b) => Date.parse(a.timestamp || '') - Date.parse(b.timestamp || ''));
    const overturns = rows.filter((event) => event.event_type === 'review_overturned'
      || (event.event_type === 'appeal_resolved' && event.payload?.decision === 'overturn'));
    const overturn = overturns.at(-1);
    if (!overturn) return null;
    const correction = rows.filter((event) => event.event_type === 'review_overturned').at(-1);
    const bannedEvent = all.find((event) => event.id === overturn.payload?.ban_event_id);
    const lineageSource = correction || bannedEvent || overturn;
    const overturnRoots = new Set(this.localProtectionLineage(lineageSource, all));
    const overturnTime = Date.parse(overturn.timestamp || '');
    if (!Number.isFinite(overturnTime)) return overturn;
    const local = this.localProtectionEvidence(target, chatId);
    const approvedIds = new Set(local.evidence
      .filter((item) => item.eventType === 'review_upheld' && item.localApproval === true)
      .map((item) => item.eventId));
    // Reuse the production evidence decision for freshness, retraction, expiry,
    // and root counting instead of a divergent ad hoc filter.
    const localDecision = this.localProtectionDecision(target, chatId);
    const activeIds = new Set(localDecision.action === 'remove' ? (localDecision.roots || []) : []);
    const independent = rows.some((event) => {
      if (event.event_type !== 'review_upheld' || !approvedIds.has(event.id) || !activeIds.has(event.id)) return false;
      const created = Date.parse(event.timestamp || '');
      if (!Number.isFinite(created) || created <= overturnTime) return false;
      const roots = this.localProtectionLineage(event, all);
      // Unknown or overlapping lineage cannot clear a local correction.
      if (!roots.length || !overturnRoots.size) return false;
      return !roots.some((root) => overturnRoots.has(root));
    });
    return independent ? null : overturn;
  }

  async checkJoinProtection(chat = {}, member = {}, episodeKey = '') {
    if (!member?.id || member.is_bot === true || String(member.id) === String(await this.getBotId().catch(() => ''))) {
      return { action: 'allow', reason: 'protected_bot' };
    }
    let targetIsAdmin = false;
    let adminLookupOk = true;
    try {
      targetIsAdmin = await this.isTelegramChatAdmin(chat.id, member.id, { throwOnFailure: true });
    } catch {
      adminLookupOk = false;
    }
    const targetIsOwner = this.config.botOwnerIds?.has?.(String(member.id)) === true;
    const episode = String(episodeKey || `${chat.id}:${member.id}:${this.currentUpdateId || Date.now()}`);
    const localOverride = this.localProtectionOverride(member, chat.id);
    if (localOverride) {
      const decision = {
        policyVersion: PROTECTION_POLICY_VERSION,
        action: 'allow',
        reason: 'local_overturn',
        autoRemove: this.config.joinAutoRemove === true,
        exactIdentity: true,
        evidenceCount: 0,
        confirmedEvidenceCount: 0,
        activeConfirmedEvidenceCount: 0,
        evidenceRef: `appeal:${localOverride.id}`
      };
      await this.record('join_protection_check', { chat, from: member }, {
        target: member,
        target_key: targetKey(member),
        decision: decision.action,
        reason: decision.reason,
        summary: 'A local admin overturned this ban for this chat; automatic removal is suppressed.',
        protection_policy_version: decision.policyVersion,
        graph_ok: true,
        admin_lookup_ok: adminLookupOk,
        evidence_complete: true,
        membership_episode: episode,
        auto_remove: this.config.joinAutoRemove === true,
        appeal_overturn_event_id: localOverride.id,
        evidence: [`Local admin override ${localOverride.id}; creator global record is unchanged.`]
      }, { writeDkg: false, idempotencyKey: `join-protection:${chat.id}:${member.id}:${episode}:local-overturn:${localOverride.id}` });
      return decision;
    }
    const local = this.localProtectionEvidence(member, chat.id);
    const remote = typeof this.dkg?.queryProtectionEvidence === 'function'
      ? await this.dkg.queryProtectionEvidence({ userId: member.id })
      : { ok: false, error: 'protection_query_unavailable', evidence: [], complete: false };
    let creator = { ok: true, configured: false, status: 'disabled', evidence: [], complete: true, error: '' };
    if (this.config.creatorCuratorUrl) {
      creator = await fetchCreatorAttestation({
        baseUrl: this.config.creatorCuratorUrl,
        userId: member.id,
        publicKey: this.config.creatorCuratorPublicKey,
        token: this.config.creatorCuratorReadToken || this.config.creatorCuratorToken,
        issuer: this.config.creatorCuratorIssuer,
        minConfidence: this.config.creatorCuratorMinConfidence,
        minRoots: this.config.creatorCuratorMinRoots,
        maxAgeDays: this.config.creatorCuratorMaxAgeDays,
        timeoutMs: this.config.creatorCuratorTimeoutMs,
        fetchImpl: this.creatorCuratorFetch || globalThis.fetch
      });
    }
    const evidence = [...local.evidence, ...(remote.evidence || []), ...(creator.evidence || [])];
    const evidenceComplete = local.complete !== false && remote.complete !== false && creator.complete !== false;
    const decision = evaluateJoinProtection({
      target: member,
      evidence,
      chatId: chat.id,
      policy: {
        autoRemove: this.config.joinAutoRemove === true,
        allowedChatIds: this.config.joinAutoRemoveChats || [],
        maxAgeDays: this.config.joinEvidenceMaxAgeDays || 180,
        minRoots: this.config.joinMinConfirmedRoots || 1,
        creatorMinConfidence: this.config.creatorCuratorMinConfidence || 90,
        trustedLayers: this.config.joinTrustedLayers || ['local'],
        trustedSources: this.config.joinTrustedSources || [],
        evidenceComplete,
        targetIsAdmin,
        targetIsOwner
      }
    });
    const graphOk = Boolean(remote.ok) && adminLookupOk && creator.ok !== false;
    const eventType = graphOk ? 'join_protection_check' : 'join_protection_degraded';
    const protectionReady = graphOk && evidenceComplete && decision.action === 'remove' && adminLookupOk && !targetIsAdmin && !targetIsOwner;
    const pausedBeforeRecord = protectionReady && this.joinAutoRemovalPaused(chat.id);
    const auditDecision = pausedBeforeRecord
      ? { ...decision, action: 'flag', reason: 'join_auto_removal_paused' }
      : decision;
    await this.record(eventType, { chat, from: member }, {
      target: member,
      target_key: targetKey(member),
      decision: auditDecision.action,
      reason: auditDecision.reason,
      summary: protectionSummary(auditDecision),
      protection_policy_version: auditDecision.policyVersion,
      graph_ok: Boolean(remote.ok),
      creator_ok: creator.ok !== false,
      creator_status: creator.status || 'disabled',
      creator_configured: creator.configured === true,
      admin_lookup_ok: adminLookupOk,
      evidence_complete: evidenceComplete,
      membership_episode: episode,
      graph_error: remote.error ? String(remote.error).slice(0, 200) : '',
      creator_error: creator.error ? String(creator.error).slice(0, 200) : '',
      auto_remove: this.config.joinAutoRemove === true,
      trusted_layers: auditDecision.trustedLayers,
      evidence_ref: auditDecision.evidenceRef,
      evidence_roots: (auditDecision.roots || []).slice(0, 5),
      evidence_count: auditDecision.evidenceCount,
      confirmed_evidence_count: auditDecision.confirmedEvidenceCount,
      active_confirmed_evidence_count: auditDecision.activeConfirmedEvidenceCount || 0,
      evidence: [protectionSummary(auditDecision)]
    }, { writeDkg: false, idempotencyKey: `join-protection:${chat.id}:${member.id}:${episode}:${auditDecision.evidenceRef || auditDecision.reason}` });

    if (!protectionReady) {
      return decision;
    }
    if (pausedBeforeRecord) {
      return auditDecision;
    }
    if (this.joinAutoRemovalPaused(chat.id)) {
      await this.record('join_protection_suppressed', { chat, from: member }, {
        target: member,
        target_key: targetKey(member),
        reason: 'join_auto_removal_paused',
        membership_episode: episode,
        evidence_ref: decision.evidenceRef,
        evidence: ['A group admin paused future automatic join removals; evidence capture and sharing continue, but no destructive action ran.']
      }, { writeDkg: false, idempotencyKey: `join-protection-paused:${chat.id}:${member.id}:${episode}:${decision.evidenceRef}` });
      return { ...auditDecision, action: 'flag', reason: 'join_auto_removal_paused' };
    }

    let result;
    try {
      result = await this.enforceConfirmedScam(chat.id, member, [], `join-protection:${chat.id}:${member.id}:${episode}:${decision.evidenceRef}`, { joinProtection: true });
    } catch (error) {
      result = { banned: false, reason: error instanceof Error ? error.message : String(error) };
    }
    if (result?.banned) {
      await this.record('ban_executed', { chat, from: member }, {
        target: member,
        target_key: targetKey(member),
        confidence: 100,
        local_confidence: 100,
        admin_verified: false,
        source: 'silent_join_protection',
        enforcement_action: 'ban',
        enforcement_observed_from: 'tracabot_join_protection',
        consent_to_share: false,
        reason_provided: false,
        membership_episode: episode,
        evidence_root_ids: decision.roots || [],
        evidence: [
          protectionSummary(decision),
          'Removed silently under explicit join auto-removal policy from exact stable-identity confirmed evidence'
        ]
      }, { writeDkg: false, idempotencyKey: `join-protection-ban:${chat.id}:${member.id}:${episode}:${decision.evidenceRef}` });
      return { ...decision, enforced: true };
    }
    await this.record('join_protection_suppressed', { chat, from: member }, {
      target: member,
      target_key: targetKey(member),
      reason: String(result?.reason || 'ban_not_carried_out').slice(0, 200),
      membership_episode: episode,
      evidence_ref: decision.evidenceRef,
      evidence: ['Join protection matched confirmed exact-identity evidence but no removal was carried out; protection failed closed.']
    }, { writeDkg: false, idempotencyKey: `join-protection-suppressed:${chat.id}:${member.id}:${episode}:${decision.evidenceRef}` });
    return { ...decision, action: 'flag', reason: result?.reason === 'join_auto_removal_paused' ? 'join_auto_removal_paused' : 'removal_not_carried_out' };
  }

  async handleNewMembers(message) {
    const policy = this.chatPolicy(message.chat?.id);
    for (const member of message.new_chat_members) {
      const botId = await this.getBotId().catch(() => null);
      if (member.is_bot === true || (botId && String(member.id) === String(botId))) continue;
      const joinMessage = { ...message, from: member, text: `new member joined @${member.username || member.id}` };
      this.rememberUser(message.chat, member, joinMessage.text);
      const membership = this.openMembershipEpisode(message.chat.id, member.id, {
        messageId: message.message_id,
        eventDate: message.date,
        updateId: this.currentUpdateId
      });
      if (membership.replay) continue;
      const membershipEpisode = membership.episodeId;
      const protection = await this.checkJoinProtection(message.chat, member, membershipEpisode);
      if (protection.action === 'remove' && protection.enforced) continue;
      if (protection.reason === 'local_overturn') continue;
      const risk = await this.assess(joinMessage, member, joinMessage.text);
      if (risk.confidence >= policy.restrictThreshold) {
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
    if (newStatus === 'kicked' && oldStatus !== 'kicked') {
      await this.handleNativeAdminBan(chatMemberUpdate, member, oldStatus, newStatus);
      this.closeMembershipEpisode(chatMemberUpdate.chat?.id, member.id, { eventDate: chatMemberUpdate.date, updateId: this.currentUpdateId });
      this.joinChallenges.delete(key);
      this.clearJoinChallengeTimer(key);
      this.solvedJoinChallenges.delete(key);
      return;
    }
    if (oldStatus === 'kicked' && newStatus !== 'kicked') {
      await this.handleNativeAdminUnban(chatMemberUpdate, member);
      this.closeMembershipEpisode(chatMemberUpdate.chat?.id, member.id, { eventDate: chatMemberUpdate.date, updateId: this.currentUpdateId });
      this.joinChallenges.delete(key);
      this.clearJoinChallengeTimer(key);
      this.solvedJoinChallenges.delete(key);
      return;
    }
    const departed = ['left', 'kicked'].includes(newStatus)
      || (newStatus === 'restricted' && chatMemberUpdate.new_chat_member?.is_member === false);
    if (departed) {
      this.closeMembershipEpisode(chatMemberUpdate.chat?.id, member.id, { eventDate: chatMemberUpdate.date, updateId: this.currentUpdateId });
      this.joinChallenges.delete(key);
      this.clearJoinChallengeTimer(key);
      this.solvedJoinChallenges.delete(key);
      return;
    }
    const joined = ['left', 'kicked'].includes(oldStatus) && ['member', 'restricted'].includes(newStatus);
    if (joined) {
      this.joinChallenges.delete(key);
      this.clearJoinChallengeTimer(key);
      await this.handleNewMembers({
        chat: chatMemberUpdate.chat,
        from: chatMemberUpdate.from || member,
        date: chatMemberUpdate.date,
        new_chat_members: [member]
      });
      return;
    }
    const fingerprint = matchKnownCampaignFingerprint(member, this.knownCampaignPatterns());
    const priorIdentity = fingerprint ? this.priorIdentityForTarget(chatMemberUpdate.chat, member) : null;
    if (fingerprint && priorIdentity) {
      const oldName = priorIdentity.label;
      const newName = [member.first_name, member.last_name].filter(Boolean).join(' ') || member.username || String(member.id);
      const evidence = `Telegram identity change: ${oldName} -> ${newName} (prior event ${priorIdentity.eventId})`;
      await this.handleKnownCampaignIdentityChange({
        chat: chatMemberUpdate.chat,
        from: member,
        date: chatMemberUpdate.date,
        text: evidence
      }, {
        ...member,
        identityChange: { oldName, newName, evidence }
      }, {
        source: 'chat_member',
        sourceId: this.currentUpdateId || `${chatMemberUpdate.date || ''}:${oldStatus}:${newStatus}`,
        sourceEvidence: evidence
      });
      return;
    }
  }

  async nativeAdminActor(chatMemberUpdate) {
    const actor = chatMemberUpdate.from || {};
    if (!actor.id && !actor.username) return null;
    if (actor.id) {
      const botId = this.botId || await this.getBotId().catch(() => null);
      if (botId && String(actor.id) === String(botId)) return null;
    }
    const ownUsername = this.ownBotUsername();
    if (actor.username && ownUsername && String(actor.username).replace(/^@/, '').toLowerCase() === ownUsername) return null;
    return actor;
  }

  scheduleEvidencePromotion() {
    if (this.config.autoPromoteEvidence === false || this.config.dkgWrites === false) return null;
    return Promise.resolve()
      .then(() => promoteEligibleEvidence({ store: this.store, dkg: this.dkg, config: this.config }))
      .catch((error) => console.error(`evidence promotion failed: ${error instanceof Error ? error.message : String(error)}`));
  }

  async handleNativeAdminBan(chatMemberUpdate, member, oldStatus, newStatus) {
    const actor = await this.nativeAdminActor(chatMemberUpdate);
    if (!actor) return null;
    const flag = Number(chatMemberUpdate.date || 0);
    const actionAtMs = flag > 0 ? flag * 1000 : Date.now();
    const occurredAt = new Date(actionAtMs).toISOString();
    const banContext = this.buildBanContext(chatMemberUpdate.chat?.id, member.id, actionAtMs);
    const contextLine = banContext.observed_message_count > 0
      ? `Recent observed pre-ban context: ${banContext.observed_message_count} message(s), category ${banContext.category}; causal link unverified`
      : 'No messages from this target were observed by the bot before the ban; ban context unavailable';
    const event = await this.record('ban_executed', {
      chat: chatMemberUpdate.chat,
      from: member,
      date: chatMemberUpdate.date
    }, {
      target: member,
      target_key: targetKey(member),
      reason: 'reason not provided',
      reason_provided: false,
      admin_verified: true,
      enforcement_verified: true,
      consent_to_share: this.config.autoPromoteEvidence !== false && this.config.dkgWrites !== false,
      enforcement_action: 'ban',
      enforcement_observed_from: 'telegram_chat_member',
      enforcement_source: 'telegram_chat_member',
      source: 'native_chat_member_admin_ban',
      enforcement_confidence: 100,
      confidence: 0,
      local_confidence: 0,
      scam_type: 'admin_enforcement',
      context_category: banContext.category,
      context_severity: banContext.severity,
      context_confidence: banContext.confidence,
      ban_context: banContext,
      performed_by: { id: actor.id, username: actor.username || '', is_bot: actor.is_bot === true },
      performed_by_key: actorKey(actor),
      previous_status: oldStatus,
      new_status: newStatus,
      occurred_at: occurredAt,
      telegram_update_id: this.currentUpdateId,
      campaign_root_eligible: false,
      patterns: [],
      domains: [],
      wallets: [],
      evidence: [
        'Telegram chat_member update observed a live ban transition by a community administrator',
        'Reason not provided through the Telegram Bot API',
        'Live membership update only; Telegram Recent Actions and pre-install history are not available to bots',
        contextLine
      ]
    }, {
      writeDkg: false,
      idempotencyKey: `native-admin-ban:${chatMemberUpdate.chat?.id || ''}:${member.id}:${flag || this.currentUpdateId || ''}`
    });
    this.scheduleEvidencePromotion();
    return event;
  }

  async handleNativeAdminUnban(chatMemberUpdate, member) {
    const actor = await this.nativeAdminActor(chatMemberUpdate);
    if (!actor) return null;
    const history = this.store.all();
    const target = member;
    const ban = [...history].reverse().find((event) => event.event_type === 'ban_executed'
      && event.payload?.provenance !== 'automatic_evidence_policy'
      && sameChat(event.chat?.id, chatMemberUpdate.chat?.id)
      && sameActorTarget(event.user || event.payload?.target || {}, target));
    if (!ban) return null;
    if (history.some((event) => event.event_type === 'review_overturned' && event.payload?.target_event_id === ban.id)) return null;
    const flag = Number(chatMemberUpdate.date || 0);
    const occurredAt = flag > 0 ? new Date(flag * 1000).toISOString() : new Date().toISOString();
    const event = await this.record('review_overturned', {
      chat: chatMemberUpdate.chat,
      from: member,
      date: chatMemberUpdate.date
    }, {
      target_event_id: ban.id,
      evidence_root_ids: ban.payload?.evidence_root_ids || [],
      review_decision: 'reject',
      reason: 'native membership update shows the ban was lifted; no reason provided',
      correction_source: 'native_chat_member_unban',
      enforcement_action: 'unban',
      enforcement_observed_from: 'telegram_chat_member',
      reason_provided: false,
      admin_verified: true,
      retracted: true,
      reviewed_target: member,
      reviewed_target_key: targetKey(member),
      consent_to_share: this.config.autoPromoteEvidence !== false && this.config.dkgWrites !== false,
      performed_by: { id: actor.id, username: actor.username || '', is_bot: actor.is_bot === true },
      performed_by_key: actorKey(actor),
      occurred_at: occurredAt,
      telegram_update_id: this.currentUpdateId,
      evidence: [
        'Telegram chat_member update observed a live unban or correction transition by a community administrator',
        'The original enforcement record is retained; the shared claim is marked retracted'
      ]
    }, {
      writeDkg: this.config.autoPromoteEvidence !== false && this.config.dkgWrites !== false,
      idempotencyKey: `native-admin-unban:${chatMemberUpdate.chat?.id || ''}:${member.id}:${ban.id}`
    });
    this.closeMembershipEpisode(chatMemberUpdate.chat?.id, member.id, { eventDate: chatMemberUpdate.date, updateId: this.currentUpdateId });
    this.scheduleEvidencePromotion();
    return event;
  }

  async expireJoinChallenges() {
    const now = Date.now();
    for (const [key, challenge] of this.joinChallenges.entries()) {
      if (now < challenge.expiresAt) continue;
      this.joinChallenges.delete(key);
      this.clearJoinChallengeTimer(key);
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
      await this.deleteJoinChallengePrompt(challenge);
      await this.sendEphemeral(challenge.chat.id, `${userMention(challenge.user)} did not complete DKG verification in time.`, { parse_mode: 'HTML', autoDelete: true }, this.config.successMessageTtlSeconds || 45).catch(() => null);
    }
  }

  async proactiveScan() {
    if (Date.now() < this.nextProactiveScanAt) return;
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;
    flushFederationQueue({ store: this.store, config: this.config }).catch((error) => {
      console.error(`federation submission flush failed: ${error instanceof Error ? error.message : String(error)}`);
    });

    const svc = (() => { try { return TracabotSkillService.fromEnv(); } catch { return null; } })();

    for (const entry of this.observedUsers.values()) {
      if (this.targetResolutionForObservation(entry)) continue;
      const message = {
        chat: entry.chat,
        from: entry.user,
        text: entry.context || `proactive scan @${entry.user.username || entry.user.id}`
      };
      const risk = await this.assess(message, entry.user, message.text);
      const policy = this.chatPolicy(entry.chat?.id);

      if (risk.confidence >= policy.actionThreshold) {
        await this.applyRiskAction(message, risk);
        continue;
      }

      // Deeper polling enhancement: feed medium-risk proactive scans through the graph-aware artefact curator
      if (svc && risk.confidence >= policy.warnThreshold - 10) {
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
    if (this.config.autoPromoteEvidence === true) {
      await promoteEligibleEvidence({ store: this.store, dkg: this.dkg, config: this.config })
        .catch((error) => console.error(`evidence promotion failed: ${error instanceof Error ? error.message : String(error)}`));
    }
  }

  async pollOnce({ signal } = {}) {
    let updates;
    try {
      updates = await this.call('getUpdates', {
        offset: this.offset,
        timeout: 25,
        allowed_updates: ['message', 'callback_query', 'chat_member', 'my_chat_member']
      }, { signal });
      this.notePollingSuccess();
    } catch (error) {
      if (error && typeof error === 'object') error.telegramPollingFailure = true;
      throw error;
    }
    for (const update of updates) {
      if (signal?.aborted) break;
      const claim = this.store.claimUpdate?.(this.botKey, update) || 'claimed';
      if (claim === 'completed') {
        this.offset = Math.max(this.offset, update.update_id + 1);
        continue;
      }
      if (claim === 'processing') break;
      this.currentUpdateId = update.update_id;
      try {
        if (update.callback_query) await this.handleCallbackQuery(update.callback_query);
        else if (update.message) await this.handleMessage(update.message);
        else if (update.chat_member) await this.handleChatMemberUpdate(update.chat_member);
        const nextOffset = update.update_id + 1;
        this.store.completeUpdate?.(this.botKey, update.update_id, nextOffset);
        this.offset = nextOffset;
        this.store.incrementMetric?.('telegram_updates_completed');
      } catch (error) {
        this.store.failUpdate?.(this.botKey, update.update_id, error instanceof Error ? error.message : String(error));
        this.store.incrementMetric?.('telegram_updates_failed');
        throw error;
      } finally {
        this.currentUpdateId = null;
      }
    }
    if (signal?.aborted) return;
    this.proactiveScan().catch((error) => console.error(`proactive scan failed: ${error instanceof Error ? error.message : String(error)}`));
    this.expireJoinChallenges().catch((error) => console.error(`join challenge expiry failed: ${error instanceof Error ? error.message : String(error)}`));
    this.maybePostDailySafeTip().catch((error) => console.error(`daily safe tip failed: ${error instanceof Error ? error.message : String(error)}`));
  }

  notePollingSuccess() {
    if (!this.pollingFailureCount) return;
    console.error(`Telegram getUpdates recovered after ${this.pollingFailureCount} consecutive failure(s)`);
    this.store.incrementMetric?.('telegram_poll_recoveries');
    this.pollingFailureCount = 0;
    this.lastPollingErrorLogAt = 0;
  }

  notePollingFailure(error) {
    this.pollingFailureCount += 1;
    const kind = pollingFailureKind(error);
    const exponential = Math.min(POLLING_BACKOFF_MAX_MS, POLLING_BACKOFF_BASE_MS * (2 ** Math.min(this.pollingFailureCount - 1, 10)));
    const delayMs = Math.min(POLLING_BACKOFF_MAX_MS, Math.round(exponential * (0.75 + Math.random() * 0.5)));
    const now = Date.now();
    const shouldLog = this.pollingFailureCount === 1 || now - this.lastPollingErrorLogAt >= POLLING_ERROR_LOG_INTERVAL_MS;
    if (shouldLog) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Telegram getUpdates failed (kind=${kind}, consecutive=${this.pollingFailureCount}, retry_ms=${delayMs}): ${message}`);
      this.lastPollingErrorLogAt = now;
    }
    this.store.incrementMetric?.('telegram_poll_failures');
    this.store.incrementMetric?.(`telegram_poll_${kind}_failures`);
    this.store.incrementMetric?.('telegram_poll_backoff_ms_total', delayMs);
    return delayMs;
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

  async dropPendingUpdates({ signal } = {}) {
    const persistedOffset = this.store.pollingOffset?.(this.botKey);
    if (persistedOffset !== null && persistedOffset !== undefined) {
      this.offset = persistedOffset;
      return;
    }
    if (this.config.dropPendingUpdatesOnStart === false) {
      this.offset = this.store.initializePollingOffset?.(this.botKey, this.offset) ?? this.offset;
      return;
    }
    const updates = await this.call('getUpdates', { offset: -1, limit: 1, timeout: 0, allowed_updates: ['message', 'callback_query', 'chat_member', 'my_chat_member'] }, { signal });
    if (updates.length) this.offset = updates[0].update_id + 1;
    this.offset = this.store.initializePollingOffset?.(this.botKey, this.offset) ?? this.offset;
  }

  async run({ signal } = {}) {
    if (!this.config.telegramToken) throw new Error('TELEGRAM_BOT_TOKEN is required');
    if (signal?.aborted) return;
    await this.botUsername().catch(() => '');
    if (signal?.aborted) return;
    try {
      await this.dkg.ensureContextGraph();
    } catch (error) {
      console.error(`DKG startup check failed; continuing with Telegram polling: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (signal?.aborted) return;
    try {
      const commandScopes = [
        null,
        { type: 'all_private_chats' },
        { type: 'all_group_chats' },
        { type: 'all_chat_administrators' }
      ];
      for (const scope of commandScopes) {
        if (signal?.aborted) return;
        const payload = scope ? { scope } : {};
        await this.call('deleteMyCommands', payload, { signal }).catch(() => {});
        await this.call('setMyCommands', { ...payload, commands: TELEGRAM_COMMANDS }, { signal });
      }
    } catch (error) {
      if (signal?.aborted) return;
      console.error(`setMyCommands failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (signal?.aborted) return;
    try {
      await this.dropPendingUpdates({ signal });
    } catch (error) {
      if (signal?.aborted) return;
      console.error(`dropPendingUpdates failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    while (!signal?.aborted) {
      try {
        await this.pollOnce({ signal });
      } catch (error) {
        if (signal?.aborted) break;
        const delayMs = error?.telegramPollingFailure
          ? this.notePollingFailure(error)
          : 3000;
        if (!error?.telegramPollingFailure) console.error(error instanceof Error ? error.message : String(error));
        await abortableSleep(delayMs, signal);
      }
    }
  }
}

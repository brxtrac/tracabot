import { randomUUID } from 'node:crypto';
import { canAutonomouslyEscalate, combineRisk, formatBanReply, formatDkgReference, formatReportReply, formatRiskAssessment, formatScanReply, formatStatsReply, formatStatsSourcesReply, isObviousLocalScam } from './risk-engine.js';
import { extractWallets } from './dkg-client.js';
import { buildSafetyPrompt, fallbackSafetyReply, isSafetyQuestion, sanitizeSafetyReply, shouldConversationallyReply } from './conversation.js';
import { redactedOpenClawStatus } from './openclaw-config.js';

export const TELEGRAM_COMMANDS = [
  { command: 'scan', description: 'Check a user, wallet, or replied message for scam risk' },
  { command: 'report', description: 'Report a suspicious user, wallet, or message to DKG' },
  { command: 'dmreport', description: 'Report off-platform DM impersonation scams' },
  { command: 'ban', description: 'Ban a replied user and publish ban evidence' },
  { command: 'stats', description: 'Show recent fraud checks and detections' },
  { command: 'why', description: 'Explain a tracabot event decision' },
  { command: 'watch', description: 'Admin: watch a suspicious actor' },
  { command: 'unwatch', description: 'Admin: remove a watched actor' },
  { command: 'watchlist', description: 'Admin: show watches, mutes, and review items' },
  { command: 'appeal', description: 'Submit an appeal or correction for an event' },
  { command: 'review', description: 'Admin: uphold or overturn an event' },
  { command: 'digest', description: 'Show recent moderation digest' },
  { command: 'status', description: 'Admin: show bot, DKG, and conversation status' },
  { command: 'help', description: 'Show tracabot commands and autonomous policy' }
];

const MAX_TEXT_CHARS = 4096;
const MAX_CONTEXT_CHARS = 500;
const OBSERVED_CONTEXT_TTL_MS = 24 * 60 * 60 * 1000;
const RECENT_JOIN_RENAME_WINDOW_MS = 30 * 60 * 1000;
const ADMIN_CACHE_TTL_MS = 10 * 60 * 1000;
const SOLVED_JOIN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const DKG_UAL_RE = /^did:dkg:[^\s<>"']{8,}$/i;
const DM_REPORT_RE = /\b(?:dm|direct message|private message|inbox|pm)\b/i;
const REPORT_INTENT_RE = /\b(?:report|warn|alert|heads?\s*up|ongoing|impersonator|impersonating|pretending|fake)\b/i;
const ROLE_RE = /\b(?:cto|ceo|cfo|coo|founder|co-?founder|admin|moderator|mod|support|team|core team|vc|investor|partner|ambassador|lead|manager|director|official|developer|devrel)\b/i;
const DM_SCAM_REQUEST_RE = /\b(?:connect|verify|validate|sync|link|unlock|restore|claim|airdrop|giveaway|seed phrase|private key|recovery phrase|wallet|funds?|send|deposit|investment|support)\b/i;

function boundedText(value = '', max = MAX_TEXT_CHARS) {
  return String(value || '').slice(0, max);
}

function messageText(message = {}) {
  return boundedText([message.text, message.caption].filter(Boolean).join('\n'));
}

function repliedText(message = {}) {
  const reply = message.reply_to_message || {};
  return boundedText([reply.text, reply.caption].filter(Boolean).join('\n'));
}

function evidenceText(message = {}) {
  return boundedText([messageText(message), repliedText(message)].filter(Boolean).join('\n'));
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
    .replace(/^\/dmreport(?:@\w+)?\s*/i, '')
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
  return actorKey(eventUser) === key || event.payload?.target_key === key || event.payload?.watch_target_key === key;
}

function textFingerprint(text = '') {
  const words = String(text).toLowerCase().replace(/https?:\/\/\S+/g, '').replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((word) => word.length > 2);
  return words.slice(0, 16).join(' ');
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
  return String(id || '').slice(0, 8) || 'unknown';
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
  if (eventType.startsWith('join_challenge_')) return false;
  if (['ban_executed', 'restrict_executed', 'fraud_finding', 'report_submitted', 'dm_scam_report', 'fraud_campaign', 'appeal_submitted', 'review_upheld', 'review_overturned'].includes(eventType)) return true;
  if (['risk_review_needed', 'risk_action_suppressed', 'report_review_needed'].includes(eventType)) {
    return Number(payload.confidence || 0) >= 60 || Boolean(payload.dkg_evidence?.length || payload.wallets?.length || payload.domains?.length || payload.patterns?.length);
  }
  return false;
}

function formatDmReportReply(event, decision = {}) {
  if (!decision.accepted) {
    return '⚠️ I logged this DM scam note locally, but need stronger details before sharing it to DKG: impersonated name/role, the request they made, wallet/link, or screenshot caption.';
  }
  const alias = event.payload?.reported_alias || event.payload?.reportedAlias || 'reported DM impersonator';
  const role = event.payload?.claimed_role ? ` (${event.payload.claimed_role})` : '';
  return `⚠️ DM scam report saved: ${alias}${role}. I saved the evidence to DKG fraud memory for cross-community warnings. Warn users not to trust unsolicited DMs; verify through official channels.`;
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
    this.nextProactiveScanAt = Date.now() + this.config.proactiveScanMinutes * 60 * 1000;
    this.conversationLastReply = new Map();
  }

  async call(method, payload) {
    return telegram(this.config.telegramToken, method, payload, this.config.telegramTimeoutMs);
  }

  async send(chatId, text, extra = {}) {
    return this.call('sendMessage', { chat_id: chatId, text, ...extra });
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
    if (!isPrivate && await this.hasDeleteRights(chatId)) this.scheduleDelete(chatId, sent?.message_id, ttlSeconds);
    return sent;
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
    try {
      return await this.call('exportChatInviteLink', { chat_id: chat.id });
    } catch {
      return '';
    }
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
    const text = [
      backed
        ? '🚨 Admin heads-up: confirmed fraud signal, but I do not have ban rights here.'
        : '⚠️ Admin review note: local risk signal only; I do not have enough confirmed evidence for action.',
      formatRiskAssessment({ target: actorFromMessage(message), risk }),
      'Evidence was saved privately for admin review; internal DKG receipts are not posted in group chat.',
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
    const warn = this.config.warnThreshold ?? 60;
    const restrict = this.config.restrictThreshold ?? 75;
    const ban = this.config.banThreshold ?? this.config.actionThreshold ?? 85;
    return [
      'tracabot commands:',
      '/scan <user|id|wallet|message> - check risk using local analysis + DKG shared memory. Reply to SangMata alerts works.',
      '/report <user|wallet|text> - submit suspicious evidence to DKG when it has independent signal.',
      '/dmreport <name/role/request> - report DM impersonators who are not in the group. Captions/screenshots can be attached.',
      '/ban - admin-only; reply to a user to ban and publish evidence.',
      '/stats - show recent DKG threat activity. Use /stats sources for receipts.',
      '/why <event-id> - explain local + DKG evidence behind a decision.',
      '/watch - admin-only; reply to a user or SangMata alert. Also works as /watch <telegram-id> or /watch @user.',
      '/unwatch - admin-only; reply to a user or SangMata alert. Also works as /unwatch <telegram-id> or /unwatch @user.',
      '/watchlist - admin-only; show active watches, temp mutes, and review items. Use /watchlist muted or /watchlist review.',
      '/appeal <event-id> reason - submit a correction or appeal to DKG. Use /why <event-id> first if unsure.',
      '/review <event-id> uphold reason - admin-only; keep the decision. Use overturn to reverse it.',
      '/stats campaigns - show repeated domains, wallets, patterns, or text fingerprints.',
      '/digest - summarize recent actions, reports, watches, appeals, and campaigns.',
      '/status - admin-only; show DKG, Telegram permission, and conversational mode status.',
      '/help - show this command guide.',
      '',
      `Autonomous policy: warn/log at ${warn}%, delete/restrict at ${restrict}%, delete/ban at ${ban}%.`,
      'DKG memory: reads and writes shared fraud evidence for cross-community protection.',
      `Join challenge: ${this.config.joinChallenge ? `new users verify with a Knowledge Asset address within ${this.config.joinChallengeTtlSeconds || 60}s` : 'off'}.`,
      'Conversational mode: answers scam/safety questions only and falls back to evidence-based templates if OpenClaw LLM is unavailable.',
      'Safeguards: no auto-action against Telegram admins or bot accounts; weak reports stay local.'
    ].join('\n');
  }

  async formatStatus(message) {
    const chatId = message.chat.id;
    const [dkgOk, canBan, canDelete] = await Promise.all([
      this.dkgReachable(),
      this.hasBanRights(chatId),
      this.hasDeleteRights(chatId)
    ]);
    const openclaw = redactedOpenClawStatus(this.config);
    return [
      'TRACaBot status',
      `DKG: ${dkgOk ? 'reachable' : 'unreachable'}`,
      `Telegram rights: delete=${canDelete ? 'yes' : 'no'}, restrict/ban=${canBan ? 'yes' : 'no'}`,
      `Autonomous thresholds: warn ${this.config.warnThreshold}%, restrict ${this.config.restrictThreshold}%, ban ${this.config.banThreshold}%`,
      `Join challenge: ${this.config.joinChallenge ? `on; Knowledge Asset address; ttl ${this.config.joinChallengeTtlSeconds || 60}s; timeout ${this.config.joinChallengeAction || 'kick'}` : 'off'}`,
      `Conversation: ${this.config.conversational === false ? 'off' : 'on'}; provider=${this.config.llmProvider || 'auto'}; proactive >= ${this.config.proactiveReplyThreshold}%`,
      `OpenClaw LLM: ${openclaw.available ? 'configured' : 'not discovered'}`,
      'Secrets and internal endpoints are not displayed in group chat.'
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
    const resolved = new Set(this.store.all().filter((event) => ['review_upheld', 'review_overturned', 'ban_executed'].includes(event.event_type)).map((event) => event.payload?.target_event_id || event.payload?.report_event_id).filter(Boolean));
    return this.store.all()
      .filter((event) => ['risk_review_needed', 'risk_action_suppressed', 'report_review_needed', 'ban_requested_no_reply', 'ban_requested_no_rights'].includes(event.event_type))
      .filter((event) => !resolved.has(event.id))
      .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  }

  formatWatchItem(event, index) {
    const target = event.payload?.target || event.user || {};
    const reason = event.payload?.reason || event.payload?.evidence?.[0] || event.payload?.report_reason || 'watching';
    const key = event.payload?.watch_target_key || targetKey(target) || 'unknown';
    return `${index}. ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}\n   ${ageLabel(event.timestamp)} | Event ${shortId(event.id)} | ${escapeHtml(reason)}\n   Actions: /scan ${escapeHtml(String(target.id || target.username || key))} | /unwatch ${escapeHtml(String(target.id || target.username || key))} | /why ${event.id}`;
  }

  formatRestrictionItem(event, index) {
    const target = event.user || {};
    const until = event.payload?.restricted_until ? `until ${event.payload.restricted_until.replace(/\.\d{3}Z$/, 'Z')}` : 'expiry unknown';
    const evidence = event.payload?.evidence?.slice(-2).join('; ') || event.payload?.scam_type || 'restriction';
    return `${index}. ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}\n   ${ageLabel(event.timestamp)} | ${until} | Event ${shortId(event.id)}\n   ${escapeHtml(evidence)}\n   Actions: /scan ${escapeHtml(String(target.id || target.username || ''))} | /why ${event.id}`;
  }

  formatReviewItem(event, index) {
    const target = event.user || event.payload?.target || {};
    const confidence = event.payload?.confidence !== undefined ? `${event.payload.confidence}%` : 'n/a';
    const evidence = event.payload?.evidence?.slice(0, 2).join('; ') || event.payload?.reason || event.event_type;
    return `${index}. ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}\n   ${ageLabel(event.timestamp)} | ${confidence} | Event ${shortId(event.id)}\n   ${escapeHtml(evidence)}\n   Actions: /why ${event.id} | /review ${event.id} uphold reason | /review ${event.id} overturn reason`;
  }

  formatWatchlist(filter = '') {
    const watches = this.activeWatches();
    const restrictions = this.recentRestrictions();
    const reviews = this.pendingReviewItems();
    const sections = [`👀 Watchlist manager`, `${watches.length} active watches | ${restrictions.length} active mutes | ${reviews.length} review items`];
    const addSection = (title, items, formatter) => {
      if (!items.length) return;
      sections.push('', title, ...items.slice(0, 8).map((event, index) => formatter.call(this, event, index + 1)));
    };
    if (!filter || filter === 'all' || filter === 'active') addSection('Active watches', watches, this.formatWatchItem);
    if (!filter || filter === 'all' || filter === 'muted' || filter === 'mutes') addSection('Temp mutes', restrictions, this.formatRestrictionItem);
    if (!filter || filter === 'all' || filter === 'review') addSection('Needs review', reviews, this.formatReviewItem);
    if (sections.length === 2) sections.push('', 'Nothing matching that filter. Try /watchlist all, /watchlist muted, or /watchlist review.');
    return sections.join('\n');
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
    if (!campaigns.length) return 'No repeated fraud campaigns found in recent local memory.';
    return ['Recent campaign signals:', ...campaigns.map((campaign) => `- ${campaign.key} across ${plural(campaign.events.length, 'event')}: ${campaign.events.slice(0, 4).map((event) => event.id).join(', ')}`)].join('\n');
  }

  formatDigest() {
    const events = this.recentEvents(24 * 60 * 60 * 1000);
    const count = (types) => events.filter((event) => types.includes(event.event_type)).length;
    const campaigns = this.campaignSummary(24 * 60 * 60 * 1000);
    const high = events.filter((event) => Number(event.payload?.confidence || 0) >= 80).length;
    const watches = this.activeWatches();
    const restrictions = this.recentRestrictions();
    const reviews = this.pendingReviewItems();
    return [
      '📌 tracabot digest (24h)',
      '',
      'Risk movement',
      `- ${plural(events.length, 'local event')}; ${plural(high, 'high-confidence signal')}`,
      `- ${plural(count(['ban_executed']), 'ban')}; ${plural(count(['restrict_executed']), 'temp mute')}; ${plural(count(['report_submitted']), 'accepted report')}`,
      `- ${plural(count(['appeal_submitted']), 'appeal')}; ${plural(count(['review_upheld', 'review_overturned']), 'review decision')}`,
      '',
      'Watchlist',
      `- ${plural(watches.length, 'active watch')}; ${plural(restrictions.length, 'active temp mute')}; ${plural(reviews.length, 'pending review item')}`,
      campaigns.length ? `- Top campaign: ${campaigns[0].key} across ${campaigns[0].events.length} events` : '- No repeated campaign cluster in the last 24h',
      '',
      'Recommended follow-up',
      '- /watchlist review',
      '- /watchlist muted',
      '- /stats sources',
      '- /why <event-id>'
    ].join('\n');
  }

  isRiskQuery(message) {
    return isSafetyQuestion(message);
  }

  isDmReportMention(message) {
    const text = messageText(message);
    return /@(?:tracabot|tracethembot)\b/i.test(text) && DM_REPORT_RE.test(text) && REPORT_INTENT_RE.test(text);
  }

  canPublishFindingFromRisk(risk = {}) {
    return Number(risk.confidence || 0) >= 80 && Number(risk.local_confidence || 0) >= 60 && (risk.evidence?.length || 0) > 0;
  }

  shouldSendConversation(message, target, risk, explicit = false) {
    if (!shouldConversationallyReply({ message, risk, explicit, config: this.config })) return false;
    const key = conversationKey(message, target);
    const last = this.conversationLastReply.get(key) || 0;
    if (Date.now() - last < (this.config.conversationRateLimitSeconds || 0) * 1000) return false;
    this.conversationLastReply.set(key, Date.now());
    return true;
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
    if (!this.llm || this.config.conversational === false) return {};
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
    const hasDmContext = DM_REPORT_RE.test(contextText) || /^\/dmreport/i.test(commandText) || /\b(?:impersonat|pretend|fake|unsolicited)\b/i.test(text);
    const hasRequest = DM_SCAM_REQUEST_RE.test(text) || Boolean(wallets.length || domains.length || scamRequest);
    const hasAlias = Boolean(reportedAlias);
    const trusted = await this.isTrustedModerator(message).catch(() => false);
    let confidence = 35;
    if (hasDmContext) confidence += 15;
    if (hasAlias) confidence += 15;
    if (hasRole) confidence += 15;
    if (hasRequest) confidence += 20;
    if (files.length) confidence += 10;
    if (trusted) confidence += 10;
    confidence = Math.min(95, confidence);
    const accepted = confidence >= 75 && hasDmContext && (hasAlias || hasRole) && (hasRequest || files.length || trusted);
    const reason = accepted ? 'dm impersonation evidence accepted' : 'needs stronger dm impersonation evidence';
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
        has_telegram_username: /@\w{3,32}/.test(text),
        report_decision: accepted ? 'accepted' : 'weak',
        report_reason: reason,
        report_outcome: accepted && confidence >= 80 ? 'high_confidence_dm_report' : accepted ? 'accepted_dm_report' : 'local_dm_review',
        source: 'dm_scam_report',
        domains,
        wallets,
        patterns,
        evidence
      }
    };
  }

  async handleDmReport(message, explicitText = '') {
    const report = await this.buildDmReport(message, explicitText);
    const eventType = report.accepted ? 'dm_scam_report' : 'report_review_needed';
    const event = await this.record(eventType, message, report.payload, { writeDkg: report.accepted });
    if (report.accepted) await this.maybeRecordCampaign({ ...message, text: report.payload.evidence.join('\n') }, report.payload);
    await this.send(message.chat.id, formatDmReportReply(event, report), { reply_to_message_id: message.message_id });
    return event;
  }

  async assess(message, targetUser = actorFromMessage(message), text = message.text || '') {
    const bounded = boundedText(text);
    this.rememberUser(message.chat, targetUser, bounded);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: targetUser.username, userId: targetUser.id, aliases: actorAliases(targetUser), text: bounded });
    const adminUsernames = (await this.adminIdentities(message.chat.id)).filter((id) => !/^\d+$/.test(id));
    const renameCopycat = this.adminRenameCopycat(message.chat, targetUser, adminUsernames);
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
    if (!canAutonomouslyEscalate(risk)) {
      if (isObviousLocalScam(risk)) {
        const canDelete = this.config.autoDelete !== false && await this.hasDeleteRights(message.chat.id);
        const deletedMessage = canDelete ? await this.deleteMessage(message.chat.id, message.message_id).then(() => true).catch(() => false) : false;
        const finding = await this.publishHighConfidenceFinding(message, {
          ...risk,
          recommended_action: 'delete_and_review',
          evidence: [...risk.evidence, deletedMessage ? 'obvious local scam message removed' : 'obvious local scam message removal unavailable', 'local-only finding published for cross-community review; no ban/restrict without DKG backing']
        });
        return this.record('risk_review_needed', message, {
          ...risk,
          recommended_action: 'delete_and_review',
          finding_event_id: finding.id,
          evidence: [...risk.evidence, deletedMessage ? 'triggering message removed' : 'triggering message removal unavailable', `finding event ${finding.id}`, 'no ban/restrict without DKG backing']
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
      const restrictedUntil = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
      await this.restrict(message.chat.id, actorFromMessage(message).id, restrictedUntil);
      await this.record('restrict_executed', message, {
        ...risk,
        restricted_until: new Date(restrictedUntil * 1000).toISOString(),
        action_duration_seconds: 24 * 60 * 60,
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
    if (text.startsWith('/status')) {
      if (!await this.isTrustedModerator(message)) {
        await this.sendEphemeral(chatId, '⚠️ /status is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      await this.send(chatId, await this.formatStatus(message), { reply_to_message_id: message.message_id });
      return;
    }
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
    if (text.startsWith('/watchlist')) {
      if (!await this.isTrustedModerator(message)) {
        await this.sendEphemeral(chatId, '⚠️ /watchlist is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const filter = this.commandText(message, 'watchlist').split(/\s+/)[0]?.toLowerCase() || '';
      await this.send(chatId, this.formatWatchlist(filter), { reply_to_message_id: message.message_id, parse_mode: 'HTML', disable_web_page_preview: true });
      return;
    }
    if (text.startsWith('/watch')) {
      if (!await this.isTrustedModerator(message)) {
        await this.sendEphemeral(chatId, '⚠️ /watch is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const { target } = this.resolveCommandTarget(message, 'watch');
      const reason = this.commandReason(message, 'watch', 'admin watch');
      const evidence = ['admin watch started: ' + reason, target.sangmata?.evidence, target.id && target.source === 'telegram_id' ? `Telegram user ID watched: ${target.id}` : ''].filter(Boolean);
      const event = await this.record('watch_started', { ...message, from: target }, {
        watch_target_key: targetKey(target),
        target,
        reason,
        moderator: actorFromMessage(message),
        evidence
      }, { writeDkg: false });
      await this.send(chatId, `👀 Watching ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}. Event: ${event.id}. Reason: ${escapeHtml(reason)}. This increases scrutiny only; it will not ban by itself.`, { reply_to_message_id: message.message_id, parse_mode: 'HTML' });
      return;
    }
    if (text.startsWith('/unwatch')) {
      if (!await this.isTrustedModerator(message)) {
        await this.sendEphemeral(chatId, '⚠️ /unwatch is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const { target } = this.resolveCommandTarget(message, 'unwatch');
      const reason = this.commandReason(message, 'unwatch', 'admin unwatch');
      const evidence = ['admin watch ended: ' + reason, target.sangmata?.evidence].filter(Boolean);
      const event = await this.record('watch_ended', { ...message, from: target }, {
        watch_target_key: targetKey(target),
        target,
        reason,
        moderator: actorFromMessage(message),
        evidence
      }, { writeDkg: false });
      await this.send(chatId, `✅ Removed watch for ${userMention(target)}${target.id ? ` (ID ${escapeHtml(target.id)})` : ''}. Event: ${event.id}. Reason: ${escapeHtml(reason)}.`, { reply_to_message_id: message.message_id, parse_mode: 'HTML' });
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
      await this.send(chatId, `📝 Appeal logged to DKG as ${event.id}. Next: admins can run /review ${eventId || '<event-id>'} uphold reason or /review ${eventId || '<event-id>'} overturn reason.`, { reply_to_message_id: message.message_id });
      return;
    }
    if (text.startsWith('/review')) {
      if (!await this.isTrustedModerator(message)) {
        await this.sendEphemeral(chatId, '⚠️ /review is restricted to configured admins or Telegram chat admins.', { reply_to_message_id: message.message_id });
        return;
      }
      const [eventId, decisionRaw, ...reasonParts] = this.commandText(message, 'review').split(/\s+/);
      const decision = /^(uphold|upheld)$/i.test(decisionRaw || '') ? 'upheld' : /^(overturn|overturned|reject)$/i.test(decisionRaw || '') ? 'overturned' : '';
      if (!eventId || !decision) {
        await this.sendEphemeral(chatId, 'Usage: /review <event-id> uphold reason or /review <event-id> overturn reason', { reply_to_message_id: message.message_id });
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
      await this.send(chatId, `✅ Review ${decision}. I saved the review decision to DKG fraud memory. Reason: ${reason}.`, { reply_to_message_id: message.message_id });
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
    if (text.startsWith('/dmreport')) {
      await this.handleDmReport(message, this.commandText(message, 'dmreport') || evidenceText(message));
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
      if (replyMessageId && await this.hasDeleteRights(chatId)) {
        try {
          await this.deleteMessage(chatId, replyMessageId);
          repliedMessageDeleted = true;
        } catch (error) {
          repliedMessageDeleteError = error instanceof Error ? error.message : String(error);
        }
      }
      await this.ban(chatId, replyUser.id);
      const event = await this.record('ban_executed', { ...message, from: replyUser }, {
        ...risk,
        reason,
        replied_message_id: replyMessageId || '',
        replied_message_deleted: repliedMessageDeleted,
        replied_message_delete_error: repliedMessageDeleteError,
        confidence: Math.max(100, risk.confidence),
        scam_type: risk.scam_type || 'admin_action',
        evidence: [...risk.evidence, reason, replyUser.sangmata?.evidence || '', repliedMessageDeleted ? 'replied scam message deleted' : replyMessageId ? 'replied scam message deletion unavailable' : '', 'manual /ban command'].filter(Boolean)
      });
      await this.maybeRecordCampaign({ ...message, from: replyUser, text: context }, risk);
      await this.send(chatId, `${formatBanReply(replyUser, event.id)} ${repliedMessageDeleted ? 'Removed the replied scam message.' : replyMessageId ? 'Could not remove the replied message.' : 'No replied message to remove.'}`);
    }
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
    const canRestrict = true;
    await this.allowTextOnly(chatId, member.id, Math.floor(expiresAt / 1000)).catch(() => null);
    const qa = this.selectJoinChallengeQa(chatId, member);
    const sent = await this.send(chatId, await this.challengeText(chatId, member), { parse_mode: 'HTML', disable_web_page_preview: true });
    this.joinChallenges.set(key, { chat: message.chat, user: member, startedAt: Date.now(), expiresAt, messageId: sent?.message_id || '', attempts: 0, mode: qa ? 'qa' : 'ual', qa });
    await this.record('join_challenge_started', { ...message, from: member }, {
      target: member,
      target_key: targetKey(member),
      challenge_type: qa ? 'dkg_asset_qa' : 'dkg_ual',
      challenge_id: qa?.id || '',
      ttl_seconds: this.config.joinChallengeTtlSeconds || 60,
      restricted_text_only: Boolean(canRestrict),
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

  async handleJoinChallengeMessage(message, challenge, options = {}) {
    const text = String(message.text || '').trim();
    const chatId = message.chat.id;
    const replyChatId = options.sourceChatId || chatId;
    const key = this.challengeKey(chatId, message.from.id);
    const shouldRemindInGroup = !options.dm && !challenge.groupReminderSent;
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
          attempts: challenge.attempts,
          challenge_type: 'dkg_asset_qa',
          challenge_id: challenge.qa?.id || '',
          verification_channel: options.dm ? 'dm' : 'group',
          evidence: ['pending join challenge user sent an incorrect DKG asset answer']
        }, { writeDkg: false });
        const invalidText = `${options.dm ? '' : `${userMention(message.from)}, `}that answer did not match this DKG challenge. Open the Knowledge Asset again and answer: ${escapeHtml(challenge.qa?.question || 'the posted question')}`;
        if (options.dm) await this.send(replyChatId, invalidText, { disable_web_page_preview: true, private: true, parse_mode: 'HTML' });
        else if (shouldRemindInGroup) {
          challenge.groupReminderSent = true;
          await this.sendEphemeral(replyChatId, invalidText, { reply_to_message_id: challenge.messageId || message.message_id, parse_mode: 'HTML', disable_web_page_preview: true }, this.config.challengeMessageTtlSeconds || 120);
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
        attempts: challenge.attempts,
        verification_channel: options.dm ? 'dm' : 'group',
          evidence: ['pending join challenge user sent an invalid Knowledge Asset address first message']
      }, { writeDkg: false });
      const reminderText = `${options.dm ? '' : `${userMention(message.from)}, `}paste a Knowledge Asset address that starts with did:dkg: to complete verification.`;
      if (options.dm) await this.send(replyChatId, reminderText, { private: true });
      else if (shouldRemindInGroup) {
        challenge.groupReminderSent = true;
        await this.sendEphemeral(replyChatId, reminderText, { reply_to_message_id: challenge.messageId || message.message_id, parse_mode: 'HTML' }, this.config.challengeMessageTtlSeconds || 120);
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
        attempts: challenge.attempts,
        ual: text.slice(0, 240),
        validation_reason: validation.reason,
        verification_channel: options.dm ? 'dm' : 'group',
        evidence: ['pending join challenge user sent a Knowledge Asset address that did not validate on DKG']
      }, { writeDkg: false });
      const invalidText = `${options.dm ? '' : `${userMention(message.from)}, `}I could not validate that Knowledge Asset address. Try another one from https://dkg.origintrail.io/.`;
      if (options.dm) await this.send(replyChatId, invalidText, { disable_web_page_preview: true, private: true });
      else if (shouldRemindInGroup) {
        challenge.groupReminderSent = true;
        await this.sendEphemeral(replyChatId, invalidText, { reply_to_message_id: message.message_id, parse_mode: 'HTML', disable_web_page_preview: true }, this.config.challengeMessageTtlSeconds || 120);
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
      await this.deleteMessage(chatId, message.message_id).catch(() => null);
      if (challenge.messageId) await this.deleteMessage(chatId, challenge.messageId).catch(() => null);
    }
    await this.record('join_challenge_solved', message, {
      target: message.from,
      target_key: targetKey(message.from),
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

  async handleMessage(message) {
    if (message.new_chat_members?.length) {
      await this.handleNewMembers(message);
      return;
    }
    if (!message.text) return;
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
    if (message.text.startsWith('/')) {
      await this.handleCommand(message);
      return;
    }
    if (this.isDmReportMention(message)) {
      await this.handleDmReport(message, evidenceText(message));
      return;
    }
    if (this.isRiskQuery(message)) {
      const targetMessage = message.reply_to_message || message;
      const explicitNamedTarget = this.targetFromSafetyQuestion(message);
      if (!message.reply_to_message && !this.targetFromMention(message) && !explicitNamedTarget && /\b(?:is|are)\s+(?!(?:this|that|it|he|she|they|them|him|her|me|i)\b)[\p{L}\p{N}_-]{2,32}\s+(?:a\s+|an\s+)?(?:legit(?:imate)?|safe|unsafe|real|fake|scam(?:mer|ming)?|fraud(?:ster)?|risky?|trusted|trustworthy|blacklisted|flagged|suspicious|sus|dangerous|malicious)\b/iu.test(String(message.text || '').replace(/@(?:tracabot|tracethembot)\b/ig, ' '))) {
        await this.sendEphemeral(message.chat.id, 'I cannot identify that user from a display name alone. Reply to one of their messages and ask “is this a scam?” so I can check the actual Telegram account.', { reply_to_message_id: message.message_id });
        return;
      }
      const target = this.targetFromMention(message) || explicitNamedTarget || sangmataTargetFromText(targetMessage.text || '') || actorFromMessage(targetMessage);
      const risk = await this.assess({ ...message, from: target }, target, `${message.text}\n${targetMessage.text || ''}`);
      const event = await this.record('risk_query', { ...message, from: target }, risk);
      const finding = this.canPublishFindingFromRisk(risk) ? await this.publishHighConfidenceFinding({ ...message, from: target }, risk) : null;
      await this.maybeRecordCampaign({ ...message, from: target }, risk);
      const conversational = await this.conversationReply(message, target, risk, event, true);
      if (conversational) await this.send(message.chat.id, conversational, { reply_to_message_id: message.message_id });
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
      } else if (this.config.joinChallenge) {
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
      await this.record('join_challenge_expired', message, {
        target: challenge.user,
        target_key: targetKey(challenge.user),
        action: this.config.joinChallengeAction || 'kick',
        attempts: challenge.attempts,
        evidence: ['new user did not complete DKG Knowledge Asset UAL verification before timeout']
      }, { writeDkg: false });
      if (challenge.messageId && await this.hasDeleteRights(challenge.chat.id)) await this.deleteMessage(challenge.chat.id, challenge.messageId).catch(() => null);
      await this.sendEphemeral(challenge.chat.id, `${userMention(challenge.user)} did not complete DKG verification in time.`, { parse_mode: 'HTML' }, this.config.successMessageTtlSeconds || 45).catch(() => null);
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
      allowed_updates: ['message', 'chat_member', 'my_chat_member']
    });
    for (const update of updates) {
      this.offset = update.update_id + 1;
      if (update.message) await this.handleMessage(update.message);
      if (update.chat_member) await this.handleChatMemberUpdate(update.chat_member);
    }
    await this.proactiveScan();
    await this.expireJoinChallenges();
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

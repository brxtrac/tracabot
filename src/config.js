import { existsSync, readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

const CONTEXT_GRAPH_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}(?:\/[a-zA-Z0-9][a-zA-Z0-9_-]{0,63})?$/;
const ON_CHAIN_CONTEXT_GRAPH_ID_RE = /^\d+$/;

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  if (/^(true|1|yes)$/i.test(value)) return true;
  if (/^(false|0|no)$/i.test(value)) return false;
  throw new Error(`Invalid boolean value: ${value}`);
}

function readOptionalFile(path = '') {
  const value = String(path || '').trim();
  if (!value) return '';
  const resolved = resolve(value);
  if (!existsSync(resolved)) throw new Error(`configured key file does not exist: ${value}`);
  return readFileSync(resolved, 'utf8');
}

function assertEd25519KeyMaterial(value = '', label = 'creator curator key') {
  if (!value) return;
  let key;
  try {
    key = createPublicKey(value);
  } catch {
    throw new Error(`${label} must be a valid PEM key`);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error(`${label} must be an Ed25519 key`);
  }
}

function readLocalDkgToken() {
  const tokenPath = resolve(homedir(), '.dkg', 'auth.token');
  if (!existsSync(tokenPath)) return '';
  return readFileSync(tokenPath, 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line && !line.startsWith('#')) || '';
}

function parseChallengeBank(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('challenge bank must be an array');
    return parsed.map((entry, index) => {
      const answers = Array.isArray(entry.answers) ? entry.answers : [entry.answer];
      return {
        id: String(entry.id || `challenge-${index + 1}`),
        question: String(entry.question || '').trim(),
        answers: answers.map((answer) => String(answer || '').trim()).filter(Boolean)
      };
    }).filter((entry) => entry.question && entry.answers.length);
  } catch (error) {
    throw new Error(`TRACABOT_JOIN_CHALLENGE_QA_BANK must be JSON array of {question, answers}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function parseChatIdList(value = '') {
  const items = String(value || '')
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
  const invalid = items.filter((item) => !/^-?\d{4,24}$/.test(item));
  if (invalid.length) throw new Error(`TRACABOT_JOIN_AUTO_REMOVE_CHATS must contain numeric Telegram chat IDs; got ${invalid.join(', ')}`);
  return [...new Set(items)];
}

function parseTrustedSources(value = '') {
  return [...new Set(String(value || '')
    .split(/[\s,]+/)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .map((item) => item.slice(0, 160)))]
    .slice(0, 50);
}

function parseTrustedLayers(value = '') {
  const supported = new Set(['verified-memory', 'local', 'shared-working-memory', 'creator-curator']);
  const layers = String(value || 'local')
    .split(/[\s,]+/)
    .map((item) => item.trim().toLowerCase().replace(/_/g, '-'))
    .filter(Boolean);
  const unknown = layers.filter((layer) => !supported.has(layer));
  if (unknown.length) throw new Error(`TRACABOT_JOIN_TRUSTED_LAYERS supports only verified-memory, local, shared-working-memory, creator-curator; got ${unknown.join(', ')}`);
  return [...new Set(layers)];
}

function parseKnownCampaignPatterns(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return [];
  return raw
    .split(/[\n,|]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseCommunityTokens(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`TRACABOT_COMMUNITY_TOKENS must be a JSON array: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (!Array.isArray(parsed)) throw new Error('TRACABOT_COMMUNITY_TOKENS must be a JSON array');
  return parsed.map((entry, index) => {
    const token = String(entry?.token || '').trim();
    const communityId = String(entry?.communityId || entry?.community_id || '').trim();
    if (token.length < 16) throw new Error(`TRACABOT_COMMUNITY_TOKENS[${index}].token must be at least 16 characters`);
    if (!communityId || communityId.length > 128) throw new Error(`TRACABOT_COMMUNITY_TOKENS[${index}].communityId must be 1-128 characters`);
    const scopes = Array.isArray(entry?.scopes) && entry.scopes.length ? entry.scopes : ['evidence:write'];
    if (scopes.some((scope) => !['evidence:write'].includes(scope))) {
      throw new Error(`TRACABOT_COMMUNITY_TOKENS[${index}].scopes supports only evidence:write`);
    }
    return { token, communityId, name: String(entry?.name || '').trim().slice(0, 120), instanceId: String(entry?.instanceId || entry?.instance_id || '').trim().slice(0, 64), scopes: [...new Set(scopes)] };
  });
}

export function loadConfig(env = process.env) {
  const contextGraph = env.TRACABOT_CONTEXT_GRAPH || 'tracabot';
  const warnThreshold = Number(env.TRACABOT_WARN_THRESHOLD || 60);
  const restrictThreshold = Number(env.TRACABOT_RESTRICT_THRESHOLD || 75);
  const actionThreshold = Number(env.TRACABOT_ACTION_THRESHOLD || 85);
  const banThreshold = Number(env.TRACABOT_BAN_THRESHOLD || actionThreshold);
  const proactiveScanMinutes = Number(env.TRACABOT_PROACTIVE_SCAN_MINUTES || 30);
  const telegramTimeoutMs = Number(env.TRACABOT_TELEGRAM_TIMEOUT_MS || 30000);
  const dkgQueryTimeoutMs = Number(env.TRACABOT_DKG_QUERY_TIMEOUT_MS || 4000);
  const adminIds = new Set((env.TRACABOT_ADMINS || '')
    .split(',')
    .map((id) => id.trim().replace(/^@/, '').toLowerCase())
    .filter(Boolean));
  const botOwnerIds = new Set((env.TRACABOT_BOT_OWNER_IDS || env.TRACABOT_BOT_OWNER_ID || '')
    .split(',')
    .map((id) => id.trim().replace(/^@/, '').toLowerCase())
    .filter(Boolean));
  if (!Number.isFinite(actionThreshold) || actionThreshold < 50 || actionThreshold > 100) {
    throw new Error('TRACABOT_ACTION_THRESHOLD must be a number from 50 to 100');
  }
  if (!Number.isFinite(warnThreshold) || warnThreshold < 1 || warnThreshold > 100) {
    throw new Error('TRACABOT_WARN_THRESHOLD must be a number from 1 to 100');
  }
  if (!Number.isFinite(restrictThreshold) || restrictThreshold < warnThreshold || restrictThreshold > 100) {
    throw new Error('TRACABOT_RESTRICT_THRESHOLD must be a number from warn threshold to 100');
  }
  if (!Number.isFinite(banThreshold) || banThreshold < restrictThreshold || banThreshold > 100) {
    throw new Error('TRACABOT_BAN_THRESHOLD must be a number from restrict threshold to 100');
  }
  if (!CONTEXT_GRAPH_RE.test(contextGraph)) {
    throw new Error('TRACABOT_CONTEXT_GRAPH must be one or two slash-separated segments, each 1-64 characters using letters, numbers, underscores, or hyphens');
  }
  const publishContextGraphId = String(env.TRACABOT_PUBLISH_CONTEXT_GRAPH_ID || '').trim();
  if (publishContextGraphId && !ON_CHAIN_CONTEXT_GRAPH_ID_RE.test(publishContextGraphId)) {
    throw new Error('TRACABOT_PUBLISH_CONTEXT_GRAPH_ID must be a decimal on-chain context graph ID');
  }
  if (!Number.isFinite(proactiveScanMinutes) || proactiveScanMinutes < 5) {
    throw new Error('TRACABOT_PROACTIVE_SCAN_MINUTES must be at least 5');
  }
  if (!Number.isFinite(telegramTimeoutMs) || telegramTimeoutMs < 5000) {
    throw new Error('TRACABOT_TELEGRAM_TIMEOUT_MS must be at least 5000');
  }
  if (!Number.isFinite(dkgQueryTimeoutMs) || dkgQueryTimeoutMs < 1000) {
    throw new Error('TRACABOT_DKG_QUERY_TIMEOUT_MS must be at least 1000');
  }
  const conversationMinConfidence = Number(env.TRACABOT_CONVERSATION_MIN_CONFIDENCE || 60);
  const proactiveReplyThreshold = Number(env.TRACABOT_PROACTIVE_REPLY_THRESHOLD || 75);
  const conversationRateLimitSeconds = Number(env.TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS || 8);
  const conversationMaxChars = Number(env.TRACABOT_CONVERSATION_MAX_CHARS || 700);
  const joinChallengeTtlSeconds = Number(env.TRACABOT_JOIN_CHALLENGE_TTL_SECONDS || 60);
  const joinChallengeMaxAttempts = Number(env.TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS || 3);
  const joinChallengeRepeatFailureThreshold = Number(env.TRACABOT_JOIN_CHALLENGE_REPEAT_FAILURE_THRESHOLD || 2);
  const joinChallengeRepeatBadAttemptThreshold = Number(env.TRACABOT_JOIN_CHALLENGE_REPEAT_BAD_ATTEMPT_THRESHOLD || 3);
  const botMessageTtlSeconds = Number(env.TRACABOT_BOT_MESSAGE_TTL_SECONDS || 60);
  const challengeMessageTtlSeconds = Number(env.TRACABOT_CHALLENGE_MESSAGE_TTL_SECONDS || 120);
  const successMessageTtlSeconds = Number(env.TRACABOT_SUCCESS_MESSAGE_TTL_SECONDS || 45);
  const channelMemoryMinConfidence = Number(env.TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE || 80);
  const channelMemoryMaxTextChars = Number(env.TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS || 1000);
  const wmArtifactMinConfidence = Number(env.TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE || 40);
  const wmArtifactMaxTextChars = Number(env.TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS || 700);
  const banContextMaxMessages = Number(env.TRACABOT_BAN_CONTEXT_MAX_MESSAGES || 8);
  const banContextMaxAgeMinutes = Number(env.TRACABOT_BAN_CONTEXT_MAX_AGE_MINUTES || 60);
  const banContextMaxTextChars = Number(env.TRACABOT_BAN_CONTEXT_MAX_TEXT_CHARS || 1000);
  const pendingReviewNotificationIntervalHours = Number(env.TRACABOT_PENDING_REVIEW_NOTIFICATION_INTERVAL_HOURS || 12);
  const instanceId = String(env.TRACABOT_INSTANCE_ID || '').trim();
  if (instanceId && !/^[A-Za-z0-9._-]{1,64}$/.test(instanceId)) {
    throw new Error('TRACABOT_INSTANCE_ID must be 1-64 characters using letters, numbers, dots, underscores, or hyphens');
  }
  const joinAutoRemove = parseBoolean(env.TRACABOT_JOIN_AUTO_REMOVE, false);
  const joinAutoRemoveChats = parseChatIdList(env.TRACABOT_JOIN_AUTO_REMOVE_CHATS || '');
  const joinEvidenceMaxAgeDays = Number(env.TRACABOT_JOIN_EVIDENCE_MAX_AGE_DAYS || 180);
  if (!Number.isFinite(joinEvidenceMaxAgeDays) || joinEvidenceMaxAgeDays < 1 || joinEvidenceMaxAgeDays > 3650) {
    throw new Error('TRACABOT_JOIN_EVIDENCE_MAX_AGE_DAYS must be a number from 1 to 3650');
  }
  const joinMinConfirmedRoots = Number(env.TRACABOT_JOIN_MIN_CONFIRMED_ROOTS || 1);
  if (!Number.isFinite(joinMinConfirmedRoots) || joinMinConfirmedRoots < 1 || joinMinConfirmedRoots > 5) {
    throw new Error('TRACABOT_JOIN_MIN_CONFIRMED_ROOTS must be a number from 1 to 5');
  }
  const joinTrustedLayers = parseTrustedLayers(env.TRACABOT_JOIN_TRUSTED_LAYERS || '');
  const joinTrustedSources = parseTrustedSources(env.TRACABOT_JOIN_TRUSTED_SOURCES || '');
  const submitSharedEvidence = parseBoolean(env.TRACABOT_SUBMIT_SHARED_EVIDENCE, false);
  const creatorSubmitUrl = String(env.TRACABOT_CREATOR_SUBMIT_URL || '').trim();
  if (creatorSubmitUrl) {
    let parsed;
    try { parsed = new URL(creatorSubmitUrl); } catch { throw new Error('TRACABOT_CREATOR_SUBMIT_URL must be a valid http(s) URL'); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('TRACABOT_CREATOR_SUBMIT_URL must use http or https');
  }
  const creatorSubmitToken = String(env.TRACABOT_CREATOR_SUBMIT_TOKEN || '').trim();
  if (creatorSubmitToken && creatorSubmitToken.length < 16) {
    throw new Error('TRACABOT_CREATOR_SUBMIT_TOKEN must be at least 16 characters when configured');
  }
  if (submitSharedEvidence && (!creatorSubmitUrl || !creatorSubmitToken)) {
    throw new Error('TRACABOT_SUBMIT_SHARED_EVIDENCE=true requires TRACABOT_CREATOR_SUBMIT_URL and TRACABOT_CREATOR_SUBMIT_TOKEN');
  }
  const creatorCuratorUrl = String(env.TRACABOT_CREATOR_CURATOR_URL || '').trim().replace(/\/+$/, '');
  if (creatorCuratorUrl) {
    let parsed;
    try { parsed = new URL(creatorCuratorUrl); } catch { throw new Error('TRACABOT_CREATOR_CURATOR_URL must be a valid http(s) URL'); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('TRACABOT_CREATOR_CURATOR_URL must use http or https');
  }
  const creatorCuratorPublicKey = String(env.TRACABOT_CREATOR_CURATOR_PUBLIC_KEY || '').trim()
    || readOptionalFile(env.TRACABOT_CREATOR_CURATOR_PUBLIC_KEY_PATH);
  if (creatorCuratorUrl && !creatorCuratorPublicKey) {
    throw new Error('TRACABOT_CREATOR_CURATOR_URL requires TRACABOT_CREATOR_CURATOR_PUBLIC_KEY or TRACABOT_CREATOR_CURATOR_PUBLIC_KEY_PATH');
  }
  const creatorCuratorPrivateKey = String(env.TRACABOT_CREATOR_CURATOR_PRIVATE_KEY || '').trim()
    || readOptionalFile(env.TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH);
  assertEd25519KeyMaterial(creatorCuratorPublicKey, 'TRACABOT_CREATOR_CURATOR_PUBLIC_KEY');
  assertEd25519KeyMaterial(creatorCuratorPrivateKey, 'TRACABOT_CREATOR_CURATOR_PRIVATE_KEY');
  const creatorCuratorToken = String(env.TRACABOT_CREATOR_CURATOR_TOKEN || '').trim();
  if (creatorCuratorToken && creatorCuratorToken.length < 16) {
    throw new Error('TRACABOT_CREATOR_CURATOR_TOKEN must be at least 16 characters when configured');
  }
  const creatorCuratorReadToken = String(env.TRACABOT_CREATOR_CURATOR_READ_TOKEN || '').trim();
  if (creatorCuratorReadToken && creatorCuratorReadToken.length < 16) {
    throw new Error('TRACABOT_CREATOR_CURATOR_READ_TOKEN must be at least 16 characters when configured');
  }
  if (creatorCuratorUrl && !(creatorCuratorReadToken || creatorCuratorToken)) {
    throw new Error('TRACABOT_CREATOR_CURATOR_URL requires TRACABOT_CREATOR_CURATOR_READ_TOKEN or TRACABOT_CREATOR_CURATOR_TOKEN');
  }
  if ((creatorCuratorPrivateKey || creatorCuratorToken) && !creatorCuratorPrivateKey) {
    throw new Error('creator curator API requires TRACABOT_CREATOR_CURATOR_PRIVATE_KEY or TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH');
  }
  const creatorCuratorIssuer = String(env.TRACABOT_CREATOR_CURATOR_ISSUER || 'tracabot-creator-curator').trim();
  if (creatorCuratorIssuer.length < 3 || creatorCuratorIssuer.length > 120) {
    throw new Error('TRACABOT_CREATOR_CURATOR_ISSUER must be 3-120 characters');
  }
  const creatorCuratorMinConfidence = Number(env.TRACABOT_CREATOR_CURATOR_MIN_CONFIDENCE || 90);
  if (!Number.isFinite(creatorCuratorMinConfidence) || creatorCuratorMinConfidence < 50 || creatorCuratorMinConfidence > 100) {
    throw new Error('TRACABOT_CREATOR_CURATOR_MIN_CONFIDENCE must be a number from 50 to 100');
  }
  const creatorCuratorMinRoots = Number(env.TRACABOT_CREATOR_CURATOR_MIN_ROOTS || 1);
  if (!Number.isFinite(creatorCuratorMinRoots) || creatorCuratorMinRoots < 1 || creatorCuratorMinRoots > 5) {
    throw new Error('TRACABOT_CREATOR_CURATOR_MIN_ROOTS must be a number from 1 to 5');
  }
  const creatorCuratorMaxAgeDays = Number(env.TRACABOT_CREATOR_CURATOR_MAX_AGE_DAYS || 180);
  if (!Number.isFinite(creatorCuratorMaxAgeDays) || creatorCuratorMaxAgeDays < 1 || creatorCuratorMaxAgeDays > 3650) {
    throw new Error('TRACABOT_CREATOR_CURATOR_MAX_AGE_DAYS must be a number from 1 to 3650');
  }
  const creatorCuratorTimeoutMs = Number(env.TRACABOT_CREATOR_CURATOR_TIMEOUT_MS || 4000);
  if (!Number.isFinite(creatorCuratorTimeoutMs) || creatorCuratorTimeoutMs < 500 || creatorCuratorTimeoutMs > 30000) {
    throw new Error('TRACABOT_CREATOR_CURATOR_TIMEOUT_MS must be a number from 500 to 30000');
  }
  const creatorCuratorReadRateLimitPerHour = Number(env.TRACABOT_CREATOR_CURATOR_READ_RATE_LIMIT_PER_HOUR || 120);
  if (!Number.isFinite(creatorCuratorReadRateLimitPerHour) || creatorCuratorReadRateLimitPerHour < 1 || creatorCuratorReadRateLimitPerHour > 10000) {
    throw new Error('TRACABOT_CREATOR_CURATOR_READ_RATE_LIMIT_PER_HOUR must be a number from 1 to 10000');
  }
  const creatorCuratorWriteRateLimitPerHour = Number(env.TRACABOT_CREATOR_CURATOR_WRITE_RATE_LIMIT_PER_HOUR || 30);
  if (!Number.isFinite(creatorCuratorWriteRateLimitPerHour) || creatorCuratorWriteRateLimitPerHour < 1 || creatorCuratorWriteRateLimitPerHour > 10000) {
    throw new Error('TRACABOT_CREATOR_CURATOR_WRITE_RATE_LIMIT_PER_HOUR must be a number from 1 to 10000');
  }
  const creatorCuratorStorePath = String(env.TRACABOT_CREATOR_CURATOR_STORE || './data/creator-attestations.json').trim();
  const appealMaxPerHour = Number(env.TRACABOT_APPEAL_MAX_PER_HOUR || 3);
  if (!Number.isFinite(appealMaxPerHour) || appealMaxPerHour < 1 || appealMaxPerHour > 20) {
    throw new Error('TRACABOT_APPEAL_MAX_PER_HOUR must be a number from 1 to 20');
  }
  const appealDedupHours = Number(env.TRACABOT_APPEAL_DEDUP_HOURS || 24);
  if (!Number.isFinite(appealDedupHours) || appealDedupHours < 1 || appealDedupHours > 168) {
    throw new Error('TRACABOT_APPEAL_DEDUP_HOURS must be a number from 1 to 168');
  }
  const appealMaxReasonChars = Number(env.TRACABOT_APPEAL_MAX_REASON_CHARS || 500);
  if (!Number.isFinite(appealMaxReasonChars) || appealMaxReasonChars < 80 || appealMaxReasonChars > 1000) {
    throw new Error('TRACABOT_APPEAL_MAX_REASON_CHARS must be a number from 80 to 1000');
  }
  const llmTimeoutMs = Number(env.TRACABOT_LLM_TIMEOUT_MS || 30000);
  if (!Number.isFinite(llmTimeoutMs) || llmTimeoutMs < 1000 || llmTimeoutMs > 120000) {
    throw new Error('TRACABOT_LLM_TIMEOUT_MS must be a number from 1000 to 120000');
  }
  const llmMaxTokens = Number(env.TRACABOT_LLM_MAX_TOKENS || 220);
  if (!Number.isFinite(llmMaxTokens) || llmMaxTokens < 32 || llmMaxTokens > 2000) {
    throw new Error('TRACABOT_LLM_MAX_TOKENS must be a number from 32 to 2000');
  }
  const joinChallengeMode = /^(memory-card|qa|ual)$/i.test(env.TRACABOT_JOIN_CHALLENGE_MODE || '') ? env.TRACABOT_JOIN_CHALLENGE_MODE.toLowerCase() : 'memory-card';
  const joinChallengeQaBank = parseChallengeBank(env.TRACABOT_JOIN_CHALLENGE_QA_BANK || '');
  const dkgMode = env.TRACABOT_DKG_MODE || 'openclaw-adapter';
  const legacyStorePath = env.TRACABOT_LEGACY_STORE_PATH || env.TRACABOT_STORE_PATH || './data/tracabot-events.jsonl';
  const databasePath = env.TRACABOT_DB_PATH || legacyStorePath.replace(/\.jsonl$/i, '.sqlite');
  const dkgWrites = parseBoolean(env.TRACABOT_DKG_WRITES, true);
  const dkgPseudonymKey = String(env.TRACABOT_DKG_PSEUDONYM_KEY || '');
  // Clear, high-evidence known-campaign auto-ban (SangMata renames + prior ban roots).
  // Independent of broad TRACABOT_AUTO_BAN so BC GAME-class waves can be removed without re-enabling all classifier bans.
  const knownCampaignAutoBan = parseBoolean(env.TRACABOT_KNOWN_CAMPAIGN_AUTO_BAN, true);
  const knownCampaignMinBanRoots = Number(env.TRACABOT_KNOWN_CAMPAIGN_MIN_BAN_ROOTS || 2);
  const knownCampaignPatterns = parseKnownCampaignPatterns(env.TRACABOT_KNOWN_CAMPAIGN_PATTERNS || '');
  if (!Number.isFinite(knownCampaignMinBanRoots) || knownCampaignMinBanRoots < 1 || knownCampaignMinBanRoots > 20) {
    throw new Error('TRACABOT_KNOWN_CAMPAIGN_MIN_BAN_ROOTS must be a number from 1 to 20');
  }
  const communityTokens = parseCommunityTokens(env.TRACABOT_COMMUNITY_TOKENS || '');
  const evidenceHighConfidenceThreshold = Number(env.TRACABOT_EVIDENCE_HIGH_CONFIDENCE_THRESHOLD || 85);
  const evidenceLocalConfidenceThreshold = Number(env.TRACABOT_EVIDENCE_LOCAL_CONFIDENCE_THRESHOLD || 60);
  const evidenceMinIndependentSignals = Number(env.TRACABOT_EVIDENCE_MIN_INDEPENDENT_SIGNALS || 2);
  const evidenceMinIndependentCommunities = Number(env.TRACABOT_EVIDENCE_MIN_INDEPENDENT_COMMUNITIES || 2);
  const evidencePromotionThreshold = Number(env.TRACABOT_EVIDENCE_PROMOTION_THRESHOLD || 85);
  const autoPromoteIntervalMs = Number(env.TRACABOT_AUTO_PROMOTE_INTERVAL_MS || 300000);
  const publicPort = Number(env.TRACABOT_PUBLIC_PORT || 8787);
  const publicRateLimitPerHour = Number(env.TRACABOT_PUBLIC_RATE_LIMIT_PER_HOUR || 30);
  const publicJoinRateLimitPerHour = Number(env.TRACABOT_PUBLIC_JOIN_RATE_LIMIT_PER_HOUR || 5);
  for (const [name, value] of [
    ['TRACABOT_EVIDENCE_HIGH_CONFIDENCE_THRESHOLD', evidenceHighConfidenceThreshold],
    ['TRACABOT_EVIDENCE_LOCAL_CONFIDENCE_THRESHOLD', evidenceLocalConfidenceThreshold],
    ['TRACABOT_EVIDENCE_PROMOTION_THRESHOLD', evidencePromotionThreshold]
  ]) {
    if (!Number.isFinite(value) || value < 1 || value > 100) throw new Error(`${name} must be a number from 1 to 100`);
  }
  for (const [name, value] of [
    ['TRACABOT_EVIDENCE_MIN_INDEPENDENT_SIGNALS', evidenceMinIndependentSignals],
    ['TRACABOT_EVIDENCE_MIN_INDEPENDENT_COMMUNITIES', evidenceMinIndependentCommunities]
  ]) {
    if (!Number.isFinite(value) || value < 1 || value > 10) throw new Error(`${name} must be a number from 1 to 10`);
  }
  if (!Number.isFinite(autoPromoteIntervalMs) || autoPromoteIntervalMs < 30000) {
    throw new Error('TRACABOT_AUTO_PROMOTE_INTERVAL_MS must be at least 30000');
  }
  if (!Number.isFinite(publicPort) || publicPort < 0 || publicPort > 65535) {
    throw new Error('TRACABOT_PUBLIC_PORT must be a number from 0 to 65535');
  }
  const publicMaxBodyBytes = Number(env.TRACABOT_PUBLIC_MAX_BODY_BYTES || 32768);
  if (!Number.isFinite(publicMaxBodyBytes) || publicMaxBodyBytes < 1024 || publicMaxBodyBytes > 1048576) {
    throw new Error('TRACABOT_PUBLIC_MAX_BODY_BYTES must be a number from 1024 to 1048576');
  }
  for (const [name, value] of [
    ['TRACABOT_PUBLIC_RATE_LIMIT_PER_HOUR', publicRateLimitPerHour],
    ['TRACABOT_PUBLIC_JOIN_RATE_LIMIT_PER_HOUR', publicJoinRateLimitPerHour]
  ]) {
    if (!Number.isFinite(value) || value < 1 || value > 10000) throw new Error(`${name} must be a number from 1 to 10000`);
  }
  if (dkgMode !== 'openclaw-adapter') {
    throw new Error('TRACABOT_DKG_MODE currently supports only openclaw-adapter');
  }
  if (!Number.isFinite(conversationMinConfidence) || conversationMinConfidence < 0 || conversationMinConfidence > 100) {
    throw new Error('TRACABOT_CONVERSATION_MIN_CONFIDENCE must be a number from 0 to 100');
  }
  if (!Number.isFinite(proactiveReplyThreshold) || proactiveReplyThreshold < conversationMinConfidence || proactiveReplyThreshold > 100) {
    throw new Error('TRACABOT_PROACTIVE_REPLY_THRESHOLD must be a number from conversation minimum to 100');
  }
  if (!Number.isFinite(conversationRateLimitSeconds) || conversationRateLimitSeconds < 0) {
    throw new Error('TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS must be a non-negative number');
  }
  if (!Number.isFinite(conversationMaxChars) || conversationMaxChars < 160 || conversationMaxChars > 2000) {
    throw new Error('TRACABOT_CONVERSATION_MAX_CHARS must be a number from 160 to 2000');
  }
  if (!Number.isFinite(joinChallengeTtlSeconds) || joinChallengeTtlSeconds < 15 || joinChallengeTtlSeconds > 900) {
    throw new Error('TRACABOT_JOIN_CHALLENGE_TTL_SECONDS must be a number from 15 to 900');
  }
  if (!Number.isFinite(joinChallengeMaxAttempts) || joinChallengeMaxAttempts < 1 || joinChallengeMaxAttempts > 20) {
    throw new Error('TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS must be a number from 1 to 20');
  }
  if (!Number.isFinite(joinChallengeRepeatFailureThreshold) || joinChallengeRepeatFailureThreshold < 2 || joinChallengeRepeatFailureThreshold > 20) {
    throw new Error('TRACABOT_JOIN_CHALLENGE_REPEAT_FAILURE_THRESHOLD must be a number from 2 to 20');
  }
  if (!Number.isFinite(joinChallengeRepeatBadAttemptThreshold) || joinChallengeRepeatBadAttemptThreshold < 1 || joinChallengeRepeatBadAttemptThreshold > 20) {
    throw new Error('TRACABOT_JOIN_CHALLENGE_REPEAT_BAD_ATTEMPT_THRESHOLD must be a number from 1 to 20');
  }
  if (!Number.isFinite(botMessageTtlSeconds) || botMessageTtlSeconds < 5 || botMessageTtlSeconds > 86400) {
    throw new Error('TRACABOT_BOT_MESSAGE_TTL_SECONDS must be a number from 5 to 86400');
  }
  if (!Number.isFinite(challengeMessageTtlSeconds) || challengeMessageTtlSeconds < 15 || challengeMessageTtlSeconds > 86400) {
    throw new Error('TRACABOT_CHALLENGE_MESSAGE_TTL_SECONDS must be a number from 15 to 86400');
  }
  if (!Number.isFinite(successMessageTtlSeconds) || successMessageTtlSeconds < 5 || successMessageTtlSeconds > 86400) {
    throw new Error('TRACABOT_SUCCESS_MESSAGE_TTL_SECONDS must be a number from 5 to 86400');
  }
  if (!Number.isFinite(channelMemoryMinConfidence) || channelMemoryMinConfidence < 60 || channelMemoryMinConfidence > 100) {
    throw new Error('TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE must be a number from 60 to 100');
  }
  if (!Number.isFinite(channelMemoryMaxTextChars) || channelMemoryMaxTextChars < 160 || channelMemoryMaxTextChars > 2000) {
    throw new Error('TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS must be a number from 160 to 2000');
  }
  if (!Number.isFinite(wmArtifactMinConfidence) || wmArtifactMinConfidence < 0 || wmArtifactMinConfidence > 100) {
    throw new Error('TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE must be a number from 0 to 100');
  }
  if (!Number.isFinite(wmArtifactMaxTextChars) || wmArtifactMaxTextChars < 160 || wmArtifactMaxTextChars > 2000) {
    throw new Error('TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS must be a number from 160 to 2000');
  }
  if (!Number.isFinite(banContextMaxMessages) || banContextMaxMessages < 1 || banContextMaxMessages > 20) {
    throw new Error('TRACABOT_BAN_CONTEXT_MAX_MESSAGES must be a number from 1 to 20');
  }
  if (!Number.isFinite(banContextMaxAgeMinutes) || banContextMaxAgeMinutes < 5 || banContextMaxAgeMinutes > 1440) {
    throw new Error('TRACABOT_BAN_CONTEXT_MAX_AGE_MINUTES must be a number from 5 to 1440');
  }
  if (!Number.isFinite(banContextMaxTextChars) || banContextMaxTextChars < 160 || banContextMaxTextChars > 2000) {
    throw new Error('TRACABOT_BAN_CONTEXT_MAX_TEXT_CHARS must be a number from 160 to 2000');
  }
  if (!Number.isFinite(pendingReviewNotificationIntervalHours) || pendingReviewNotificationIntervalHours < 1 || pendingReviewNotificationIntervalHours > 168) {
    throw new Error('TRACABOT_PENDING_REVIEW_NOTIFICATION_INTERVAL_HOURS must be a number from 1 to 168');
  }
  return {
    telegramToken: env.TELEGRAM_BOT_TOKEN || '',
    botUsername: env.TRACABOT_BOT_USERNAME || '',
    adminIds,
    botOwnerIds,
    autoDelete: parseBoolean(env.TRACABOT_AUTO_DELETE, true),
    autoRestrict: parseBoolean(env.TRACABOT_AUTO_RESTRICT, false),
    autoBan: parseBoolean(env.TRACABOT_AUTO_BAN, false),
    knownCampaignAutoBan,
    highConfidenceAutoBan: parseBoolean(env.TRACABOT_HIGH_CONFIDENCE_AUTO_BAN, false),
    knownCampaignMinBanRoots,
    knownCampaignPatterns,
    warnThreshold,
    restrictThreshold,
    banThreshold,
    actionThreshold,
    proactiveScanMinutes,
    telegramTimeoutMs,
    dkgQueryTimeoutMs,
    dropPendingUpdatesOnStart: parseBoolean(env.TRACABOT_DROP_PENDING_UPDATES_ON_START, true),
    contextGraph,
    publishContextGraphId,
    communityId: env.TRACABOT_COMMUNITY_ID || '',
    communityName: env.TRACABOT_COMMUNITY_NAME || '',
    communityType: env.TRACABOT_COMMUNITY_TYPE || 'telegram_group',
    instanceId,
    policyId: env.TRACABOT_POLICY_ID || 'default',
    dkgMode,
    dkgNodeUrl: env.DKG_NODE_URL || 'http://127.0.0.1:9200',
    dkgAuthToken: env.DKG_AUTH_TOKEN || readLocalDkgToken(),
    dkgReads: parseBoolean(env.TRACABOT_DKG_READS, true),
    dkgWrites,
    dkgPublishVerified: parseBoolean(env.TRACABOT_DKG_PUBLISH_VERIFIED, false),
    dkgPseudonymKey,
    openClawDkgAdapterPath: env.OPENCLAW_DKG_ADAPTER_PATH || '',
    storePath: databasePath,
    databasePath,
    legacyStorePath,
    agentDid: env.TRACABOT_AGENT_DID || 'did:dkg:agent:tracabot',
    testMode: parseBoolean(env.TRACABOT_TEST_MODE, false),
    openClawWorkspace: env.OPENCLAW_WORKSPACE || resolve(homedir(), '.openclaw', 'workspace'),
    conversational: parseBoolean(env.TRACABOT_CONVERSATIONAL, true),
    llmProvider: env.TRACABOT_LLM_PROVIDER || 'auto',
    llmBaseUrl: env.TRACABOT_LLM_BASE_URL || '',
    llmApiKey: env.TRACABOT_LLM_API_KEY || '',
    llmModel: env.TRACABOT_LLM_MODEL || '',
    llmTimeoutMs,
    llmMaxTokens,
    openClawConfigPath: env.OPENCLAW_CONFIG_PATH || resolve(homedir(), '.openclaw', 'openclaw.json'),
    conversationMinConfidence,
    proactiveReplyThreshold,
    conversationRateLimitSeconds,
    conversationMaxChars,
    joinChallenge: parseBoolean(env.TRACABOT_JOIN_CHALLENGE, false),
    joinChallengeMode,
    joinChallengeAssetUrl: env.TRACABOT_JOIN_CHALLENGE_ASSET_URL || '',
    joinChallengeQaBank,
    joinChallengeTtlSeconds,
    joinChallengeMaxAttempts,
    joinChallengeRepeatFailureThreshold,
    joinChallengeRepeatBadAttemptThreshold,
    joinChallengeAction: /^(kick|ban|mute)$/i.test(env.TRACABOT_JOIN_CHALLENGE_ACTION || '') ? env.TRACABOT_JOIN_CHALLENGE_ACTION.toLowerCase() : 'kick',
    joinChallengeDeleteOnPass: parseBoolean(env.TRACABOT_JOIN_CHALLENGE_DELETE_ON_PASS, true),
    joinChallengeDeleteBadAttempts: parseBoolean(env.TRACABOT_JOIN_CHALLENGE_DELETE_BAD_ATTEMPTS, true),
    joinChallengeDkgValidate: parseBoolean(env.TRACABOT_JOIN_CHALLENGE_DKG_VALIDATE, true),
    joinAutoRemove,
    joinAutoRemoveChats,
    joinEvidenceMaxAgeDays,
    joinMinConfirmedRoots,
    joinTrustedLayers,
    joinTrustedSources,
    submitSharedEvidence,
    creatorSubmitUrl,
    creatorSubmitToken,
    creatorCuratorUrl,
    creatorCuratorPublicKey,
    creatorCuratorPrivateKey,
    creatorCuratorToken,
    creatorCuratorReadToken,
    creatorCuratorIssuer,
    creatorCuratorMinConfidence,
    creatorCuratorMinRoots,
    creatorCuratorMaxAgeDays,
    creatorCuratorTimeoutMs,
    creatorCuratorStorePath,
    creatorCuratorReadRateLimitPerHour,
    creatorCuratorWriteRateLimitPerHour,
    appealMaxPerHour,
    appealDedupHours,
    appealMaxReasonChars,
    autoDeleteBotMessages: parseBoolean(env.TRACABOT_AUTO_DELETE_BOT_MESSAGES, true),
    botMessageTtlSeconds,
    challengeMessageTtlSeconds,
    successMessageTtlSeconds,
    channelMemory: parseBoolean(env.TRACABOT_CHANNEL_MEMORY, true),
    channelMemoryMinConfidence,
    channelMemoryMaxTextChars,
    banContext: parseBoolean(env.TRACABOT_BAN_CONTEXT, true),
    banContextMaxMessages,
    banContextMaxAgeMinutes,
    banContextMaxTextChars,
    wmArtifacts: parseBoolean(env.TRACABOT_WM_ARTIFACTS, true),
    wmArtifactShareLowConfidence: parseBoolean(env.TRACABOT_WM_ARTIFACT_SHARE_LOW_CONFIDENCE, false),
    wmArtifactRedact: parseBoolean(env.TRACABOT_WM_ARTIFACT_REDACT, true),
    wmArtifactMinConfidence,
    wmArtifactMaxTextChars,
    pendingReviewNotifications: parseBoolean(env.TRACABOT_PENDING_REVIEW_NOTIFICATIONS, true),
    pendingReviewNotificationIntervalHours,
    dailySafeTipIntervalHours: Number(env.TRACABOT_DAILY_SAFE_TIP_INTERVAL_HOURS ?? 0),
    artefactReviewThreshold: Number(env.TRACABOT_ARTEFACT_REVIEW_THRESHOLD || 70),
    proactiveAlertCrossGroup: parseBoolean(env.TRACABOT_PROACTIVE_ALERT_CROSS_GROUP, true),
    skillAllowUnauthenticatedWrites: parseBoolean(env.TRACABOT_SKILL_ALLOW_UNAUTHENTICATED_WRITES, false),
    evidenceHighConfidenceThreshold,
    evidenceLocalConfidenceThreshold,
    evidenceMinIndependentSignals,
    evidenceMinIndependentCommunities,
    evidencePromotionThreshold,
    autoPromoteEvidence: parseBoolean(env.TRACABOT_AUTO_PROMOTE_EVIDENCE, true),
    autoPromoteIntervalMs,
    publicHost: env.TRACABOT_PUBLIC_HOST || '127.0.0.1',
    publicPort,
    publicBaseUrl: env.TRACABOT_PUBLIC_BASE_URL || '',
    publicReadDkg: parseBoolean(env.TRACABOT_PUBLIC_READ_DKG, true),
    publicRateLimitPerHour,
    publicJoinRateLimitPerHour,
    publicMaxBodyBytes,
    communityTokens
  };
}

export function validateDkgPseudonymKey(config = {}) {
  if (config.dkgWrites && Buffer.byteLength(config.dkgPseudonymKey || '', 'utf8') < 32) {
    throw new Error('TRACABOT_DKG_PSEUDONYM_KEY must be at least 32 bytes when DKG writes are enabled');
  }
}

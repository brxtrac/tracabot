import { existsSync, readFileSync } from 'node:fs';
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
  const joinChallengeMode = /^(qa|ual)$/i.test(env.TRACABOT_JOIN_CHALLENGE_MODE || '') ? env.TRACABOT_JOIN_CHALLENGE_MODE.toLowerCase() : 'qa';
  const joinChallengeQaBank = parseChallengeBank(env.TRACABOT_JOIN_CHALLENGE_QA_BANK || '');
  const dkgMode = env.TRACABOT_DKG_MODE || 'openclaw-adapter';
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
  return {
    telegramToken: env.TELEGRAM_BOT_TOKEN || '',
    adminIds,
    autoDelete: parseBoolean(env.TRACABOT_AUTO_DELETE, true),
    autoRestrict: parseBoolean(env.TRACABOT_AUTO_RESTRICT, true),
    autoBan: parseBoolean(env.TRACABOT_AUTO_BAN, true),
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
    policyId: env.TRACABOT_POLICY_ID || 'default',
    dkgMode,
    dkgNodeUrl: env.DKG_NODE_URL || 'http://127.0.0.1:9200',
    dkgAuthToken: env.DKG_AUTH_TOKEN || readLocalDkgToken(),
    openClawDkgAdapterPath: env.OPENCLAW_DKG_ADAPTER_PATH || '',
    storePath: env.TRACABOT_STORE_PATH || './data/tracabot-events.jsonl',
    agentDid: env.TRACABOT_AGENT_DID || 'did:dkg:agent:tracabot',
    testMode: parseBoolean(env.TRACABOT_TEST_MODE, false),
    openClawWorkspace: env.OPENCLAW_WORKSPACE || resolve(homedir(), '.openclaw', 'workspace'),
    conversational: parseBoolean(env.TRACABOT_CONVERSATIONAL, true),
    llmProvider: env.TRACABOT_LLM_PROVIDER || 'auto',
    llmBaseUrl: env.TRACABOT_LLM_BASE_URL || '',
    llmApiKey: env.TRACABOT_LLM_API_KEY || '',
    llmModel: env.TRACABOT_LLM_MODEL || '',
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
    autoDeleteBotMessages: parseBoolean(env.TRACABOT_AUTO_DELETE_BOT_MESSAGES, true),
    botMessageTtlSeconds,
    challengeMessageTtlSeconds,
    successMessageTtlSeconds,
    channelMemory: parseBoolean(env.TRACABOT_CHANNEL_MEMORY, true),
    channelMemoryMinConfidence,
    channelMemoryMaxTextChars,
    wmArtifacts: parseBoolean(env.TRACABOT_WM_ARTIFACTS, true),
    wmArtifactShareLowConfidence: parseBoolean(env.TRACABOT_WM_ARTIFACT_SHARE_LOW_CONFIDENCE, false),
    wmArtifactRedact: parseBoolean(env.TRACABOT_WM_ARTIFACT_REDACT, true),
    wmArtifactMinConfidence,
    wmArtifactMaxTextChars,
    dailySafeTipIntervalHours: Number(env.TRACABOT_DAILY_SAFE_TIP_INTERVAL_HOURS ?? 0),
    artefactReviewThreshold: Number(env.TRACABOT_ARTEFACT_REVIEW_THRESHOLD || 70),
    proactiveAlertCrossGroup: parseBoolean(env.TRACABOT_PROACTIVE_ALERT_CROSS_GROUP, true)
  };
}

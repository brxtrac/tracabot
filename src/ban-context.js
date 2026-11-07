import { analyzeMessage } from './scam-analyzer.js';
import { canonicalizeMessageText } from './message-patterns.js';
import { extractDomains, extractPatterns, extractWallets } from './dkg-client.js';

export const BAN_CONTEXT_VERSION = 'tracabot-ban-context-v1';
export const BAN_CONTEXT_LIMITS = Object.freeze({
  maxMessages: 8,
  maxAgeMs: 60 * 60 * 1000,
  maxTextChars: 1000
});

const THREAT_RE = /\b(?:kill|murder|shoot|shooting|stab|bomb|rape|arson|dox(?:x)?|swat|death threat|beat you|hurt you|acid attack)\b/i;
const HARASSMENT_RE = /\b(?:idiot|stupid|moron|imbecile|loser|scum|worthless|shut up|clown|bastard)\b/i;
const SPAM_RE = /\b(?:buy now|limited time|promo(?:tion)?|discount code|subscribe|join (?:my|our|this) (?:channel|group)|dm me|check my (?:channel|profile)|casino|betting|bet now|free spins|referral code|earn money|work from home)\b/i;
const LINK_RE = /\b(?:https?:\/\/\S+|t\.me\/\S+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)/gi;

function bounded(value = '', max = BAN_CONTEXT_LIMITS.maxTextChars) {
  return String(value || '').slice(0, max);
}

function messageTextOf(message = {}) {
  return [message.text, message.caption].filter(Boolean).join('\n').trim();
}

function indicatorSet(messages = []) {
  const text = messages.map(messageTextOf).join('\n');
  return {
    domains: [...new Set(extractDomains(text))].slice(0, 10),
    wallets: [...new Set(extractWallets(text))].slice(0, 10),
    patterns: [...new Set(extractPatterns(text))].slice(0, 10)
  };
}

function classifyText(text = '') {
  const normalized = canonicalizeMessageText(text);
  if (!normalized) return { category: 'unknown', severity: 'unknown', confidence: 0, behavior_flags: [] };
  const threat = THREAT_RE.test(normalized);
  const harassment = !threat && HARASSMENT_RE.test(normalized);
  const behaviorFlags = [...(threat ? ['threat'] : []), ...(harassment ? ['harassment'] : [])];
  const links = normalized.match(LINK_RE) || [];
  const spam = links.length >= 2 || SPAM_RE.test(normalized);
  const analysis = analyzeMessage({ text: normalized });
  if (analysis.is_scam && Number(analysis.confidence || 0) >= 60) {
    return { category: 'suspected_scam', severity: 'high', confidence: Math.min(90, Number(analysis.confidence || 0)), behavior_flags: behaviorFlags };
  }
  if (threat) return { category: 'behavior', severity: 'high', confidence: 70, behavior_flags: behaviorFlags };
  if (harassment) return { category: 'behavior', severity: 'medium', confidence: 50, behavior_flags: behaviorFlags };
  if (spam) return { category: 'spam', severity: 'medium', confidence: 60, behavior_flags: behaviorFlags };
  return { category: 'unknown', severity: 'low', confidence: 0, behavior_flags: behaviorFlags };
}

function repeatedSignal(messages = [], kinds = []) {
  for (const kind of kinds) {
    const seen = new Map();
    for (const message of messages) {
      for (const value of indicatorSet([message])[kind]) {
        seen.set(value, (seen.get(value) || 0) + 1);
      }
    }
    if ([...seen.values()].some((count) => count >= 2)) return true;
  }
  return false;
}

function duplicateText(messages = []) {
  const seen = new Set();
  for (const message of messages) {
    const text = canonicalizeMessageText(messageTextOf(message)).toLowerCase();
    if (text.length < 20) continue;
    if (seen.has(text)) return true;
    seen.add(text);
  }
  return false;
}

export function emptyBanContext({ reason = 'no_observed_messages', limits = BAN_CONTEXT_LIMITS } = {}) {
  return {
    version: BAN_CONTEXT_VERSION,
    provenance: 'recent_pre_ban_context',
    causal_link: 'unverified',
    label: 'recent pre-ban context; causal link unverified',
    disclaimer: 'Messages the bot observed before the ban. They are not proof of the ban reason.',
    category: 'unknown',
    severity: 'unknown',
    confidence: 0,
    confirmed_scam: false,
    evidence_based_suspicion: false,
    behavior_flags: [],
    observed_message_count: 0,
    text_message_count: 0,
    media_only_count: 0,
    media_only: false,
    partial: false,
    reason,
    window: {
      max_messages: limits.maxMessages,
      max_age_seconds: Math.round(limits.maxAgeMs / 1000)
    },
    indicators: { domains: [], wallets: [], patterns: [] },
    messages: []
  };
}

export function analyzeBanContext(messages = [], { limits = BAN_CONTEXT_LIMITS, reason = '' } = {}) {
  const boundedMessages = messages
    .filter((message) => message && message.message_id)
    .slice(0, limits.maxMessages)
    .map((message) => {
      const text = bounded(message.text, limits.maxTextChars);
      const caption = bounded(message.caption, limits.maxTextChars);
      const classification = classifyText(messageTextOf({ text, caption }));
      return {
        message_id: Number(message.message_id),
        date: message.message_date ? new Date(Number(message.message_date) * 1000).toISOString() : '',
        text,
        caption,
        has_media: message.has_media === true || Number(message.has_media) === 1,
        category: classification.category,
        severity: classification.severity,
        confidence: classification.confidence,
        behavior_flags: classification.behavior_flags
      };
    });
  const result = emptyBanContext({ limits });
  result.observed_message_count = boundedMessages.length;
  result.text_message_count = boundedMessages.filter((message) => messageTextOf(message)).length;
  result.media_only_count = boundedMessages.filter((message) => !messageTextOf(message) && message.has_media).length;
  result.media_only = result.observed_message_count > 0 && result.text_message_count === 0;
  result.partial = result.media_only || result.media_only_count > 0;
  result.messages = boundedMessages;
  result.indicators = indicatorSet(boundedMessages);
  result.behavior_flags = [...new Set(boundedMessages.flatMap((message) => message.behavior_flags || []))].sort();

  if (!boundedMessages.length) {
    result.reason = reason || 'no_observed_messages';
    return result;
  }

  const classifications = boundedMessages.filter((message) => messageTextOf(message));
  if (!classifications.length) {
    result.reason = 'observed_media_only';
    return result;
  }

  const suspicious = classifications.filter((message) => message.category === 'suspected_scam');
  const behavior = classifications.filter((message) => message.category === 'behavior');
  const spam = classifications.filter((message) => message.category === 'spam');
  const campaignSignal = suspicious.length >= 2
    && (repeatedSignal(suspicious, ['domains', 'wallets']) || duplicateText(suspicious));
  if (campaignSignal) {
    result.category = 'suspected_campaign';
  } else if (suspicious.length) {
    result.category = 'suspected_scam';
  } else if (spam.length) {
    result.category = 'spam';
  } else if (behavior.length) {
    result.category = 'behavior';
  } else {
    result.category = 'unknown';
    result.reason = 'observed_text_no_known_signal';
    return result;
  }

  result.severity = behavior.some((message) => message.severity === 'high')
    ? 'high'
    : result.category === 'suspected_campaign' || result.category === 'suspected_scam'
      ? 'high'
      : 'medium';
  result.confidence = Math.max(...classifications.map((message) => message.confidence));
  result.evidence_based_suspicion = true;
  result.reason = 'observed_recent_messages';
  return result;
}

import { displayName } from './risk-engine.js';
import { safetyCloser, safetyStyleInstruction } from './reply-style.js';

const SAFETY_TERMS = /\b(scam|scammer|scamming|fraud|fraudster|phish|phishing|drain|drainer|wallet|seed phrase|private key|airdrop|giveaway|safe|unsafe|dangerous|suspicious|sus|risk|risky|trusted|trust|trustworthy|legit|legitimate|real|fake|blacklisted|flagged|known|malicious|impersonat|support|admin|dm)\b/i;
const ASK_TERMS = /\b(is this|am i|are they|is he|is she|is it|can i|should i|trust|trust this|trusted|trustworthy|safe|unsafe|legit|legitimate|real|fake|scam|scammer|scammed|blacklisted|flagged|fraud|fraudster|suspicious|sus|dangerous|malicious|risk|risky)\b/i;
const FORBIDDEN = /\b(seed phrase|private key)\b.*\b(send|share|paste|enter|provide)\b/i;

export function isSafetyQuestion(message = {}) {
  const text = String(message.text || '');
  const replyText = String(message.reply_to_message?.text || '');
  const mentionsBot = /@tracabot\b|@tracethembot\b/i.test(text);
  const compact = text.replace(/@(?:tracabot|tracethembot)\b/ig, ' ').replace(/\s+/g, ' ').trim();
  const hasQuestion = ASK_TERMS.test(compact) || /\?/.test(text);
  return (mentionsBot || Boolean(message.reply_to_message)) && SAFETY_TERMS.test(`${compact}\n${replyText}`) && hasQuestion;
}

export function shouldConversationallyReply({ message = {}, risk = {}, explicit = false, config = {} }) {
  if (config.conversational === false) return false;
  const confidence = Number(risk.confidence || 0);
  const threshold = Number(config.proactiveReplyThreshold ?? 75);
  if (explicit) return confidence >= threshold;
  if (!SAFETY_TERMS.test(message.text || '')) return false;
  const actionable = ['warn', 'restrict', 'ban'].includes(String(risk.recommended_action || '').toLowerCase());
  const strongEvidence = (risk.evidence?.length || 0) > 0 || (risk.dkg_evidence?.length || 0) > 0;
  return confidence >= threshold && actionable && strongEvidence;
}

export function buildSafetyPrompt({ message = {}, target = {}, risk = {}, event = {}, maxChars = 700 }) {
  const evidence = (risk.evidence || []).slice(0, 8).join('\n- ');
  const dkg = (risk.dkg_evidence || []).slice(0, 4).map((item) => `${item.ual || 'DKG'}${item.eventId ? ` event ${item.eventId}` : ''}`).join('\n- ');
  const system = [
    'You are TRACaBot, a Telegram anti-scam safety agent.',
    'Only answer questions about scam, fraud, phishing, wallet safety, impersonation, or the evidence supplied.',
    'Use only the supplied risk data. Do not invent DKG evidence or claim certainty beyond the confidence score.',
    'Never tell users to share seed phrases, private keys, passwords, or click suspicious links.',
    'Do not execute or suggest bypassing admin-only moderation commands.',
    safetyStyleInstruction(maxChars)
  ].join('\n');
  const user = [
    `Telegram question/message: ${String(message.text || '').slice(0, 1000)}`,
    `Replied message: ${String(message.reply_to_message?.text || '').slice(0, 1000)}`,
    `Target: ${displayName(target)}`,
    `Confidence: ${risk.confidence || 0}% (local ${risk.local_confidence || 0}%, DKG ${risk.dkg_confidence || 0}%)`,
    `Type: ${risk.scam_type || 'unknown'}`,
    `Recommendation: ${risk.recommended_action || 'ignore'}`,
    `Event: ${event.id || ''}`,
    `Evidence:\n- ${evidence || 'No strong evidence.'}`,
    `DKG sources:\n- ${dkg || 'No DKG source refs.'}`
  ].join('\n');
  return { system, user };
}

export function fallbackSafetyReply({ target = {}, risk = {}, event = {} }) {
  const name = displayName(target);
  const evidence = publicEvidence(risk).join('; ') || 'no strong public scam signal';
  const closer = safetyCloser({ target, risk, seed: event.id || evidence });
  if (Number(risk.confidence || 0) >= 80) {
    return `TRACaBot warning: ${name} looks high risk (${risk.confidence}%). Public signals: ${evidence}. ${closer}`;
  }
  if (Number(risk.confidence || 0) >= 60) {
    return `TRACaBot caution: ${name} needs review (${risk.confidence}%). Public signals: ${evidence}. ${closer}`;
  }
  return `TRACaBot check: I do not see strong scam evidence for ${name} (${risk.confidence || 0}%). ${closer}`;
}

export function publicEvidence(risk = {}) {
  return (risk.evidence || [])
    .filter((item) => !/\b(DKG|UAL|Context Graph|Shared Memory|event\s+[a-f0-9-]{8,}|Active watchlist|admin watch|configured admin)\b/i.test(String(item)))
    .map((item) => String(item).replace(/:\s*[a-f0-9-]{8,}/ig, '').slice(0, 140))
    .filter(Boolean)
    .slice(0, 3);
}

export function sanitizeSafetyReply(reply = '', { risk = {}, maxChars = 700, fallback = '' } = {}) {
  const text = String(reply || '').replace(/\s+/g, ' ').trim();
  if (!text || !SAFETY_TERMS.test(text) || FORBIDDEN.test(text)) return fallback;
  const cautious = Number(risk.confidence || 0) < 80
    ? text.replace(/\b(definitely|certainly|confirmed scammer|guaranteed scam)\b/gi, 'possibly')
    : text;
  return cautious.slice(0, maxChars).trim() || fallback;
}

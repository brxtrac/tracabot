import { displayName } from './risk-engine.js';

const SAFETY_TERMS = /\b(scam|scammer|fraud|fraudster|phish|phishing|drain|wallet|seed phrase|private key|airdrop|giveaway|safe|risk|trustworthy|blacklisted|impersonat|support|admin|dm)\b/i;
const ASK_TERMS = /\b(is this|am i|are they|is he|is she|is it|trust|trustworthy|safe|scam|scammed|blacklisted|fraud|risk)\b/i;
const FORBIDDEN = /\b(seed phrase|private key)\b.*\b(send|share|paste|enter|provide)\b/i;

export function isSafetyQuestion(message = {}) {
  const text = String(message.text || '');
  const replyText = String(message.reply_to_message?.text || '');
  const mentionsBot = /@tracabot\b|@tracethembot\b/i.test(text);
  return (mentionsBot || Boolean(message.reply_to_message)) && SAFETY_TERMS.test(`${text}\n${replyText}`) && ASK_TERMS.test(text);
}

export function shouldConversationallyReply({ message = {}, risk = {}, explicit = false, config = {} }) {
  if (config.conversational === false) return false;
  if (explicit) return true;
  if (!SAFETY_TERMS.test(message.text || '')) return false;
  return Number(risk.confidence || 0) >= Number(config.proactiveReplyThreshold ?? 75);
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
    `Keep the reply under ${maxChars} characters. Be clear, calm, and practical.`
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
  const evidence = (risk.evidence || []).slice(0, 3).join('; ') || 'no strong local or DKG evidence';
  if (Number(risk.confidence || 0) >= 80) {
    return `TRACaBot warning: ${name} looks high risk (${risk.confidence}%). Evidence: ${evidence}. Do not click links, DM fake support, or share wallet secrets. Event: ${event.id || 'local'}`;
  }
  if (Number(risk.confidence || 0) >= 60) {
    return `TRACaBot caution: ${name} needs review (${risk.confidence}%). Evidence: ${evidence}. Avoid links or wallet requests until an admin checks it. Event: ${event.id || 'local'}`;
  }
  return `TRACaBot check: I do not see strong scam evidence for ${name} (${risk.confidence || 0}%). Still avoid sharing seed phrases, private keys, or connecting wallets from chat links. Event: ${event.id || 'local'}`;
}

export function sanitizeSafetyReply(reply = '', { risk = {}, maxChars = 700, fallback = '' } = {}) {
  const text = String(reply || '').replace(/\s+/g, ' ').trim();
  if (!text || !SAFETY_TERMS.test(text) || FORBIDDEN.test(text)) return fallback;
  const cautious = Number(risk.confidence || 0) < 80
    ? text.replace(/\b(definitely|certainly|confirmed scammer|guaranteed scam)\b/gi, 'possibly')
    : text;
  return cautious.slice(0, maxChars).trim() || fallback;
}

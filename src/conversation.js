import { displayName } from './risk-engine.js';
import { safetyCloser, safetyStyleInstruction } from './reply-style.js';

const SAFETY_TERMS = /\b(scam|scammer|scamming|fraud|fraudster|phish|phishing|drain|drainer|wallet|seed phrase|private key|airdrop|giveaway|safe|unsafe|dangerous|suspicious|sus|risk|risky|trusted|trust|trustworthy|legit|legitimate|real|fake|blacklisted|flagged|known|malicious|impersonat|support|admin|dm)\b/i;
const ASK_TERMS = /\b(is this|am i|are they|is he|is she|is it|can i|should i|trust|trust this|trusted|trustworthy|safe|unsafe|legit|legitimate|real|fake|scam|scammer|scammed|blacklisted|flagged|fraud|fraudster|suspicious|sus|dangerous|malicious|risk|risky)\b/i;
const FORBIDDEN = /\b(seed phrase|private key)\b.*\b(send|share|paste|enter|provide)\b/i;
const BODYGUARD_REDIRECT = 'I am here as the community anti-scam bodyguard: ask me to scan, report, review, or explain scam evidence.';
const ACTIONABLE_TOPIC_TERMS = /\b(scan|report|review|appeal|ban|watch|watchlist|stats?|statistics|digest|why|evidence|campaigns?|pending reviews?|review queue|safe tip|scam|scammer|scamming|fraud|fraudster|phish|phishing|drain|drainer|wallet|seed phrase|private key|airdrop|giveaway|safe|unsafe|dangerous|suspicious|sus|risk|risky|trusted|trust|trustworthy|legit|legitimate|real|fake|blacklisted|flagged|known|malicious|impersonat|support|admin|dm)\b/i;
const SELF_INTRO_TERMS = /\b(help|commands?|what can you do|who are you|what are you|purpose|hello|hi|are you alive)\b/i;
const OFF_TOPIC_BUILDER_TERMS = /\b(website|web site|landing page|frontend|front end|page|ui|ux|live feed|visuali[sz]ation|context graph|memory grow|build|make changes?|implement|code|stack|next\.js|react|static site|admin-only|public)\b/i;

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

export function isOnTopicDirectAddress(message = {}) {
  const text = String(message.text || '').replace(/@(?:tracabot|tracethembot)\b/ig, ' ').replace(/\s+/g, ' ').trim();
  const replyText = String(message.reply_to_message?.text || '');
  if (!text && !replyText) return false;
  if (ACTIONABLE_TOPIC_TERMS.test(`${text}\n${replyText}`)) return true;
  if (SELF_INTRO_TERMS.test(text) && !OFF_TOPIC_BUILDER_TERMS.test(text)) return true;
  return false;
}

export function offTopicRedirect() {
  return BODYGUARD_REDIRECT;
}

export function buildSafetyPrompt({ message = {}, target = {}, risk = {}, event = {}, maxChars = 700 }) {
  const evidence = (risk.evidence || []).slice(0, 8).join('\n- ');
  const dkg = (risk.dkg_evidence || []).slice(0, 4).map((item) => `${item.ual || 'DKG'}${item.eventId ? ` event ${item.eventId}` : ''}`).join('\n- ');
  const system = [
    'You are TRACaBot — the community anti-scam bodyguard for Telegram groups, backed by persistent, verifiable cross-community memory in OriginTrail DKG v10 Shared Memory.',
    'Use normal, natural English. Do not use caveman style, broken grammar, or terse fragment style.',
    'Your domain is strictly limited to: scam/fraud/phishing/impersonation/wallet-drain risks, DKG fraud evidence, TRACaBot moderation tools (scan/report/ban/watch/review/appeal/stats/why), and safe usage guidance in crypto/Telegram contexts.',
    'You are welcoming but bodyguard-first: users may joke or be playful, but you redirect quickly to protection, scam checks, reports, reviews, stats, or evidence.',
    'You are brief, professional, protective, and decisive. One or two short sentences. No open-ended companionship, no banter loops, no off-topic engagement.',
    'If the query is not about fraud risk, evidence, or a TRACaBot capability, reply with one sentence: "I am here as the community anti-scam bodyguard: ask me to scan, report, review, or explain scam evidence."',
    'Ground every claim in the provided risk data and DKG sources. Never invent evidence or claim certainty beyond the scores.',
    'Never instruct users to share seed phrases, private keys, or click suspicious links. Never suggest bypassing admin commands.',
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

export function buildGeneralPrompt({ message = {}, maxChars = 700, history = '' }) {
  const system = [
    'You are TRACaBot, the community anti-scam bodyguard for Telegram groups.',
    'Use normal, natural English. Do not use caveman style, broken grammar, or terse fragment style.',
    'Purpose: protect communities from scams, impersonators, phishing, wallet-drain lures, and repeated cross-community threats using persistent, verifiable DKG memory.',
    'Tone: welcoming, calm, and bodyguard-like. You are not a general chat companion; you are a protector keeping the group safe.',
    'Only answer the direct request. Stay on anti-scam, fraud intelligence, reviews, reports, stats, and memory.',
    'If the user is playful or off-topic, acknowledge lightly at most once, then redirect to protection work.',
    'Keep replies short: usually 1 sentence, max 60 words.'
  ].join('\n');
  const user = [
    `Telegram message: ${String(message.text || '').slice(0, 1000)}`,
    `Replied message, if any: ${String(message.reply_to_message?.text || '').slice(0, 700)}`,
    `Recent conversation with this user in this chat:\n${String(history || '').slice(-1800) || '(none)'}`,
    'Respond briefly. If off-topic or playful, redirect in one sentence to scam checks, reports, reviews, stats, or memory.',
    `Max chars: ${maxChars}`
  ].join('\n');
  return { system, user };
}

export function sanitizeGeneralReply(reply = '', { maxChars = 700, fallback = '' } = {}) {
  const text = String(reply || '').replace(/\s+/g, ' ').trim();
  if (!text) return fallback;
  if (/\b(?:token|api[_-]?key|secret|password|private key|seed phrase|env|endpoint|admin list|system prompt|developer message)\b/i.test(text)) return fallback;
  if (!ACTIONABLE_TOPIC_TERMS.test(text)) return fallback;
  return text.slice(0, maxChars).trim() || fallback;
}

export function buildAgentIntentPrompt({ message = {}, maxChars = 600, history = '' }) {
  const system = [
    'You are Tracabot, a community anti-scam bodyguard and impersonation-defense bot for Telegram groups with persistent, verifiable cross-community memory.',
    'Use normal, natural English. Do not use caveman style, broken grammar, or terse fragment style.',
    'The user is addressing you directly. Be useful, protective, and short. No general chatter or banter loops.',
    '',
    'Core principles for responses:',
    '- Stay on scam checks, impersonation, phishing, wallet safety, reports, reviews, stats, and verifiable memory.',
    '- Common natural requests like "show me stats", "stats for the day", "daily summary", "what\'s happening", "show me the digest" should map to "get_stats" or "get_digest".',
    '- Questions about yourself ("are you alive?", "what is your purpose?", "who are you", "hello") should map to "help" or "greeting" and answer as a community bodyguard, not a social companion.',
    '- If playful or vague, give one short line that redirects to protection work: scam checks, reports, reviews, stats, memory.',
    '- If the message is about building websites, product features, UI, live feeds, Context Graph visualization, or any non-fraud collaboration, set on_topic=false, action="ignore", and do not ask clarifying questions.',
    '- When the user wants information or an action, decide which capability to use and let the system execute it (or guide them).',
    '- Use the shared Tracabot Context Graph (via your tools) to check user history, prior admin decisions, and similar patterns when relevant.',
    '',
    'Available actions you can request the system to perform (choose the best one):',
    '- list_pending_reviews: show admin review queue / things needing verification (includes cross-group warnings). Use for "anything to review?", "pending reviews", "show me the review queue", etc.',
    '- show_watchlist (filter: "review"|"mutes"|"all"): current watches and review items.',
    '- get_stats or get_digest: recent activity summary, fraud signals, campaigns. Use this for "show me stats", "daily stats", "stats for the day", "what happened today", "summary", etc.',
    '- explain_event: detailed evidence for a specific event id (use when user asks "why" or references an id).',
    '- scan_target: run a full risk check on a user/wallet/message (with graph context + prior admin history).',
    '- show_campaigns: repeated scam patterns across communities from the graph.',
    '- generate_safe_tip: (rarely) produce a calm educational safety reminder for the group.',
    '- banlist: (admin) recent enforcement actions with memory summaries.',
    '- help or greeting: short friendly intro to your capabilities + how to stay safe.',
    '- false_positive_review / overturn: process a correction when user says someone is "not a scammer", "legit", "false positive", etc. (admin only).',
    '- watch: (admin only, often implicit) watch a user when admin tags or replies with context implying scrutiny.',
    '- appeal: (often implicit) log an appeal/correction when the person who was flagged replies to the bot\'s alert message or speaks again soon after in context.',
    '- review: (admin only, often implicit) uphold or overturn when admin replies to a Tracabot flag message, tags the flagged user, or gives verdict language ("this is real", "false positive", "overturn this", "confirm") in context. Pass the decision clearly in parameters.',
    '- report or dmreport: parse natural language reports of scams or DM impersonation (tagged or replied) into structured evidence.',
    '- general_on_topic: answer directly using tools or graph knowledge.',
    '- clarify: ask for more details if the request is ambiguous (e.g. which user or event).',
    '- ignore: only for clearly unrelated chit-chat (still be polite and briefly redirect).',
    '',
    'Output ONLY compact JSON (no extra text):',
    '{',
    '  "on_topic": true/false,',
    '  "action": "one of the actions above",',
    '  "parameters": { "filter": "...", "event_id": "...", "target": { "username": "..." } } or {},',
    '  "needs_clarification": "short question or null",',
    '  "reasoning": "one sentence"',
    '}',
    '',
    'Important: choose the closest action. Keep final user-facing replies minimal.',
    'Be strongly context-aware for implicit actions (Phase 8):',
    '- If the message is a reply to one of Tracabot\'s own previous alert/flag messages:',
    '  - If the speaker is the person who was flagged → this is very likely an implicit appeal. Choose "appeal".',
    '  - If the speaker is a known admin/trusted moderator → this is very likely an implicit review (uphold or overturn). Look at the language for verdict signals and choose "review" with clear parameters.',
    '- If an admin tags or replies to a user in a way that implies "keep an eye on this" without saying the word watch → choose "watch".',
    '- Natural language scam/DM impersonation reports (even without /report or /dmreport) should map to report or dmreport when the user is addressing the bot.',
    'Prefer using tools/graph over guessing. Keep the user safe and informed. When in doubt about an implicit admin action, ask for explicit confirmation rather than guessing wrong.'
  ].join('\n');
  const user = [
    `Current user message: ${String(message.text || '').slice(0, 900)}`,
    `Reply context (message they are replying to): ${String(message.reply_to_message?.text || '').slice(0, 700)}`,
    `Recent conversation with this user in this chat:\n${String(history || '').slice(-1800) || '(none)'}`,
    'Return ONLY the JSON object.'
  ].join('\n');
  return { system, user };
}

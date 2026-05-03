const LOW_RISK_CLOSERS = [
  '🟢 Low signal. Keep wallet actions outside random chat links.',
  'No red flag in the signals I can see. Treat surprise DMs carefully.',
  'Looks quiet from public evidence. Do not rush wallet approvals.',
  'Nothing strong surfaced. Verify links through official channels.',
  'Low evidence for now. Be careful with anyone asking you to move funds.',
  'No strong hit. If they DM you first, slow down and verify.',
  'Signals look clean enough. Still avoid signing unknown transactions.',
  'I do not see a solid scam pattern. Keep seed phrases offline.',
  'Low risk on current evidence. Ignore pressure tactics and urgent links.',
  'Nothing decisive here. Use official sites, not links dropped in chat.',
  'Public signals are calm. Be suspicious of private support offers.',
  'No strong scam match. Never paste recovery words anywhere.',
  'Looks low risk. Double-check usernames before trusting DMs.',
  'No clear issue found. Avoid wallet connects from unsolicited messages.',
  'Current evidence is light. Ask an admin if money or keys are involved.',
  'Low signal. Do not approve transactions you did not initiate.',
  'No strong warning from me. Keep funds and recovery info separate from chat.',
  'Looks okay on available signals. Beware copycat accounts.',
  'Nothing strong detected. Pause if anyone creates urgency around your wallet.',
  'Low-risk read. Confirm links manually before clicking.',
  'No solid public evidence. Keep private keys private, always.',
  'Signals do not look bad right now. Treat new DMs as untrusted by default.'
];

const REVIEW_CLOSERS = [
  '⚠️ Hold off on wallet actions until an admin checks it.',
  'Worth a human review before trusting links or DMs.',
  'Do not connect a wallet here until the account is verified.',
  'Pause and verify through official channels first.',
  'If money, keys, or approvals are involved, wait for admin review.',
  'Keep this in review mode and avoid private support offers.',
  'Ask for confirmation from a known admin before engaging.',
  'Treat links and wallet prompts as unsafe until cleared.',
  'Do not act on urgency. Let an admin inspect the context.',
  'Good candidate for manual review before anyone clicks.'
];

const HIGH_RISK_CLOSERS = [
  '🚨 Do not click, DM, or connect a wallet.',
  'Block contact and avoid any wallet interaction.',
  'Treat links and private messages from this account as unsafe.',
  'Do not share secrets or approve transactions.',
  'Admins should review and remove if the context matches.',
  'Avoid engagement; this pattern is not safe.',
  'Do not follow instructions from this account.',
  'Keep wallets disconnected and report any DM follow-up.',
  'Assume wallet-drain risk until proven otherwise.',
  'No wallet signatures, no recovery words, no private DMs.'
];

function stableIndex(seed = '', length = 1) {
  let hash = 2166136261;
  for (const char of String(seed)) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return Math.abs(hash) % length;
}

export function safetyCloser({ target = {}, risk = {}, seed = '' } = {}) {
  const confidence = Number(risk.confidence || 0);
  const pool = confidence >= 80 ? HIGH_RISK_CLOSERS : confidence >= 60 ? REVIEW_CLOSERS : LOW_RISK_CLOSERS;
  const identity = [target.id, target.username, target.label, risk.confidence, risk.scam_type, seed].filter(Boolean).join(':');
  return pool[stableIndex(identity, pool.length)];
}

export function safetyStyleInstruction(maxChars = 700) {
  return [
    `Keep the reply under ${maxChars} characters.`,
    'Be concise, evidence-backed, and conversational.',
    'Vary the final safety note instead of repeating the same seed phrase/private key/link warning every time.',
    'Use at most one small emoji when useful.',
    'Do not expose internal DKG UALs, event IDs, model names, admin IDs, or setup details.'
  ].join(' ');
}

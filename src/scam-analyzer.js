const URGENCY = ['urgent', 'hurry', 'fast', 'last chance', 'limited', 'now', 'expires'];
const CRYPTO_LURES = ['airdrop', 'free usdt', 'giveaway', 'double your', 'seed phrase', 'private key'];
const WALLET_LURE_PATTERNS = [
  /\b(?:verify|validate|sync|connect|link|unlock|restore)\s+(?:your\s+)?wallet\b/i,
  /\bwallet\s+(?:verification|validation|sync|connect|drain(?:er)?)\b/i,
  /\b(?:claim|airdrop|giveaway)\b.*\bwallet\b/i,
  /\bwallet\b.*\b(?:claim|airdrop|giveaway)\b/i,
  /\b(?:seed phrase|private key|recovery phrase)\b/i
];
const IMPERSONATION = ['admin', 'support', 'moderator', 'mod', 'official', 'verify me'];
const LINK_PATTERNS = [/https?:\/\/\S+/i, /\bt\.me\/\S+/i, /\bbit\.ly\/\S+/i, /\bclaim\b.*\blink\b/i];
const INVESTMENT_TESTIMONIAL_PATTERNS = [
  /\bfrom\s+(zero|nothing)\s+to\s+[$€£]?\s?\d[\d,.]*\s?[kKmM]?\s+(profit|earned|income|returns?)\b/i,
  /\b(i\s+)?(joined|started with)\b.*\b(trading|signals?|alpha|investment|forex|crypto)\b.*\b(months?|weeks?|days?)\s+ago\b/i,
  /\bwithin\s+(the\s+past\s+)?\d+\s+(months?|weeks?|days?)\b.*\b(earned|made|profit|returns?)\b/i,
  /\b(earned|made|profit|returns?)\b.*[$€£]\s?\d[\d,.]*\s?[kKmM]?\b/i,
  /\b(thanks to|coach(?:ing)?|mentor|education|strategy|community support|signals?)\b.*\b(profit|earned|trading|investment|returns?)\b/i,
  /\bmr\s+[a-z]+\b.*\b(provides|coach(?:ing)?|strategy|signals?)\b/i
];
const PARTNERSHIP_LURE_PATTERNS = [
  /\b(institutional|strategic|vc|venture capital|investment)\s+(investment\s+)?partnership\b/i,
  /\b(who|whom)\s+can\s+i\s+(discuss|speak|talk|connect)\b.*\b(partnership|collab(?:oration)?|investment|vc|venture capital)\b/i,
  /\b(vc|venture capital|institutional|serious)\s+(partners?|investors?|funds?)\b.*\b(interested|exploring|discuss|partner|partnership|project)\b/i,
  /\b(interested|exploring)\b.*\b(investment|partnership|collab(?:oration)?|vc|venture capital)\b.*\b(project|protocol|community)\b/i,
  /\b(partnership|collab(?:oration)?|listing|marketing)\s+(proposal|offer|opportunity)\b/i
];
const DM_HELP_PATTERNS = [
  /\b(dm|pm|message|inbox)\s+(me|us|support|admin|moderator|mod)\b/i,
  /\b(contact|reach out to)\s+(me|support|admin|moderator|mod)\b/i,
  /\bneed\s+help\b.*\b(dm|pm|message|inbox|contact)\b/i,
  /\b(help|support)\b.*\b(dm|pm|message|inbox)\b/i
];

function matchesAny(text, terms) {
  const lower = text.toLowerCase();
  return terms.filter((term) => lower.includes(term));
}

function normalizeHandle(value = '') {
  return String(value).toLowerCase().replace(/^@/, '').replace(/[^a-z0-9]/g, '');
}

function adminImpersonationMatches(user = {}) {
  const handles = [user.username, user.first_name, [user.first_name, user.last_name].filter(Boolean).join(' ')]
    .map(normalizeHandle)
    .filter(Boolean);
  if (!handles.length) return [];
  return (user.adminUsernames || [])
    .map(normalizeHandle)
    .filter((admin) => admin && handles.some((handle) => handle !== admin && (handle.includes(admin) || admin.includes(handle))));
}

export function analyzeMessage({ text = '', user = {}, globalIntel = null }) {
  const evidence = [];
  const urgency = matchesAny(text, URGENCY);
  const lures = matchesAny(text, CRYPTO_LURES);
  const walletLures = WALLET_LURE_PATTERNS.filter((pattern) => pattern.test(text));
  const userIdentityText = `${user.username || ''} ${user.first_name || ''}`;
  const impersonation = matchesAny(text, IMPERSONATION);
  const identityImpersonation = matchesAny(userIdentityText, IMPERSONATION);
  const links = LINK_PATTERNS.filter((pattern) => pattern.test(text));
  const investmentTestimonials = INVESTMENT_TESTIMONIAL_PATTERNS.filter((pattern) => pattern.test(text));
  const partnershipLures = PARTNERSHIP_LURE_PATTERNS.filter((pattern) => pattern.test(text));
  const dmHelp = DM_HELP_PATTERNS.filter((pattern) => pattern.test(text));
  const adminCopycats = adminImpersonationMatches(user);
  const adminRenameCopycat = Boolean(user.adminRenameCopycat);

  let score = 0;
  if (urgency.length) {
    score += 20;
    evidence.push(`Urgency language: ${urgency.slice(0, 3).join(', ')}`);
  }
  if (lures.length || walletLures.length) {
    score += 30;
    evidence.push(`Crypto lure terms: ${[...lures, walletLures.length ? 'wallet verification/claim phrase' : ''].filter(Boolean).slice(0, 3).join(', ')}`);
  }
  if (impersonation.length) {
    score += 25;
    evidence.push(`Impersonation indicators: ${impersonation.slice(0, 3).join(', ')}`);
  }
  if (identityImpersonation.length && (links.length || walletLures.length || lures.length || dmHelp.length)) {
    score += 25;
    evidence.push(`Identity impersonation indicators: ${identityImpersonation.slice(0, 3).join(', ')}`);
  }
  if (links.length) {
    score += 15;
    evidence.push('Suspicious link or claim-link pattern');
  }
  if (investmentTestimonials.length) {
    score += 75;
    evidence.push('Investment-profit testimonial lure');
  }
  if (partnershipLures.length) {
    score += 55;
    evidence.push('Investment/partnership outreach lure');
  }
  if (dmHelp.length) {
    score += 40;
    evidence.push('Suspicious request to move help/support into DMs');
  }
  if (adminCopycats.length) {
    score += 45;
    evidence.push(`Username resembles configured admin: ${adminCopycats.slice(0, 2).join(', ')}`);
  }
  if (adminRenameCopycat) {
    score += 50;
    evidence.push('User changed identity after joining to resemble a configured admin');
  }
  if (globalIntel?.reportsAcrossCommunities > 0) {
    const boost = Math.min(20, globalIntel.reportsAcrossCommunities * 5);
    score += boost;
    evidence.push(`DKG Shared Memory reports for this actor: ${globalIntel.reportsAcrossCommunities}`);
  }

  const confidence = Math.max(0, Math.min(99, score));
  const scamType = investmentTestimonials.length || partnershipLures.length ? 'investment_scam' : impersonation.length || identityImpersonation.length || adminCopycats.length || adminRenameCopycat || dmHelp.length ? 'impersonation' : lures.length || walletLures.length ? 'giveaway' : links.length ? 'phishing' : 'other';
  const isScam = confidence >= 70;
  const recommendedAction = confidence >= 90 ? 'ban' : confidence >= 70 ? 'warn' : 'ignore';

  return {
    is_scam: isScam,
    confidence,
    scam_type: scamType,
    evidence,
    recommended_action: recommendedAction,
    explanation: isScam
      ? `Likely ${scamType} scam based on message content and shared intelligence.`
      : 'No high-confidence scam pattern detected.'
  };
}

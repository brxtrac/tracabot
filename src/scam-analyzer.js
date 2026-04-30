const URGENCY = ['urgent', 'hurry', 'fast', 'last chance', 'limited', 'now', 'expires'];
const CRYPTO_LURES = ['airdrop', 'free usdt', 'giveaway', 'double your', 'claim', 'wallet', 'seed phrase', 'private key'];
const IMPERSONATION = ['admin', 'support', 'moderator', 'mod', 'official', 'verify me'];
const LINK_PATTERNS = [/https?:\/\/\S+/i, /\bt\.me\/\S+/i, /\bbit\.ly\/\S+/i, /\bclaim\b.*\blink\b/i];

function matchesAny(text, terms) {
  const lower = text.toLowerCase();
  return terms.filter((term) => lower.includes(term));
}

export function analyzeMessage({ text = '', user = {}, globalIntel = null }) {
  const evidence = [];
  const urgency = matchesAny(text, URGENCY);
  const lures = matchesAny(text, CRYPTO_LURES);
  const impersonation = matchesAny(`${text} ${user.username || ''} ${user.first_name || ''}`, IMPERSONATION);
  const links = LINK_PATTERNS.filter((pattern) => pattern.test(text));

  let score = 0;
  if (urgency.length) {
    score += 20;
    evidence.push(`Urgency language: ${urgency.slice(0, 3).join(', ')}`);
  }
  if (lures.length) {
    score += 30;
    evidence.push(`Crypto lure terms: ${lures.slice(0, 3).join(', ')}`);
  }
  if (impersonation.length) {
    score += 25;
    evidence.push(`Impersonation indicators: ${impersonation.slice(0, 3).join(', ')}`);
  }
  if (links.length) {
    score += 15;
    evidence.push('Suspicious link or claim-link pattern');
  }
  if (globalIntel?.reportsAcrossCommunities > 0) {
    const boost = Math.min(20, globalIntel.reportsAcrossCommunities * 5);
    score += boost;
    evidence.push(`DKG Shared Memory reports for this actor: ${globalIntel.reportsAcrossCommunities}`);
  }

  const confidence = Math.max(0, Math.min(99, score));
  const scamType = impersonation.length ? 'impersonation' : lures.length ? 'giveaway' : links.length ? 'phishing' : 'other';
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

export function displayName(target) {
  if (!target) return 'this account';
  if (target.label) return target.label;
  if (target.username) return `@${target.username}`;
  const fullName = [target.first_name, target.last_name].filter(Boolean).join(' ').trim();
  if (fullName) return fullName;
  return target.id || 'this account';
}

export function combineRisk({ analysis, dkgIntel, threshold = 85 }) {
  const evidence = [...(analysis.evidence || [])];
  const dkgEvidence = dkgIntel?.evidence || [];
  const dkgScore = dkgIntel?.riskScore || 0;
  if (dkgIntel?.reportsAcrossCommunities) {
    evidence.push(`DKG Context Graph reports: ${dkgIntel.reportsAcrossCommunities}`);
  }
  if (dkgIntel?.wallets?.length) {
    evidence.push(`Wallets checked: ${dkgIntel.wallets.join(', ')}`);
  }
  if (dkgIntel?.patterns?.length) {
    evidence.push(`Scam patterns checked: ${dkgIntel.patterns.join(', ')}`);
  }
  for (const item of dkgEvidence.slice(0, 3)) {
    evidence.push(`DKG evidence: ${item.source || item.s || item.wallet || item.pattern}`);
  }

  const confidence = Math.max(analysis.confidence || 0, dkgScore);
  const highConfidence = confidence >= threshold;
  return {
    is_scam: highConfidence || analysis.is_scam,
    confidence,
    scam_type: analysis.scam_type || 'unknown',
    evidence,
    recommended_action: highConfidence ? 'ban' : analysis.recommended_action,
    dkg_evidence: dkgEvidence,
    wallets: dkgIntel?.wallets || [],
    patterns: dkgIntel?.patterns || [],
    community_verified_flag: highConfidence ? 'candidate-high-confidence' : ''
  };
}

export function formatRiskAssessment({ target, risk }) {
  const name = displayName(target);
  const verdict = risk.confidence >= 85 ? 'HIGH RISK' : risk.confidence >= 60 ? 'REVIEW' : 'LOW RISK';
  const evidence = risk.evidence?.length ? risk.evidence.slice(0, 6).join('; ') : 'No matching DKG evidence or high-confidence pattern found.';
  return `tracabot risk for ${name}: ${verdict} (${risk.confidence}%). Type: ${risk.scam_type}. Evidence: ${evidence}. Recommendation: ${risk.recommended_action}.`;
}

export function formatScanReply({ target, risk, eventId = '', findingId = '' }) {
  const name = displayName(target);
  if (risk.confidence < 60) {
    return `🛡️ ${name} looks clean! DKG scan came back ${risk.confidence}% risk — no strong matches. Safe to chat. Event: ${eventId}`;
  }
  if (risk.confidence >= 80) {
    const evidence = risk.evidence?.slice(0, 3).join('; ') || 'DKG + behavior match';
    return `🚨 HIGH RISK (${risk.confidence}%) on ${name} — ${evidence}. Full evidence logged${findingId ? ` (${findingId})` : ''}. Want me to /ban or /report this?`;
  }
  return `⚠️ ${name} needs a closer look (${risk.confidence}% risk). Evidence is thin but not nothing. Event: ${eventId}`;
}

export function formatReportReply(eventId) {
  return `✅ Reported. I've published the details + evidence to DKG v10 for the whole network to see. Thanks for helping keep the community safe! Event ID: ${eventId}`;
}

export function formatBanReply(target, eventId) {
  const name = displayName(target);
  return `🔨 Banned ${name} + evidence logged to DKG v10 (event ID: ${eventId}). This one won't bother us again.`;
}

export function formatStatsReply(stats) {
  const high = stats.highConfidence || 0;
  if (!stats.total) {
    return '📊 Last 7 days: 0 high-confidence busts, DKG vault staying strong. All quiet on the scam front.';
  }
  return [
    `📊 Last 7 days from DKG: ${high} high-confidence busts, ${stats.total} fraud intel events.`,
    `Event mix: ${JSON.stringify(stats.byEventType || {})}`,
    `Risk mix: ${JSON.stringify(stats.byRiskType || {})}`,
    high ? 'DKG vault has receipts.' : 'All quiet on the scam front.'
  ].join('\n');
}

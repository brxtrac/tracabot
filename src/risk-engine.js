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
    const ref = item.ual ? `UAL ${item.ual}` : 'Shared Memory';
    const event = item.eventId ? ` event ${item.eventId}` : '';
    evidence.push(`DKG evidence: ${ref}${event}`);
  }

  const confidence = Math.max(analysis.confidence || 0, dkgScore);
  const highConfidence = confidence >= threshold;
  return {
    is_scam: highConfidence || analysis.is_scam,
    confidence,
    local_confidence: analysis.confidence || 0,
    dkg_confidence: dkgScore,
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

export function formatDkgReference(event) {
  if (!event) return '';
  if (event.dkg?.ual) {
    const share = event.dkg.shareOperation ? ` share ${event.dkg.shareOperation}` : '';
    return `${event.dkg.ual} event ${event.id}${share}`;
  }
  return event.id || '';
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

export function formatReportReply(event, decision = null) {
  if (decision && decision.decision !== 'accepted') {
    return `⚠️ Report not published to DKG: ${decision.reason}. Add concrete evidence by replying to the suspicious message or include the wallet/link/text that should be checked.`;
  }
  const ref = formatDkgReference(event);
  return `✅ Reported. Evidence published to DKG Shared Memory. UAL: ${ref}`;
}

export function formatBanReply(target, eventId) {
  const name = displayName(target);
  return `🔨 Banned ${name} + evidence logged to DKG v10 (event ID: ${eventId}). This one won't bother us again.`;
}

function labelStatKey(key = '') {
  return String(key)
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatStatList(values = {}, empty = 'None') {
  const entries = Object.entries(values)
    .filter(([, count]) => Number(count) > 0)
    .sort((a, b) => Number(b[1]) - Number(a[1]) || a[0].localeCompare(b[0]));
  if (!entries.length) return empty;
  return entries.map(([key, count]) => `${labelStatKey(key)}: ${count}`).join(', ');
}

export function formatStatsReply(stats) {
  const high = stats.highConfidence || 0;
  const total = stats.total || 0;
  if (!total) {
    return '🛡️ Last 7 days from DKG: LOW RISK. No fraud intel events found. No high-confidence findings, reports, or bans in Shared Memory.';
  }
  const review = Math.max(0, total - high);
  const highRate = Math.round((high / total) * 100);
  const verdict = high >= 10 || highRate >= 50 ? 'HIGH ACTIVITY' : high >= 3 ? 'REVIEW' : 'LOW ACTIVITY';
  const action = high
    ? 'Review recent high-confidence findings and ban evidence before promoting anything to Verified Memory.'
    : 'No high-confidence action needed right now.';
  return [
    `📊 DKG stats for the last 7 days: ${verdict}.`,
    `Signals: ${high} high-confidence / ${total} total fraud intel events (${highRate}%). ${review} review-level or audit events.`,
    `Events: ${formatStatList(stats.byEventType)}`,
    `Risk types: ${formatStatList(stats.byRiskType, 'No risk types recorded')}`,
    `Recommendation: ${action}`
  ].join('\n');
}

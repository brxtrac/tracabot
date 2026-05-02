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
  if (dkgIntel?.domains?.length) {
    evidence.push(`Domains checked: ${dkgIntel.domains.join(', ')}`);
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
    domains: dkgIntel?.domains || [],
    patterns: dkgIntel?.patterns || [],
    community_verified_flag: highConfidence ? 'auto-publish-high-confidence' : ''
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
    return `⚠️ Report not published to DKG: ${decision.reason}. Reply to the suspicious message, mention a recently active suspect, or include the wallet/link/text that should be checked.`;
  }
  const ref = formatDkgReference(event);
  if (event?.dkg?.publish) {
    return `✅ Reported. Evidence written to DKG and auto-published to the Context Graph. UAL: ${ref}`;
  }
  if (event?.dkg?.publish_error) {
    return `✅ Reported. Evidence written to DKG Shared Memory and automatic Context Graph publish was attempted. UAL: ${ref}`;
  }
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

function sortedStats(values = {}) {
  return Object.entries(values)
    .filter(([, count]) => Number(count) > 0)
    .sort((a, b) => Number(b[1]) - Number(a[1]) || a[0].localeCompare(b[0]));
}

function topStat(values = {}, empty = 'no dominant pattern') {
  const [key, count] = sortedStats(values)[0] || [];
  return key ? `${labelStatKey(key)} (${count})` : empty;
}

function countStat(values = {}, key = '') {
  return Number(values[key] || 0);
}

function plural(count, singular, pluralWord = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralWord}`;
}

export function formatStatsReply(stats) {
  const high = stats.highConfidence || 0;
  const total = stats.total || 0;
  const graph = stats.graph || 'tracabot';
  if (!total) {
    return `📊 TRACaBot report (7d): all quiet. DKG graph ${graph} shows 0 production events and 0 high-confidence signals.\nVault is looking solid. Use /stats sources for receipts.`;
  }
  const highRate = Math.round((high / total) * 100);
  const verdict = high >= 10 || highRate >= 50 ? 'hot week' : high >= 3 ? 'active watch' : 'mostly calm';
  const bans = countStat(stats.byEventType, 'ban_executed');
  const reports = countStat(stats.byEventType, 'report_submitted');
  const scans = countStat(stats.byEventType, 'risk_query') + countStat(stats.byEventType, 'risk_check');
  const topRisk = topStat(stats.byRiskType);
  const closing = high
    ? 'DKG vault has receipts. Use /scan on anyone suspicious.'
    : 'No urgent action on my radar. Use /scan if someone feels off.';
  return [
    `📊 TRACaBot report (7d): ${verdict}. ${plural(high, 'high-confidence signal')} from ${plural(total, 'DKG event')} (${highRate}%).`,
    `Top pattern: ${topRisk}. Actions: ${plural(bans, 'ban')}, ${plural(reports, 'report')}, ${plural(scans, 'scan')}.`,
    `${closing} Source: DKG graph ${graph}; /stats sources shows IDs.`
  ].join('\n');
}

export function formatStatsSourcesReply(stats) {
  const graph = stats.graph || 'tracabot';
  const sources = stats.sources || [];
  if (!sources.length) {
    return `🔎 Stats sources: DKG graph ${graph} has no production events in the last 7 days.`;
  }
  const lines = sources.map((source) => {
    const confidence = source.confidence ? ` ${source.confidence}%` : '';
    const created = source.created ? ` - ${source.created.replace(/\.\d{3}Z$/, 'Z')}` : '';
    return `- ${labelStatKey(source.eventType)}${confidence} - ${source.eventId}${created}`;
  });
  return [`🔎 Stats sources from DKG graph ${graph}:`, ...lines].join('\n');
}

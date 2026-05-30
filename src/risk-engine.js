import { safetyCloser } from './reply-style.js';

export function displayName(target) {
  if (!target) return 'this account';
  if (target.label) return target.label;
  if (target.username) return `@${target.username}`;
  const fullName = [target.first_name, target.last_name].filter(Boolean).join(' ').trim();
  if (fullName) return fullName;
  return target.id || 'this account';
}

function publicEvidence(risk = {}) {
  return (risk.evidence || [])
    .filter((item) => !/\b(DKG|UAL|Context Graph|Shared Memory|event\s+[a-f0-9-]{8,}|Active watchlist|admin watch|configured admin)\b/i.test(String(item)))
    .map((item) => String(item).replace(/:\s*[a-f0-9-]{8,}/ig, '').slice(0, 140))
    .filter(Boolean)
    .slice(0, 3);
}

function hasDkgEvidence(dkgIntel = {}) {
  return Boolean(
    Number(dkgIntel.riskScore || 0) > 0
    || Number(dkgIntel.reportsAcrossCommunities || 0) > 0
    || dkgIntel.evidence?.length
  );
}

function hasStrongLocalPattern(analysis = {}) {
  const evidence = (analysis.evidence || []).join('\n');
  if (/changed identity after joining|resembles configured admin|Investment-profit testimonial lure/i.test(evidence)) return true;
  if (/Active watchlist entry/i.test(evidence)) return true;
  if (/Suspicious link or claim-link pattern/i.test(evidence) && /Crypto lure terms|Impersonation indicators|Suspicious request to move help\/support into DMs/i.test(evidence)) return true;
  return false;
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
  for (const item of (dkgIntel?.artifactEvidence || []).slice(0, 2)) {
    const event = item.eventId ? ` event ${item.eventId}` : '';
    evidence.push(`DKG working-memory artifact:${event}`);
  }

  const dkgBacked = hasDkgEvidence(dkgIntel);
  const strongLocalPattern = hasStrongLocalPattern(analysis);
  const localConfidence = analysis.confidence || 0;
  const cappedLocalConfidence = !dkgBacked && !strongLocalPattern && localConfidence >= 60 ? Math.min(localConfidence, 59) : localConfidence;
  const confidence = Math.max(cappedLocalConfidence, dkgScore);
  const highConfidence = confidence >= threshold;
  return {
    is_scam: highConfidence || Boolean((dkgBacked || strongLocalPattern) && analysis.is_scam),
    confidence,
    local_confidence: cappedLocalConfidence,
    raw_local_confidence: localConfidence,
    dkg_confidence: dkgScore,
    scam_type: analysis.scam_type || 'unknown',
    evidence,
    recommended_action: highConfidence ? 'admin_review' : analysis.recommended_action,
    dkg_evidence: dkgEvidence,
    dkg_artifact_evidence: dkgIntel?.artifactEvidence || [],
    wallets: dkgIntel?.wallets || [],
    domains: dkgIntel?.domains || [],
    patterns: dkgIntel?.patterns || [],
    dkg_backed: dkgBacked,
    strong_local_pattern: strongLocalPattern,
    community_verified_flag: highConfidence ? 'auto-publish-high-confidence' : ''
  };
}

export function canAutonomouslyEscalate(risk = {}) {
  return Boolean(risk.dkg_backed || risk.dkg_evidence?.length);
}

export function isObviousLocalScam(risk = {}) {
  return Boolean(
    !canAutonomouslyEscalate(risk)
    && risk.strong_local_pattern
    && Number(risk.confidence || 0) >= 80
    && (risk.evidence?.length || 0) > 0
  );
}

export function formatRiskAssessment({ target, risk }) {
  const name = displayName(target);
  const verdict = risk.confidence >= 85 ? 'HIGH RISK' : risk.confidence >= 60 ? 'REVIEW' : 'LOW RISK';
  const evidence = publicEvidence(risk).join('; ') || 'No strong public scam signal found.';
  return `TRACaBot check for ${name}: ${verdict} (${risk.confidence}%). Type: ${risk.scam_type}. Public signals: ${evidence}. Ask an admin to review. Flagged users can reply directly to the alert with an appeal or correction.`;
}

/**
 * Humble, review-queue specific summary.
 * Never uses absolute "HIGH RISK 100%" framing when we are only queuing for humans
 * (especially when !hasDkgBacking).
 */
export function formatReviewNeededSummary({ target, risk, hasDkgBacking = false }) {
  const name = displayName(target);
  const conf = risk.confidence || 0;
  const type = risk.scam_type || 'suspicious';
  const ev = publicEvidence(risk).join('; ') || 'local signals';

  if (hasDkgBacking) {
    return `TRACaBot flagged ${name} for admin review (${conf}% confidence, DKG-backed). Pattern: ${type}. Signals: ${ev}.`;
  }
  return `TRACaBot flagged ${name} for admin review (${conf}% local confidence). Pattern: ${type}. Signals: ${ev}. Awaiting admin decision — no strong cross-community DKG evidence yet.`;
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
  const closer = safetyCloser({ target, risk, seed: eventId || findingId });
  if (risk.confidence < 60) {
    return `🛡️ ${name} looks low risk (${risk.confidence}%). No strong public scam signal found. ${closer}`;
  }
  if (risk.confidence >= 80) {
    const evidence = publicEvidence(risk).join('; ') || 'behavior matches known scam patterns';
    return `🚨 HIGH RISK (${risk.confidence}%) on ${name}. Public signals: ${evidence}. ${closer} Admins can use /why privately with the event ID if needed.`;
  }
  return `⚠️ ${name} needs a closer look (${risk.confidence}% risk). Public signals are limited, but caution is warranted. ${closer}`;
}

export function formatReportReply(event, decision = null) {
  if (decision && decision.decision !== 'accepted') {
    return `⚠️ I need stronger evidence before sending this to admin review. Reply to the suspicious message, mention a recently active suspect, or include the wallet, link, or text that should be checked.`;
  }
  return '✅ Reported. I added this to the admin review queue. Admins can review it from the Tracabot menu.';
}

export function formatBanReply(target, eventId) {
  const name = displayName(target);
  return `🔨 Banned ${name}. I saved the moderation evidence to DKG fraud memory for future protection.`;
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
    return `📊 TRACaBot report (7d): all quiet. DKG graph ${graph} shows 0 production events and 0 high-confidence signals.\nVault is looking solid. Use Stats > Sources for receipts.`;
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
    `${closing} Source: DKG graph ${graph}; Stats > Sources shows IDs.`
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

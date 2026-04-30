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
  const name = target?.username ? `@${target.username}` : target?.id || 'this account';
  const verdict = risk.confidence >= 85 ? 'HIGH RISK' : risk.confidence >= 60 ? 'REVIEW' : 'LOW RISK';
  const evidence = risk.evidence?.length ? risk.evidence.slice(0, 6).join('; ') : 'No matching DKG evidence or high-confidence pattern found.';
  return `tracabot risk for ${name}: ${verdict} (${risk.confidence}%). Type: ${risk.scam_type}. Evidence: ${evidence}. Recommendation: ${risk.recommended_action}.`;
}

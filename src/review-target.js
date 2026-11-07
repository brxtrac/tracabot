const WRAPPER_TYPES = new Set(['review_upheld', 'review_overturned']);

// Evidence/finding events that may legitimately carry the reviewed subject.
// Arbitrary actor-only events are deliberately excluded so a moderator cannot
// become the subject by being the only user on a wrapper or message event.
const FINDING_TYPES = new Set([
  'risk_review_needed',
  'risk_action_suppressed',
  'report_review_needed',
  'ban_requested_no_reply',
  'ban_requested_no_rights',
  'proactive_cross_group_warning',
  'fraud_finding',
  'ban_executed',
  'restrict_executed',
  'unsafe_chat_event',
  'channel_observation',
  'report_submitted',
  'dm_scam_report',
  'fraud_campaign'
]);

function hasSubject(subject = {}) {
  return Boolean(subject && (subject.id || subject.username || subject.label));
}

function subjectKey(subject = {}, payload = {}) {
  return String(payload.reviewed_target_key || payload.target_key
    || (subject.id ? `id:${subject.id}` : '')
    || (subject.username ? `username:${String(subject.username).replace(/^@/, '').toLowerCase()}` : ''));
}

export function isReviewWrapper(event = {}) {
  return WRAPPER_TYPES.has(event.event_type);
}

export function isGenuineFinding(event = {}) {
  return FINDING_TYPES.has(event.event_type);
}

/**
 * Resolve the reviewed subject from an existing finding. Review/wrapper events
 * never fall back to their own event.user (the reviewer). They may resolve an
 * existing target_event_id recursively, bounded and cycle-safe.
 */
export function resolveReviewTarget(events = [], eventId = '', { maxDepth = 5 } = {}) {
  const id = String(eventId || '');
  if (!id) return { ok: false, error: 'missing referenced finding' };
  const byId = new Map(events.map((event) => [String(event.id || ''), event]));
  let start = byId.get(id);
  if (!start) {
    const matches = events.filter((event) => event.payload?.target_event_id === id || event.payload?.report_event_id === id);
    if (matches.length > 1) return { ok: false, error: 'ambiguous referenced finding' };
    if (matches.length === 0) return { ok: false, error: 'missing referenced finding' };
    start = matches[0];
  }
  const seen = new Set();
  let current = start;
  for (let depth = 0; depth <= maxDepth; depth += 1) {
    const currentId = String(current.id || '');
    if (!currentId || seen.has(currentId)) return { ok: false, error: 'cyclic review lineage' };
    seen.add(currentId);
    const payload = current.payload || {};
    if (isReviewWrapper(current)) {
      const nextId = String(payload.target_event_id || '');
      if (!nextId) return { ok: false, error: 'subjectless review wrapper' };
      const next = byId.get(nextId);
      if (!next) return { ok: false, error: 'missing underlying finding' };
      current = next;
      continue;
    }
    if (!isGenuineFinding(current)) {
      return { ok: false, error: 'referenced event is not a genuine fraud finding' };
    }
    const subject = payload.reviewed_target || payload.target || current.user || {};
    if (!hasSubject(subject)) return { ok: false, error: 'finding has no reviewed subject' };
    const targetChatId = payload.target_chat_id || current.chat?.id || '';
    if (!targetChatId) return { ok: false, error: 'finding has no target chat' };
    return {
      ok: true,
      finding: current,
      subject,
      subjectKey: subjectKey(subject, payload),
      targetChatId: String(targetChatId)
    };
  }
  return { ok: false, error: 'review lineage too deep' };
}

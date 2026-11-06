#!/usr/bin/env node
import { loadConfig } from '../src/config.js';
import { EventStore } from '../src/store.js';

const [, , command = 'list', requestId = '', ...noteParts] = process.argv;
const config = loadConfig();
const store = new EventStore(config.databasePath || config.storePath, { legacyPath: config.legacyStorePath });
const requests = store.all().filter((event) => event.event_type === 'community_join_requested');
const decisions = new Map(store.all()
  .filter((event) => ['community_membership_approved', 'community_membership_rejected'].includes(event.event_type))
  .map((event) => [event.payload?.request_id, event]));
const pending = requests.filter((event) => !decisions.has(event.id));

if (command === 'list') {
  const rows = pending.map((event) => ({
    requestId: event.id,
    community: event.payload?.community_name || '',
    contact: event.payload?.contact || '',
    graph: event.payload?.requested_graph || '',
    agent: event.payload?.agent || '',
    createdAt: event.timestamp
  }));
  process.stdout.write(`${JSON.stringify({ pending: rows }, null, 2)}\n`);
} else if (command === 'approve' || command === 'reject') {
  const request = requests.find((event) => event.id === requestId);
  if (!request) throw new Error(`Unknown membership request: ${requestId}`);
  if (decisions.has(requestId)) throw new Error(`Membership request already decided: ${requestId}`);
  const note = noteParts.join(' ').trim();
  store.append({
    id: `membership-${command}:${requestId}`,
    event_type: command === 'approve' ? 'community_membership_approved' : 'community_membership_rejected',
    timestamp: new Date().toISOString(),
    local_only: true,
    payload: {
      request_id: requestId,
      community_name: request.payload?.community_name || '',
      operator_note: note,
      evidence: [`operator ${command} for community membership request ${requestId}; no token or graph created automatically`]
    }
  });
  process.stdout.write(`${JSON.stringify({
    ok: true,
    requestId,
    decision: command === 'approve' ? 'approved' : 'rejected',
    next: command === 'approve'
      ? 'Provision a scoped token in TRACABOT_COMMUNITY_TOKENS and verify the context graph separately. No write access exists until then.'
      : 'No token was issued.'
  }, null, 2)}\n`);
} else {
  throw new Error('Usage: tracabot-membership <list|approve|reject> [requestId] [note]');
}
store.db?.close?.();

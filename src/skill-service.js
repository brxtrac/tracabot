import { randomUUID } from 'node:crypto';
import { analyzeMessage } from './scam-analyzer.js';
import { DkgClient } from './dkg-client.js';
import { EventStore } from './store.js';
import { loadConfig } from './config.js';
import { combineRisk } from './risk-engine.js';

function actorAliases(user = {}) {
  return [user.username, user.first_name, [user.first_name, user.last_name].filter(Boolean).join(' ')].filter(Boolean);
}

function targetFromInput(input = {}) {
  return {
    id: input.telegramUserId || input.userId || input.id || '',
    username: String(input.username || '').replace(/^@/, ''),
    first_name: input.firstName || input.first_name || input.label || '',
    label: input.label || '',
    kind: input.kind || 'user'
  };
}

export class TracabotSkillService {
  constructor({ config, analyzer = analyzeMessage, dkg, store }) {
    this.config = config;
    this.analyzer = analyzer;
    this.dkg = dkg;
    this.store = store;
  }

  static fromEnv(env = process.env) {
    const config = loadConfig(env);
    return new TracabotSkillService({
      config,
      dkg: new DkgClient(config),
      store: new EventStore(config.storePath)
    });
  }

  async scanTarget(input = {}) {
    const target = targetFromInput(input);
    const text = String(input.text || input.messageText || input.context || '').slice(0, 4096);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: target.username, userId: target.id, aliases: actorAliases(target), text });
    const local = this.analyzer({ text, user: { ...target, adminUsernames: [...this.config.adminIds].filter((id) => !/^\d+$/.test(id)) }, globalIntel: dkgIntel });
    const risk = combineRisk({ analysis: local, dkgIntel, threshold: this.config.actionThreshold });
    return {
      tool: 'scan_target',
      target,
      risk,
      dkgEvidence: risk.dkg_evidence || [],
      recommendedAction: risk.recommended_action,
      writesDkg: false
    };
  }

  explainEvent(input = {}) {
    const eventId = input.eventId || input.event_id || '';
    const event = this.store.all().find((item) => item.id === eventId || item.payload?.target_event_id === eventId || item.payload?.report_event_id === eventId);
    if (!event) return { tool: 'explain_event', found: false, eventId };
    return {
      tool: 'explain_event',
      found: true,
      eventId: event.id,
      eventType: event.event_type,
      timestamp: event.timestamp,
      user: event.user,
      confidence: event.payload?.confidence ?? 0,
      localConfidence: event.payload?.local_confidence ?? 0,
      dkgConfidence: event.payload?.dkg_confidence ?? 0,
      evidence: event.payload?.evidence || [],
      dkg: event.dkg || null,
      localOnly: Boolean(event.local_only)
    };
  }

  getDigest() {
    const events = this.store.all().filter((event) => Date.now() - Date.parse(event.timestamp || '') <= 24 * 60 * 60 * 1000);
    const count = (types) => events.filter((event) => types.includes(event.event_type)).length;
    return {
      tool: 'get_digest',
      windowHours: 24,
      totalEvents: events.length,
      highConfidence: events.filter((event) => Number(event.payload?.confidence || 0) >= 80).length,
      bans: count(['ban_executed']),
      restrictions: count(['restrict_executed']),
      reports: count(['report_submitted']),
      appeals: count(['appeal_submitted']),
      reviews: count(['review_upheld', 'review_overturned'])
    };
  }

  getWatchlist(input = {}) {
    const active = new Map();
    const restrictions = [];
    const reviews = [];
    const now = Date.now();
    for (const event of this.store.all()) {
      const key = event.payload?.watch_target_key;
      if (key && event.event_type === 'watch_started') active.set(key, event);
      if (key && event.event_type === 'watch_ended') active.delete(key);
      if (event.event_type === 'restrict_executed' && (!event.payload?.restricted_until || Date.parse(event.payload.restricted_until) >= now)) restrictions.push(event);
      if (['risk_review_needed', 'risk_action_suppressed', 'report_review_needed'].includes(event.event_type)) reviews.push(event);
    }
    return {
      tool: 'get_watchlist',
      filter: input.filter || 'all',
      watches: [...active.values()].map((event) => ({ eventId: event.id, target: event.payload?.target || event.user, reason: event.payload?.reason || '', timestamp: event.timestamp })),
      restrictions: restrictions.map((event) => ({ eventId: event.id, target: event.user, restrictedUntil: event.payload?.restricted_until || '', confidence: event.payload?.confidence || 0 })),
      reviews: reviews.slice(-20).map((event) => ({ eventId: event.id, target: event.user, type: event.event_type, confidence: event.payload?.confidence || 0 }))
    };
  }

  queryCampaigns() {
    const buckets = new Map();
    for (const event of this.store.all()) {
      if (event.event_type !== 'fraud_campaign') continue;
      buckets.set(event.payload?.campaign_key || event.id, event);
    }
    return {
      tool: 'query_campaigns',
      campaigns: [...buckets.values()].slice(-20).map((event) => ({
        eventId: event.id,
        key: event.payload?.campaign_key || '',
        relatedEventIds: event.payload?.related_event_ids || [],
        evidenceRootIds: event.payload?.evidence_root_ids || [],
        affectedCommunityIds: event.payload?.affected_community_ids || [],
        eventCount: event.payload?.campaign_event_count || (event.payload?.related_event_ids || []).length,
        communityCount: event.payload?.campaign_community_count || (event.payload?.affected_community_ids || []).length,
        domains: event.payload?.domains || [],
        wallets: event.payload?.wallets || [],
        patterns: event.payload?.patterns || [],
        evidence: event.payload?.evidence || []
      }))
    };
  }

  async submitAppeal(input = {}) {
    const event = {
      id: randomUUID(),
      event_type: 'appeal_submitted',
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: input.chat || { id: input.chatId || 'openclaw-skill' },
      user: input.actor || { id: input.actorId || 'openclaw-skill', username: input.actorUsername || 'openclaw' },
      payload: { target_event_id: input.eventId || '', reason: input.reason || 'appeal submitted via OpenClaw skill', evidence: [`OpenClaw skill appeal: ${input.reason || 'appeal submitted'}`] }
    };
    event.dkg = await this.dkg.writeEvent(event);
    this.store.append(event);
    return { tool: 'submit_appeal', eventId: event.id, dkg: event.dkg };
  }

  async reviewEvent(input = {}) {
    const decision = /overturn/i.test(input.decision || '') ? 'overturned' : 'upheld';
    const event = {
      id: randomUUID(),
      event_type: decision === 'overturned' ? 'review_overturned' : 'review_upheld',
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: input.chat || { id: input.chatId || 'openclaw-skill' },
      user: input.actor || { id: input.actorId || 'openclaw-skill', username: input.actorUsername || 'openclaw' },
      payload: { target_event_id: input.eventId || '', review_decision: decision, admin_verified: true, reviewer: { id: input.actorId || '', username: input.actorUsername || 'openclaw' }, reason: input.reason || `review ${decision} via OpenClaw skill`, evidence: [`OpenClaw skill review ${decision}: ${input.reason || ''}`] }
    };
    event.dkg = await this.dkg.writeEvent(event);
    this.store.append(event);
    return { tool: 'review_event', eventId: event.id, decision, dkg: event.dkg };
  }

  async monitorChatEvent(input = {}) {
    const target = targetFromInput(input);
    const text = String(input.text || input.messageText || input.context || '').slice(0, 4096);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: target.username, userId: target.id, aliases: actorAliases(target), text });
    const local = this.analyzer({ text, user: { ...target, adminUsernames: [...this.config.adminIds].filter((id) => !/^\d+$/.test(id)) }, globalIntel: dkgIntel });
    const risk = combineRisk({ analysis: local, dkgIntel, threshold: this.config.actionThreshold });
    const unsafe = Boolean(risk.is_scam || risk.confidence >= 60 || ['phishing', 'impersonation', 'giveaway', 'investment_scam'].includes(risk.scam_type));
    if (!unsafe) return { tool: 'monitor_chat_event', monitored: false, risk, writesDkg: false };
    const adminVerified = Boolean(input.adminVerified || input.verifiedByAdmin);
    const highConfidence = Number(risk.confidence || 0) >= 95 && Number(risk.local_confidence || 0) >= 80;
    const event = {
      id: randomUUID(),
      event_type: 'unsafe_chat_event',
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: input.chat || { id: input.chatId || 'openclaw-skill' },
      user: target,
      payload: {
        ...risk,
        target,
        target_key: target.kind === 'wallet' ? `wallet:${target.id}` : target.id ? `id:${target.id}` : target.username ? `username:${target.username.toLowerCase()}` : target.label || '',
        message_text: text.slice(0, 1000),
        community_id: input.communityId || input.chatId || this.config.communityId || '',
        community_name: input.communityName || this.config.communityName || '',
        community_type: input.communityType || this.config.communityType || 'telegram_group',
        policy_id: input.policyId || this.config.policyId || 'default',
        source: 'openclaw_monitor_chat_event',
        admin_verified: adminVerified,
        reviewer: adminVerified ? { id: input.actorId || '', username: input.actorUsername || 'openclaw' } : undefined,
        community_verified_flag: adminVerified ? 'group_admin_verified' : '',
        publication_status: adminVerified || highConfidence ? 'context_graph_auto_publish_eligible' : 'shared_memory',
        evidence: [...(risk.evidence || []), `OpenClaw monitor classified chat event as ${risk.scam_type || 'unsafe'} with ${risk.confidence || 0}% confidence`]
      }
    };
    event.dkg = await this.dkg.writeEvent(event);
    this.store.append(event);
    return { tool: 'monitor_chat_event', monitored: true, eventId: event.id, risk, adminVerified, highConfidence, dkg: event.dkg, writesDkg: true };
  }
}

export async function runSkillTool(tool, input = {}, env = process.env) {
  const service = TracabotSkillService.fromEnv(env);
  if (tool === 'scan_target') return service.scanTarget(input);
  if (tool === 'explain_event') return service.explainEvent(input);
  if (tool === 'get_digest') return service.getDigest(input);
  if (tool === 'get_watchlist') return service.getWatchlist(input);
  if (tool === 'query_campaigns') return service.queryCampaigns(input);
  if (tool === 'monitor_chat_event') return service.monitorChatEvent(input);
  if (tool === 'submit_appeal') return service.submitAppeal(input);
  if (tool === 'review_event') return service.reviewEvent(input);
  throw new Error(`Unknown tracabot skill tool: ${tool}`);
}

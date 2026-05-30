import { randomUUID } from 'node:crypto';
import { analyzeMessage } from './scam-analyzer.js';
import { DkgClient } from './dkg-client.js';
import { EventStore } from './store.js';
import { loadConfig } from './config.js';
import { combineRisk } from './risk-engine.js';
import { LlmClient } from './llm-client.js';

function actorAliases(user = {}) {
  return [user.username, user.first_name, [user.first_name, user.last_name].filter(Boolean).join(' ')].filter(Boolean);
}

function normalizeArtifactText(text = '') {
  return String(text || '')
    .slice(0, 700)
    .replace(/0x[a-fA-F0-9]{40}/g, (wallet) => `${wallet.slice(0, 8)}...${wallet.slice(-6)}`)
    .replace(/\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g, (wallet) => `${wallet.slice(0, 8)}...${wallet.slice(-6)}`)
    .replace(/\b\d{7,}\b/g, '[telegram-id]')
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, '[url]')
    .replace(/\s+/g, ' ')
    .trim();
}

function redactArtifactText(text = '') {
  return String(text || '')
    .slice(0, 700)
    .replace(/0x[a-fA-F0-9]{40}/g, (wallet) => `${wallet.slice(0, 8)}...${wallet.slice(-6)}`)
    .replace(/\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b/g, (wallet) => `${wallet.slice(0, 8)}...${wallet.slice(-6)}`)
    .replace(/\b\d{7,}\b/g, '[telegram-id]')
    .replace(/(?:api[_-]?key|token|secret|password|private[_-]?key)\s*[:=]\s*\S+/gi, '$1=[redacted]');
}

function textFingerprint(text = '') {
  return String(text).toLowerCase().replace(/https?:\/\/\S+/g, '').replace(/[^a-z0-9\s]/g, ' ').split(/\s+/).filter((word) => word.length > 2).slice(0, 16).join(' ');
}

function artifactQuality({ risk = {}, text = '', adminVerified = false } = {}) {
  let score = adminVerified ? 30 : 0;
  if (Number(risk.local_confidence || risk.confidence || 0) >= 40) score += 25;
  if (Number(risk.local_confidence || risk.confidence || 0) >= 60) score += 20;
  if ((risk.domains || []).length) score += 20;
  if ((risk.wallets || []).length) score += 20;
  if ((risk.patterns || []).length) score += 15;
  if (/report|warn|alert|fake|impersonat|phish|scam|wallet|airdrop|support|admin/i.test(text)) score += 10;
  return Math.min(100, score);
}

function commitReceiptId({ artifactKind = '', quality = 0, risk = {}, sourceEventIds = [], text = '' } = {}) {
  const basis = [artifactKind, quality, risk.scam_type || '', risk.confidence || 0, sourceEventIds.join(','), textFingerprint(text)].join(':');
  return `commit:${randomUUID().slice(0, 8)}:${Buffer.from(basis).toString('base64url').slice(0, 16)}`;
}

function writeTokenValid(input = {}, config = {}, env = process.env) {
  const expected = env.TRACABOT_SKILL_WRITE_TOKEN || config.skillWriteToken || '';
  return Boolean(expected && input.writeToken && String(input.writeToken) === String(expected));
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
    if (!writeTokenValid(input, this.config)) throw new Error('review_event requires authorized write token');
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

  async decideArtefactAction(input = {}) {
    const text = String(input.text || '');
    let quality = this._basicQuality(input);
    const hasAdminSignal = Boolean(input.adminVerified);

    // Local fast-path history (always available)
    const priorReviews = this.store.all().filter(e =>
      ['review_upheld', 'review_overturned', 'risk_review_needed', 'proactive_cross_group_warning'].includes(e.event_type) &&
      (String(e.user?.id || '') === String(input.telegramUserId || '') ||
       String(e.payload?.target?.id || '') === String(input.telegramUserId || '') ||
       String(e.payload?.target_key || '').includes(String(input.telegramUserId || '')))
    );
    let hasPriorAdminDecision = priorReviews.some(e => ['review_upheld', 'review_overturned', 'proactive_cross_group_warning'].includes(e.event_type));

    // Real Context Graph lookup (the key improvement for intelligent curation)
    let graphHistory = { hasPriorAdminAction: false, events: [] };
    try {
      if (typeof this.dkg?.queryAdminHistoryForActor === 'function') {
        graphHistory = await this.dkg.queryAdminHistoryForActor({
          userId: input.telegramUserId,
          username: input.username,
          aliases: actorAliases({ username: input.username, first_name: input.firstName || input.label })
        }).catch(() => ({ hasPriorAdminAction: false, events: [] }));
      }
    } catch {}

    if (graphHistory.hasPriorAdminAction) {
      hasPriorAdminDecision = true;
      // Boost quality when the actor has prior severe admin outcomes elsewhere
      quality = Math.min(100, quality + 20);
    }

    let recommendation = 'local_wm_draft';
    let publication = 'working_memory';

    const reviewThreshold = this.config.artefactReviewThreshold || 70;

    if (hasAdminSignal || quality >= reviewThreshold) {
      recommendation = 'commit_to_swm';
      publication = 'shared_memory';
    } else if (quality >= 55 || hasPriorAdminDecision) {
      recommendation = 'queue_for_admin_review';
    }

    const priorCount = (graphHistory.events || []).length + priorReviews.length;

    return {
      tool: 'decide_artefact_action',
      recommendation,
      quality,
      publication_status: publication,
      reasoning: hasAdminSignal ? 'admin verified' :
                graphHistory.hasPriorAdminAction ? `prior admin action(s) in Tracabot Context Graph (${graphHistory.events.length})` :
                hasPriorAdminDecision ? 'prior admin decision on this actor (local)' :
                `quality ${quality}`,
      writes_dkg: recommendation !== 'local_wm_draft',
      prior_reviews_found: priorCount,
      graph_history: {
        has_prior_admin_action: graphHistory.hasPriorAdminAction,
        events: graphHistory.events?.slice(0, 3) || []
      },
      cross_group_boost_applied: graphHistory.hasPriorAdminAction
    };
  }

  _basicQuality(input = {}) {
    let score = input.adminVerified ? 30 : 0;
    const conf = Number(input.confidence || input.local_confidence || 0);
    if (conf >= 60) score += 25;
    if ((input.domains || []).length || (input.wallets || []).length) score += 20;
    if (/scam|report|impersonat|phish|wallet/i.test(String(input.text || ''))) score += 15;
    return Math.min(100, score);
  }

  async monitorChatEvent(input = {}) {
    const target = targetFromInput(input);
    const text = String(input.text || input.messageText || input.context || '').slice(0, 4096);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: target.username, userId: target.id, aliases: actorAliases(target), text });
    const local = this.analyzer({ text, user: { ...target, adminUsernames: [...this.config.adminIds].filter((id) => !/^\d+$/.test(id)) }, globalIntel: dkgIntel });
    const risk = combineRisk({ analysis: local, dkgIntel, threshold: this.config.actionThreshold });
    const unsafe = Boolean(risk.is_scam || risk.confidence >= 60 || ['phishing', 'impersonation', 'giveaway', 'investment_scam'].includes(risk.scam_type));
    if (!unsafe) return { tool: 'monitor_chat_event', monitored: false, risk, writesDkg: false };
    const adminVerified = writeTokenValid(input, this.config) && Boolean(input.adminVerified || input.verifiedByAdmin);
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

  async sortConversationArtifact(input = {}) {
    const target = targetFromInput(input);
    const text = String(input.text || input.messageText || input.context || '').slice(0, 4096);
    const dkgIntel = await this.dkg.queryRiskIndicators({ username: target.username, userId: target.id, aliases: actorAliases(target), text });
    const local = this.analyzer({ text, user: { ...target, adminUsernames: [...this.config.adminIds].filter((id) => !/^\d+$/.test(id)) }, globalIntel: dkgIntel });
    const risk = combineRisk({ analysis: local, dkgIntel, threshold: this.config.actionThreshold });
    const adminVerified = writeTokenValid(input, this.config) && Boolean(input.adminVerified || input.verifiedByAdmin);
    const quality = artifactQuality({ risk, text, adminVerified });
    const writeDkg = adminVerified || quality >= 70 || (input.shareLowConfidence === true && quality >= 40);
    const sourceEventIds = input.sourceEventIds || [];
    const receiptId = writeDkg ? commitReceiptId({ artifactKind: input.artifactKind || 'openclaw_sorted_conversation', quality, risk, sourceEventIds, text }) : '';
    const event = {
      id: randomUUID(),
      event_type: 'conversation_artifact',
      timestamp: new Date().toISOString(),
      agentDid: this.config.agentDid,
      chat: input.chat || { id: input.chatId || 'openclaw-skill' },
      user: target,
      payload: {
        ...risk,
        target,
        target_key: target.kind === 'wallet' ? `wallet:${target.id}` : target.id ? `id:${target.id}` : target.username ? `username:${target.username.toLowerCase()}` : target.label || '',
        artifact_kind: input.artifactKind || 'openclaw_sorted_conversation',
        artifact_quality: quality,
        conversation_role: input.conversationRole || 'openclaw_sorter',
        redaction_level: 'redacted',
        normalized_text: normalizeArtifactText(text),
        message_text: redactArtifactText(text),
        text_fingerprint: textFingerprint(text),
        source_event_ids: sourceEventIds,
        operator_note: input.operatorNote || '',
        learning_value: quality >= 70 ? 'high' : quality >= 45 ? 'medium' : 'low',
        teaches_tactics: risk.patterns || [],
        commit_receipt_id: receiptId,
        commit_policy: writeDkg ? (adminVerified ? 'human_or_admin_verified' : 'artifact_quality_threshold') : 'draft_only',
        commit_authority: writeDkg ? (adminVerified ? 'admin_review' : 'openclaw_policy_rule') : '',
        publication_status: writeDkg ? 'shared_memory' : 'working_memory',
        lifecycle_stage: writeDkg ? 'shared_memory' : 'working_memory_draft',
        evidence: [...(risk.evidence || []), `OpenClaw sorted conversation artifact with quality ${quality}`, writeDkg ? `commit receipt ${receiptId} authorizes Shared Memory projection` : 'draft only; not eligible for Shared Memory until committed']
      }
    };
    if (writeDkg) event.dkg = await this.dkg.writeEvent(event);
    else event.local_only = true;
    this.store.append(event);
    return { tool: 'sort_conversation_artifact', eventId: event.id, risk, artifactQuality: quality, writesDkg: writeDkg, dkg: event.dkg || null };
  }

  async generateSafeTip() {
    // Safe Tips skill implementation — used by the bot for proactive education and by external OpenClaw agents
    const llm = new LlmClient(this.config);

    const system = [
      'You are Tracabot, a calm, professional anti-scam bodyguard for Telegram communities.',
      'Create one short, varied, practical safety sentence (max 140 chars).',
      'Rotate topics naturally: DM impersonators, urgent wallet links, fake support, seed phrases, verification habits, staying on TRAC, checking official channels.',
      'Tone: protective and helpful, never alarmist. Focus on one clear habit.',
      'Output ONLY the sentence. No quotes, no intro, no extra text.'
    ].join('\n');

    const response = await llm.complete({ system, user: 'Generate today\'s short safety reminder.' }).catch(() => ({ text: '' }));
    const tip = String(response.text || '').trim().replace(/^["']|["']$/g, '');

    if (tip.length > 15 && tip.length < 160) {
      return tip;
    }

    // High-quality rotating fallbacks (varied, non-repetitive)
    const fallbacks = [
      'Stay on TRAC: verify through official channels before any wallet action.',
      'Never share seed phrases or private keys with anyone claiming to be support.',
      'DMs asking you to "verify" or "sync" your wallet are almost always scams.',
      'Check the official project account yourself — never click links from strangers.',
      'Real teams never DM you first asking for wallet access or recovery phrases.',
      'When in doubt, ask in the main group chat before clicking anything.',
      'Scammers often impersonate admins or support — verify usernames carefully.',
      'A quick search for the exact phrase they used often reveals the scam pattern.'
    ];
    return fallbacks[Math.floor(Math.random() * fallbacks.length)];
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
  if (tool === 'sort_conversation_artifact') return service.sortConversationArtifact(input);
  if (tool === 'submit_appeal') return service.submitAppeal(input);
  if (tool === 'review_event') return service.reviewEvent(input);
  if (tool === 'decide_artefact_action') return service.decideArtefactAction(input);
  if (tool === 'generate_safe_tip') return service.generateSafeTip(input);
  throw new Error(`Unknown tracabot skill tool: ${tool}`);
}

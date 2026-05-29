import { randomUUID } from 'node:crypto';
import { TracabotSkillService } from './skill-service.js';

function processedDraftIds(store) {
  return new Set(store.all()
    .filter((event) => ['learning_draft_processed', 'learning_draft_skipped', 'learning_draft_failed'].includes(event.event_type))
    .map((event) => event.payload?.target_event_id)
    .filter(Boolean));
}

export function learningDrafts(store, { limit = 25 } = {}) {
  const processed = processedDraftIds(store);
  return store.all()
    .filter((event) => event.event_type === 'conversation_artifact')
    .filter((event) => event.local_only || event.payload?.publication_status === 'working_memory')
    .filter((event) => event.payload?.lifecycle_stage === 'working_memory_draft')
    .filter((event) => event.payload?.conversation_role !== 'openclaw_autonomous_curator')
    .filter((event) => !processed.has(event.id))
    .slice(-Math.max(1, limit));
}

function inputFromDraft(draft) {
  const payload = draft.payload || {};
  const user = draft.user || payload.target || {};
  return {
    telegramUserId: user.id || payload.target?.id || '',
    username: user.username || payload.target?.username || '',
    firstName: user.first_name || payload.target?.first_name || '',
    label: user.label || payload.target?.label || '',
    text: payload.message_text || payload.normalized_text || '',
    artifactKind: payload.artifact_kind || 'openclaw_sorted_conversation',
    conversationRole: 'openclaw_autonomous_curator',
    sourceEventIds: [draft.id, ...(payload.source_event_ids || [])].filter(Boolean),
    operatorNote: `autonomous OpenClaw learning pass for WM draft ${draft.id}`,
    chat: draft.chat,
    chatId: draft.chat?.id || '',
    communityId: payload.community_id || draft.chat?.id || '',
    communityName: payload.community_name || draft.chat?.title || '',
    communityType: payload.community_type || draft.chat?.type || 'telegram_group',
    policyId: payload.policy_id || 'default'
  };
}

export async function processLearningDrafts({ service = TracabotSkillService.fromEnv(), limit = 25, dryRun = false } = {}) {
  const drafts = learningDrafts(service.store, { limit });
  const results = [];
  for (const draft of drafts) {
    const input = inputFromDraft(draft);
    if (dryRun) {
      results.push({ draftId: draft.id, dryRun: true, input });
      continue;
    }
    try {
      // Phase 3: Consult the artefact curator for a recommendation before/around sorting
      let curatorRec = null;
      try {
        curatorRec = await service.decideArtefactAction({
          ...input,
          artifactKind: input.artifactKind || 'openclaw_sorted_conversation'
        });
      } catch (e) {}

      const result = await service.sortConversationArtifact(input);

      service.store.append({
        id: randomUUID(),
        event_type: 'learning_draft_processed',
        timestamp: new Date().toISOString(),
        agentDid: service.config.agentDid,
        chat: draft.chat,
        user: draft.user,
        local_only: true,
        payload: {
          target_event_id: draft.id,
          sorted_event_id: result.eventId,
          writes_dkg: Boolean(result.writesDkg),
          artifact_quality: result.artifactQuality,
          curator_recommendation: curatorRec?.recommendation || null,
          evidence: [`autonomous OpenClaw learning processed WM draft ${draft.id}`]
        }
      });
      results.push({ draftId: draft.id, ok: true, result, curatorRec });
    } catch (error) {
      service.store.append({
        id: randomUUID(),
        event_type: 'learning_draft_failed',
        timestamp: new Date().toISOString(),
        agentDid: service.config.agentDid,
        chat: draft.chat,
        user: draft.user,
        local_only: true,
        payload: {
          target_event_id: draft.id,
          error: error instanceof Error ? error.message : String(error),
          evidence: [`autonomous OpenClaw learning failed for WM draft ${draft.id}`]
        }
      });
      results.push({ draftId: draft.id, ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  }
  return { processed: results.length, results };
}

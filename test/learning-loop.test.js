import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { processLearningDrafts, learningDrafts } from '../src/learning-loop.js';
import { TracabotSkillService } from '../src/skill-service.js';
import { EventStore } from '../src/store.js';

function makeService() {
  const dkgWrites = [];
  const service = new TracabotSkillService({
    config: {
      agentDid: 'did:dkg:agent:test',
      adminIds: new Set(),
      actionThreshold: 85,
      contextGraph: 'tracabot',
      communityId: '',
      communityName: '',
      communityType: 'telegram_group',
      policyId: 'default'
    },
    analyzer: ({ text }) => /wallet|support|verify/i.test(text)
      ? { is_scam: true, confidence: 75, scam_type: 'phishing', evidence: ['Suspicious link or claim-link pattern', 'Crypto lure terms: wallet verification/claim phrase'], patterns: ['wallet-drain'], recommended_action: 'warn' }
      : { is_scam: false, confidence: 0, scam_type: 'other', evidence: [], recommended_action: 'ignore' },
    dkg: {
      async queryRiskIndicators({ text = '' } = {}) { return { riskScore: 0, reportsAcrossCommunities: 0, wallets: [], domains: [], patterns: /wallet|support|verify/i.test(text) ? ['wallet-drain'] : [], evidence: [] }; },
      async writeEvent(event) { dkgWrites.push(event); return { ual: 'did:dkg:context-graph:tracabot/_shared_memory', eventId: event.id }; }
    },
    store: new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-learning-')), 'events.jsonl'))
  });
  return { service, dkgWrites };
}

test('learning loop drains draft artifacts through OpenClaw sorter once', async () => {
  const { service, dkgWrites } = makeService();
  service.store.append({
    id: 'draft-1',
    event_type: 'conversation_artifact',
    timestamp: new Date().toISOString(),
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    user: { id: 86, username: 'builder' },
    local_only: true,
    payload: {
      artifact_kind: 'tactic_candidate',
      lifecycle_stage: 'working_memory_draft',
      publication_status: 'working_memory',
      message_text: 'fake support says verify wallet now'
    }
  });

  assert.equal(learningDrafts(service.store).length, 1);
  const first = await processLearningDrafts({ service, limit: 10 });
  const second = await processLearningDrafts({ service, limit: 10 });

  assert.equal(first.processed, 1);
  assert.equal(second.processed, 0);
  assert.equal(service.store.all().filter((event) => event.event_type === 'learning_draft_processed').length, 1);
  assert.equal(dkgWrites.length, 1);
  assert.equal(dkgWrites[0].event_type, 'conversation_artifact');
  assert.match(dkgWrites[0].payload.commit_receipt_id, /^commit:/);
  assert.deepEqual(dkgWrites[0].payload.source_event_ids, ['draft-1']);
});

test('learning loop keeps benign low-quality drafts local after sorting', async () => {
  const { service, dkgWrites } = makeService();
  service.store.append({
    id: 'draft-benign',
    event_type: 'conversation_artifact',
    timestamp: new Date().toISOString(),
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    user: { id: 87, username: 'builder2' },
    local_only: true,
    payload: {
      artifact_kind: 'benign_conversation_flow',
      lifecycle_stage: 'working_memory_draft',
      publication_status: 'working_memory',
      message_text: 'Working Memory to Shared Memory needs governance gate discussion'
    }
  });

  const result = await processLearningDrafts({ service, limit: 10 });
  const sorted = service.store.all().find((event) => event.event_type === 'conversation_artifact' && event.id !== 'draft-benign');

  assert.equal(result.processed, 1);
  assert.equal(dkgWrites.length, 0);
  assert.equal(sorted.local_only, true);
  assert.equal(sorted.payload.lifecycle_stage, 'working_memory_draft');
  assert.equal(sorted.payload.commit_policy, 'draft_only');
});

test('learning loop does not retry failed drafts forever', async () => {
  const { service } = makeService();
  service.sortConversationArtifact = async () => { throw new Error('sorter unavailable'); };
  service.store.append({
    id: 'draft-fail',
    event_type: 'conversation_artifact',
    timestamp: new Date().toISOString(),
    chat: { id: -100, title: 'demo', type: 'supergroup' },
    user: { id: 88, username: 'builder3' },
    local_only: true,
    payload: {
      artifact_kind: 'tactic_candidate',
      lifecycle_stage: 'working_memory_draft',
      publication_status: 'working_memory',
      message_text: 'fake support says verify wallet now'
    }
  });

  const first = await processLearningDrafts({ service, limit: 10 });
  const second = await processLearningDrafts({ service, limit: 10 });

  assert.equal(first.processed, 1);
  assert.equal(first.results[0].ok, false);
  assert.equal(second.processed, 0);
  assert.equal(service.store.all().filter((event) => event.event_type === 'learning_draft_failed').length, 1);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';

test('loadConfig rejects unsafe context graph names', () => {
  assert.throws(() => loadConfig({ TRACABOT_CONTEXT_GRAPH: 'bad graph' }), /TRACABOT_CONTEXT_GRAPH/);
  assert.throws(() => loadConfig({ TRACABOT_CONTEXT_GRAPH: '../bad' }), /TRACABOT_CONTEXT_GRAPH/);
  assert.throws(() => loadConfig({ TRACABOT_CONTEXT_GRAPH: 'owner/project/extra' }), /TRACABOT_CONTEXT_GRAPH/);
});

test('loadConfig accepts wallet-scoped context graph names', () => {
  const config = loadConfig({ TRACABOT_CONTEXT_GRAPH: '0x6c6ad1453153ea0dc5e0c86524e1756aa279C1Ad/tracabot' });
  assert.equal(config.contextGraph, '0x6c6ad1453153ea0dc5e0c86524e1756aa279C1Ad/tracabot');
});

test('loadConfig parses on-chain publish context graph id', () => {
  const config = loadConfig({ TRACABOT_PUBLISH_CONTEXT_GRAPH_ID: '13' });
  assert.equal(config.publishContextGraphId, '13');
  assert.throws(() => loadConfig({ TRACABOT_PUBLISH_CONTEXT_GRAPH_ID: 'tracabot' }), /TRACABOT_PUBLISH_CONTEXT_GRAPH_ID/);
});

test('loadConfig parses community scope settings', () => {
  const config = loadConfig({
    TRACABOT_COMMUNITY_ID: '-100123',
    TRACABOT_COMMUNITY_NAME: 'Example DAO',
    TRACABOT_COMMUNITY_TYPE: 'telegram_group',
    TRACABOT_POLICY_ID: 'strict-v1'
  });
  assert.equal(config.communityId, '-100123');
  assert.equal(config.communityName, 'Example DAO');
  assert.equal(config.communityType, 'telegram_group');
  assert.equal(config.policyId, 'strict-v1');
});

test('loadConfig parses bot owner ids for global trust roots', () => {
  const config = loadConfig({ TRACABOT_BOT_OWNER_IDS: '1234,@brx' });
  assert.equal(config.botOwnerIds.has('1234'), true);
  assert.equal(config.botOwnerIds.has('brx'), true);
});

test('loadConfig parses boolean environment values strictly', () => {
  assert.equal(loadConfig({ TRACABOT_AUTO_BAN: '0' }).autoBan, false);
  assert.equal(loadConfig({ TRACABOT_AUTO_BAN: 'yes' }).autoBan, true);
  assert.throws(() => loadConfig({ TRACABOT_AUTO_BAN: 'maybe' }), /Invalid boolean/);
});

test('loadConfig parses graduated autonomous enforcement thresholds', () => {
  const config = loadConfig({
    TRACABOT_WARN_THRESHOLD: '55',
    TRACABOT_RESTRICT_THRESHOLD: '76',
    TRACABOT_BAN_THRESHOLD: '92',
    TRACABOT_AUTO_DELETE: 'false',
    TRACABOT_AUTO_RESTRICT: 'true'
  });
  assert.equal(config.warnThreshold, 55);
  assert.equal(config.restrictThreshold, 76);
  assert.equal(config.banThreshold, 92);
  assert.equal(config.autoDelete, false);
  assert.equal(config.autoRestrict, true);
  assert.throws(() => loadConfig({ TRACABOT_WARN_THRESHOLD: '80', TRACABOT_RESTRICT_THRESHOLD: '70' }), /TRACABOT_RESTRICT_THRESHOLD/);
});

test('loadConfig parses conversational safety settings', () => {
  const config = loadConfig({
    TRACABOT_CONVERSATIONAL: 'true',
    TRACABOT_LLM_PROVIDER: 'auto',
    TRACABOT_CONVERSATION_MIN_CONFIDENCE: '55',
    TRACABOT_PROACTIVE_REPLY_THRESHOLD: '78',
    TRACABOT_CONVERSATION_RATE_LIMIT_SECONDS: '15',
    TRACABOT_CONVERSATION_MAX_CHARS: '500'
  });
  assert.equal(config.conversational, true);
  assert.equal(config.llmProvider, 'auto');
  assert.equal(config.conversationMinConfidence, 55);
  assert.equal(config.proactiveReplyThreshold, 78);
  assert.equal(config.conversationRateLimitSeconds, 15);
  assert.equal(config.conversationMaxChars, 500);
  assert.throws(() => loadConfig({ TRACABOT_CONVERSATION_MIN_CONFIDENCE: '90', TRACABOT_PROACTIVE_REPLY_THRESHOLD: '80' }), /TRACABOT_PROACTIVE_REPLY_THRESHOLD/);
});

test('loadConfig parses DKG join challenge settings', () => {
  const config = loadConfig({
    TRACABOT_JOIN_CHALLENGE: 'true',
    TRACABOT_JOIN_CHALLENGE_TTL_SECONDS: '90',
    TRACABOT_JOIN_CHALLENGE_ACTION: 'ban',
    TRACABOT_JOIN_CHALLENGE_MODE: 'qa',
    TRACABOT_JOIN_CHALLENGE_ASSET_URL: 'https://dkg.origintrail.io/explore?ual=did:dkg:test/1',
    TRACABOT_JOIN_CHALLENGE_QA_BANK: '[{"id":"signal","question":"What is the signal color?","answers":["amber"]}]',
    TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS: '5',
    TRACABOT_JOIN_CHALLENGE_REPEAT_FAILURE_THRESHOLD: '3',
    TRACABOT_JOIN_CHALLENGE_REPEAT_BAD_ATTEMPT_THRESHOLD: '4',
    TRACABOT_JOIN_CHALLENGE_DELETE_ON_PASS: 'false',
    TRACABOT_JOIN_CHALLENGE_DELETE_BAD_ATTEMPTS: 'true',
    TRACABOT_JOIN_CHALLENGE_DKG_VALIDATE: 'false',
    TRACABOT_AUTO_DELETE_BOT_MESSAGES: 'false',
    TRACABOT_BOT_MESSAGE_TTL_SECONDS: '30',
    TRACABOT_CHALLENGE_MESSAGE_TTL_SECONDS: '180',
    TRACABOT_SUCCESS_MESSAGE_TTL_SECONDS: '20'
  });
  assert.equal(config.joinChallenge, true);
  assert.equal(config.joinChallengeMode, 'qa');
  assert.equal(config.joinChallengeAssetUrl, 'https://dkg.origintrail.io/explore?ual=did:dkg:test/1');
  assert.deepEqual(config.joinChallengeQaBank, [{ id: 'signal', question: 'What is the signal color?', answers: ['amber'] }]);
  assert.equal(config.joinChallengeTtlSeconds, 90);
  assert.equal(config.joinChallengeMaxAttempts, 5);
  assert.equal(config.joinChallengeRepeatFailureThreshold, 3);
  assert.equal(config.joinChallengeRepeatBadAttemptThreshold, 4);
  assert.equal(config.joinChallengeAction, 'ban');
  assert.equal(config.joinChallengeDeleteOnPass, false);
  assert.equal(config.joinChallengeDeleteBadAttempts, true);
  assert.equal(config.joinChallengeDkgValidate, false);
  assert.equal(config.autoDeleteBotMessages, false);
  assert.equal(config.botMessageTtlSeconds, 30);
  assert.equal(config.challengeMessageTtlSeconds, 180);
  assert.equal(config.successMessageTtlSeconds, 20);
  assert.throws(() => loadConfig({ TRACABOT_JOIN_CHALLENGE_TTL_SECONDS: '5' }), /TRACABOT_JOIN_CHALLENGE_TTL_SECONDS/);
  assert.throws(() => loadConfig({ TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS: '0' }), /TRACABOT_JOIN_CHALLENGE_MAX_ATTEMPTS/);
  assert.throws(() => loadConfig({ TRACABOT_JOIN_CHALLENGE_REPEAT_FAILURE_THRESHOLD: '1' }), /TRACABOT_JOIN_CHALLENGE_REPEAT_FAILURE_THRESHOLD/);
  assert.throws(() => loadConfig({ TRACABOT_JOIN_CHALLENGE_REPEAT_BAD_ATTEMPT_THRESHOLD: '0' }), /TRACABOT_JOIN_CHALLENGE_REPEAT_BAD_ATTEMPT_THRESHOLD/);
  assert.throws(() => loadConfig({ TRACABOT_JOIN_CHALLENGE_QA_BANK: 'not json' }), /TRACABOT_JOIN_CHALLENGE_QA_BANK/);
  assert.throws(() => loadConfig({ TRACABOT_BOT_MESSAGE_TTL_SECONDS: '1' }), /TRACABOT_BOT_MESSAGE_TTL_SECONDS/);
});

test('loadConfig rejects unsupported DKG modes', () => {
  assert.throws(() => loadConfig({ TRACABOT_DKG_MODE: 'shell' }), /openclaw-adapter/);
});

test('loadConfig parses channel shared-memory policy', () => {
  const config = loadConfig({
    TRACABOT_CHANNEL_MEMORY: 'true',
    TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE: '85',
    TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS: '900'
  });
  assert.equal(config.channelMemory, true);
  assert.equal(config.channelMemoryMinConfidence, 85);
  assert.equal(config.channelMemoryMaxTextChars, 900);
  assert.throws(() => loadConfig({ TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE: '40' }), /TRACABOT_CHANNEL_MEMORY_MIN_CONFIDENCE/);
  assert.throws(() => loadConfig({ TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS: '80' }), /TRACABOT_CHANNEL_MEMORY_MAX_TEXT_CHARS/);
});

test('loadConfig parses conversation artifact working-memory policy', () => {
  const config = loadConfig({
    TRACABOT_WM_ARTIFACTS: 'true',
    TRACABOT_WM_ARTIFACT_SHARE_LOW_CONFIDENCE: 'true',
    TRACABOT_WM_ARTIFACT_REDACT: 'false',
    TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE: '35',
    TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS: '600'
  });
  assert.equal(config.wmArtifacts, true);
  assert.equal(config.wmArtifactShareLowConfidence, true);
  assert.equal(config.wmArtifactRedact, false);
  assert.equal(config.wmArtifactMinConfidence, 35);
  assert.equal(config.wmArtifactMaxTextChars, 600);
  assert.throws(() => loadConfig({ TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE: '120' }), /TRACABOT_WM_ARTIFACT_MIN_CONFIDENCE/);
  assert.throws(() => loadConfig({ TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS: '80' }), /TRACABOT_WM_ARTIFACT_MAX_TEXT_CHARS/);
});

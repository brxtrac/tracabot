import { lineagePrivacyAudit } from './evidence-policy.js';

function chatId(value) {
  const id = value?.chat?.id ?? value;
  return id === undefined || id === null ? '' : String(id);
}

/**
 * One policy producer for both the main bot artifact staging path and the
 * standalone artifact poller. It returns explicit sharing consent. Any denial,
 * disabled promotion setting, channel-memory limitation, or source-chat opt-out
 * makes the artifact local-only; callers must not share or stage it to DKG.
 */
export function artifactSharingPolicy({
  config = {},
  message = {},
  update = {},
  history = [],
  sourceEventIds = []
} = {}) {
  const messageChatId = chatId(message) || chatId(update?.channel_post) || chatId(update?.message);
  const isChannel = Boolean(update?.channel_post || message?.chat?.type === 'channel');
  const optOutChats = new Set((Array.isArray(config.artifactOptOutChats) ? config.artifactOptOutChats : [])
    .map((value) => String(value)));
  const sourceIds = [...new Set((Array.isArray(sourceEventIds) ? sourceEventIds : [])
    .map((value) => String(value || ''))
    .filter(Boolean))];
  const sourceChatIds = new Set();
  const lineageOk = { value: true };
  let lineageDenied = false;
  for (const id of sourceIds) {
    const audit = lineagePrivacyAudit(history, id);
    if (!audit.ok) lineageOk.value = false;
    if (audit.denied) lineageDenied = true;
    for (const sourceChatId of audit.chatIds) sourceChatIds.add(sourceChatId);
  }

  const reasons = [];
  if (config.wmArtifacts === false) reasons.push('artifacts_disabled');
  if (config.dkgWrites === false) reasons.push('writes_disabled');
  if (config.autoPromoteEvidence !== true) reasons.push('automatic_promotion_disabled');
  if (isChannel && config.channelMemory !== true) reasons.push('channel_memory_disabled');
  if (message?.consent_to_share === false || message?.privacy_opt_out === true) reasons.push('explicit_privacy_denial');
  if (optOutChats.has(messageChatId)) reasons.push('chat_opt_out');
  for (const id of sourceChatIds) if (optOutChats.has(id)) reasons.push('source_chat_opt_out');
  if (!lineageOk.value) reasons.push('lineage_incomplete');
  if (lineageDenied) reasons.push('lineage_privacy_denial');

  return {
    allowed: reasons.length === 0,
    reasons: [...new Set(reasons)],
    messageChatId,
    sourceChatIds: [...sourceChatIds],
    isChannel
  };
}

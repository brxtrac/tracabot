export const GROUP_MODE_ADMIN = 'admin_protection';
export const GROUP_MODE_OBSERVER = 'observer';

export const DESTRUCTIVE_TELEGRAM_METHODS = Object.freeze([
  'banChatMember',
  'unbanChatMember',
  'restrictChatMember',
  'deleteMessage'
]);

const DESTRUCTIVE = new Set(DESTRUCTIVE_TELEGRAM_METHODS);
const ADMIN_STATUSES = new Set(['creator', 'administrator']);

export function isDestructiveTelegramMethod(method = '') {
  return DESTRUCTIVE.has(String(method || ''));
}

function bool(value) {
  return value === true;
}

/**
 * Normalize one live getChatMember result (or my_chat_member.new_chat_member)
 * into the effective mode and the exact Telegram rights it proves. Missing or
 * failed lookups are observer/degraded, never admin.
 */
export function resolveGroupCapabilities({ chatId = '', member = null, botProfile = null, error = '', source = 'getChatMember', checkedAt = Date.now() } = {}) {
  const status = String(member?.status || '').toLowerCase();
  const known = Boolean(member && status);
  const admin = known && ADMIN_STATUSES.has(status);
  const creator = known && status === 'creator';
  const isMember = known && (admin || status === 'member'
    || (status === 'restricted' && member?.is_member !== false));
  const removed = known && (['left', 'kicked'].includes(status)
    || (status === 'restricted' && member?.is_member === false));
  const canRestrictMembers = admin && (creator || bool(member?.can_restrict_members));
  // Telegram only proves delete ability with an explicit true for a normal
  // administrator. Creator status is the Telegram exception.
  const canDeleteMessages = admin && (creator || member?.can_delete_messages === true);
  const canPostMessages = known && !removed && (admin || status === 'member'
    || (status === 'restricted' && member?.is_member !== false && member?.can_send_messages !== false));
  const privacyDisabled = botProfile?.can_read_all_group_messages === true;
  const privacyKnown = botProfile !== null && botProfile?.can_read_all_group_messages !== undefined;
  const allMessages = known && !removed && admin;
  // BotFather privacy disabled is only a delivery configuration. For observer
  // mode it is not proof that the current group membership receives all
  // ordinary messages; a leave/re-add can be required for it to take effect.
  const broaderDeliveryUnverified = known && !removed && !admin && privacyDisabled;
  const ordinaryMessageVisibility = removed
    ? 'none'
    : allMessages
      ? 'all'
      : broaderDeliveryUnverified
        ? 'broader_delivery_unverified'
        : (privacyKnown ? 'limited' : 'unknown');
  const degraded = !known || Boolean(error);
  const mode = admin ? GROUP_MODE_ADMIN : GROUP_MODE_OBSERVER;

  const coverage = degraded
    ? {
      memberEvents: 'unknown',
      joins: 'unknown',
      banCapture: 'unknown',
      ordinaryMessages: 'unknown',
      history: 'unavailable',
      unbanRecovery: 'unknown',
      eventFeedComprehensive: false,
      enforcementComprehensive: false,
      comprehensive: false
    }
    : {
      memberEvents: admin ? 'live_chat_member' : 'none',
      joins: admin ? 'live_chat_member_and_service' : (isMember ? 'service_messages_only' : 'none'),
      banCapture: admin ? 'live_chat_member' : 'none',
      ordinaryMessages: removed
        ? 'none'
        : allMessages
          ? 'all_group_messages'
          : broaderDeliveryUnverified
            ? 'broader_delivery_unverified'
            : (privacyKnown ? 'privacy_limited' : 'unknown'),
      history: 'unavailable',
      unbanRecovery: admin ? 'live_chat_member' : 'none',
      eventFeedComprehensive: admin,
      enforcementComprehensive: admin && canRestrictMembers,
      comprehensive: admin && canRestrictMembers
    };

  return {
    chatId: String(chatId || ''),
    status: known ? status : 'unknown',
    source,
    checkedAt,
    degraded,
    error: String(error || '').slice(0, 200),
    mode,
    isAdmin: admin,
    isCreator: creator,
    isMember,
    removed,
    botOperationsEnabled: known && !removed,
    canRestrictMembers,
    canDeleteMessages,
    canPostMessages,
    canRemoveMembers: canRestrictMembers,
    canUnbanMembers: canRestrictMembers,
    canRunJoinChallenge: canRestrictMembers,
    canObserveChatMember: admin,
    canVerifyJoins: admin,
    canObserveServiceJoins: isMember,
    canObserveBanEvents: admin,
    canReadAllGroupMessages: privacyDisabled,
    privacyModeKnown: privacyKnown,
    privacyModeEnabled: privacyKnown ? !privacyDisabled : null,
    broaderDeliveryUnverified,
    ordinaryMessageVisibility,
    unseenHistoryAvailable: false,
    updateSubscription: {
      chatMember: true,
      myChatMember: true
    },
    coverage,
    rights: {
      canRestrictMembers,
      canDeleteMessages,
      canManageChat: admin && (creator || bool(member?.can_manage_chat)),
      canInviteUsers: admin && (creator || bool(member?.can_invite_users)),
      canPinMessages: admin && (creator || bool(member?.can_pin_messages)),
      canPromoteMembers: admin && (creator || bool(member?.can_promote_members)),
      canChangeInfo: admin && (creator || bool(member?.can_change_info))
    }
  };
}

export function groupCapabilityStatusLabel(capabilities = {}) {
  if (capabilities.degraded) return '⚠️ Degraded / permission lookup unavailable';
  if (capabilities.removed) return '⛔ Bot removed from group';
  if (capabilities.mode === GROUP_MODE_ADMIN) {
    return capabilities.canRemoveMembers
      ? '🛡️ Admin protection'
      : '🛡️ Admin event observation (no remove rights)';
  }
  return '👁️ Observer (partial coverage)';
}

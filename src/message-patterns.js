const KEYCAP_MARKS = /[\uFE0F\u20E3]/g;
const GAMBLING_CONTEXT = /\b(?:bc\s*games?|casino|gambl(?:e|ing)|sportsbooks?|bet(?:s|ting)?|wager(?:s|ing)?|slots?)\b/i;
const PROMOTIONAL_OFFER = /\b(?:bonuses?|free\s+(?:money|cash|credit)|giveaways?|new\s+(?:players?|users?|customers?)|sign[ -]?up|welcome\s+(?:offers?|bonuses?)|dropping\s+\$?\s*\d|claim\s+\$?\s*\d)\b/i;
const PRESSURE_OR_PAYMENT = /\b(?:urgent|hurry|last chance|limited|now|expires?|instant(?:ly)?|get in|hit(?:s)?\s+(?:your\s+)?wallet|funds?\s+(?:hit|arrive|credit))\b/i;
const PROMOTIONAL_ACTION = /\b(?:claim\s+(?:the\s+)?bonus|claim\s+\$?\s*\d|sign[ -]?up\s+now|join\s+now|get\s+in\s+now|funds?\s+(?:hit|arrive|credit)(?:s)?\s+(?:your\s+)?wallet|wallet\s+instant(?:ly)?)\b/i;
const WARNING_CONTEXT = /\b(?:do not|don't|never)\s+(?:claim|trust|join|sign)|\b(?:warning|warned|scammers?\s+say|report\s+(?:this|these))\b/i;

export function canonicalizeMessageText(value = '') {
  return String(value)
    .normalize('NFKC')
    .replace(KEYCAP_MARKS, '')
    .replace(/\s+/g, ' ')
    .trim();
}

export function detectGamblingPromotion(value = '') {
  const text = canonicalizeMessageText(value);
  const gambling = GAMBLING_CONTEXT.test(text);
  const offer = PROMOTIONAL_OFFER.test(text);
  const pressureOrPayment = PRESSURE_OR_PAYMENT.test(text);
  const promotionalAction = PROMOTIONAL_ACTION.test(text);
  const warning = WARNING_CONTEXT.test(text);
  return {
    matched: gambling && offer && pressureOrPayment && promotionalAction && !warning,
    gambling,
    offer,
    pressureOrPayment,
    promotionalAction,
    warning
  };
}

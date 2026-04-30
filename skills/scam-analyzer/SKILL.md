---

name: scam_analyzer

description: Analyzes incoming Telegram messages or users for scams, impersonation, phishing, or suspicious activity. Outputs structured JSON for further action (log/ban). High confidence required for auto-actions. Uses heuristics + LLM reasoning.

user-invocable: true

tags: [security, telegram, scam-detection, community-protection]

version: 0.1.0

author: ClawShield Team (template)

---



# Scam Analyzer Skill



## When to Use

- Automatically on every new message in protected groups (configure via agent routing).
- Automatically on every new Telegram join event and periodic proactive scan of recently observed users.

- On explicit commands: /scan @username or /analyze [message text].
- On natural queries such as "@tracabot is @username a fraudster?" or replies asking "is this scam?".

- Before any ban or report action.



## Inputs

- `message_text`: string (the chat message)

- `user_info`: object {username, user_id, join_date, bio, message_count, is_admin_claim}

- `group_context`: {group_id, group_name, recent_bans}



## Workflow (Strict)

1. **Heuristics Check** (fast, rule-based):

   - Urgency words: "fast", "limited", "claim now", "hurry", "exclusive".

   - Crypto/giveaway promises: "free USDT", "airdrop", "double your crypto", "verify wallet".

   - Impersonation flags: Username similar to known admin/mod (Levenshtein distance <3 or contains "admin", "mod", "support" + new account). Bio claiming official role without verification.

   - Suspicious links: Shorteners (bit.ly, t.me short), unknown domains, or "verify" / "claim" pages.

   - New/low-activity user + high-value ask.

   - Common TG scam patterns: "DM me for details", fake support tickets, pump & dump signals.



2. **LLM Deep Analysis** (if heuristics flag or on /scan):

   - Prompt the core model: "You are a veteran Telegram scam hunter. Analyze this message and user for fraud indicators. Consider context of crypto communities. Output ONLY valid JSON: {\"is_scam\": boolean, \"confidence\": 0-100, \"scam_type\": \"giveaway|impersonation|phishing|other\", \"evidence\": [\"list of reasons\"], \"recommended_action\": \"ban|warn|ignore|report\", \"explanation\": \"short human-readable\"}"

   - Cross-reference with DKG v10 Context Graph evidence for the actor, wallets, scam patterns, blacklisted addresses, and community-verified flags.



3. **Output** (MANDATORY structured JSON, no extra text):

   ```json

   {

     "is_scam": true,

     "confidence": 92,

     "scam_type": "giveaway",

     "evidence": ["Urgency language + free crypto promise", "New account (joined 2h ago)", "Username mimics @realadmin (similarity 0.85)"],

     "recommended_action": "ban",

     "explanation": "Classic fake airdrop impersonating group admin. High risk to community funds."

   }

   ```



4. **Edge Cases**:

   - Confidence >=85: publish finding to DKG v10 and ban if admin rights are available; otherwise alert group admins with DKG evidence.

   - Low confidence (<70): Log as "suspicious" only, no auto-ban. Suggest admin review.

   - False positive risk: Always provide evidence. User can /override.

   - Legit promotions: Check if from verified admin or whitelisted.



## Tools Available to You

- Built-in: message history, user lookup (if OpenClaw exposes), web_browse for link safety.

- dkg-logger (companion skill): For pulling recent similar reports.



## Example Invocation

User: /scan @newuser123 "Claim your 500 USDT now! Link in bio fast!!!"

Agent: [runs analysis] → Returns JSON above.



**Guardrails**: Never ban without high confidence + evidence. Prioritize community safety but minimize disruption. Log EVERY analysis to DKG for learning (even negatives for false-positive training data).

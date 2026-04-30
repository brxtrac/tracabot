---

name: ban_guard

description: Handles quick admin commands like /ban, /warn, /report for Telegram groups. Executes bans (requires bot admin rights), logs EVERY action to DKG via dkg-logger skill, provides evidence-based decisions. Agent-first, auditable.

user-invocable: true

tags: [telegram, moderation, ban, security, dkg-logging]

version: 0.1.0

author: ClawShield Team (template)

---



# Ban Guard & Command Skill



## Supported Commands (in group chats or DM to bot)

- `/ban @username [reason]` or `/ban user_id [reason]` → Immediate ban + DKG log.

- `/warn @username [message]` → Warn user + log.

- `/report @username [details]` or reply to message → Manual report → analyze + log to DKG (no auto-ban).

- `/scan @username` or reply → Full scam_analyzer run + recommendation.

- `/stats` → Query DKG for community threat summary (top scam types, recent activity, false positive rate).

- `/shield status` → Agent health, DKG connection, protected groups count.



## Workflow for /ban or Auto-Action

1. **Parse Command**: Extract target user, reason. Validate admin issuer (or bot has elevated rights in group).

2. **Pre-Check**: Run scam_analyzer on recent messages/user profile if not already done.

3. **Confirm High Confidence**: If <85% or ambiguous → "⚠️ Recommendation: ban? Evidence: [list]. Reply YES to proceed or provide override."

4. **Execute Ban** (if approved or confidence >=85):

   - Use OpenClaw Telegram channel tools or Bot API: `banChatMember` with until_date if temporary.

   - Confirm success via TG API response.

   - If bot lacks admin rights, immediately report to group admins with DKG evidence, message context, and recommended action.

5. **Log to DKG** (MANDATORY, via dkg-logger skill):

   - event_type: "ban_executed"

   - payload: {target_user, reason, evidence_from_analyzer, confidence, executed_by: "admin|auto", timestamp, group_id}

   - This creates immutable record: "Why was this user banned? Full provenance."

   - High-confidence findings are also published as `fraud_finding` Knowledge Asset-shaped records in Shared Memory for cross-community reuse.

6. **Notify Group**: "🛡️ @scammer banned for [reason]. Logged to DKG for community transparency. UAL: [link]"

7. **Post-Ban**: Monitor for evasion (new accounts) → auto flag.



## For /report or Manual

- Always analyze first.

- Log as "report_submitted" even if not banned (builds dataset).

- Suggest: "This matches 3 prior logged scams in our Shared Memory. Recommend ban?"



## DKG Logging Details (see dkg-logger skill)

- All actions create assertions in "claw-shield-intel" Context Graph.

- Enables /stats: "In last 7 days: 12 scams detected (8 giveaway, 3 impersonation), 9 bans executed. 2 false positives logged for learning."

- Shared across communities: One group's intel helps others (e.g., known scammer IDs).



## Security & Permissions

- Bot MUST be group admin with ban rights.

- Commands restricted to group admins (check via TG API is_admin).

- Sandbox: Auto-ban only at confidence >=85 and only when bot admin rights are confirmed.

- Audit: Every decision logged → full transparency, reduces abuse claims.



## Example Interaction

Admin: /ban @cryptoairdropbot "Fake giveaway scam, new account mimicking support"

Agent: [analyzes] "High confidence 94%. Evidence: ... Proceeding with ban + DKG log."

[Ban executed]

"✅ Banned. Event #47 logged to DKG Working Memory. View full report: [UAL or explorer link]"



## Future Enhancements (Post-Submission)

- Temporary bans with auto-unban timer (cron skill).

- Appeal process logged to DKG.

- Integration with external scam DBs (via browser tool).

- Multi-group sync via Shared Memory.



**This skill + dkg-logger makes every moderation action a permanent, queryable, shareable knowledge asset — exactly what DKG v10 Working/Shared Memory is for.**



Guardrails: Human-in-loop for edge cases. Prioritize "do no harm" — better to warn than over-ban. All code open for community audit.

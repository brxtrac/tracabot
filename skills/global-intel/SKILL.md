---

name: global_intel

description: Queries the shared global "claw-shield-intel" Context Graph for cross-community insights, reputation scores, emerging threats, and blacklists. This is the feature that makes ClawShield vastly superior to any isolated TG bot — real-time collective intelligence from every participating community.

user-invocable: true

tags: [dkg, shared-memory, global-intel, reputation, emerging-threats, bounty]

version: 0.1.0

author: ClawShield Team (template)

---



# Global Intel Skill — Shared Context Graph Queries



## Purpose (The Killer Feature for Superiority)

This skill lets the agent **pull live intelligence from the entire network** before making local decisions. 

- "Is this user known as a scammer in other groups?"

- "What are the hottest new scam tactics across Telegram right now?"

- "Reputation score for this account based on global history?"



No other TG bot has this. This is pure DKG Shared Memory power.



## Supported Commands / Triggers

- `/globalintel` or `/networkstats` — Overall network health + top threats.

- In analysis: Auto-call this skill to enrich local scam_analyzer output with global context.

- "Check reputation of @username"

- "What giveaway scams are trending network-wide?"



## Workflow

1. **Query the Shared Graph** (use DKG HTTP query endpoints or SPARQL-like on assertions in "claw-shield-intel"):

   - Example for user reputation:

     ```bash

     curl -X POST "$DKG_NODE_URL/api/assertion/scam_reports/query" \

       -H "Authorization: Bearer $DKG_AUTH_TOKEN" \

       -d '{"filter": {"user_id": "123456"}, "aggregate": "count_bans"}'

     ```

   - Or broader: Recent high-confidence reports filtered by scamType="giveaway" + last 7 days.



2. **Enrich Local Decision**:

   - If global hits > 2 in other communities → boost confidence + recommend stronger action.

   - Emerging pattern match → warn group proactively.



3. **Output Structured Insights**:

   ```json

   {

     "global_reputation": "high_risk",

     "reports_across_communities": 7,

     "recent_similar_scams": 12,

     "top_threat_this_week": "impersonation_of_admins",

     "recommendation": "Ban immediately + log as high-priority"

   }

   ```



4. **Log the Query** (optional, for audit): Record that global intel was consulted.



## Why This Matters for the Bounty & Real Impact

- **Shared Memory in Action**: Every publish from any community instantly improves *your* agent's intelligence.

- **Network Effects**: Adoption = exponential value. 10 groups = good. 100 groups = unstoppable collective shield.

- **Agent-Native**: Purely conversational. "Hey ClawShield, is this new user suspicious globally?"

- **Forward Path**: These queries become even more powerful with Verified Memory oracles in later rounds.



## Implementation Notes

- Start with simple filters on existing assertions (scamType, groupCategory, confidence thresholds).

- For advanced: Use DKG's semantic/query capabilities or build lightweight aggregations.

- Tag all publishes richly so queries are fast and useful.



**This skill turns ClawShield from "just another moderator" into the network's shared immune system.** Use it in scam_analyzer and ban-guard flows for maximum effect.

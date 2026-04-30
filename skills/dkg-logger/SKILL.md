---

name: dkg_logger

description: Publishes structured scam reports, detections, bans, and actions to OriginTrail DKG v10 Working/Shared Memory as Context Graph assertions. Enables verifiable, queryable, cross-community shared intelligence. Uses public HTTP API only.

user-invocable: true

tags: [dkg, origintrail, logging, provenance, shared-memory, bounty]

version: 0.1.0

author: ClawShield Team (template)

---



# DKG Logger Skill (Working Memory Integration)



## Purpose (Bounty Critical)

Logs all ClawShield activity to DKG v10 **Context Graph** "claw-shield-intel" (or per-community variants). 

- **Working Memory**: Real-time reports (pre-verification).

- **Shared Memory**: Patterns visible to other agents/communities.

- Each entry = RDF assertion with UAL for full provenance. Ready for promotion to Verified Memory.



## Prerequisites (User Must Configure)

- Running DKG v10 node (local/testnet): `dkg start`

- Auth: `DKG_AUTH_TOKEN` env or `~/.dkg/auth.token`

- Node URL: Default `http://127.0.0.1:9200` (or your public/test endpoint). Set in skill config or env `DKG_NODE_URL`.

- Test first with: https://github.com/OriginTrail/dkg-hello-world



## Inputs

- `event_type`: "risk_check" | "risk_query" | "scam_detection" | "fraud_finding" | "impersonator_detected" | "ban_executed" | "report_submitted" | "false_positive"

- `payload`: JSON object with details (user_id, username, wallets, patterns, group_id, evidence, confidence, action_taken, timestamp, admin_approver?, group_category="crypto|nft|general")

- `context_graph_id`: Optional, default "claw-shield-intel" (the **global shared graph** — this is what enables cross-community intelligence)



## Workflow (Exact Steps - Agent Follows This)

1. **Ensure Context Graph Exists**:

   ```bash

   curl -X POST $DKG_NODE_URL/api/context-graph/create \

     -H "Authorization: Bearer $DKG_AUTH_TOKEN" \

     -d '{"id": "claw-shield-intel"}' || echo "Already exists (409 OK)"

   ```



2. **Construct Assertion Name** (e.g. "scam_reports" or "action_logs_<group>"):

   - Use event_type for assertion: `scam_reports`, `impersonator_detections`, `community_actions`



3. **Build RDF Triples** (for /api/assertion/<name>/write):

   - subject: blank node or generated UUID

   - Triples (example for scam_report):

     - rdf:type → claw-shield:ScamReport

     - schema:identifier → "scam-2026-04-27-uuid123"

     - dcterms:created → "2026-04-27T13:41:00Z"^^xsd:dateTime

     - dcterms:creator → "did:dkg:agent:claw-shield-v1" (or admin DID)

     - schema:description → "Fake airdrop by @scammer123 in group XYZ"

     - claw-shield:scamType → "giveaway"

     - claw-shield:confidence → "92"

     - claw-shield:evidence → JSON string of evidence array

     - claw-shield:groupId → "@testgroup"

     - claw-shield:ual (if promoting later) → will be returned

     - claw-shield:status → "working_memory"



4. **POST to DKG** (use curl or agent's terminal tool; handle response):

   ```bash

   curl -X POST "$DKG_NODE_URL/api/assertion/scam_reports/write" \

     -H "Authorization: Bearer $DKG_AUTH_TOKEN" \

     -H "Content-Type: application/json" \

     -d '{

       "triples": [

         {"predicate": "rdf:type", "object": "claw-shield:ScamReport"},

         {"predicate": "dcterms:created", "object": "\"2026-04-27T...\"^^xsd:dateTime"},

         {"predicate": "dcterms:creator", "object": "\"did:dkg:agent:claw-shield\""},

         {"predicate": "schema:description", "object": "\"[full evidence]\""},

         {"predicate": "claw-shield:confidence", "object": "92"},

         {"predicate": "claw-shield:group", "object": "\"@mycommunity\""}

       ]

     }'

   ```

   - Capture response UAL or assertion ID. Return to user: "Logged to DKG! UAL: [link or ID] View: https://origintrail.io/explorer/... "



5. **Query Before Action**:

   - On message, join, proactive scan, or @query, query the Context Graph for actor username, Telegram user ID when known, wallet addresses, scam patterns, and communityVerifiedFlag values.
   - Return risk score + evidence to the caller.

6. **Error Handling**:

   - If node down: Queue locally + retry (cron skill).

   - Auth fail: Instruct user to check token.

   - Always log the attempt (even failures) for audit.



## Output

- Success: "✅ Event logged to **global shared** DKG Context Graph 'claw-shield-intel'. UAL: [returned]. This now benefits *every* ClawShield community."

- Include link to explorer if available.

- **Query Examples for Shared Intelligence** (use in global-intel or stats skills):

  - "How many reports for this user_id across all groups?"

  - "Top scam_types in last 48h network-wide?"

  - "Reputation score: number of bans vs. false positives for @username"

  - These queries run against the same Context Graph, giving your local agent global context before any decision.



## The Shared Knowledge Advantage (Core Differentiator)

By publishing **with rich tags** (scamType, groupCategory, confidence), the graph becomes queryable for:

- Cross-community blacklists

- Emerging threat detection (e.g., new impersonation patterns spreading)

- Reputation systems

- Autoresearch by other agents



This is why ClawShield is superior: **Your bot gets smarter the more communities join.** Isolated bots can't do this.



## Integration Notes (for Bounty Reviewers)

- Uses **only public DKG v10 HTTP API** (no internal packages).

- Data structured for seamless promotion to Verified Memory (add conviction tags later).

- Supports Shared Memory: Same graph queryable by Hermes/OpenClaw agents in other communities.

- Provenance: Every triple has creator/timestamp → full audit trail.

- Terminology: Context Graph, Assertion, Working Memory (pre-verif layer).



## Example Full Log (scam_detection)

Event logged → Community now has immutable record. Other agents can autoresearch: "What are current giveaway scam patterns in crypto TGs?"



**Guardrails**: Only publish with explicit admin approval for sensitive actions. No PII beyond necessary (user_id hashed if possible). Complies with v10 design principles: agent-first, trust gradient, conversational.



**Test Command**: After setup, run `/log_test` to publish a sample greeting-style entry.

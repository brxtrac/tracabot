---
name: artefact-curator
description: Decides whether chat events or conversation artefacts should stay in local Working Memory, be committed to DKG Shared Memory, or queued for admin /review. Uses full Tracabot Context Graph history (including prior admin decisions) for smarter decisions.
user-invocable: true
tags: [openclaw, dkg-v10, artefact, review-queue, curator]
version: 1.0.0
---

# Artefact Curator Skill for Tracabot

This skill helps the Tracabot agent (and external OpenClaw agents) make high-quality decisions about what belongs in Working Memory vs. Shared Memory vs. the admin review queue.

## Two curators, different jobs

Do not treat these as the same tool.

- `decide_artefact_action` on `node ./bin/tracabot-skill.js` is a recommendation only. It scores a draft and can look up prior admin history. It returns `local_wm_draft`, `commit_to_swm`, or `queue_for_admin_review`. It does not promote a Working Memory Knowledge Asset by itself.
- `node ./bin/tracabot-curator.js --once` is the production DKG gate. It lists unsealed Working Memory drafts, drops weak or expired ones, and asks the OpenCode `tracabot-curator` agent (`9router/cx/gpt-6-sol`, variant `medium`) for JSON. Promote only when the message itself supports concrete fraud, impersonation, or harmful scam behavior and the evidence string is an exact substring. Invalid, unavailable, or `hold` reviews never share. Run one instance per bot identity.

## Tool

Call the recommendation through the tracabot skill bridge:

`decide_artefact_action`

Use `sort_conversation_artifact` only for the separate OpenClaw learning-loop sorter. That path is not the DKG Working Memory curator.

Core logic:
- Takes a draft artefact or monitored chat event + optional graph context.
- Runs quality scoring + performs a live query against the Tracabot Context Graph (via `queryAdminHistoryForActor`) for prior admin actions, bans, reviews, and cross-group signals on the actor.
- Returns recommended action: `local_wm_draft`, `commit_to_swm`, `queue_for_admin_review`, plus quality, reasoning, `graph_history`, and whether a cross-group boost was applied.
- The decision is used by the learning loop, live message handling (tactic_candidate artefacts), and external OpenClaw agents.

## Memory Policy (enforced)
- Weak, ambiguous, or low-history signals → local WM draft only (useful for future learning).
- Evidence-backed or repeated patterns with admin history → Shared Memory with commit receipt.
- Borderline or high-impact → queued as `risk_review_needed` for human admin via /review.

This skill is the central decision point that makes the Tracabot Context Graph grow intelligently over time.

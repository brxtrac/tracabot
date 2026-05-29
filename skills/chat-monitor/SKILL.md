---
name: chat-monitor
description: Allows external OpenClaw agents to poll or push Telegram chat messages for scam/spam analysis, with decisions on whether to create artefacts or queue for review using the full Tracabot Context Graph.
user-invocable: true
---

# Chat Monitor Skill

This skill is the bridge for external agents to participate in monitoring without needing their own Telegram connection.

Core tools: `monitor_chat_event` + `decide_artefact_action` (via the tracabot skill).

`monitor_chat_event` classifies incoming chat messages for scam/spam risk (with DKG Shared Memory lookup) and can write unsafe events.

`decide_artefact_action` (the artefact curator) makes the WM / SWM / admin-review decision. It performs live queries against the Tracabot Context Graph for prior admin actions on the actor (including cross-group history) and returns a recommendation plus graph evidence.

External OpenClaw agents can poll chats and use the curator for intelligent, memory-aware artefact decisions. The live Tracabot bot also consults the curator for low-confidence tactic candidates.

# TRACaBot Demo Video Script (5-8 Minutes)

Legacy draft. Use `docs/TESTING.md`, `docs/DEMO.md`, and `docs/DESIGN_BRIEF.md` for current testing and bounty review guidance.


**Goal**: Prove it's a *working*, production-grade integration with real DKG v10 logging. Show end-to-end: detection → action → immutable log → queryable memory. Judges should see "this protects communities *today* and builds shared knowledge."



**Recording Tips**:

- Screen + voiceover (clear, enthusiastic).

- Use real (or realistic test) Telegram group + local DKG node.

- Timestamp chapters in description.

- End with "This is open source — fork it, protect your group, submit your own enhancements."

- Host on YouTube (unlisted or public) or Loom. Link in GitHub README and dkg-integrations PR.



## Video Structure & Narration Script



**[0:00 - 0:45] Title & Hook**

- Screen: TRACaBot logo or text overlay + Telegram group screenshot with a scam message.

- Voice: "Hi OriginTrail team. This is TRACaBot: an open-source OpenClaw Telegram agent that detects scammers and impersonators in real time, executes guarded moderation commands like /ban, and writes evidence-backed events to OriginTrail DKG v10 Shared Memory and the tracabot Context Graph.

Protecting communities while building verifiable, agent-native threat intelligence. Perfect fit for Round 1 OpenClaw priority."



**[0:45 - 1:30] Problem & Vision**

- Show examples of real TG scams (screenshots, no doxxing).

- "Rose and Shieldy are great for basic rules, but they can't reason about new impersonation tactics or share knowledge across groups. Scammers just rotate. 

TRACaBot fixes this with agent-readable evidence and DKG shared memory."



**[1:30 - 3:00] Live Setup (Fast-Forward OK)**

- Terminal: `openclaw gateway` running.

- Show `skills/tracabot/skill.json` and the `tracabot-skill` CLI bridge.

- Quick: Open DKG node status (`dkg status`).

- TG: Add bot to test group (show bot is admin).

- "Skills hot-reload — no restart needed."



**[3:00 - 5:30] Core Demo — Detection + Action + DKG Log (The Money Shot)**

- In TG group chat (screen share):

  1. Send test scam as "bad actor": "🚨 URGENT: Free 2000 USDT airdrop for all members! Click t.me/fakeclaim NOW or miss out!!! DM @supportadmin to verify 🔥"

     (Make it look real — urgency + crypto + impersonation of support).

  2. Bot auto-replies (or on slight delay): "TRACaBot Analysis: HIGH CONFIDENCE SCAM (94%). Type: Giveaway + Impersonation. Evidence: [lists urgency words, suspicious domain, support lure]. Recommended: Ban. Logging to DKG..."

  3. Admin (or auto if high-conf): Type `/ban @badactor "Fake airdrop impersonating support"`

  4. Bot: "✅ Banned. Event logged to DKG Context Graph 'tracabot' as assertion 'action_logs'. UAL: [show returned UAL or explorer link]. Full provenance recorded."

- Switch to DKG side:

  - Show curl or DKG UI: Query the assertion → See the RDF triples with confidence, evidence, creator, timestamp.

- "This is evidence-backed Shared Memory. Local weak observations stay in TRACaBot working memory, while accepted evidence becomes queryable by any other TRACaBot/OpenClaw agent using the same Context Graph."



**[5:30 - 6:30] /stats Command — Shared Memory in Action**

- In TG: `/stats`

- Bot: "TRACaBot Community Health (last 7 days, from DKG Shared Memory):

  - 14 detections (9 giveaway, 4 impersonation, 1 phishing)

  - 11 bans executed (all logged with UALs)

  - 2 false positives (logged for model improvement)

  - Top threat: New accounts claiming 'admin verification'

  - Your group protected. Total across 3 connected communities: 47 reports."

- "This is the power of Shared Memory — collective defense, not silos."



**[6:30 - 7:30] Technical Highlights & v10 Compliance**

- Quick screen: dkg-logger SKILL.md showing exact HTTP API calls (public endpoints only).

- "Uses the OpenClaw DKG adapter for Context Graph creation, Shared Memory writes, Shared Memory queries, and targeted publication. High-confidence reports automatically publish to the Context Graph once they meet policy."

- "Agent-first: All via natural chat. No dashboards. Sandboxed skills. Full tests + security notes in repo."



**[7:30 - 8:00] Call to Action & Close**

- "This is fully open source (MIT). Deploy in 5 minutes to protect your group. 

  - GitHub: [link]

  - Design Brief + full code in repo.

  - Ready for dkg-integrations PR.

- OriginTrail: This turns DKG into the shared brain for thousands of protected communities. Let's make agent memory verifiable and useful *today*.

- Questions? Happy to iterate. Thanks for the opportunity — excited to contribute to the v10 ecosystem. 🛡️🦞 #cfi-dkgv10-r1"



**Post-Production**:

- Chapters in YouTube: Setup, Detection, Ban+Log, Stats, Technical, Submit.

- Description: Full links, "Fork & submit your own integration!", bounty tag.

- Thumbnail: Telegram scam message + DKG logo + "TRACaBot x OriginTrail".



**Variations for Stronger Submission**:

- Add 2nd community showing Shared Memory (one group logs, another queries same graph).

- Show false-positive handling: Admin overrides → logged as learning data.

- Mention test coverage (run `npm test` live).

- End with "This meets every Flagship criterion: adoption, fit, faithfulness, engineering, impact."



**Length**: Keep tight — judges watch many submissions. Focus on *working DKG integration* and *real protection*.



Record this, upload, link it — your submission is now bounty-competitive. Good luck! This will stand out.

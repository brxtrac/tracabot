# Bounty Reference

Submitted for OriginTrail DKG v10 Bounty Program Round 1 (`cfi-dkgv10-r1`): Working and Shared Memory integrations for LLM-Wiki/autoresearch agents, with OpenClaw as a priority target.

## Summary

tracabot is an OpenClaw-compatible Telegram Shieldy-style anti-scam agent. It detects phishing, fake airdrops, support/admin impersonation, and suspicious moderation events, then writes structured scam knowledge to DKG v10 Shared Memory in the `claw-shield-intel` Context Graph.

Telegram commands are registered on startup:

- `/scan`: check a user, wallet, or replied message for scam risk.
- `/report`: report a suspicious user, wallet, or message to DKG.
- `/ban`: ban a replied user and publish ban evidence.
- `/stats`: show recent fraud checks and detections.

## DKG v10 Fit

- Memory layers: Working Memory and Shared Memory.
- Public interface: `dkg` CLI subprocess only.
- Primitives: Context Graph, Assertion, Entity, Integration, Curator, Knowledge Asset, Knowledge Collection, UAL.
- Curator model: automatic Verified Memory `PUBLISH` is intentionally disabled; promotion is documented as a Curator-controlled path.

## Verification

Local OpenClaw mini PC verification:

```text
dkg --version
10.0.0-rc.1-dev.1777554347.b80a299

dkg status
Node: BRX
Role: edge
PeerId: 12D3KooWQm9sJCkUTU7kRXsNQttHaYTQV4ZjR8QaBNVUMqVMLC6R

npm run demo
Writing to shared memory: 10/10 quads
Share operation: swm-1777560651535-gq4j3e9f
Graph: did:dkg:context-graph:claw-shield-intel/_shared_memory
```

Tests and audit:

```text
npm test
2 test files passed

npm audit --omit=dev
found 0 vulnerabilities
```

Telegram runtime:

```text
Bot: @tracethembot
Service: tracabot.service active (running)
```

## Security Attestation

I attest that this code is my own work or properly licensed, contains no intentional backdoors, uses no dynamic remote code loading, and has no preinstall or postinstall scripts. Network egress is declared as `api.telegram.org` plus the configured local DKG node. DKG write authority is limited to Context Graph creation and Shared Memory writes; Verified Memory publishing remains Curator-controlled.

## Maintenance

Maintainer: valcyclovir  
Support window: at least six months after registry acceptance.

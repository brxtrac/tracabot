# OpenDKG collaboration alignment

Status: **proposal and readiness only**. TRACaBot is not yet an accepted OpenDKG
project. Nothing in this document transfers ownership, creates a shared graph,
commits funds, or changes TRACaBot's license or operating authority.

## Current position

TRACaBot remains an independent, MIT-licensed project maintained in
`brxtrac/tracabot`. The proposed OpenDKG umbrella is a collaboration layer for
independent projects, not a merger of source repositories. TRACaBot intends to
participate if the founders and maintainers agree on the terms below; acceptance
is pending.

The initial joint-rules discussion is intentionally narrow. Broader governance,
funding platforms, domains, legal entities, and shared infrastructure are later
decisions. This repository does not encode founder identities, contact details,
voting rules, financial commitments, or a governance charter.

## Ownership and authority boundaries

- Repository, organization, domain, release, and trademark ownership stay with
  the current TRACaBot owner unless a separate written decision changes them.
- An OpenDKG umbrella role does not grant TRACaBot graph curator, DKG write,
  Telegram admin, deployment, membership, appeal, or enforcement authority.
- TRACaBot creator-curator keys, community tokens, bot tokens, HMAC keys, and
  local databases remain under TRACaBot operator control.
- TRACaBot's curator/admin trust boundaries remain unchanged: evidence level,
  provenance, consent, exact identity, and independent approval still gate any
  promotion or removal.
- Cross-project collaboration does not make one project's evidence, reputation,
  or approval automatically trusted by another project.

## Proposed umbrella model

The proposed model is a public umbrella of independent projects. Each project
keeps its own repository, maintainers, license, releases, infrastructure, and
security process while sharing:

- public discussion of proposals and decisions;
- public progress updates and contribution records;
- shared goals and coordination notes;
- optional future DKG context-graph coordination with project-scoped provenance.

Public coordination records must contain only information that is already safe
to publish. Private founder contact details, private appeals, raw threat
evidence, moderator notes, credentials, and personal data stay private.

## Data and evidence separation

Keep three record classes separate:

1. **Public coordination records** - project status, proposals, decisions,
   contribution references, public proofs, and published allocations.
2. **Public threat records** - sanitized TRACaBot evidence already permitted by
   its evidence policy and public-reader projection.
3. **Private operational records** - appeal text, reporter identity, raw
   Telegram identifiers, message context, keys, tokens, and local-only evidence.

An umbrella coordination record must never be used as a shortcut to publish
private threat data, and a public threat record must not be treated as a
governance vote or funding proof.

## Future graph mapping (optional, not deployed)

If the projects later agree on a shared DKG context graph, the minimal mapping
would be:

- one umbrella coordination graph for public proposals, decisions, progress,
  contributions, and published funding allocations;
- one project subgraph or project-scoped provenance label per project;
- explicit `project`, `proposal`, `decision`, `contribution`, `allocation`, and
  `proof` references on coordination records;
- TRACaBot threat evidence staying in its existing context graph and evidence
  policy, with no automatic cross-project trust inheritance.

No shared graph, namespace, curator key, subgraph, or deployment exists today.
Creating one requires a separate human decision and a security/privacy review.

## Funding and contributions (proposed, not implemented)

- Project donations and general umbrella funding are separate.
- Published allocations should reference a public goal, contribution, decision,
  and proof.
- Smaller contributors should be eligible for grants through a published,
  reviewable process.
- No donation address, funding account, split percentage, payout, or financial
  commitment is created by this document.
- Contributions are recognized from public repository history and reviewed
  records, not from private messages or unverifiable claims.

## Readiness checklist

Repository baseline:

- [x] MIT `LICENSE` retained; no license change proposed.
- [x] `README.md` states the current independent-project status and links here.
- [x] `SECURITY.md` documents private reporting and data boundaries.
- [x] `CONTRIBUTING.md` documents review, testing, and privacy expectations.
- [x] GitHub Actions CI runs tests, command-loop checks, audit, and packaging.
- [x] Evidence levels, provenance, consent, and fail-closed behavior are
  documented and tested.
- [x] Public-reader and shared-write paths remain opt-in and sanitized.
- [x] Private appeal and creator-curator authority boundaries are documented.
- [x] Issue and pull-request templates ask for tests, privacy, and write-scope
  disclosure.

Still requiring a human decision:

- [ ] Accept, decline, or narrow TRACaBot's participation in the umbrella.
- [ ] Adopt a shared governance charter, membership rule, and decision process.
- [ ] Name public maintainers and a security contact for the umbrella.
- [ ] Adopt a code of conduct and enforcement process.
- [ ] Choose any shared discussion venue and moderation policy.
- [ ] Decide funding destinations, custody, allocation rules, grants, and
  publication format.
- [ ] Decide domain, legal entity, trademark, and public-representation details.
- [ ] Approve any shared DKG context graph, namespace, key custody, retention,
  and subgraph mapping.
- [ ] Approve any cross-project moderation, escalation, or evidence-sharing
  policy.
- [ ] Approve any future license, ownership, or repository-transfer change.

## Explicit non-claims

This document does not claim:

- that TRACaBot has been accepted into OpenDKG;
- that any shared graph, funding account, donation address, governance body, or
  joint domain exists;
- that OpenDKG has reviewed or endorsed TRACaBot's evidence or enforcement;
- that any founder, maintainer, or contributor has agreed to a financial or
  governance commitment;
- that TRACaBot is deployed as a public platform by this repository.

See `README.md` for the current feature and deployment status, `SECURITY.md` for
reporting, and `CONTRIBUTING.md` for the review workflow.

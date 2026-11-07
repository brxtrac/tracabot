# Contributing

TRACaBot is an independent, MIT-licensed project maintained for the OriginTrail
DKG v10 integration bounty with a minimum six-month support window after
registry acceptance. Collaboration under a proposed OpenDKG umbrella does not
transfer repository ownership or TRACaBot curator, admin, or enforcement
authority. See [docs/OPENDKG_ALIGNMENT.md](./docs/OPENDKG_ALIGNMENT.md).

## Workflow

1. Open or comment on an issue before large changes so scope and evidence
   expectations are clear.
2. Keep pull requests focused. Include affected callers, tests, fixtures, and
   configuration or documentation changes.
3. Run `npm test` and `npm run test:commands`. Run `npm audit --omit=dev` when
   dependencies or the package surface change.
4. Describe any new network egress, DKG write, public read, or enforcement path
   in the pull request and update `SECURITY.md` when the trust boundary changes.
5. A maintainer reviews the change before merge. Unreviewed changes are not
   accepted as project decisions or evidence.

## Security and privacy

- Never commit `.env`, bot or DKG tokens, private keys, local databases, raw
  Telegram identifiers, private appeal text, screenshots, or real user data.
- Report vulnerabilities privately as described in [SECURITY.md](./SECURITY.md),
  not in a public issue.
- Use synthetic or sanitized data in tests. Preserve the evidence policy:
  observations, allegations, admin enforcement, and confirmed findings are not
  interchangeable.
- Keep DKG writes, public reads, federation submissions, and automatic removal
  opt-in and fail closed by default.

## Vocabulary and review

Preserve the DKG v10 vocabulary: Context Graph, Working Memory, Shared Memory,
Knowledge Asset, Knowledge Collection, Integration, Curator, SHARE, and PUBLISH.
Pull requests should state the claim level and provenance of any new shared
evidence, the tests that cover failure and retraction paths, and any remaining
human decision or deployment step.

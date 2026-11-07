# Contributing

TRACaBot is an independent, MIT-licensed project maintained for the OriginTrail
DKG v10 integration bounty with a minimum six-month support window after
registry acceptance. It is published in the new repository
[OpenDKG/tracabot](https://github.com/OpenDKG/tracabot), with its original
maintainer repository retained at [brxtrac/tracabot](https://github.com/brxtrac/tracabot).
Publication does not transfer repository ownership or TRACaBot curator, admin,
or enforcement authority. See
[docs/OPENDKG_ALIGNMENT.md](./docs/OPENDKG_ALIGNMENT.md).

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

## Review evidence

`main` requires the `ai-review/evidence` status in addition to tests. It is
recorded by a maintainer from an actual independent review, not by PR content
and not as a GitHub pull-request approval or app identity claim.

Save the review artifact with the exact reviewed commit SHA:

````markdown
<!-- tracabot-review-evidence:v1 -->

```json
{
  "reviewed_sha": "<40-character commit SHA>",
  "verdict": "approved",
  "reviewer": "<reviewer identity>",
  "method": "<what was reviewed>",
  "reviewed_at": "<ISO-8601 timestamp>"
}
```

<review findings and limitations>
````

Dry-run first, then publish only after completing the review:

```bash
GITHUB_TOKEN=$(gh auth token) node scripts/record-review-evidence.js \
  --repo brxtrac/tracabot --pr <number> --artifact <path>
GITHUB_TOKEN=$(gh auth token) node scripts/record-review-evidence.js \
  --repo brxtrac/tracabot --pr <number> --artifact <path> --publish
```

The command verifies that the authenticated actor has `admin` or `maintain`
permission, the artifact targets the exact current open non-draft PR head, and
the PR belongs to the same repository. GitHub reports a maintain role as
`permission: "write"` with `role_name: "maintain"`; the publisher accepts that
role while rejecting ordinary `write` access and ambiguous custom roles. It
posts the artifact as a PR comment and creates an `ai-review/evidence` commit
status tied to that SHA. A new commit invalidates the old status; record a new
artifact for the new head. The artifact is public, so remove private notes,
credentials, raw identifiers, and other non-public material before publishing.

## License

TRACaBot is released under the MIT License in [`LICENSE`](./LICENSE). The
license text and copyright notice are unchanged. This repository retains MIT as
a repository-specific written exception to OpenDKG's Apache-2.0 default; it does
not change that default or relicense existing contributions. See
[`docs/OPENDKG_ALIGNMENT.md`](./docs/OPENDKG_ALIGNMENT.md#repository-specific-license-exception-2026-11-07).

By intentionally submitting a contribution, you agree that it is licensed under
the repository's MIT terms to the extent you hold the rights, and you confirm
that you have the authority to grant that license. You retain copyright; this is
not a copyright assignment.

OpenDKG's existing contribution process still applies. Contributors must follow
the [OpenDKG Contributor Agreement v1.0](https://github.com/OpenDKG/.github/blob/d56279b4f3c25dd8f9e68699d61be23a0c7a6b07/CONTRIBUTOR_AGREEMENT.md)
at the revision pinned by OpenDKG's public adoption record, and use the
Developer Certificate of Origin `Signed-off-by` trailer where required. Those
organization requirements are separate from, and do not replace, the
repository's MIT license. Do not submit code you cannot license under MIT.

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

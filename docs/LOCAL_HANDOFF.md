# Local Handoff

GitHub is currently blocked by account suspension, so this repository is staged locally for the same flow.

## Local Repositories

- Source repo: `/root/claw-shield-dkg-starter`
- Local bare remote: `/root/local-git/tracabot.git`
- Registry clone: `/root/dkg-integrations`
- Registry branch: `bounty/tracabot`

## Source Commit

```text
6df730105221177046c3eb8c4ee30770bf6fd6a7
```

## Registry Commit

```text
d14397a4df732d39e16488e14e8ec71fa59d7867
```

## Artifacts

- `/root/tracabot-main.bundle`
- `/root/dkg-integrations-tracabot.bundle`
- `/root/tracabot-dkg-integrations.patch`
- `/root/claw-shield-dkg-starter/tracabot-0.1.0.tgz`

## Resume Commands After GitHub Account Fix

```bash
cd /root/claw-shield-dkg-starter
git remote add github git@github.com:valcyclovir/tracabot.git
git push -u github main
```

Publish after creating an npm token and a GitHub release:

```bash
npm publish --provenance --access public
```

Then update `integrations/tracabot.json` if the pinned commit or package version changed.

```bash
cd /root/dkg-integrations
git remote add fork git@github.com:valcyclovir/dkg-integrations.git
git push -u fork bounty/tracabot
```

Open a PR to `OriginTrail/dkg-integrations` with:

```text
[Bounty] tracabot - OpenClaw + Telegram + DKG v10 Shieldy Bot
```

Use `docs/PR_BODY.md` as the PR body.

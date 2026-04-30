# Local Handoff

GitHub is currently blocked by account suspension, so this repository is staged locally for the same flow.

## Local Repositories

- Source repo: `/root/claw-shield-dkg-starter`
- Local bare remote: `/root/local-git/tracabot.git`
- Registry clone: `/root/dkg-integrations`
- Registry branch: `bounty/tracabot`

## Source Commit

```text
9b61798891664bc5b83d2303737b1d50c4971885
```

## Registry Commit

```text
3f4f73e
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

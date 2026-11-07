## Summary

Describe the change and the problem it solves.

## Scope

List affected commands, modules, callers, tests, configuration, and documentation.

## Tests

- [ ] `npm test`
- [ ] `npm run test:commands`
- [ ] `npm audit --omit=dev` (when dependencies or package contents change)
- [ ] Focused tests for new failure, retraction, or authorization paths

## Security, privacy, and authority

- [ ] No secrets, `.env` values, private keys, local databases, or real user data
- [ ] No raw Telegram identifiers, private appeal text, screenshots, or reporter data in public output
- [ ] DKG writes, public reads, federation, and enforcement remain opt-in and fail closed
- [ ] Evidence claim level and provenance are stated for any new shared record
- [ ] No new graph curator, admin, umbrella, or cross-project authority is implied

## Evidence and limitations

State what was actually run or observed, and what remains untested, simulated, or
not deployed. Do not claim a live deployment, public accusation, graph
publication, funding commitment, or OpenDKG acceptance.

## Review status

- [ ] Maintainer review completed before merge
- [ ] Review evidence artifact targets the exact current PR head and is recorded
      with `scripts/record-review-evidence.js` (`ai-review/evidence`)

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).

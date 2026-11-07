#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { recordReviewEvidence, REVIEW_EVIDENCE_CONTEXT } from '../src/review-evidence.js';

const { values } = parseArgs({
  options: {
    repo: { type: 'string' },
    pr: { type: 'string' },
    artifact: { type: 'string' },
    publish: { type: 'boolean', default: false },
    'api-url': { type: 'string', default: 'https://api.github.com' },
    help: { type: 'boolean', default: false }
  }
});

if (values.help) {
  console.log(`Usage: node scripts/record-review-evidence.js --repo OWNER/REPO --pr NUMBER --artifact PATH [--publish]

Validates a SHA-bound review artifact and, with --publish, posts it as a PR comment and
creates the ${REVIEW_EVIDENCE_CONTEXT} commit status for the exact current PR head.
Dry-run is the default. Requires GITHUB_TOKEN or GH_TOKEN with repo push access.`);
  process.exit(0);
}

if (!values.repo || !values.pr || !values.artifact) {
  console.error('Missing --repo, --pr, or --artifact. Use --help for usage.');
  process.exit(1);
}

const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
if (!token) {
  console.error('Set GITHUB_TOKEN or GH_TOKEN in the environment. Do not pass tokens on the command line.');
  process.exit(1);
}

try {
  const artifactText = await readFile(values.artifact, 'utf8');
  const result = await recordReviewEvidence({
    apiUrl: values['api-url'],
    token,
    repo: values.repo,
    prNumber: values.pr,
    artifactText,
    publish: Boolean(values.publish)
  });
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}

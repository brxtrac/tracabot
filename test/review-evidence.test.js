import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REVIEW_EVIDENCE_CONTEXT,
  REVIEW_EVIDENCE_RECORD_MARKER,
  parseReviewArtifact,
  recordReviewEvidence,
  validateReviewEvidence
} from '../src/review-evidence.js';

const HEAD_SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);

function artifact(overrides = {}) {
  const metadata = {
    reviewed_sha: HEAD_SHA,
    verdict: 'approved',
    reviewer: 'OpenCode independent review (build)',
    method: 'line-by-line diff, tests, and privacy review',
    reviewed_at: '2026-11-07T18:00:00Z',
    ...overrides
  };
  return [
    '# Independent review',
    '',
    '<!-- tracabot-review-evidence:v1 -->',
    '',
    '```json',
    JSON.stringify(metadata, null, 2),
    '```',
    '',
    'Findings: no blocking issues in this scoped revision.'
  ].join('\n');
}

function jsonResponse(status, value) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return value;
    }
  };
}

function pullRequest(overrides = {}) {
  return {
    state: 'open',
    draft: false,
    head: { sha: HEAD_SHA, repo: { full_name: 'brxtrac/tracabot' } },
    base: { repo: { full_name: 'brxtrac/tracabot' } },
    ...overrides
  };
}

function mockGitHub(routes) {
  const calls = [];
  async function fetchImpl(url, options = {}) {
    const parsed = new URL(url);
    const method = options.method || 'GET';
    const key = `${method} ${parsed.pathname}`;
    calls.push({ key, url, options, body: options.body ? JSON.parse(options.body) : null });
    const handler = routes[key];
    if (!handler) return jsonResponse(404, { message: `no mock for ${key}` });
    return handler({ url, options, body: options.body ? JSON.parse(options.body) : null });
  }
  return { calls, fetchImpl };
}

function baseRoutes(overrides = {}) {
  return {
    'GET /repos/brxtrac/tracabot/pulls/2': () => jsonResponse(200, pullRequest()),
    'GET /user': () => jsonResponse(200, { login: 'brxtrac' }),
    'GET /repos/brxtrac/tracabot/collaborators/brxtrac/permission': () => jsonResponse(200, { permission: 'admin' }),
    'GET /repos/brxtrac/tracabot/issues/2/comments': () => jsonResponse(200, []),
    'POST /repos/brxtrac/tracabot/issues/2/comments': ({ body }) => jsonResponse(201, {
      html_url: 'https://github.com/brxtrac/tracabot/pull/2#issuecomment-1',
      body: body.body
    }),
    [`POST /repos/brxtrac/tracabot/statuses/${HEAD_SHA}`]: ({ body }) => jsonResponse(201, {
      state: body.state,
      context: body.context,
      description: body.description,
      target_url: body.target_url
    }),
    ...overrides
  };
}

test('parseReviewArtifact accepts a SHA-bound JSON metadata block', () => {
  const parsed = parseReviewArtifact(artifact());
  assert.equal(parsed.metadata.reviewed_sha, HEAD_SHA);
  assert.equal(parsed.metadata.verdict, 'approved');
  assert.equal(parsed.metadata.reviewed_at, '2026-11-07T18:00:00.000Z');
  assert.match(parsed.digest, /^[0-9a-f]{64}$/);
  assert.equal(parsed.artifact, artifact());
});

test('parseReviewArtifact rejects missing marker, malformed JSON, and invalid fields', () => {
  assert.throws(() => parseReviewArtifact('review text without evidence'), /missing/);
  assert.throws(
    () => parseReviewArtifact('<!-- tracabot-review-evidence:v1 -->\n```json\nnot json\n```'),
    /valid JSON/
  );
  assert.throws(() => parseReviewArtifact(artifact({ reviewed_sha: 'abc' })), /reviewed_sha/);
  assert.throws(() => parseReviewArtifact(artifact({ verdict: 'looks-good' })), /verdict/);
  assert.throws(() => parseReviewArtifact(artifact({ reviewer: ' ' })), /reviewer/);
  assert.throws(() => parseReviewArtifact(artifact({ method: '' })), /method/);
  assert.throws(() => parseReviewArtifact(artifact({ reviewed_at: 'not a date' })), /reviewed_at/);
});

test('parseReviewArtifact rejects oversized artifacts', () => {
  const oversized = `${artifact()}\n${'x'.repeat(60_000)}`;
  assert.throws(() => parseReviewArtifact(oversized), /exceeds/);
});

test('validateReviewEvidence requires the exact current head and a maintainer', () => {
  const approved = validateReviewEvidence({
    artifact: artifact(),
    headSha: HEAD_SHA,
    permission: 'admin'
  });
  assert.equal(approved.state, 'success');
  assert.match(approved.description, /artifact sha256:/);
  assert.equal(
    validateReviewEvidence({ artifact: artifact(), headSha: HEAD_SHA, permission: 'maintain' }).state,
    'success'
  );

  assert.throws(
    () => validateReviewEvidence({ artifact: artifact(), headSha: OTHER_SHA, permission: 'admin' }),
    /current head/
  );
  assert.throws(
    () => validateReviewEvidence({ artifact: artifact(), headSha: HEAD_SHA, permission: 'write' }),
    /permission/
  );
  assert.throws(
    () => validateReviewEvidence({ artifact: artifact(), headSha: HEAD_SHA, permission: 'admin', prState: 'closed' }),
    /closed/
  );
  assert.throws(
    () => validateReviewEvidence({ artifact: artifact(), headSha: HEAD_SHA, permission: 'admin', draft: true }),
    /draft/
  );
});

test('validateReviewEvidence does not turn a non-approval into success', () => {
  const result = validateReviewEvidence({
    artifact: artifact({ verdict: 'changes-requested' }),
    headSha: HEAD_SHA,
    permission: 'admin'
  });
  assert.equal(result.state, 'failure');
  assert.match(result.description, /changes-requested/);
});

test('recordReviewEvidence dry-run validates without writing', async () => {
  const { calls, fetchImpl } = mockGitHub(baseRoutes());
  const result = await recordReviewEvidence({
    fetchImpl,
    token: 'test-token',
    repo: 'brxtrac/tracabot',
    prNumber: 2,
    artifactText: artifact(),
    publish: false
  });
  assert.equal(result.published, false);
  assert.equal(result.head_sha, HEAD_SHA);
  assert.equal(result.state, 'success');
  assert.equal(result.comment_url, null);
  assert.equal(result.status, null);
  assert.equal(calls.some((call) => call.key.startsWith('POST ')), false);
});

test('recordReviewEvidence publishes a comment and SHA-bound status', async () => {
  const { calls, fetchImpl } = mockGitHub(baseRoutes());
  const result = await recordReviewEvidence({
    fetchImpl,
    token: 'test-token',
    repo: 'brxtrac/tracabot',
    prNumber: 2,
    artifactText: artifact(),
    publish: true
  });

  assert.equal(result.published, true);
  assert.equal(result.state, 'success');
  assert.equal(result.comment_url, 'https://github.com/brxtrac/tracabot/pull/2#issuecomment-1');
  assert.equal(result.status.context, REVIEW_EVIDENCE_CONTEXT);
  assert.equal(result.status.state, 'success');
  assert.equal(result.status.target_url, result.comment_url);

  const commentCall = calls.find((call) => call.key === 'POST /repos/brxtrac/tracabot/issues/2/comments');
  assert.ok(commentCall.body.body.includes(REVIEW_EVIDENCE_RECORD_MARKER));
  assert.ok(commentCall.body.body.includes(`Reviewed SHA: ${HEAD_SHA}`));
  assert.ok(commentCall.body.body.includes(`Artifact SHA-256: ${result.artifact_sha256}`));
  assert.ok(commentCall.body.body.includes("This is an external review record, not a GitHub pull-request approval"));

  const statusCall = calls.find((call) => call.key === `POST /repos/brxtrac/tracabot/statuses/${HEAD_SHA}`);
  assert.equal(statusCall.body.context, REVIEW_EVIDENCE_CONTEXT);
  assert.equal(statusCall.body.target_url, result.comment_url);
});

test('recordReviewEvidence reuses an existing evidence comment', async () => {
  const digest = parseReviewArtifact(artifact()).digest;
  const existingBody = [
    REVIEW_EVIDENCE_RECORD_MARKER,
    `Reviewed SHA: ${HEAD_SHA}`,
    `Artifact SHA-256: ${digest}`
  ].join('\n');
  const { calls, fetchImpl } = mockGitHub(baseRoutes({
    'GET /repos/brxtrac/tracabot/issues/2/comments': () => jsonResponse(200, [{
      user: { login: 'brxtrac' },
      body: existingBody,
      html_url: 'https://github.com/brxtrac/tracabot/pull/2#issuecomment-existing'
    }])
  }));

  const result = await recordReviewEvidence({
    fetchImpl,
    token: 'test-token',
    repo: 'brxtrac/tracabot',
    prNumber: 2,
    artifactText: artifact(),
    publish: true
  });

  assert.equal(result.comment_url, 'https://github.com/brxtrac/tracabot/pull/2#issuecomment-existing');
  assert.equal(calls.some((call) => call.key === 'POST /repos/brxtrac/tracabot/issues/2/comments'), false);
  assert.equal(result.status.target_url, result.comment_url);
});

test('recordReviewEvidence refuses a reviewer without admin or maintain permission', async () => {
  const { calls, fetchImpl } = mockGitHub(baseRoutes({
    'GET /repos/brxtrac/tracabot/collaborators/brxtrac/permission': () => jsonResponse(200, { permission: 'write' })
  }));

  await assert.rejects(
    recordReviewEvidence({
      fetchImpl,
      token: 'test-token',
      repo: 'brxtrac/tracabot',
      prNumber: 2,
      artifactText: artifact(),
      publish: true
    }),
    /permission/
  );
  assert.equal(calls.some((call) => call.key.startsWith('POST ')), false);
});

test('recordReviewEvidence refuses evidence for a different head SHA', async () => {
  const { calls, fetchImpl } = mockGitHub(baseRoutes({
    'GET /repos/brxtrac/tracabot/pulls/2': () => jsonResponse(200, pullRequest({
      head: { sha: OTHER_SHA, repo: { full_name: 'brxtrac/tracabot' } }
    }))
  }));

  await assert.rejects(
    recordReviewEvidence({
      fetchImpl,
      token: 'test-token',
      repo: 'brxtrac/tracabot',
      prNumber: 2,
      artifactText: artifact(),
      publish: true
    }),
    /current head/
  );
  assert.equal(calls.some((call) => call.key.startsWith('POST ')), false);
});

test('recordReviewEvidence refuses a fork head and a draft PR', async () => {
  const fork = mockGitHub(baseRoutes({
    'GET /repos/brxtrac/tracabot/pulls/2': () => jsonResponse(200, pullRequest({
      head: { sha: HEAD_SHA, repo: { full_name: 'someone/tracabot' } }
    }))
  }));
  await assert.rejects(
    recordReviewEvidence({
      fetchImpl: fork.fetchImpl,
      token: 'test-token',
      repo: 'brxtrac/tracabot',
      prNumber: 2,
      artifactText: artifact(),
      publish: false
    }),
    /head repository/
  );

  const draft = mockGitHub(baseRoutes({
    'GET /repos/brxtrac/tracabot/pulls/2': () => jsonResponse(200, pullRequest({ draft: true }))
  }));
  await assert.rejects(
    recordReviewEvidence({
      fetchImpl: draft.fetchImpl,
      token: 'test-token',
      repo: 'brxtrac/tracabot',
      prNumber: 2,
      artifactText: artifact(),
      publish: false
    }),
    /draft/
  );
});

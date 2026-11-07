import { createHash } from 'node:crypto';

export const REVIEW_EVIDENCE_MARKER = '<!-- tracabot-review-evidence:v1 -->';
export const REVIEW_EVIDENCE_RECORD_MARKER = '<!-- tracabot-review-evidence-record:v1 -->';
export const REVIEW_EVIDENCE_CONTEXT = 'ai-review/evidence';

const REVIEWER_PERMISSIONS = new Set(['admin', 'maintain']);
const VERDICTS = new Set(['approved', 'changes-requested', 'rejected']);
const SHA_PATTERN = /^[0-9a-f]{40}$/i;
const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_ARTIFACT_BYTES = 60_000;

function invalid(message) {
  throw new Error(message);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function parseReviewArtifact(artifactText) {
  if (typeof artifactText !== 'string' || !artifactText.trim()) invalid('review artifact is empty');
  if (Buffer.byteLength(artifactText, 'utf8') > MAX_ARTIFACT_BYTES) {
    invalid(`review artifact exceeds ${MAX_ARTIFACT_BYTES} bytes`);
  }

  const markerIndex = artifactText.indexOf(REVIEW_EVIDENCE_MARKER);
  if (markerIndex === -1) invalid(`review artifact is missing ${REVIEW_EVIDENCE_MARKER}`);

  const afterMarker = artifactText.slice(markerIndex + REVIEW_EVIDENCE_MARKER.length);
  const block = afterMarker.match(/^\s*```json[ \t]*\r?\n([\s\S]*?)\r?\n```/i);
  if (!block) invalid('review artifact must contain a fenced json metadata block after the marker');

  let metadata;
  try {
    metadata = JSON.parse(block[1]);
  } catch {
    invalid('review artifact metadata is not valid JSON');
  }
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    invalid('review artifact metadata must be a JSON object');
  }

  const reviewedSha = String(metadata.reviewed_sha || '').toLowerCase();
  if (!SHA_PATTERN.test(reviewedSha)) invalid('reviewed_sha must be a 40-character commit SHA');

  const verdict = String(metadata.verdict || '');
  if (!VERDICTS.has(verdict)) invalid('verdict must be approved, changes-requested, or rejected');

  const reviewer = String(metadata.reviewer || '').trim();
  if (!reviewer || reviewer.length > 200) invalid('reviewer must be a non-empty string of at most 200 characters');

  const method = String(metadata.method || '').trim();
  if (!method || method.length > 200) invalid('method must be a non-empty string of at most 200 characters');

  const reviewedAt = new Date(String(metadata.reviewed_at || ''));
  if (Number.isNaN(reviewedAt.getTime())) invalid('reviewed_at must be an ISO-8601 timestamp');

  return {
    metadata: {
      reviewed_sha: reviewedSha,
      verdict,
      reviewer,
      method,
      reviewed_at: reviewedAt.toISOString()
    },
    digest: sha256(artifactText),
    artifact: artifactText
  };
}

export function validateReviewEvidence({
  artifact,
  headSha,
  permission,
  prState = 'open',
  draft = false
}) {
  const parsed = parseReviewArtifact(artifact);
  const currentHead = String(headSha || '').toLowerCase();
  if (!SHA_PATTERN.test(currentHead)) invalid('current pull request head SHA is invalid');
  if (parsed.metadata.reviewed_sha !== currentHead) {
    invalid(`review artifact targets ${parsed.metadata.reviewed_sha}, current head is ${currentHead}`);
  }
  if (!REVIEWER_PERMISSIONS.has(permission)) {
    invalid(`reviewer permission ${permission || 'none'} is not admin or maintain`);
  }
  if (prState !== 'open') invalid(`pull request is ${prState}`);
  if (draft) invalid('pull request is a draft');

  const state = parsed.metadata.verdict === 'approved' ? 'success' : 'failure';
  const shortSha = currentHead.slice(0, 12);
  const shortDigest = parsed.digest.slice(0, 12);
  const description = state === 'success'
    ? `Review evidence approved ${shortSha}; artifact sha256:${shortDigest}`
    : `Review evidence ${parsed.metadata.verdict} for ${shortSha}; artifact sha256:${shortDigest}`;

  return { ...parsed, state, description };
}

export function buildEvidenceComment({ artifact, validation, actor, prNumber, headSha }) {
  return [
    REVIEW_EVIDENCE_RECORD_MARKER,
    `Review evidence recorded by @${actor} for PR #${prNumber} at head ${headSha}.`,
    '',
    `Reviewer: ${validation.metadata.reviewer}`,
    `Method: ${validation.metadata.method}`,
    `Reviewed at: ${validation.metadata.reviewed_at}`,
    `Reviewed SHA: ${headSha}`,
    `Artifact SHA-256: ${validation.digest}`,
    `Verdict: ${validation.metadata.verdict}`,
    `Status context: ${REVIEW_EVIDENCE_CONTEXT}`,
    '',
    'This is an external review record, not a GitHub pull-request approval or an app identity claim.',
    '',
    '---',
    '',
    artifact
  ].join('\n');
}

function apiError(method, path, status, data) {
  const detail = data && typeof data.message === 'string' ? `: ${data.message}` : '';
  return new Error(`GitHub API ${method} ${path} failed with ${status}${detail}`);
}

export async function recordReviewEvidence({
  fetchImpl,
  apiUrl = 'https://api.github.com',
  token,
  repo,
  prNumber,
  artifactText,
  publish = false
} = {}) {
  if (!token) invalid('GITHUB_TOKEN or GH_TOKEN is required');
  if (!REPO_PATTERN.test(String(repo || ''))) invalid('repo must be owner/name');
  const pr = Number(prNumber);
  if (!Number.isInteger(pr) || pr < 1) invalid('pr must be a positive integer');
  if (typeof artifactText !== 'string') invalid('artifactText must be a string');

  const doFetch = fetchImpl || globalThis.fetch;
  if (typeof doFetch !== 'function') invalid('fetch is not available');

  const baseUrl = String(apiUrl).replace(/\/+$/, '');
  async function request(path, options = {}) {
    const method = options.method || 'GET';
    const response = await doFetch(`${baseUrl}${path}`, {
      ...options,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'tracabot-review-evidence',
        ...(options.body ? { 'content-type': 'application/json' } : {}),
        ...(options.headers || {})
      }
    });
    const data = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) throw apiError(method, path, response.status, data);
    return data;
  }

  const pull = await request(`/repos/${repo}/pulls/${pr}`);
  if (!pull || !pull.head || !pull.head.sha) invalid('GitHub pull request response is incomplete');
  if (!pull.head.repo || !pull.base || !pull.base.repo) invalid('pull request repository provenance is incomplete');
  if (String(pull.base.repo.full_name).toLowerCase() !== repo.toLowerCase()) {
    invalid(`pull request base repository ${pull.base.repo.full_name} does not match ${repo}`);
  }
  if (String(pull.head.repo.full_name).toLowerCase() !== repo.toLowerCase()) {
    invalid(`pull request head repository ${pull.head.repo.full_name} is not ${repo}`);
  }

  const user = await request('/user');
  if (!user || !user.login) invalid('authenticated GitHub user response is incomplete');
  const permissionResponse = await request(
    `/repos/${repo}/collaborators/${encodeURIComponent(user.login)}/permission`
  );
  const validation = validateReviewEvidence({
    artifact: artifactText,
    headSha: pull.head.sha,
    permission: permissionResponse && permissionResponse.permission,
    prState: pull.state,
    draft: Boolean(pull.draft)
  });

  const commentBody = buildEvidenceComment({
    artifact: artifactText,
    validation,
    actor: user.login,
    prNumber: pr,
    headSha: pull.head.sha
  });

  // shortcut: scans the first 100 comments; paginate if review threads routinely exceed that.
  const comments = await request(`/repos/${repo}/issues/${pr}/comments?per_page=100`);
  const existingComment = Array.isArray(comments)
    ? comments.find((comment) => comment
      && comment.user
      && comment.user.login === user.login
      && typeof comment.body === 'string'
      && comment.body.includes(REVIEW_EVIDENCE_RECORD_MARKER)
      && comment.body.includes(`Reviewed SHA: ${pull.head.sha}`)
      && comment.body.includes(`Artifact SHA-256: ${validation.digest}`))
    : null;

  let commentUrl = existingComment ? existingComment.html_url : null;
  if (!existingComment && publish) {
    const createdComment = await request(`/repos/${repo}/issues/${pr}/comments`, {
      method: 'POST',
      body: JSON.stringify({ body: commentBody })
    });
    commentUrl = createdComment && createdComment.html_url;
    if (!commentUrl) invalid('GitHub did not return a comment URL');
  }

  let status = null;
  if (publish) {
    status = await request(`/repos/${repo}/statuses/${pull.head.sha}`, {
      method: 'POST',
      body: JSON.stringify({
        state: validation.state,
        context: REVIEW_EVIDENCE_CONTEXT,
        description: validation.description,
        target_url: commentUrl
      })
    });
  }

  return {
    ok: true,
    repo,
    pr,
    head_sha: pull.head.sha,
    reviewer: validation.metadata.reviewer,
    method: validation.metadata.method,
    verdict: validation.metadata.verdict,
    artifact_sha256: validation.digest,
    state: validation.state,
    comment_url: commentUrl,
    status: status
      ? {
        state: status.state,
        context: status.context,
        description: status.description,
        target_url: status.target_url
      }
      : null,
    published: Boolean(publish && status)
  };
}

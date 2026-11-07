import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { EventStore } from '../src/store.js';
import {
  FEDERATION_QUEUE_TYPE,
  FEDERATION_SENT_TYPE,
  FEDERATION_FAILED_TYPE,
  federationSubmissionFor,
  flushFederationQueue,
  queueFederationSubmission
} from '../src/federation-client.js';

function makeStore() {
  return new EventStore(join(mkdtempSync(join(tmpdir(), 'tracabot-federation-')), 'events.jsonl'));
}

function config(overrides = {}) {
  return {
    submitSharedEvidence: true,
    creatorSubmitUrl: 'https://creator.example/api/public/evidence',
    creatorSubmitToken: 'test-token-at-least-16-chars',
    instanceId: 'instance-a',
    ...overrides
  };
}

function sourceEvent() {
  return {
    id: 'event-source-1',
    event_type: 'fraud_finding',
    user: { id: '123456789', username: 'fake_support' },
    payload: { target: { id: '123456789' }, scam_type: 'impersonation' }
  };
}

function promotedEvent() {
  return {
    id: 'event-promoted-1',
    event_type: 'fraud_finding',
    user: { id: '123456789' },
    payload: {
      target: { id: '123456789' },
      claim_level: 'high_confidence_flag',
      scam_type: 'impersonation',
      domains: ['fake-support.example'],
      wallets: [],
      patterns: ['fake-support'],
      evidence: ['private evidence text must not be submitted verbatim']
    }
  };
}

test('federation submission is opt-in and sanitizes private evidence text', () => {
  assert.equal(federationSubmissionFor({ promotedEvent: promotedEvent(), sourceEvent: sourceEvent(), config: config({ submitSharedEvidence: false }) }), null);
  const submission = federationSubmissionFor({ promotedEvent: promotedEvent(), sourceEvent: sourceEvent(), config: config() });
  assert.equal(submission.claimType, 'observation');
  assert.equal(submission.subject.telegramUserId, '123456789');
  assert.deepEqual(submission.indicators.domains, ['fake-support.example']);
  assert.doesNotMatch(JSON.stringify(submission), /private evidence text/);
  assert.doesNotMatch(JSON.stringify(submission), /@fake_support/);
});

test('federation queue is idempotent and opt-out prevents new sends', async () => {
  const store = makeStore();
  const first = queueFederationSubmission({ store, promotedEvent: promotedEvent(), sourceEvent: sourceEvent(), config: config() });
  const second = queueFederationSubmission({ store, promotedEvent: promotedEvent(), sourceEvent: sourceEvent(), config: config() });
  assert.equal(first.queued, true);
  assert.equal(second.duplicate, true);
  assert.equal(store.all().filter((event) => event.event_type === FEDERATION_QUEUE_TYPE).length, 1);

  const disabled = await flushFederationQueue({ store, config: config({ submitSharedEvidence: false }), fetchImpl: async () => { throw new Error('must not send'); } });
  assert.equal(disabled.disabled, true);
  assert.equal(store.all().some((event) => event.event_type === FEDERATION_SENT_TYPE), false);
});

test('federation flush sends once, records success, and does not resend', async () => {
  const store = makeStore();
  const cfg = config();
  queueFederationSubmission({ store, promotedEvent: promotedEvent(), sourceEvent: sourceEvent(), config: cfg });
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return { ok: true, status: 202, async text() { return JSON.stringify({ publicId: 'evt_public', eventId: 'remote-1' }); } };
  };
  const first = await flushFederationQueue({ store, config: cfg, fetchImpl });
  assert.equal(first.sent, 1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.headers['idempotency-key'], store.all().find((event) => event.event_type === FEDERATION_QUEUE_TYPE).payload.queue_id);
  assert.equal(store.all().find((event) => event.event_type === FEDERATION_SENT_TYPE).payload.remote_event_id, 'remote-1');
  const second = await flushFederationQueue({ store, config: cfg, fetchImpl });
  assert.equal(second.sent, 0);
  assert.equal(calls.length, 1);
});

test('backlog drains oldest-first without starving older pending submissions', async () => {
  const store = makeStore();
  const cfg = config();
  for (let index = 0; index < 15; index += 1) {
    queueFederationSubmission({
      store,
      promotedEvent: { ...promotedEvent(), id: `promoted-${index}` },
      sourceEvent: { ...sourceEvent(), id: `source-${index}` },
      config: cfg
    });
  }
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push(JSON.parse(options.body).subject.telegramUserId);
    return { ok: true, status: 202, async text() { return '{}'; } };
  };
  const first = await flushFederationQueue({ store, config: cfg, fetchImpl, limit: 10 });
  assert.equal(first.sent, 10);
  assert.equal(calls.length, 10);
  const second = await flushFederationQueue({ store, config: cfg, fetchImpl, limit: 10 });
  assert.equal(second.sent, 5);
  assert.equal(calls.length, 15);
});

test('federation failure is bounded, recorded, and retried after backoff', async () => {
  const store = makeStore();
  const cfg = config();
  queueFederationSubmission({ store, promotedEvent: promotedEvent(), sourceEvent: sourceEvent(), config: cfg });
  let calls = 0;
  const failing = async () => { calls += 1; return { ok: false, status: 503, async text() { return 'unavailable'; } }; };
  const now = Date.parse('2026-11-06T12:00:00.000Z');
  const first = await flushFederationQueue({ store, config: cfg, fetchImpl: failing, now });
  assert.equal(first.failed, 1);
  const failure = store.all().find((event) => event.event_type === FEDERATION_FAILED_TYPE);
  assert.equal(failure.payload.attempts, 1);
  assert.ok(Date.parse(failure.payload.retry_at) > now);
  const second = await flushFederationQueue({ store, config: cfg, fetchImpl: failing, now: now + 1000 });
  assert.equal(second.sent, 0);
  assert.equal(second.skipped, 1);
  assert.equal(calls, 1);
  const third = await flushFederationQueue({ store, config: cfg, fetchImpl: failing, now: Date.parse(failure.payload.retry_at) + 1 });
  assert.equal(third.failed, 1);
  assert.equal(calls, 2);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import {
  createAttestation,
  fetchCreatorAttestation,
  keyIdFor,
  signPayload,
  verifyAttestation,
  verifyStatusEnvelope
} from '../src/creator-attestation.js';
import { createCreatorAttestation, creatorStatus, revokeCreatorAttestation } from '../src/creator-curator.js';
import { loadConfig } from '../src/config.js';
import { EventStore } from '../src/store.js';
import { createPublicServer } from '../src/public-server.js';

const keys = generateKeyPairSync('ed25519');
const privateKey = keys.privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
const issuer = 'tracabot-creator-curator';
const roots = (userId = '4242') => [
  { id: `ban:${userId}:a`, event_type: 'ban_executed', community_id: '-100', platform: 'telegram', user_id: userId },
  { id: `ban:${userId}:b`, event_type: 'ban_executed', community_id: '-200', platform: 'telegram', user_id: userId }
];

function attestation(overrides = {}) {
  return createAttestation({
    subject: { platform: 'telegram', user_id: '4242' },
    classification: 'fraud',
    confidence: 96,
    roots: roots(),
    ttlDays: 30,
    issuer,
    privateKey,
    now: Date.parse('2026-11-01T00:00:00.000Z'),
    ...overrides
  });
}

test('creator attestations verify exact subject, fraud/scam classification, roots, issue and expiry', () => {
  const envelope = attestation();
  const verified = verifyAttestation(envelope, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedUserId: '4242', expectedIssuer: issuer, minConfidence: 90, minRoots: 2 });
  assert.equal(verified.ok, true);
  assert.equal(verified.classification, 'fraud');
  assert.equal(verified.roots.length, 2);
  assert.equal(verifyAttestation(envelope, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedUserId: '9999', expectedIssuer: issuer }).reason, 'subject_mismatch');
  assert.equal(verifyAttestation(envelope, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedIssuer: issuer, minRoots: 3 }).reason, 'insufficient_independent_roots');
  assert.equal(verifyAttestation(attestation({ ttlDays: 300 }), publicKey, { now: Date.parse('2027-06-01T00:00:00.000Z'), expectedIssuer: issuer }).reason, 'attestation_too_old');
  assert.equal(verifyAttestation(attestation({ ttlDays: 1 }), publicKey, { now: Date.parse('2026-11-03T00:00:00.000Z'), expectedIssuer: issuer }).reason, 'attestation_expired');
});

test('tampered, wrong classification, wrong key, and duplicate-lineage attestations never verify', () => {
  const envelope = attestation();
  const tampered = JSON.parse(JSON.stringify(envelope));
  tampered.payload.confidence = 100;
  assert.equal(verifyAttestation(tampered, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedIssuer: issuer }).reason, 'invalid_signature');

  const wrongKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  assert.equal(verifyAttestation(envelope, wrongKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedIssuer: issuer }).reason, 'key_id_mismatch');

  const behavior = createAttestation({ subject: { platform: 'telegram', user_id: '4242' }, classification: 'scam', confidence: 96, roots: roots(), ttlDays: 30, issuer, privateKey, now: Date.parse('2026-11-01T00:00:00.000Z') });
  assert.equal(verifyAttestation(behavior, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedIssuer: issuer }).ok, true);

  assert.throws(() => createAttestation({
    subject: { platform: 'telegram', user_id: '4242' },
    classification: 'fraud',
    confidence: 80,
    roots: roots(),
    ttlDays: 30,
    issuer,
    privateKey
  }), /confidence_below_threshold/);

  assert.throws(() => createAttestation({
    subject: { platform: 'telegram', user_id: '4242' },
    classification: 'fraud',
    confidence: 96,
    roots: [
      { id: 'one', event_type: 'ban_executed', community_id: 'a', user_id: '4242', lineage_id: 'same' },
      { id: 'two', event_type: 'ban_executed', community_id: 'b', user_id: '4242', lineage_id: 'same' }
    ],
    ttlDays: 30,
    issuer,
    privateKey
  }), /lineage must be independent/);
});

test('Ed448 or other asymmetric keys are rejected even when labeled ed25519', () => {
  const ed448 = generateKeyPairSync('ed448');
  const ed448Private = ed448.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const ed448Public = ed448.publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => keyIdFor(ed448Public), /ed25519/);
  assert.throws(() => signPayload({ test: true }, ed448Private), /ed25519/);
  assert.throws(() => createAttestation({ subject: { platform: 'telegram', user_id: '4242' }, classification: 'fraud', confidence: 96, roots: roots(), ttlDays: 30, issuer, privateKey: ed448Private }), /ed25519/);
  assert.throws(() => loadConfig({
    TRACABOT_CREATOR_CURATOR_URL: 'https://creator.example',
    TRACABOT_CREATOR_CURATOR_PUBLIC_KEY: ed448Public,
    TRACABOT_CREATOR_CURATOR_READ_TOKEN: 'creator-read-token-123456'
  }), /Ed25519/);
  assert.equal(verifyAttestation(attestation(), ed448Public, { expectedIssuer: issuer }).reason, 'invalid_key_type');
  assert.equal(verifyStatusEnvelope(signPayload({ probe: true }, privateKey), ed448Public).reason, 'invalid_key_type');
});

test('signed creator status reads expose fresh active, revoked, expired, and not-found states', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-'));
  const storePath = join(dir, 'attestations.json');
  try {
    const created = createCreatorAttestation({
      storePath,
      privateKey,
      subject: { platform: 'telegram', user_id: '4242' },
      classification: 'fraud',
      confidence: 96,
      roots: roots(),
      ttlDays: 30,
      issuer,
      now: Date.parse('2026-11-01T00:00:00.000Z')
    });
    assert.equal(created.payload.subject.user_id, '4242');
    const active = creatorStatus({ storePath, privateKey, subject: { platform: 'telegram', user_id: '4242' }, issuer, now: Date.parse('2026-11-02T00:00:00.000Z') });
    const verifiedActive = verifyStatusEnvelope(active, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedUserId: '4242', expectedIssuer: issuer, minRoots: 2 });
    assert.equal(verifiedActive.status, 'active');
    assert.ok(verifiedActive.evidence.eventId.startsWith('creator:4242:'));

    const revoked = revokeCreatorAttestation({ storePath, privateKey, subject: { platform: 'telegram', user_id: '4242' }, reason: 'new exculpatory evidence', now: Date.parse('2026-11-03T00:00:00.000Z') });
    assert.equal(verifyStatusEnvelope(revoked, publicKey, { now: Date.parse('2026-11-03T00:00:00.000Z'), expectedUserId: '4242', expectedIssuer: issuer }).status, 'revoked');
    assert.match(JSON.stringify(revoked), /new exculpatory evidence/);

    const missing = creatorStatus({ storePath, privateKey, subject: { platform: 'telegram', user_id: '9999' }, issuer, now: Date.parse('2026-11-03T00:00:00.000Z') });
    assert.equal(verifyStatusEnvelope(missing, publicKey, { now: Date.parse('2026-11-03T00:00:00.000Z'), expectedUserId: '9999', expectedIssuer: issuer }).status, 'not_found');

    const stale = verifyStatusEnvelope(active, publicKey, { now: Date.parse('2026-11-02T01:00:00.000Z'), expectedUserId: '4242', expectedIssuer: issuer });
    assert.equal(stale.reason, 'stale_status_read');

    const tampered = JSON.parse(JSON.stringify(active));
    tampered.payload.status = 'revoked';
    assert.equal(verifyStatusEnvelope(tampered, publicKey, { now: Date.parse('2026-11-02T00:00:00.000Z'), expectedUserId: '4242', expectedIssuer: issuer }).reason, 'invalid_signature');
    assert.equal(verifyStatusEnvelope({}, publicKey).reason, 'missing_signed_payload');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('creator CLI attests, reports status, and revokes with the private key', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-cli-'));
  const keyPath = join(dir, 'private.pem');
  const storePath = join(dir, 'attestations.json');
  writeFileSync(keyPath, privateKey, { mode: 0o600 });
  const env = {
    ...process.env,
    TRACABOT_CREATOR_CURATOR_PRIVATE_KEY_PATH: keyPath,
    TRACABOT_CREATOR_CURATOR_STORE: storePath,
    TRACABOT_CREATOR_CURATOR_MIN_CONFIDENCE: '90',
    TRACABOT_CREATOR_CURATOR_MIN_ROOTS: '2'
  };
  try {
    const created = JSON.parse(execFileSync(process.execPath, ['bin/tracabot-curator.js', '--attest', '--subject', '4242', '--classification', 'fraud', '--confidence', '96', '--ttl-days', '30', '--root', 'id=cli-a,community_id=-100,event_type=ban_executed', '--root', 'id=cli-b,community_id=-200,event_type=ban_executed'], { cwd: process.cwd(), env, encoding: 'utf8' }));
    assert.equal(created.status, 'active');
    assert.equal(created.attestation.payload.subject.user_id, '4242');
    const status = JSON.parse(execFileSync(process.execPath, ['bin/tracabot-curator.js', '--status', '--subject', '4242'], { cwd: process.cwd(), env, encoding: 'utf8' }));
    assert.equal(status.envelope.payload.status, 'active');
    const revoked = JSON.parse(execFileSync(process.execPath, ['bin/tracabot-curator.js', '--revoke', '--subject', '4242', '--reason', 'cli correction'], { cwd: process.cwd(), env, encoding: 'utf8' }));
    assert.equal(revoked.envelope.payload.status, 'revoked');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('creator read and write limits are independent, auth precedes rate/sign, and read tokens never write', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-limits-'));
  const storePath = join(dir, 'attestations.json');
  const writeToken = 'creator-write-token-123456';
  const readToken = 'creator-read-token-123456';
  const config = {
    creatorCuratorStorePath: storePath,
    creatorCuratorPrivateKey: privateKey,
    creatorCuratorToken: writeToken,
    creatorCuratorReadToken: readToken,
    creatorCuratorIssuer: issuer,
    creatorCuratorReadRateLimitPerHour: 2,
    creatorCuratorWriteRateLimitPerHour: 1,
    publicMaxBodyBytes: 16384
  };
  const server = createPublicServer({ config, store: new EventStore(join(dir, 'events.sqlite')), dkg: null, autoPromote: false });
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const body = JSON.stringify({ subject: { platform: 'telegram', user_id: '4242' }, classification: 'fraud', confidence: 96, roots: roots(), ttl_days: 30 });
    const readTokenWrite = await fetch(`${base}/api/creator/attestations`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${readToken}` }, body });
    assert.equal(readTokenWrite.status, 401);
    const firstWrite = await fetch(`${base}/api/creator/attestations`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${writeToken}` }, body });
    assert.equal(firstWrite.status, 201);
    const secondWrite = await fetch(`${base}/api/creator/attestations`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${writeToken}` }, body });
    assert.equal(secondWrite.status, 429);

    const firstRead = await fetch(`${base}/api/creator/attestations/telegram/5555`, { headers: { authorization: `Bearer ${readToken}` } });
    assert.equal(firstRead.status, 200);
    const secondRead = await fetch(`${base}/api/creator/attestations/telegram/5555`, { headers: { authorization: `Bearer ${readToken}` } });
    assert.equal(secondRead.status, 200);
    const thirdRead = await fetch(`${base}/api/creator/attestations/telegram/5555`, { headers: { authorization: `Bearer ${readToken}` } });
    assert.equal(thirdRead.status, 429);
    const unauthRead = await fetch(`${base}/api/creator/attestations/telegram/5555`);
    assert.equal(unauthRead.status, 401);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});


test('authenticated curator API creates and revokes, and consumer transport fails closed on outage or missing signature', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tracabot-creator-api-'));
  const storePath = join(dir, 'attestations.json');
  const store = new EventStore(join(dir, 'events.sqlite'));
  const token = 'creator-curator-token-123456';
  const config = { creatorCuratorStorePath: storePath, creatorCuratorPrivateKey: privateKey, creatorCuratorToken: token, creatorCuratorReadToken: token, creatorCuratorIssuer: issuer, publicMaxBodyBytes: 16384 };
  const server = createPublicServer({ config, store, dkg: null, autoPromote: false });
  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;

    const unauthorized = await fetch(`${base}/api/creator/attestations`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({}) });
    assert.equal(unauthorized.status, 401);
    const created = await fetch(`${base}/api/creator/attestations`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ subject: { platform: 'telegram', user_id: '4242' }, classification: 'scam', confidence: 97, roots: roots(), ttl_days: 30 })
    });
    assert.equal(created.status, 201);
    assert.equal((await created.json()).status, 'active');

    const noReadToken = await fetch(`${base}/api/creator/attestations/telegram/4242`);
    assert.equal(noReadToken.status, 401);
    const active = await fetch(`${base}/api/creator/attestations/telegram/4242`, { headers: { authorization: `Bearer ${token}` } }).then((response) => response.json());
    assert.equal(verifyStatusEnvelope(active, publicKey, { expectedUserId: '4242', expectedIssuer: issuer, minRoots: 2 }).status, 'active');

    const fetched = await fetchCreatorAttestation({ baseUrl: base, userId: '4242', publicKey, token, issuer, minConfidence: 90, minRoots: 2, fetchImpl: fetch });
    assert.equal(fetched.ok, true);
    assert.equal(fetched.evidence.length, 1);
    assert.equal(fetched.evidence[0].trustLayer, 'creator-curator');
    assert.equal(fetched.evidence[0].publisherApprovalVerified, true);

    const outage = await fetchCreatorAttestation({ baseUrl: base, userId: '4242', publicKey, token, issuer, fetchImpl: async () => { throw new Error('network down'); } });
    assert.equal(outage.ok, false);
    assert.equal(outage.complete, false);

    const revoked = await fetch(`${base}/api/creator/attestations/telegram/4242/revoke`, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` }, body: JSON.stringify({ reason: 'curator correction' })
    });
    assert.equal(revoked.status, 200);
    const afterRevoke = await fetchCreatorAttestation({ baseUrl: base, userId: '4242', publicKey, token, issuer, minConfidence: 90, minRoots: 2, fetchImpl: fetch });
    assert.equal(afterRevoke.status, 'revoked');
    assert.equal(afterRevoke.evidence.length, 0);
    assert.equal((await fetch(`${base}/api/creator/attestations/telegram/4242`, { headers: { authorization: `Bearer ${token}` } }).then((response) => response.json())).payload.status, 'revoked');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dir, { recursive: true, force: true });
  }
});

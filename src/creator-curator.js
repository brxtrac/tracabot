import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createPublicKey, randomUUID } from 'node:crypto';
import {
  CREATOR_DEFAULT_ISSUER,
  createAttestation,
  createStatusEnvelope,
  keyIdFor,
  verifyAttestation
} from './creator-attestation.js';

const STORE_VERSION = 1;

function emptyState() {
  return { version: STORE_VERSION, records: [] };
}

export function loadCreatorState(path) {
  if (!path) return emptyState();
  if (!existsSync(path)) return emptyState();
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (!parsed || parsed.version !== STORE_VERSION || !Array.isArray(parsed.records)) throw new Error('invalid creator curator store');
  return parsed;
}

function saveCreatorState(path, state) {
  if (!path) throw new Error('creator curator store path is required');
  mkdirSync(dirname(resolve(path)), { recursive: true, mode: 0o700 });
  const temp = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  renameSync(temp, path);
}

function subjectKey(subject = {}) {
  return `${subject.platform}:${subject.user_id}`;
}

function latestRecord(state, subject) {
  const key = subjectKey(subject);
  return [...state.records].reverse().find((record) => subjectKey(record.subject) === key) || null;
}

export function createCreatorAttestation({
  storePath,
  privateKey,
  subject,
  classification = 'fraud',
  confidence = 95,
  roots = [],
  ttlDays = 180,
  issuer = CREATOR_DEFAULT_ISSUER,
  minConfidence = 90,
  now = Date.now()
} = {}) {
  if (!storePath) throw new Error('creator curator store path is required');
  if (!privateKey) throw new Error('creator curator private key is required');
  const attestation = createAttestation({ subject, classification, confidence, roots, ttlDays, issuer, now, privateKey, minConfidence });
  const state = loadCreatorState(storePath);
  const normalizedSubject = { platform: 'telegram', user_id: String(subject.user_id || subject.userId || subject.telegramUserId) };
  const key = subjectKey(normalizedSubject);
  state.records = state.records.filter((record) => subjectKey(record.subject) !== key);
  state.records.push({
    subject: normalizedSubject,
    status: 'active',
    attestation,
    key_id: keyIdFor(createPublicKey(privateKey)),
    updated_at: new Date(now).toISOString(),
    revoked_at: '',
    revocation_reason: ''
  });
  saveCreatorState(storePath, state);
  return attestation;
}

export function revokeCreatorAttestation({ storePath, privateKey, subject, reason = 'curator revocation', now = Date.now() } = {}) {
  if (!storePath) throw new Error('creator curator store path is required');
  if (!privateKey) throw new Error('creator curator private key is required');
  const normalizedSubject = { platform: 'telegram', user_id: String(subject.user_id || subject.userId || subject.telegramUserId) };
  const state = loadCreatorState(storePath);
  const record = latestRecord(state, normalizedSubject);
  if (!record) throw new Error('no creator attestation found for subject');
  // The signed attestation is never mutated. Revocation is a separate, signed
  // status read so historical evidence remains auditable.
  record.status = 'revoked';
  record.revoked_at = new Date(now).toISOString();
  record.revocation_reason = String(reason || 'curator revocation').slice(0, 300);
  record.updated_at = new Date(now).toISOString();
  saveCreatorState(storePath, state);
  return createStatusEnvelope({ record, subject: normalizedSubject, issuer: record.attestation?.payload?.issuer, now, privateKey });
}

export function creatorStatus({ storePath, privateKey, subject, issuer = CREATOR_DEFAULT_ISSUER, now = Date.now() } = {}) {
  if (!storePath) throw new Error('creator curator store path is required');
  if (!privateKey) throw new Error('creator curator private key is required');
  const normalizedSubject = { platform: 'telegram', user_id: String(subject.user_id || subject.userId || subject.telegramUserId) };
  const state = loadCreatorState(storePath);
  const record = latestRecord(state, normalizedSubject);
  return createStatusEnvelope({ record, subject: normalizedSubject, issuer: record?.attestation?.payload?.issuer || issuer, now, privateKey });
}

export function verifyCreatorStateRecord(record = {}, publicKey, options = {}) {
  return verifyAttestation(record.attestation, publicKey, options);
}

export { subjectKey as creatorSubjectKey };

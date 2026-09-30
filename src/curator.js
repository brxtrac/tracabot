import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { spawn } from 'node:child_process';
import { DkgClient, extractDomains, extractPatterns, extractWallets } from './dkg-client.js';
import { loadConfig } from './config.js';

const MODEL = '9router/cx/gpt-6-sol';
const MAX_REVIEWS = 5;
const MAX_RESPONSE_BYTES = 16000;

export function screenDraft(draft, now = Date.now()) {
  if (!Number.isFinite(Date.parse(draft.expires)) || Date.parse(draft.expires) <= now) return 'expired';
  const text = String(draft.text || '').trim();
  if (text.length < 24 || text.length > 500 || Number(draft.quality) < 70 || Number(draft.confidence) < 70) return 'weak';
  if (!extractDomains(text).length && !extractWallets(text).length && !extractPatterns(text).length) return 'weak';
  return 'review';
}

export function parseReview(content) {
  const answer = JSON.parse(content.trim());
  if (!answer || !['promote', 'reject', 'hold'].includes(answer.action)
    || !['fraud', 'impersonation', 'harmful', 'insufficient'].includes(answer.category)
    || typeof answer.reason !== 'string' || answer.reason.trim().length < 30 || answer.reason.length > 500
    || typeof answer.evidence !== 'string' || answer.evidence.trim().length < 12 || answer.evidence.length > 300) {
    throw new Error('LLM review missing valid action, category, reason, or evidence');
  }
  if (answer.action === 'promote' && answer.category === 'insufficient') throw new Error('Cannot promote insufficient evidence');
  return answer;
}

async function runCurator(prompt, { runner = spawn } = {}) {
  return new Promise((resolve, reject) => {
    const child = runner('opencode', ['run', '--agent', 'tracabot-curator', '--model', MODEL, '--variant', 'medium', '--format', 'json', '--title', 'TRACaBot evidence review', prompt],
      { cwd: '/root/tracabot', stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    let bytes = 0;
    let error = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 90000);
    child.stdout.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_RESPONSE_BYTES) { child.kill('SIGKILL'); return; }
      output += chunk;
    });
    child.stderr.on('data', (chunk) => { error = (error + chunk).slice(-1000); });
    child.on('error', (failure) => { clearTimeout(timer); reject(failure); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 || bytes > MAX_RESPONSE_BYTES) { reject(new Error(`OpenCode curator failed (${code}): ${error.slice(-200)}`)); return; }
      try {
        const events = output.split('\n').filter(Boolean).map((line) => JSON.parse(line));
        if (events.some((event) => event.type === 'error')) throw new Error('OpenCode curator reported an error');
        const text = events.filter((event) => event.type === 'text').map((event) => event.part?.text || '').join('');
        resolve(text);
      } catch (failure) { reject(failure); }
    });
  });
}

export async function reviewDraft(draft, options = {}) {
  const prompt = `Review candidate. Return JSON only. ${JSON.stringify({ message: String(draft.text).slice(0, 500), localRiskScore: draft.confidence, localQualityScore: draft.quality })}`;
  return parseReview(await runCurator(prompt, options));
}

export async function reviewBan(message, history, options = {}) {
  const prompt = `ban-verification. Return JSON only. ${JSON.stringify({ message: String(message.text || message.caption || '').slice(0, 500), history })}`;
  const decision = JSON.parse((await runCurator(prompt, options)).trim());
  if (!decision || !['ban', 'hold'].includes(decision.action) || typeof decision.reason !== 'string'
    || decision.reason.trim().length < 30 || decision.reason.length > 500
    || typeof decision.evidence !== 'string' || decision.evidence.length < 12 || decision.evidence.length > 300) {
    throw new Error('Invalid curator ban decision');
  }
  if (decision.action === 'ban' && (!history.some((item) => item.eventId === decision.historyEventId)
    || !String(message.text || message.caption || '').toLowerCase().includes(decision.evidence.toLowerCase()))) {
    throw new Error('Curator ban evidence or history mismatch');
  }
  return decision;
}

function reviewLedger(path) {
  const db = new DatabaseSync(path);
  db.exec(`PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS curator_reviews (
    id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, action TEXT NOT NULL,
    category TEXT NOT NULL, reason TEXT NOT NULL, evidence TEXT NOT NULL,
    status TEXT NOT NULL, updated_at TEXT NOT NULL)`);
  return db;
}

function isTransientDkgError(error) {
  const message = `${error instanceof Error ? error.message : String(error || '')} ${error?.cause?.code || ''}`;
  return /timeout|timed?\s*out|econnreset|econnrefused|enetunreach|socket|fetch failed|temporar|503|502|504|429/i.test(message);
}

async function loadPendingDrafts(dkg, limit) {
  const attempts = [0, 250, 1000];
  let lastError;
  for (let index = 0; index < attempts.length; index += 1) {
    if (attempts[index] > 0) await new Promise((resolve) => setTimeout(resolve, attempts[index]));
    try {
      return await dkg.pendingConversationArtifacts({ limit });
    } catch (error) {
      lastError = error;
      if (!isTransientDkgError(error) || index === attempts.length - 1) throw error;
    }
  }
  throw lastError;
}

export async function curateWorkingMemory({ dkg = new DkgClient(loadConfig()), limit = 100, now = Date.now(),
  reviewer = reviewDraft, ledgerPath = '/root/tracabot/data/curator-reviews.sqlite', maxReviews = MAX_REVIEWS } = {}) {
  const drafts = await loadPendingDrafts(dkg, limit);
  const results = [];
  let reviewed = 0;
  const ledger = reviewLedger(ledgerPath);
  try {
    for (const draft of drafts) {
      try {
        const screen = screenDraft(draft, now);
        if (screen === 'expired') {
          await dkg.resolveConversationArtifact(draft.id);
          results.push({ id: draft.id, action: 'discard_expired' });
          continue;
        }
        if (screen === 'weak') {
          await dkg.resolveConversationArtifact(draft.id);
          results.push({ id: draft.id, action: 'discard_filtered' });
          continue;
        }
        const fingerprint = createHash('sha256').update(JSON.stringify([draft.text, draft.quality, draft.confidence])).digest('hex');
        let row = ledger.prepare('SELECT * FROM curator_reviews WHERE id=?').get(draft.id);
        if (row && row.fingerprint !== fingerprint) throw new Error('Draft changed after review; manual review required');
        if (row?.status === 'done') { results.push({ id: draft.id, action: 'already_reviewed' }); continue; }
        if (!row) {
          if (reviewed >= maxReviews) { results.push({ id: draft.id, action: 'budget_deferred' }); continue; }
          reviewed++;
          const recommendation = await reviewer(draft);
          const verdict = parseReview(JSON.stringify(recommendation));
          ledger.prepare('INSERT INTO curator_reviews VALUES (?,?,?,?,?,?,?,?)').run(
            draft.id, fingerprint, verdict.action, verdict.category, verdict.reason.trim(), verdict.evidence.trim(),
            'reviewed', new Date().toISOString());
          row = ledger.prepare('SELECT * FROM curator_reviews WHERE id=?').get(draft.id);
        }
        if (row.action === 'promote') {
          if (!String(draft.text).toLowerCase().includes(row.evidence.toLowerCase())) {
            throw new Error('Promotion evidence does not match source message');
          }
          if (!dkg.annotateConversationArtifact) throw new Error('DKG cannot attach review provenance');
          await dkg.annotateConversationArtifact(draft.id, row);
          await dkg.resolveConversationArtifact(draft.id, { share: true });
        }
        ledger.prepare("UPDATE curator_reviews SET status='done', updated_at=? WHERE id=?")
          .run(new Date().toISOString(), draft.id);
        results.push({ id: draft.id, action: row.action, category: row.category, reason: row.reason });
      } catch (error) {
        results.push({ id: draft.id, action: 'error', error: error instanceof Error ? error.message : String(error) });
      }
    }
  } finally { ledger.close(); }
  return results;
}

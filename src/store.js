import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const OBSERVED_MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const OBSERVED_MESSAGE_MAX_PER_USER = 100;
const CLAIM_TTL_MS = 5 * 60 * 1000;

function sqlitePath(path) {
  return path.endsWith('.jsonl') ? path.replace(/\.jsonl$/i, '.sqlite') : path;
}

function legacyEventId(path, index, line) {
  return `legacy:${createHash('sha256').update(`${path}:${index}:${line}`).digest('hex')}`;
}

export class EventStore {
  constructor(path, options = {}) {
    if (!path || path === '.' || path.endsWith('/')) throw new Error('EventStore path must be a file path');
    const requestedPath = resolve(path);
    this.legacyPath = options.legacyPath ? resolve(options.legacyPath) : requestedPath.endsWith('.jsonl') ? requestedPath : '';
    this.path = resolve(sqlitePath(requestedPath));
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(this.path);
    this.eventsCache = null;
    this.eventsDataVersion = null;
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        event_type TEXT,
        timestamp TEXT,
        dedupe_key TEXT UNIQUE,
        source_update_id INTEGER,
        body TEXT NOT NULL CHECK (json_valid(body))
      ) STRICT;
      CREATE INDEX IF NOT EXISTS events_type_timestamp ON events(event_type, timestamp);
      CREATE TABLE IF NOT EXISTS imports (
        source_path TEXT PRIMARY KEY,
        source_hash TEXT NOT NULL,
        imported_rows INTEGER NOT NULL,
        malformed_rows INTEGER NOT NULL,
        imported_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS polling_state (
        bot_key TEXT PRIMARY KEY,
        next_offset INTEGER NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS telegram_updates (
        bot_key TEXT NOT NULL,
        update_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        body TEXT NOT NULL CHECK (json_valid(body)),
        error TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (bot_key, update_id)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS effects (
        effect_key TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        request TEXT NOT NULL CHECK (json_valid(request)),
        response TEXT CHECK (response IS NULL OR json_valid(response)),
        attempts INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        updated_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS metrics (
        name TEXT PRIMARY KEY,
        value INTEGER NOT NULL DEFAULT 0
      ) STRICT;
      CREATE TABLE IF NOT EXISTS observed_messages (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        message_id INTEGER NOT NULL,
        observed_at TEXT NOT NULL,
        PRIMARY KEY (chat_id, user_id, message_id)
      ) STRICT;
      CREATE TABLE IF NOT EXISTS cooldowns (
        cooldown_key TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS ban_candidates (
        candidate_key TEXT PRIMARY KEY, body TEXT NOT NULL CHECK (json_valid(body)),
        status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL, review_started_at TEXT, error TEXT
      ) STRICT;
    `);
    this.migrateSchema();
    this.insertEvent = this.db.prepare('INSERT OR IGNORE INTO events (id, event_type, timestamp, dedupe_key, source_update_id, body) VALUES (?, ?, ?, ?, ?, ?)');
    this.importLegacy();
  }

  migrateSchema() {
    const eventColumns = new Set(this.db.prepare('PRAGMA table_info(events)').all().map((column) => column.name));
    if (!eventColumns.has('dedupe_key')) this.db.exec('ALTER TABLE events ADD COLUMN dedupe_key TEXT');
    if (!eventColumns.has('source_update_id')) this.db.exec('ALTER TABLE events ADD COLUMN source_update_id INTEGER');
    const candidateColumns = new Set(this.db.prepare('PRAGMA table_info(ban_candidates)').all().map((column) => column.name));
    if (!candidateColumns.has('review_started_at')) this.db.exec('ALTER TABLE ban_candidates ADD COLUMN review_started_at TEXT');
    this.db.exec(`
      CREATE UNIQUE INDEX IF NOT EXISTS events_dedupe_key ON events(dedupe_key) WHERE dedupe_key IS NOT NULL;
      PRAGMA user_version = 2;
    `);
  }

  importLegacy() {
    if (!this.legacyPath || !existsSync(this.legacyPath)) return;
    if (this.db.prepare('SELECT 1 FROM imports WHERE source_path = ?').get(this.legacyPath)) return;
    const contents = readFileSync(this.legacyPath, 'utf8');
    const hash = createHash('sha256').update(contents).digest('hex');
    let imported = 0;
    let malformed = 0;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      if (this.db.prepare('SELECT 1 FROM imports WHERE source_path = ?').get(this.legacyPath)) {
        this.db.exec('COMMIT');
        return;
      }
      for (const [index, line] of contents.split('\n').entries()) {
        if (!line) continue;
        try {
          const event = JSON.parse(line);
          event.id ||= legacyEventId(this.legacyPath, index + 1, line);
          const result = this.insertEvent.run(event.id, event.event_type || '', event.timestamp || '', null, null, JSON.stringify(event));
          imported += Number(result.changes || 0);
        } catch {
          malformed += 1;
        }
      }
      this.db.prepare('INSERT INTO imports (source_path, source_hash, imported_rows, malformed_rows, imported_at) VALUES (?, ?, ?, ?, ?)')
        .run(this.legacyPath, hash, imported, malformed, new Date().toISOString());
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  append(event, options = {}) {
    if (!event?.id) event.id = randomUUID();
    const result = this.insertEvent.run(
      event.id,
      event.event_type || '',
      event.timestamp || '',
      options.dedupeKey || null,
      options.sourceUpdateId ?? null,
      JSON.stringify(event)
    );
    if (Number(result.changes || 0) > 0) this.eventsCache = null;
    return { event, inserted: Number(result.changes || 0) > 0 };
  }

  all() {
    const dataVersion = Number(this.db.prepare('PRAGMA data_version').get().data_version);
    if (this.eventsCache && this.eventsDataVersion === dataVersion) return this.eventsCache;
    this.eventsCache = this.db.prepare('SELECT body FROM events ORDER BY sequence').all().map((row) => JSON.parse(row.body));
    this.eventsDataVersion = dataVersion;
    return this.eventsCache;
  }

  pollingOffset(botKey) {
    const row = this.db.prepare('SELECT next_offset FROM polling_state WHERE bot_key = ?').get(botKey);
    return row ? Number(row.next_offset) : null;
  }

  initializePollingOffset(botKey, nextOffset) {
    this.db.prepare('INSERT OR IGNORE INTO polling_state (bot_key, next_offset, updated_at) VALUES (?, ?, ?)')
      .run(botKey, Number(nextOffset), new Date().toISOString());
    return this.pollingOffset(botKey);
  }

  claimUpdate(botKey, update) {
    const now = new Date().toISOString();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare('SELECT status FROM telegram_updates WHERE bot_key = ? AND update_id = ?').get(botKey, update.update_id);
      if (existing?.status === 'completed') {
        this.db.exec('COMMIT');
        return 'completed';
      }
      const processing = this.db.prepare('SELECT status, updated_at FROM telegram_updates WHERE bot_key = ? AND update_id = ?').get(botKey, update.update_id);
      if (processing?.status === 'processing' && Date.now() - Date.parse(processing.updated_at || '') < 5 * 60 * 1000) {
        this.db.exec('COMMIT');
        return 'processing';
      }
      this.db.prepare(`
        INSERT INTO telegram_updates (bot_key, update_id, status, attempts, body, updated_at)
        VALUES (?, ?, 'processing', 1, ?, ?)
        ON CONFLICT(bot_key, update_id) DO UPDATE SET status='processing', attempts=attempts+1, body=excluded.body, error=NULL, updated_at=excluded.updated_at
      `).run(botKey, update.update_id, JSON.stringify(update), now);
      this.db.exec('COMMIT');
      return 'claimed';
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  completeUpdate(botKey, updateId, nextOffset) {
    const now = new Date().toISOString();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const completed = this.db.prepare("UPDATE telegram_updates SET status='completed', error=NULL, updated_at=? WHERE bot_key=? AND update_id=? AND status='processing'").run(now, botKey, updateId);
      if (Number(completed.changes || 0) !== 1) throw new Error(`Telegram update ${updateId} is not processing`);
      this.db.prepare(`
        INSERT INTO polling_state (bot_key, next_offset, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(bot_key) DO UPDATE SET next_offset=MAX(next_offset, excluded.next_offset), updated_at=excluded.updated_at
      `).run(botKey, Number(nextOffset), now);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  failUpdate(botKey, updateId, error) {
    this.db.prepare("UPDATE telegram_updates SET status='failed', error=?, updated_at=? WHERE bot_key=? AND update_id=? AND status='processing'")
      .run(String(error || '').slice(0, 500), new Date().toISOString(), botKey, updateId);
  }

  enqueueBanCandidate(message) {
    const key = `${message.chat.id}:${message.from.id}:${message.message_id}`;
    const body = JSON.stringify({ chat: { id: message.chat.id, type: message.chat.type },
      from: { id: message.from.id }, message_id: message.message_id,
      text: String(message.text || message.caption || '').slice(0, 700), date: message.date });
    this.db.prepare("INSERT OR IGNORE INTO ban_candidates(candidate_key,body,status,updated_at) VALUES (?,?,'pending',?)")
      .run(key, body, new Date().toISOString());
  }

  nextBanCandidate() {
    this.db.prepare("UPDATE ban_candidates SET status='failed',error='Worker exited during review; manual check required' WHERE status='processing' AND updated_at<?")
      .run(new Date(Date.now() - 5 * 60000).toISOString());
    const row = this.db.prepare("SELECT candidate_key,body FROM ban_candidates WHERE status='pending' ORDER BY updated_at LIMIT 1").get();
    if (!row) return null;
    this.db.prepare("UPDATE ban_candidates SET status='processing',attempts=attempts+1,updated_at=?,review_started_at=? WHERE candidate_key=? AND status='pending'")
      .run(new Date().toISOString(), new Date().toISOString(), row.candidate_key);
    return { key: row.candidate_key, message: JSON.parse(row.body) };
  }

  finishBanCandidate(key, error = '') {
    this.db.prepare('UPDATE ban_candidates SET status=?,error=?,updated_at=? WHERE candidate_key=?')
      .run(error ? 'failed' : 'done', error.slice(0, 500), new Date().toISOString(), key);
  }

  banReviewBudget(limit = 5) {
    const count = this.db.prepare('SELECT count(*) AS n FROM ban_candidates WHERE review_started_at>=?')
      .get(new Date(Date.now() - 24 * 3600000).toISOString()).n;
    return count < limit;
  }

  beginEffect(key, kind, request, { staleAction = 'retry' } = {}) {
    if (!['retry', 'block', 'uncertain'].includes(staleAction)) throw new Error(`Invalid stale effect action: ${staleAction}`);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const serializedRequest = JSON.stringify(request);
      const row = this.db.prepare('SELECT kind, status, request, response, updated_at FROM effects WHERE effect_key = ?').get(key);
      if (row && (row.kind !== kind || row.request !== serializedRequest)) {
        throw new Error(`Effect key reuse with different request: ${key}`);
      }
      if (row?.status === 'completed') {
        this.db.exec('COMMIT');
        return { completed: true, response: row.response ? JSON.parse(row.response) : null };
      }
      if (row?.status === 'uncertain') {
        this.db.exec('COMMIT');
        return { completed: false, inProgress: false, uncertain: true };
      }
      if (row?.status === 'running') {
        const stale = Date.now() - Date.parse(row.updated_at || '') >= CLAIM_TTL_MS;
        if (!stale || staleAction === 'block') {
          this.db.exec('COMMIT');
          return { completed: false, inProgress: true };
        }
        if (staleAction === 'uncertain') {
          this.db.prepare("UPDATE effects SET status='uncertain', error=?, updated_at=? WHERE effect_key=? AND status='running'")
            .run('Effect owner disappeared before outcome was recorded', new Date().toISOString(), key);
          this.db.exec('COMMIT');
          return { completed: false, inProgress: false, uncertain: true };
        }
      }
      const now = new Date().toISOString();
      this.db.prepare(`
        INSERT INTO effects (effect_key, kind, status, request, attempts, updated_at) VALUES (?, ?, 'running', ?, 1, ?)
        ON CONFLICT(effect_key) DO UPDATE SET status='running', request=excluded.request, attempts=attempts+1, error=NULL, updated_at=excluded.updated_at
      `).run(key, kind, serializedRequest, now);
      this.db.exec('COMMIT');
      return { completed: false, inProgress: false };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  completeEffect(key, response, { allowUncertain = false } = {}) {
    const statuses = allowUncertain ? "status IN ('running', 'uncertain')" : "status='running'";
    return Number(this.db.prepare(`UPDATE effects SET status='completed', response=?, error=NULL, updated_at=? WHERE effect_key=? AND ${statuses}`)
      .run(JSON.stringify(response ?? null), new Date().toISOString(), key).changes || 0) === 1;
  }

  failEffect(key, error) {
    this.db.prepare("UPDATE effects SET status='failed', error=?, updated_at=? WHERE effect_key=? AND status='running'")
      .run(String(error || '').slice(0, 500), new Date().toISOString(), key);
  }

  markEffectUncertain(key, error) {
    this.db.prepare("UPDATE effects SET status='uncertain', error=?, updated_at=? WHERE effect_key=? AND status='running'")
      .run(String(error || '').slice(0, 500), new Date().toISOString(), key);
  }

  claimCooldown(key, intervalMs) {
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.db.prepare('SELECT status, updated_at FROM cooldowns WHERE cooldown_key = ?').get(key);
      const age = now - Date.parse(row?.updated_at || '');
      if ((row?.status === 'completed' && age < intervalMs) || (row?.status === 'reserved' && age < CLAIM_TTL_MS)) {
        this.db.exec('COMMIT');
        return false;
      }
      this.db.prepare(`
        INSERT INTO cooldowns (cooldown_key, status, updated_at) VALUES (?, 'reserved', ?)
        ON CONFLICT(cooldown_key) DO UPDATE SET status='reserved', updated_at=excluded.updated_at
      `).run(key, new Date(now).toISOString());
      this.db.exec('COMMIT');
      return true;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  completeCooldown(key) {
    this.db.prepare("UPDATE cooldowns SET status='completed', updated_at=? WHERE cooldown_key=? AND status='reserved'")
      .run(new Date().toISOString(), key);
  }

  releaseCooldown(key) {
    this.db.prepare("DELETE FROM cooldowns WHERE cooldown_key=? AND status='reserved'").run(key);
  }

  incrementMetric(name, amount = 1) {
    this.db.prepare('INSERT INTO metrics (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value').run(name, Number(amount));
  }

  rememberMessage(chatId, userId, messageId) {
    const normalizedChatId = String(chatId);
    const normalizedUserId = String(userId);
    const now = new Date();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM observed_messages WHERE observed_at < ?')
        .run(new Date(now.getTime() - OBSERVED_MESSAGE_TTL_MS).toISOString());
      this.db.prepare('INSERT OR IGNORE INTO observed_messages (chat_id, user_id, message_id, observed_at) VALUES (?, ?, ?, ?)')
        .run(normalizedChatId, normalizedUserId, Number(messageId), now.toISOString());
      this.db.prepare(`
        DELETE FROM observed_messages
        WHERE chat_id = ? AND user_id = ? AND message_id NOT IN (
          SELECT message_id FROM observed_messages
          WHERE chat_id = ? AND user_id = ?
          ORDER BY observed_at DESC, message_id DESC
          LIMIT ?
        )
      `).run(normalizedChatId, normalizedUserId, normalizedChatId, normalizedUserId, OBSERVED_MESSAGE_MAX_PER_USER);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  knownMessageIds(chatId, userId) {
    const cutoff = new Date(Date.now() - OBSERVED_MESSAGE_TTL_MS).toISOString();
    this.db.prepare('DELETE FROM observed_messages WHERE observed_at < ?').run(cutoff);
    return this.db.prepare('SELECT message_id FROM observed_messages WHERE chat_id = ? AND user_id = ? AND observed_at >= ? ORDER BY message_id')
      .all(String(chatId), String(userId), cutoff).map((row) => Number(row.message_id));
  }

  forgetMessage(chatId, userId, messageId) {
    this.db.prepare('DELETE FROM observed_messages WHERE chat_id = ? AND user_id = ? AND message_id = ?')
      .run(String(chatId), String(userId), Number(messageId));
  }

  metrics() {
    return Object.fromEntries(this.db.prepare('SELECT name, value FROM metrics ORDER BY name').all().map((row) => [row.name, Number(row.value)]));
  }

  stats(days = 7) {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const events = this.all().filter((event) => new Date(event.timestamp).getTime() >= cutoff);
    const byType = {};
    const byEventType = {};
    let highConfidence = 0;
    for (const event of events) {
      const key = event.payload?.scam_type || event.event_type || 'unknown';
      byType[key] = (byType[key] || 0) + 1;
      byEventType[event.event_type || 'unknown'] = (byEventType[event.event_type || 'unknown'] || 0) + 1;
      if (Number(event.payload?.confidence || 0) >= 85) highConfidence += 1;
    }
    return { total: events.length, byType, byEventType, highConfidence };
  }
}

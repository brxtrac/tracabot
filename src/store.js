import { mkdirSync, appendFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export class EventStore {
  constructor(path) {
    if (!path || path === '.' || path.endsWith('/')) throw new Error('EventStore path must be a file path');
    this.path = resolve(path);
    this.events = null;
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
  }

  append(event) {
    appendFileSync(this.path, `${JSON.stringify(event)}\n`, { mode: 0o600 });
    if (this.events) this.events.push(event);
  }

  all() {
    if (this.events) return this.events;
    if (!existsSync(this.path)) {
      this.events = [];
      return this.events;
    }
    this.events = readFileSync(this.path, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    return this.events;
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

import { mkdirSync, appendFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';

export class EventStore {
  constructor(path) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
  }

  append(event) {
    appendFileSync(this.path, `${JSON.stringify(event)}\n`, { mode: 0o600 });
  }

  all() {
    if (!existsSync(this.path)) return [];
    return readFileSync(this.path, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  }

  stats(days = 7) {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const events = this.all().filter((event) => new Date(event.timestamp).getTime() >= cutoff);
    const byType = {};
    for (const event of events) {
      const key = event.payload?.scam_type || event.event_type || 'unknown';
      byType[key] = (byType[key] || 0) + 1;
    }
    return { total: events.length, byType };
  }
}

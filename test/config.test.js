import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';

test('loadConfig rejects unsafe context graph names', () => {
  assert.throws(() => loadConfig({ TRACABOT_CONTEXT_GRAPH: 'bad graph' }), /TRACABOT_CONTEXT_GRAPH/);
  assert.throws(() => loadConfig({ TRACABOT_CONTEXT_GRAPH: '../bad' }), /TRACABOT_CONTEXT_GRAPH/);
});

test('loadConfig parses boolean environment values strictly', () => {
  assert.equal(loadConfig({ TRACABOT_AUTO_BAN: '0' }).autoBan, false);
  assert.equal(loadConfig({ TRACABOT_AUTO_BAN: 'yes' }).autoBan, true);
  assert.throws(() => loadConfig({ TRACABOT_AUTO_BAN: 'maybe' }), /Invalid boolean/);
});

test('loadConfig parses graduated autonomous enforcement thresholds', () => {
  const config = loadConfig({
    TRACABOT_WARN_THRESHOLD: '55',
    TRACABOT_RESTRICT_THRESHOLD: '76',
    TRACABOT_BAN_THRESHOLD: '92',
    TRACABOT_AUTO_DELETE: 'false',
    TRACABOT_AUTO_RESTRICT: 'true'
  });
  assert.equal(config.warnThreshold, 55);
  assert.equal(config.restrictThreshold, 76);
  assert.equal(config.banThreshold, 92);
  assert.equal(config.autoDelete, false);
  assert.equal(config.autoRestrict, true);
  assert.throws(() => loadConfig({ TRACABOT_WARN_THRESHOLD: '80', TRACABOT_RESTRICT_THRESHOLD: '70' }), /TRACABOT_RESTRICT_THRESHOLD/);
});

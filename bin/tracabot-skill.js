#!/usr/bin/env node
import { runSkillTool } from '../src/skill-service.js';

const [, , tool, rawInput = '{}'] = process.argv;

function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

try {
  if (!tool) throw new Error('Usage: tracabot-skill <tool> <json-input>');
  const input = JSON.parse(rawInput || '{}');
  const result = await runSkillTool(tool, input);
  writeJson({ ok: true, result });
} catch (error) {
  writeJson({ ok: false, error: error instanceof Error ? error.message : String(error) });
  process.exitCode = 1;
}

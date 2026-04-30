#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { loadConfig } from '../src/config.js';
import { DkgClient } from '../src/dkg-client.js';
import { analyzeMessage } from '../src/scam-analyzer.js';

const config = loadConfig();
const dkg = new DkgClient(config);
const payload = analyzeMessage({
  text: 'URGENT free 2000 USDT airdrop. Claim now at t.me/fakeclaim and verify wallet with support admin.',
  user: { id: 'demo-user', username: 'support_admin_bonus' },
  globalIntel: { reportsAcrossCommunities: 2 }
});

const event = {
  id: randomUUID(),
  event_type: 'scam_detection',
  timestamp: new Date().toISOString(),
  agentDid: config.agentDid,
  chat: { id: 'demo-chat', title: 'tracabot demo' },
  user: { id: 'demo-user', username: 'support_admin_bonus' },
  payload
};

const result = await dkg.writeEvent(event);
console.log(JSON.stringify({ eventId: event.id, contextGraph: config.contextGraph, result }, null, 2));

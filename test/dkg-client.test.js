import test from 'node:test';
import assert from 'node:assert/strict';
import { extractPatterns, extractWallets } from '../src/dkg-client.js';

test('extracts wallet addresses and scam patterns for DKG lookups', () => {
  const text = 'URGENT official support says verify wallet 0x1111111111111111111111111111111111111111 to claim free USDT airdrop';
  assert.deepEqual(extractWallets(text), ['0x1111111111111111111111111111111111111111']);
  assert.deepEqual(extractPatterns(text), ['fake-airdrop', 'wallet-drain', 'impersonation', 'urgency-pressure']);
});

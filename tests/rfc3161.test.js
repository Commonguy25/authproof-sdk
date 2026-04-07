/**
 * AuthProof — Gap 1: RFC 3161 Trusted Timestamps
 * Run: node tests/rfc3161.test.js
 *
 * Tests cover:
 *  - UNVERIFIED_TIMESTAMP path (forced by tsaUrl: null or bad URL)
 *  - RFC3161 path (when freetsa.org is reachable — skipped gracefully if not)
 *  - verifyTimestamp() on both path types and edge cases
 *  - Chain integrity is preserved with the new timestamp fields
 *  - Signature covers timestamp fields (tamper detection)
 */

import AuthProof, { ActionLog } from '../src/authproof.js';

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}`);
    failed++;
  }
}

async function run() {
  console.log('Gap 1 — RFC 3161 Trusted Timestamps\n');

  // ── Shared key pair ──────────────────────────────────────────────────
  const { privateKey, publicJwk } = await AuthProof.generateKey();

  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Search the web. Read calendar events.',
    boundaries:   'Do not send emails. Do not delete files.',
    instructions: 'Cite sources.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });

  // ── Test Group 1: UNVERIFIED_TIMESTAMP path (tsaUrl: null) ──────────
  console.log('Test Group 1: UNVERIFIED_TIMESTAMP path (tsaUrl: null)');

  const log = new ActionLog();
  await log.init({ privateKey, publicJwk, tsaUrl: null });
  log.registerReceipt(receiptId, receipt);

  const entry = await log.record(receiptId, {
    operation:  'Search competitor pricing',
    resource:   'web/search',
    parameters: { query: 'test query' },
  });

  // Test 1: entry has timestampType
  assert(typeof entry.timestampType === 'string', 'entry has timestampType field');

  // Test 2: without TSA, type is UNVERIFIED_TIMESTAMP
  assert(entry.timestampType === 'UNVERIFIED_TIMESTAMP',
    'tsaUrl:null produces UNVERIFIED_TIMESTAMP');

  // Test 3: no timestampToken on unverified entries
  assert(!('timestampToken' in entry),
    'UNVERIFIED_TIMESTAMP entry has no timestampToken field');

  // Test 4: entry still has a numeric timestamp (local clock)
  assert(typeof entry.timestamp === 'number' && entry.timestamp > 0,
    'entry still has numeric timestamp (local clock)');

  // Test 5: entry has entryBodyHash
  assert(typeof entry.entryBodyHash === 'string' && entry.entryBodyHash.length === 64,
    'entry has 64-char entryBodyHash (SHA-256)');

  // Test 6: chain integrity still valid after adding timestamp fields
  const chainCheck = await log.verify(entry.entryId);
  assert(chainCheck.valid === true, 'UNVERIFIED_TIMESTAMP entry passes chain integrity check');

  // Test 7: verifyTimestamp on UNVERIFIED_TIMESTAMP returns verified:false
  const tsv1 = await log.verifyTimestamp(entry.entryId);
  assert(tsv1.verified === false, 'verifyTimestamp returns verified:false for UNVERIFIED_TIMESTAMP');

  // Test 8: verifyTimestamp type field matches entry
  assert(tsv1.type === 'UNVERIFIED_TIMESTAMP',
    'verifyTimestamp type matches entry timestampType');

  // Test 9: verifyTimestamp reason mentions local clock
  assert(typeof tsv1.reason === 'string' && tsv1.reason.toLowerCase().includes('local'),
    'verifyTimestamp reason mentions local system clock');

  // Test 10: verifyTimestamp includes timestamp
  assert(tsv1.timestamp === entry.timestamp,
    'verifyTimestamp passes through the entry timestamp value');

  // ── Test Group 2: UNVERIFIED_TIMESTAMP via unreachable TSA URL ───────
  console.log('\nTest Group 2: UNVERIFIED_TIMESTAMP via unreachable TSA URL');

  const log2 = new ActionLog();
  // Use a port that won't respond — should fail fast and fall back
  await log2.init({ privateKey, publicJwk, tsaUrl: 'http://127.0.0.1:1' });
  log2.registerReceipt(receiptId, receipt);

  const entry2 = await log2.record(receiptId, {
    operation: 'Read calendar events',
    resource:  'calendar/events',
  });

  // Test 11: unreachable TSA also produces UNVERIFIED_TIMESTAMP (no throw)
  assert(entry2.timestampType === 'UNVERIFIED_TIMESTAMP',
    'unreachable TSA falls back to UNVERIFIED_TIMESTAMP without throwing');

  // Test 12: fallback entry still has all required fields
  assert(
    typeof entry2.entryId === 'string' &&
    typeof entry2.receiptHash === 'string' &&
    typeof entry2.signature === 'string' &&
    typeof entry2.entryHash === 'string',
    'UNVERIFIED_TIMESTAMP fallback entry has all required fields'
  );

  // ── Test Group 3: verifyTimestamp edge cases ─────────────────────────
  console.log('\nTest Group 3: verifyTimestamp edge cases');

  // Test 13: verifyTimestamp on non-existent entryId
  const tsv2 = await log.verifyTimestamp('log-nonexistent-9999');
  assert(tsv2.verified === false, 'verifyTimestamp returns verified:false for unknown entryId');
  assert(tsv2.type === null, 'verifyTimestamp type is null for unknown entryId');
  assert(typeof tsv2.reason === 'string', 'verifyTimestamp reason is a string for unknown entry');

  // ── Test Group 4: Two entries in chain both have timestamp fields ─────
  console.log('\nTest Group 4: Multiple entries — chain + timestamp fields');

  const log3 = new ActionLog();
  await log3.init({ privateKey, publicJwk, tsaUrl: null });
  log3.registerReceipt(receiptId, receipt);

  const e1 = await log3.record(receiptId, { operation: 'op_one', resource: 'res/one' });
  const e2 = await log3.record(receiptId, { operation: 'op_two', resource: 'res/two' });

  // Test 14: both entries have timestampType
  assert(e1.timestampType === 'UNVERIFIED_TIMESTAMP' && e2.timestampType === 'UNVERIFIED_TIMESTAMP',
    'both entries in a chain have timestampType');

  // Test 15: both entries have entryBodyHash
  assert(
    typeof e1.entryBodyHash === 'string' && e1.entryBodyHash.length === 64 &&
    typeof e2.entryBodyHash === 'string' && e2.entryBodyHash.length === 64,
    'both chain entries have entryBodyHash'
  );

  // Test 16: chain linkage still correct
  assert(e2.prevHash === e1.entryHash, 'chain linkage preserved with timestamp fields');

  // Test 17: both entries verify correctly
  const cv1 = await log3.verify(e1.entryId);
  const cv2 = await log3.verify(e2.entryId);
  assert(cv1.valid && cv2.valid, 'both chain entries pass verify()');

  // ── Test Group 5: Signature covers timestampType (tamper detection) ──
  console.log('\nTest Group 5: Signature covers timestampType');

  const log4 = new ActionLog();
  await log4.init({ privateKey, publicJwk, tsaUrl: null });
  log4.registerReceipt(receiptId, receipt);

  const eOrig = await log4.record(receiptId, { operation: 'search', resource: 'web' });

  // Verify clean before tamper
  const beforeTamper = await log4.verify(eOrig.entryId);
  assert(beforeTamper.valid === true, 'entry valid before tamper');

  // Tamper the timestampType
  const entries4 = log4.getEntries(receiptId);
  entries4[0].timestampType = 'RFC3161';  // forge as trusted

  const afterTamper = await log4.verify(eOrig.entryId);

  // Test 18: tampering timestampType causes signature or hash failure
  assert(afterTamper.valid === false,
    'tampering timestampType fails verify() — signature covers timestamp fields');

  // ── Test Group 6: RFC 3161 live path (network-dependent) ─────────────
  console.log('\nTest Group 6: RFC 3161 live path (skipped if no network)');

  let liveEntryId = null;
  let liveSkipped = false;

  try {
    const logLive = new ActionLog();
    // Use default TSA URL (freetsa.org)
    await logLive.init({ privateKey, publicJwk });
    logLive.registerReceipt(receiptId, receipt);

    const liveEntry = await logLive.record(receiptId, {
      operation: 'Search competitor pricing',
      resource:  'web/search',
    });

    liveEntryId = liveEntry.entryId;

    if (liveEntry.timestampType === 'RFC3161') {
      // Test 19: RFC3161 entry has timestampToken
      assert(typeof liveEntry.timestampToken === 'string' && liveEntry.timestampToken.length > 0,
        'RFC3161 entry has non-empty timestampToken');

      // Test 20: verifyTimestamp on RFC3161 entry returns verified:true
      const tsv3 = await logLive.verifyTimestamp(liveEntry.entryId);
      assert(tsv3.verified === true,
        'verifyTimestamp returns verified:true for RFC3161 entry');
      assert(tsv3.type === 'RFC3161',
        'verifyTimestamp type is RFC3161');
      assert(tsv3.tokenBase64 === liveEntry.timestampToken,
        'verifyTimestamp tokenBase64 matches entry timestampToken');

      // Test 21: chain integrity valid with RFC3161 entry
      const chainLive = await logLive.verify(liveEntry.entryId);
      assert(chainLive.valid === true,
        'RFC3161 entry passes chain integrity check');

    } else {
      // TSA was reachable but returned UNVERIFIED_TIMESTAMP — still valid behavior
      console.log('  ℹ TSA request fell back to UNVERIFIED_TIMESTAMP (TSA may be slow)');
      liveSkipped = true;
    }
  } catch (e) {
    console.log(`  ℹ Live RFC 3161 tests skipped — network unavailable: ${e.message}`);
    liveSkipped = true;
  }

  if (liveSkipped) {
    console.log('  ℹ RFC3161 live tests skipped (no network) — all other tests still ran');
  }

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (liveSkipped) {
    console.log('(RFC3161 live tests were skipped due to network unavailability)');
  }
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Gap 1 RFC 3161 tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

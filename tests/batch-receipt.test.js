/**
 * Feature 2 — Batch Receipt
 * Tests for BatchReceipt, ActionLog.record() batchReceiptHash, and AuthProof.createBatch
 */

import AuthProof from '../src/authproof.js';

const { BatchReceipt, ActionLog, generateKey } = AuthProof;

// ─────────────────────────────────────────────
// TEST HARNESS
// ─────────────────────────────────────────────

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

async function assertThrows(fn, label) {
  try {
    await fn();
    console.error(`  ✗ ${label} (expected throw, got none)`);
    failed++;
  } catch {
    console.log(`  ✓ ${label}`);
    passed++;
  }
}

async function assertThrowsMsg(fn, substr, label) {
  try {
    await fn();
    console.error(`  ✗ ${label} (expected throw, got none)`);
    failed++;
  } catch (e) {
    if (e.message.includes(substr)) {
      console.log(`  ✓ ${label}`);
      passed++;
    } else {
      console.error(`  ✗ ${label} (got: "${e.message}", expected to include: "${substr}")`);
      failed++;
    }
  }
}

// ─────────────────────────────────────────────
// SHARED FIXTURES
// ─────────────────────────────────────────────

console.log('\nFeature 2 — Batch Receipt\n');

const { privateKey, publicJwk } = await generateKey();
const delegationReceiptHash = 'a'.repeat(64); // fake 64-char hex

const TWO_ACTIONS = [
  { operation: 'read',  resource: 'calendar/events' },
  { operation: 'write', resource: 'calendar/summary' },
];

// ─────────────────────────────────────────────
// Test Group 1: create() — input validation
// ─────────────────────────────────────────────

console.log('Test Group 1: create() — input validation');

await assertThrowsMsg(
  () => BatchReceipt.create({ actions: TWO_ACTIONS, privateKey, publicJwk }),
  'delegationReceiptHash',
  'throws for missing delegationReceiptHash'
);
await assertThrowsMsg(
  () => BatchReceipt.create({ delegationReceiptHash, privateKey, publicJwk }),
  'actions must be a non-empty array',
  'throws for missing actions'
);
await assertThrowsMsg(
  () => BatchReceipt.create({ delegationReceiptHash, actions: [], privateKey, publicJwk }),
  'actions must be a non-empty array',
  'throws for empty actions array'
);
await assertThrowsMsg(
  () => BatchReceipt.create({ delegationReceiptHash, actions: [{ resource: 'x' }], privateKey, publicJwk }),
  'operation is required',
  'throws for action missing operation'
);
await assertThrowsMsg(
  () => BatchReceipt.create({ delegationReceiptHash, actions: [{ operation: 'read' }], privateKey, publicJwk }),
  'resource is required',
  'throws for action missing resource'
);
await assertThrowsMsg(
  () => BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, publicJwk }),
  'privateKey',
  'throws for missing privateKey'
);
await assertThrowsMsg(
  () => BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey }),
  'publicJwk',
  'throws for missing publicJwk'
);

// ─────────────────────────────────────────────
// Test Group 2: create() — output structure
// ─────────────────────────────────────────────

console.log('\nTest Group 2: create() — output structure');

const batch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });

assert(typeof batch.batchId === 'string',                                    'batchId is a string');
assert(batch.batchId.startsWith('batch-'),                                   'batchId starts with "batch-"');
assert(batch.delegationReceiptHash === delegationReceiptHash,                 'delegationReceiptHash preserved');
assert(Array.isArray(batch.actionChain),                                      'actionChain is an array');
assert(batch.actionChain.length === 2,                                        'actionChain has 2 entries');
assert(typeof batch.expiresAt === 'string',                                   'expiresAt is a string');
assert(typeof batch.createdAt === 'string',                                   'createdAt is a string');
assert(typeof batch.bodyHash === 'string' && batch.bodyHash.length === 64,    'bodyHash is 64-char hex');
assert(typeof batch.signature === 'string',                                   'signature is present');
assert(typeof batch.signerPublicKey === 'object',                             'signerPublicKey is present');
assert(batch._currentIndex === 0,                                             '_currentIndex starts at 0');
assert(Array.isArray(batch._violations) && batch._violations.length === 0,   '_violations starts empty');

// ─────────────────────────────────────────────
// Test Group 3: Hash chain integrity
// ─────────────────────────────────────────────

console.log('\nTest Group 3: Hash chain integrity');

const slot0 = batch.actionChain[0];
const slot1 = batch.actionChain[1];

assert(slot0.prevHash === delegationReceiptHash,                              'slot 0 prevHash === delegationReceiptHash');
assert(slot1.prevHash === slot0.actionHash,                                   'slot 1 prevHash === slot 0 actionHash');
assert(slot0.actionHash.length === 64,                                        'slot 0 actionHash is 64-char hex');
assert(slot1.actionHash.length === 64,                                        'slot 1 actionHash is 64-char hex');
assert(slot0.actionHash !== slot1.actionHash,                                 'each slot has a distinct actionHash');
assert(slot0.index === 0 && slot1.index === 1,                                'index fields are correct');
assert(slot0.operation === 'read' && slot0.resource === 'calendar/events',    'slot 0 operation/resource preserved');
assert(slot1.operation === 'write' && slot1.resource === 'calendar/summary',  'slot 1 operation/resource preserved');

// Chain is deterministic: same inputs produce same hashes
const batch2 = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });
assert(batch2.actionChain[0].actionHash === batch.actionChain[0].actionHash,  'hash chain is deterministic for same inputs');

// Different delegation receipt → different hashes
const batch3 = await BatchReceipt.create({
  delegationReceiptHash: 'b'.repeat(64),
  actions: TWO_ACTIONS, privateKey, publicJwk,
});
assert(batch3.actionChain[0].actionHash !== batch.actionChain[0].actionHash,  'different delegationReceiptHash produces different chain');

// ─────────────────────────────────────────────
// Test Group 4: verify()
// ─────────────────────────────────────────────

console.log('\nTest Group 4: verify()');

const vResult = await BatchReceipt.verify(batch);
assert(vResult.valid === true,                                                 'verify() returns valid:true for correct batch');
assert(typeof vResult.reason === 'string',                                     'verify() result has reason string');

const nullResult = await BatchReceipt.verify(null);
assert(nullResult.valid === false,                                             'verify(null) returns valid:false');

const { privateKey: otherKey } = await generateKey();
const tamperedBatch = { ...batch, actionChain: [...batch.actionChain, { index: 99, operation: 'delete', resource: '*', actionHash: 'x'.repeat(64), prevHash: 'y'.repeat(64) }] };
const tamperedResult = await BatchReceipt.verify(tamperedBatch);
assert(tamperedResult.valid === false,                                         'tampered actionChain fails verify()');
assert(tamperedResult.reason.includes('tampered'),                             'tamper reason mentions tampered');

// ─────────────────────────────────────────────
// Test Group 5: validateNext() — valid paths
// ─────────────────────────────────────────────

console.log('\nTest Group 5: validateNext() — valid paths');

const freshBatch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });

const v1 = BatchReceipt.validateNext(freshBatch, { operation: 'read', resource: 'calendar/events' });
assert(v1.valid === true,                                                      'correct first action is valid');
assert(typeof v1.reason === 'string',                                          'validateNext returns a reason string');
assert(v1.reason.includes('calendar/events'),                                  'reason mentions the resource');

// validateNext does NOT advance — calling twice still returns valid
const v1again = BatchReceipt.validateNext(freshBatch, { operation: 'read', resource: 'calendar/events' });
assert(v1again.valid === true,                                                 'validateNext is non-destructive (cursor unchanged)');

// ─────────────────────────────────────────────
// Test Group 6: validateNext() — invalid paths
// ─────────────────────────────────────────────

console.log('\nTest Group 6: validateNext() — invalid paths');

const vWrongOp = BatchReceipt.validateNext(freshBatch, { operation: 'delete', resource: 'calendar/events' });
assert(vWrongOp.valid === false,                                               'wrong operation returns valid:false');
assert(vWrongOp.reason.includes('delete'),                                     'reason mentions the wrong operation');

const vWrongRes = BatchReceipt.validateNext(freshBatch, { operation: 'read', resource: 'files/secret' });
assert(vWrongRes.valid === false,                                              'wrong resource returns valid:false');
assert(vWrongRes.reason.includes('files/secret'),                              'reason mentions the wrong resource');

// All actions done — advance past all slots manually
const doneBatch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });
BatchReceipt.advance(doneBatch, doneBatch.actionChain[0].actionHash);
BatchReceipt.advance(doneBatch, doneBatch.actionChain[1].actionHash);
const vDone = BatchReceipt.validateNext(doneBatch, { operation: 'read', resource: 'calendar/events' });
assert(vDone.valid === false,                                                  'validates as invalid when all actions done');
assert(vDone.reason.includes('completed'),                                     'reason mentions completed');

// Expired batch
const expiredBatch = await BatchReceipt.create({
  delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk, expiresIn: -1,
});
const vExpired = BatchReceipt.validateNext(expiredBatch, { operation: 'read', resource: 'calendar/events' });
assert(vExpired.valid === false,                                               'expired batch validateNext returns false');
assert(vExpired.reason.includes('expired') || vExpired.reason.includes('Expired'), 'reason mentions expiry');

// ─────────────────────────────────────────────
// Test Group 7: advance() — valid paths
// ─────────────────────────────────────────────

console.log('\nTest Group 7: advance() — valid paths');

const advBatch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });

const a1 = BatchReceipt.advance(advBatch, advBatch.actionChain[0].actionHash);
assert(a1.advanced === true,                                                   'advance() returns advanced:true on success');
assert(a1.batch === advBatch,                                                  'advance() returns the same batch object');
assert(advBatch._currentIndex === 1,                                           '_currentIndex incremented to 1');

const a2 = BatchReceipt.advance(advBatch, advBatch.actionChain[1].actionHash);
assert(a2.advanced === true,                                                   'advance() succeeds for second slot');
assert(advBatch._currentIndex === 2,                                           '_currentIndex incremented to 2');

const a3 = BatchReceipt.advance(advBatch, 'anything');
assert(a3.advanced === false,                                                  'advance() on completed batch returns advanced:false');
assert(a3.reason.includes('complete'),                                         'reason mentions complete');

// ─────────────────────────────────────────────
// Test Group 8: advance() — hash mismatch
// ─────────────────────────────────────────────

console.log('\nTest Group 8: advance() — hash mismatch / violations');

const vBatch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });

const badAdvance = BatchReceipt.advance(vBatch, 'wrong-hash-' + 'x'.repeat(53));
assert(badAdvance.advanced === false,                                           'wrong hash returns advanced:false');
assert(badAdvance.reason.includes('mismatch'),                                  'reason mentions mismatch');
assert(vBatch._currentIndex === 0,                                             'cursor NOT advanced on hash mismatch');
assert(vBatch._violations.length === 1,                                        'violation recorded for hash mismatch');
assert(vBatch._violations[0].index === 0,                                      'violation has correct index');
assert(typeof vBatch._violations[0].reason === 'string',                       'violation has reason string');

// Correct hash after violation still advances
const goodAfterBad = BatchReceipt.advance(vBatch, vBatch.actionChain[0].actionHash);
assert(goodAfterBad.advanced === true,                                         'correct hash advances after a violation');
assert(vBatch._currentIndex === 1,                                             'cursor now at 1 after recovery');

// ─────────────────────────────────────────────
// Test Group 9: status()
// ─────────────────────────────────────────────

console.log('\nTest Group 9: status()');

const sBatch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });

const s0 = BatchReceipt.status(sBatch);
assert(s0.completed === 0,                                                     'status: completed=0 initially');
assert(s0.remaining === 2,                                                     'status: remaining=2 initially');
assert(s0.expired === false,                                                   'status: expired=false for fresh batch');
assert(Array.isArray(s0.violations) && s0.violations.length === 0,            'status: no violations initially');

BatchReceipt.advance(sBatch, sBatch.actionChain[0].actionHash);
const s1 = BatchReceipt.status(sBatch);
assert(s1.completed === 1,                                                     'status: completed=1 after one advance');
assert(s1.remaining === 1,                                                     'status: remaining=1 after one advance');

BatchReceipt.advance(sBatch, sBatch.actionChain[1].actionHash);
const s2 = BatchReceipt.status(sBatch);
assert(s2.completed === 2,                                                     'status: completed=2 after all advances');
assert(s2.remaining === 0,                                                     'status: remaining=0 after all advances');

const expiredS = await BatchReceipt.create({
  delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk, expiresIn: -1,
});
const sExp = BatchReceipt.status(expiredS);
assert(sExp.expired === true,                                                  'status: expired=true for past expiry');

BatchReceipt.advance(sBatch, 'bad-hash'); // inject a violation via the completed batch (advances from 2 which fails)
// Instead inject via a fresh batch
const violBatch = await BatchReceipt.create({ delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk });
BatchReceipt.advance(violBatch, 'wrong-hash');
const sViol = BatchReceipt.status(violBatch);
assert(sViol.violations.length === 1,                                          'status: violations array includes recorded violation');
assert(sViol.violations[0].index === 0,                                        'violation in status has correct index');

// ─────────────────────────────────────────────
// Test Group 10: ActionLog integration — batchReceiptHash
// ─────────────────────────────────────────────

console.log('\nTest Group 10: ActionLog integration — batchReceiptHash');

const log = new ActionLog();
await log.init({ privateKey, publicJwk, tsaUrl: null });

const { receipt, receiptId } = await AuthProof.create({
  scope:        'Read calendar events and write summaries',
  boundaries:   'No deletes, no external sharing',
  instructions: 'Use structured output only.',
  privateKey,
  publicJwk,
});
log.registerReceipt(receiptId, receipt);

const integBatch = await BatchReceipt.create({
  delegationReceiptHash: receiptId,
  actions: TWO_ACTIONS,
  privateKey,
  publicJwk,
});

// Record an entry with batchReceiptHash
const entry = await log.record(receiptId, { operation: 'read', resource: 'calendar/events' }, {
  batchReceiptHash: integBatch.batchId,
});
assert(entry.batchReceiptHash === integBatch.batchId,                          'entry includes batchReceiptHash');
assert(typeof entry.entryHash === 'string',                                    'entry still has entryHash');

const entryVerify = await log.verify(entry.entryId);
assert(entryVerify.valid === true,                                             'entry with batchReceiptHash verifies as valid');

// Entry without batchReceiptHash still works
const entryNoBatch = await log.record(receiptId, { operation: 'write', resource: 'calendar/summary' });
assert(entryNoBatch.batchReceiptHash === undefined,                            'entry without batchReceiptHash has no field');
const noBatchVerify = await log.verify(entryNoBatch.entryId);
assert(noBatchVerify.valid === true,                                           'entry without batchReceiptHash verifies as valid');

// ─────────────────────────────────────────────
// Test Group 11: AuthProof.createBatch convenience method
// ─────────────────────────────────────────────

console.log('\nTest Group 11: AuthProof.createBatch convenience method');

assert(typeof AuthProof.createBatch === 'function',                            'AuthProof.createBatch is a function');
assert(typeof AuthProof.BatchReceipt === 'function' || typeof AuthProof.BatchReceipt === 'object', 'AuthProof.BatchReceipt is exported');

const convBatch = await AuthProof.createBatch({
  delegationReceiptHash, actions: TWO_ACTIONS, privateKey, publicJwk,
});
assert(convBatch.batchId.startsWith('batch-'),                                 'createBatch produces a valid batch');
assert(convBatch.actionChain.length === 2,                                     'createBatch batch has correct chain length');

// ─────────────────────────────────────────────
// Test Group 12: End-to-end sequence
// ─────────────────────────────────────────────

console.log('\nTest Group 12: End-to-end sequence');

const e2eBatch = await BatchReceipt.create({
  delegationReceiptHash,
  actions: [
    { operation: 'read',   resource: 'database/users' },
    { operation: 'write',  resource: 'report/output' },
    { operation: 'notify', resource: 'email/admin' },
  ],
  privateKey,
  publicJwk,
  expiresIn: 3_600_000,
});

// Full valid sequence
const step0Valid = BatchReceipt.validateNext(e2eBatch, { operation: 'read', resource: 'database/users' });
assert(step0Valid.valid === true,                                               'e2e: step 0 validates correctly');

BatchReceipt.advance(e2eBatch, e2eBatch.actionChain[0].actionHash);
const step1Valid = BatchReceipt.validateNext(e2eBatch, { operation: 'write', resource: 'report/output' });
assert(step1Valid.valid === true,                                               'e2e: step 1 validates after step 0 advance');

// Trying to skip step 1 and validate step 2 (wrong operation at current position)
const skip = BatchReceipt.validateNext(e2eBatch, { operation: 'notify', resource: 'email/admin' });
assert(skip.valid === false,                                                    'e2e: skipping out of order is rejected');

BatchReceipt.advance(e2eBatch, e2eBatch.actionChain[1].actionHash);
BatchReceipt.advance(e2eBatch, e2eBatch.actionChain[2].actionHash);

const finalStatus = BatchReceipt.status(e2eBatch);
assert(finalStatus.completed === 3,                                            'e2e: all 3 steps completed');
assert(finalStatus.remaining === 0,                                            'e2e: 0 remaining after full execution');
assert(finalStatus.violations.length === 0,                                    'e2e: no violations in clean execution');
assert(finalStatus.expired === false,                                          'e2e: not expired in clean execution');

// verify() still holds after all advances
const e2eVerify = await BatchReceipt.verify(e2eBatch);
assert(e2eVerify.valid === true,                                               'e2e: sealed batch still verifies after execution');

// ─────────────────────────────────────────────
// RESULTS
// ─────────────────────────────────────────────

console.log('\n' + '─'.repeat(40));
console.log(`Results: ${passed} passed, ${failed} failed`);

if (failed === 0) {
  console.log('\n✓ All Batch Receipt tests passed.');
} else {
  console.error(`\n✗ ${failed} test(s) failed.`);
  process.exit(1);
}

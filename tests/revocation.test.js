/**
 * AuthProof — Gap 3: Revocation Registry
 * Run: node tests/revocation.test.js
 *
 * Tests cover:
 *  - RevocationRegistry construction and init()
 *  - revoke() — signed record, required fields, append-only enforcement
 *  - check() — not revoked, revoked, reason + revokedAt
 *  - export() / import() — round-trip, signature verification on import
 *  - import() — skips invalid signatures and duplicate hashes
 *  - ActionLog.record() — rejects actions under a revoked receipt
 *  - ActionLog.record() — accepts actions under a non-revoked receipt
 *  - AuthProof.verify() — fails when registry marks receipt revoked
 *  - AuthProof.verify() — passes when not in registry
 *  - Cross-receipt isolation — only the revoked receipt is blocked
 */

import AuthProof, { ActionLog, RevocationRegistry } from '../src/authproof.js';

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
  console.log('Gap 3 — Revocation Registry\n');

  const { privateKey, publicJwk } = await AuthProof.generateKey();

  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Read calendar events.',
    boundaries:   'Do not send emails.',
    instructions: 'Stay in scope.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });

  // ── Test Group 1: Construction and init ──────────────────────────────
  console.log('Test Group 1: Construction and init');

  // Test 1: RevocationRegistry constructs
  const registry = new RevocationRegistry();
  assert(registry instanceof RevocationRegistry, 'RevocationRegistry constructs');

  // Test 2: init() required before revoke()
  const uninitRegistry = new RevocationRegistry();
  try {
    await uninitRegistry.revoke(receiptId);
    assert(false, 'Should throw when revoke() called before init()');
  } catch (e) {
    assert(e.message.includes('init'), 'revoke() throws when called before init()');
  }

  // Test 3: init() requires privateKey
  try {
    await registry.init({ publicJwk });
    assert(false, 'Should throw when privateKey missing');
  } catch (e) {
    assert(e.message.includes('privateKey'), 'init() throws when privateKey missing');
  }

  // Test 4: init() with valid key succeeds
  await registry.init({ privateKey, publicJwk });
  assert(true, 'init() with valid key pair succeeds');

  // ── Test Group 2: revoke() ───────────────────────────────────────────
  console.log('\nTest Group 2: revoke()');

  // Test 5: revoke returns a signed record with required fields
  const revokeResult = await registry.revoke(receiptId, {
    reason:    'user cancelled',
    revokedAt: 1_700_000_000_000,
  });
  assert(typeof revokeResult === 'object', 'revoke() returns an object');
  assert(revokeResult.receiptHash === receiptId, 'revocation record has receiptHash');
  assert(revokeResult.reason === 'user cancelled', 'revocation record has correct reason');
  assert(revokeResult.revokedAt === 1_700_000_000_000, 'revocation record has correct revokedAt');
  assert(typeof revokeResult.signature === 'string' && revokeResult.signature.length > 0,
    'revocation record is signed');
  assert(typeof revokeResult.revokedBy === 'object', 'revocation record includes revokedBy JWK');

  // Test 6: revoke() is append-only — cannot revoke twice
  try {
    await registry.revoke(receiptId, { reason: 'second revoke' });
    assert(false, 'Should throw when revoking an already-revoked receipt');
  } catch (e) {
    assert(e.message.toLowerCase().includes('already revoked'),
      'revoke() throws when receipt is already revoked');
  }

  // ── Test Group 3: check() ────────────────────────────────────────────
  console.log('\nTest Group 3: check()');

  // Test 7: check() returns revoked:false for unknown hash
  const unknownStatus = await registry.check('a'.repeat(64));
  assert(unknownStatus.revoked === false, 'check() returns revoked:false for unknown hash');

  // Test 8: check() returns revoked:true for revoked receipt
  const revokedStatus = await registry.check(receiptId);
  assert(revokedStatus.revoked === true, 'check() returns revoked:true for revoked receipt');

  // Test 9: check() includes reason
  assert(revokedStatus.reason === 'user cancelled', 'check() includes the revocation reason');

  // Test 10: check() includes revokedAt
  assert(revokedStatus.revokedAt === 1_700_000_000_000, 'check() includes revokedAt timestamp');

  // ── Test Group 4: export() / import() ───────────────────────────────
  console.log('\nTest Group 4: export() and import()');

  // Test 11: export() returns an array
  const exported = registry.export();
  assert(Array.isArray(exported), 'export() returns an array');
  assert(exported.length === 1, 'export() includes the one revocation record');

  // Test 12: export() includes the signature
  assert(typeof exported[0].signature === 'string', 'exported record includes signature');

  // Test 13: import() into fresh registry round-trips correctly
  const freshRegistry = new RevocationRegistry();
  await freshRegistry.init({ privateKey, publicJwk });
  const importResult = await freshRegistry.import(exported);
  assert(importResult.imported === 1, 'import() imports 1 valid record');
  assert(importResult.skipped  === 0, 'import() skips 0 records');
  assert(importResult.errors.length === 0, 'import() has no errors for valid records');

  // Test 14: imported registry reflects revocation
  const importedStatus = await freshRegistry.check(receiptId);
  assert(importedStatus.revoked === true, 'imported registry correctly marks receipt as revoked');
  assert(importedStatus.reason === 'user cancelled', 'imported registry preserves revocation reason');

  // Test 15: import() rejects records with invalid signatures
  const tampered = [{ ...exported[0], reason: 'tampered reason' }];
  const badImport = await freshRegistry.import(tampered);
  assert(badImport.skipped >= 1, 'import() skips record with invalid signature');
  assert(badImport.errors.length >= 1, 'import() reports error for invalid signature');

  // Test 16: import() skips duplicate (already-revoked) hashes silently
  const dupImport = await freshRegistry.import(exported);
  assert(dupImport.imported === 0, 'import() does not re-import already-revoked hashes');
  assert(dupImport.skipped  === 1, 'import() counts duplicate as skipped');

  // Test 17: import() skips records missing required fields
  const missingFields = [{ receiptHash: 'x'.repeat(64), reason: 'no sig or revokedBy' }];
  const missingResult = await freshRegistry.import(missingFields);
  assert(missingResult.skipped >= 1, 'import() skips record missing required fields');

  // ── Test Group 5: ActionLog.record() integration ─────────────────────
  console.log('\nTest Group 5: ActionLog.record() integration');

  // Test 18: record() succeeds when receipt is NOT in registry
  const { receipt: freshReceipt, receiptId: freshId } = await AuthProof.create({
    scope: 'test', boundaries: 'test', instructions: 'test',
    ttlHours: 2, privateKey, publicJwk,
  });

  const log = new ActionLog();
  await log.init({ privateKey, publicJwk, tsaUrl: null, registry });
  log.registerReceipt(freshId, freshReceipt);

  const goodEntry = await log.record(freshId, { operation: 'read', resource: 'calendar' });
  assert(typeof goodEntry.entryId === 'string', 'record() succeeds for non-revoked receipt');

  // Test 19: record() throws when receipt IS in registry
  log.registerReceipt(receiptId, receipt);
  try {
    await log.record(receiptId, { operation: 'read', resource: 'calendar' });
    assert(false, 'record() should throw for a revoked receipt');
  } catch (e) {
    assert(e.message.includes('revoked'), 'record() throws with "revoked" in message');
  }

  // Test 20: record() error message includes the revocation reason
  try {
    await log.record(receiptId, { operation: 'read', resource: 'calendar' });
  } catch (e) {
    assert(e.message.includes('user cancelled'),
      'record() error message includes the revocation reason');
  }

  // ── Test Group 6: AuthProof.verify() integration ─────────────────────
  console.log('\nTest Group 6: AuthProof.verify() integration');

  // Test 21: verify() fails when registry says receipt is revoked
  const verifyRevoked = await AuthProof.verify(receipt, receiptId, { registry });
  assert(verifyRevoked.authorized === false,
    'verify() returns authorized:false when registry marks receipt revoked');

  const notRevokedCheck = verifyRevoked.checks.find(c => c.name === 'Not revoked');
  assert(notRevokedCheck && !notRevokedCheck.passed,
    '"Not revoked" check fails when registry marks receipt revoked');

  // Test 22: verify() detail includes revocation reason from registry
  assert(notRevokedCheck.detail.includes('user cancelled'),
    '"Not revoked" detail includes registry reason');

  // Test 23: verify() passes for non-revoked receipt (registry present but no entry)
  const verifyFresh = await AuthProof.verify(freshReceipt, freshId, { registry });
  assert(verifyFresh.authorized === true,
    'verify() passes for receipt not in registry');

  // Test 24: verify() works without registry (backward compat)
  const verifyNoRegistry = await AuthProof.verify(freshReceipt, freshId);
  assert(verifyNoRegistry.authorized === true,
    'verify() works correctly with no registry option');

  // ── Test Group 7: Cross-receipt isolation ────────────────────────────
  console.log('\nTest Group 7: Cross-receipt isolation');

  // Revoke a second receipt in a separate registry
  const reg2 = new RevocationRegistry();
  await reg2.init({ privateKey, publicJwk });

  const { receipt: rA, receiptId: idA } = await AuthProof.create({
    scope: 'test A', boundaries: 'test', instructions: 'test',
    ttlHours: 2, privateKey, publicJwk,
  });
  const { receipt: rB, receiptId: idB } = await AuthProof.create({
    scope: 'test B', boundaries: 'test', instructions: 'test',
    ttlHours: 2, privateKey, publicJwk,
  });

  await reg2.revoke(idA, { reason: 'revoked A only' });

  // Test 25: only revoked receipt fails, the other is unaffected
  const statusA = await reg2.check(idA);
  const statusB = await reg2.check(idB);
  assert(statusA.revoked === true  && statusB.revoked === false,
    'revocation is isolated — only receipt A is revoked, B is not');

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Gap 3 Revocation Registry tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

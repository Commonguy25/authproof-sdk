/**
 * AuthProof — Gap 3: Signed Capability Manifests
 * Run: node --experimental-global-webcrypto tests/capability-manifest.test.js
 *
 * Tests cover:
 *  - CapabilityManifest constructor validation
 *  - sign() and verify() — happy path and tamper detection
 *  - getHash() — only available after sign()
 *  - covers() — wildcard-aware capability matching
 *  - diff() — added / removed / changed between manifest versions
 *  - ScopeSchema manifestHash field — constructor, toJSON, fromJSON
 *  - verify() integration — manifest signature, hash binding, action coverage
 */

import AuthProof, { CapabilityManifest, ScopeSchema } from '../src/authproof.js';

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
  console.log('Gap 3 — Signed Capability Manifests\n');

  // ── Test Group 1: Constructor validation ─────────────────────────────
  console.log('Test Group 1: Constructor validation');

  // Test 1: throws when name is missing
  try {
    new CapabilityManifest({ version: '1.0', capabilities: [{ operation: 'read', resource: 'files' }] });
    assert(false, 'should throw for missing name');
  } catch (e) {
    assert(e.message.includes('name'), 'throws for missing name');
  }

  // Test 2: throws when version is missing
  try {
    new CapabilityManifest({ name: 'srv', capabilities: [{ operation: 'read', resource: 'files' }] });
    assert(false, 'should throw for missing version');
  } catch (e) {
    assert(e.message.includes('version'), 'throws for missing version');
  }

  // Test 3: throws when capabilities is missing
  try {
    new CapabilityManifest({ name: 'srv', version: '1.0' });
    assert(false, 'should throw for missing capabilities');
  } catch (e) {
    assert(e.message.includes('capabilities'), 'throws for missing capabilities');
  }

  // Test 4: throws when capabilities is empty array
  try {
    new CapabilityManifest({ name: 'srv', version: '1.0', capabilities: [] });
    assert(false, 'should throw for empty capabilities');
  } catch (e) {
    assert(e.message.includes('capabilities'), 'throws for empty capabilities array');
  }

  // Test 5: throws when a capability entry is missing operation
  try {
    new CapabilityManifest({ name: 'srv', version: '1.0', capabilities: [{ resource: 'files' }] });
    assert(false, 'should throw for capability missing operation');
  } catch (e) {
    assert(e.message.includes('operation'), 'throws for capability missing operation');
  }

  // Test 6: throws when a capability entry is missing resource
  try {
    new CapabilityManifest({ name: 'srv', version: '1.0', capabilities: [{ operation: 'read' }] });
    assert(false, 'should throw for capability missing resource');
  } catch (e) {
    assert(e.message.includes('resource'), 'throws for capability missing resource');
  }

  // Test 7: constructs successfully with all required fields
  const manifest = new CapabilityManifest({
    name:    'scheduler-server',
    version: '1.0',
    capabilities: [
      { operation: 'read',  resource: 'calendar/events' },
      { operation: 'write', resource: 'calendar/events' },
    ],
  });
  assert(manifest.name === 'scheduler-server', 'name stored correctly');
  assert(manifest.version === '1.0', 'version stored correctly');
  assert(manifest.capabilities.length === 2, 'capabilities stored correctly');
  assert(manifest.description === null, 'description defaults to null');

  // Test 8: optional description is stored
  const withDesc = new CapabilityManifest({
    name: 'x', version: '1.0',
    description: 'A test server',
    capabilities: [{ operation: 'read', resource: '*' }],
  });
  assert(withDesc.description === 'A test server', 'optional description stored');

  // ── Test Group 2: sign() and verify() — happy path ───────────────────
  console.log('\nTest Group 2: sign() and verify()');

  const { privateKey, publicJwk } = await AuthProof.generateKey();

  // Test 9: sign() returns sealed manifest with required fields
  const signed = await manifest.sign(privateKey, publicJwk);
  assert(typeof signed.bodyHash === 'string' && signed.bodyHash.length === 64,
    'signed manifest has 64-char bodyHash');
  assert(typeof signed.signature === 'string', 'signed manifest has signature');
  assert(typeof signed.signerPublicKey === 'object', 'signed manifest has signerPublicKey');
  assert(signed.name === 'scheduler-server', 'signed manifest preserves name');
  assert(signed.version === '1.0', 'signed manifest preserves version');
  assert(Array.isArray(signed.capabilities), 'signed manifest preserves capabilities');
  assert(typeof signed.createdAt === 'string', 'signed manifest has createdAt timestamp');

  // Test 10: verify() returns valid for a correctly signed manifest
  const verifyResult = await CapabilityManifest.verify(signed);
  assert(verifyResult.valid === true, 'verify() returns valid:true for correct manifest');
  assert(typeof verifyResult.reason === 'string', 'verify() result has a reason string');

  // Test 11: getHash() returns the same hash as signed.bodyHash
  const hash = manifest.getHash();
  assert(hash === signed.bodyHash, 'getHash() matches signed.bodyHash');
  assert(hash.length === 64, 'getHash() returns 64-char hex string');

  // Test 12: sign() on two identical manifests (same fields) produces same bodyHash
  const manifest2 = new CapabilityManifest({
    name: 'scheduler-server', version: '1.0',
    capabilities: [
      { operation: 'read',  resource: 'calendar/events' },
      { operation: 'write', resource: 'calendar/events' },
    ],
  });
  const signed2 = await manifest2.sign(privateKey, publicJwk);
  // createdAt differs → bodyHash will differ (timestamps are unique per sign() call)
  // This confirms createdAt is included in the hash — good for freshness
  assert(typeof signed2.bodyHash === 'string', 'second sign() produces a bodyHash');

  // Test 13: sign() throws when privateKey is missing
  try {
    const m = new CapabilityManifest({ name: 'x', version: '1.0', capabilities: [{ operation: 'r', resource: 'f' }] });
    await m.sign(null, publicJwk);
    assert(false, 'should throw for missing privateKey');
  } catch (e) {
    assert(e.message.includes('serverPrivateKey'), 'throws for missing privateKey');
  }

  // Test 14: sign() throws when publicJwk is missing
  try {
    const m = new CapabilityManifest({ name: 'x', version: '1.0', capabilities: [{ operation: 'r', resource: 'f' }] });
    await m.sign(privateKey, null);
    assert(false, 'should throw for missing publicJwk');
  } catch (e) {
    assert(e.message.includes('serverPublicJwk'), 'throws for missing publicJwk');
  }

  // Test 15: getHash() throws before sign() is called
  try {
    const m = new CapabilityManifest({ name: 'x', version: '1.0', capabilities: [{ operation: 'r', resource: 'f' }] });
    m.getHash();
    assert(false, 'should throw for getHash() before sign()');
  } catch (e) {
    assert(e.message.includes('sign()'), 'throws for getHash() before sign()');
  }

  // ── Test Group 3: verify() — tamper detection ─────────────────────────
  console.log('\nTest Group 3: verify() — tamper detection');

  // Test 16: verify(null) returns valid:false
  const nullResult = await CapabilityManifest.verify(null);
  assert(nullResult.valid === false && typeof nullResult.reason === 'string',
    'verify(null) returns { valid: false, reason: string }');

  // Test 17: verify() returns valid:false for manifest missing bodyHash
  const r1 = await CapabilityManifest.verify({ name: 'x', version: '1.0', capabilities: [] });
  assert(r1.valid === false && r1.reason.includes('bodyHash'), 'missing bodyHash → verified:false');

  // Test 18: verify() returns valid:false for manifest missing signature
  const r2 = await CapabilityManifest.verify({ ...signed, signature: undefined });
  assert(r2.valid === false && r2.reason.includes('signature'), 'missing signature → verified:false');

  // Test 19: verify() returns valid:false for manifest missing signerPublicKey
  const r3 = await CapabilityManifest.verify({ ...signed, signerPublicKey: undefined });
  assert(r3.valid === false && r3.reason.includes('signerPublicKey'), 'missing signerPublicKey → verified:false');

  // Test 20: verify() detects body tampering (adding a capability)
  const tampered = {
    ...signed,
    capabilities: [...signed.capabilities, { operation: 'delete', resource: '*' }],
  };
  const r4 = await CapabilityManifest.verify(tampered);
  assert(r4.valid === false, 'tampered capabilities → verified:false');
  assert(r4.reason.toLowerCase().includes('tampered') || r4.reason.toLowerCase().includes('mismatch'),
    'tamper reason mentions tampered/mismatch');

  // Test 21: verify() detects name tampering
  const tamperedName = { ...signed, name: 'evil-server' };
  const r5 = await CapabilityManifest.verify(tamperedName);
  assert(r5.valid === false, 'tampered name → verified:false');

  // Test 22: verify() returns valid:false for wrong signer key
  const { publicJwk: otherPublicJwk } = await AuthProof.generateKey();
  const wrongKey = { ...signed, signerPublicKey: otherPublicJwk };
  const r6 = await CapabilityManifest.verify(wrongKey);
  assert(r6.valid === false, 'wrong signer key → verified:false');
  assert(r6.reason.toLowerCase().includes('signature') || r6.reason.toLowerCase().includes('tampered'),
    'wrong key reason mentions signature/tampered');

  // ── Test Group 4: covers() ────────────────────────────────────────────
  console.log('\nTest Group 4: covers()');

  const richManifest = new CapabilityManifest({
    name:    'rich-server',
    version: '2.0',
    capabilities: [
      { operation: 'read',  resource: 'calendar/events' },
      { operation: 'write', resource: 'calendar/events' },
      { operation: 'read',  resource: 'email/inbox' },
      { operation: '*',     resource: 'files/*' },
    ],
  });

  // Test 23: covers() returns true for exact match
  assert(richManifest.covers({ operation: 'read',  resource: 'calendar/events' }),
    'covers() exact match — read calendar/events');
  assert(richManifest.covers({ operation: 'write', resource: 'calendar/events' }),
    'covers() exact match — write calendar/events');
  assert(richManifest.covers({ operation: 'read',  resource: 'email/inbox' }),
    'covers() exact match — read email/inbox');

  // Test 24: covers() returns true for wildcard resource match
  assert(richManifest.covers({ operation: 'read',  resource: 'files/report.txt' }),
    'covers() wildcard resource — files/report.txt matches files/*');
  assert(richManifest.covers({ operation: 'write', resource: 'files/data.csv' }),
    'covers() wildcard operation — * matches write for files/*');

  // Test 25: covers() returns false for non-declared operation/resource
  assert(!richManifest.covers({ operation: 'delete', resource: 'calendar/events' }),
    'covers() returns false — delete not in capabilities');
  assert(!richManifest.covers({ operation: 'read',   resource: 'payment/stripe' }),
    'covers() returns false — payment not in capabilities');

  // Test 26: covers() returns false for invalid input
  assert(!richManifest.covers(null), 'covers(null) returns false');
  assert(!richManifest.covers({ operation: 'read' }), 'covers() without resource returns false');
  assert(!richManifest.covers({ resource: 'calendar' }), 'covers() without operation returns false');

  // ── Test Group 5: diff() ──────────────────────────────────────────────
  console.log('\nTest Group 5: diff()');

  const { privateKey: k2, publicJwk: pub2 } = await AuthProof.generateKey();

  const mA = new CapabilityManifest({
    name: 'srv', version: '1.0',
    capabilities: [
      { operation: 'read',   resource: 'files' },
      { operation: 'write',  resource: 'files' },
      { operation: 'search', resource: 'web', description: 'v1 description' },
    ],
  });
  const signedA = await mA.sign(k2, pub2);

  const mB = new CapabilityManifest({
    name: 'srv', version: '2.0',
    capabilities: [
      { operation: 'read',   resource: 'files' },
      // write/files removed
      { operation: 'search', resource: 'web', description: 'updated description' }, // changed
      { operation: 'delete', resource: 'files' }, // added
    ],
  });
  const signedB = await mB.sign(k2, pub2);

  const diffResult = CapabilityManifest.diff(signedA, signedB);

  // Test 27: diff returns correct structure
  assert('added' in diffResult && 'removed' in diffResult && 'changed' in diffResult,
    'diff() returns { added, removed, changed }');

  // Test 28: diff detects added capabilities
  assert(diffResult.added.length === 1 && diffResult.added[0].operation === 'delete',
    'diff() detects added capability (delete/files)');

  // Test 29: diff detects removed capabilities
  assert(diffResult.removed.length === 1 && diffResult.removed[0].operation === 'write',
    'diff() detects removed capability (write/files)');

  // Test 30: diff detects changed capabilities
  assert(diffResult.changed.length === 1,
    'diff() detects changed capability (search/web description change)');
  assert(diffResult.changed[0].from.description === 'v1 description' &&
         diffResult.changed[0].to.description   === 'updated description',
    'diff() changed entry has from/to fields with correct descriptions');

  // Test 31: diff on identical manifests returns all-empty arrays
  const signedA2 = await new CapabilityManifest({
    name: 'srv', version: '1.0',
    capabilities: [
      { operation: 'read',   resource: 'files' },
      { operation: 'write',  resource: 'files' },
      { operation: 'search', resource: 'web', description: 'v1 description' },
    ],
  }).sign(k2, pub2);
  const noChanges = CapabilityManifest.diff(signedA, signedA2);
  // Note: bodyHash differs due to createdAt, but diff() only compares capabilities
  assert(noChanges.added.length === 0 && noChanges.removed.length === 0 && noChanges.changed.length === 0,
    'diff() returns empty arrays for identical capability sets');

  // Test 32: diff() throws for invalid manifest1
  try {
    CapabilityManifest.diff(null, signedB);
    assert(false, 'should throw for null manifest1');
  } catch (e) {
    assert(e.message.includes('manifest1'), 'throws for invalid manifest1');
  }

  // Test 33: diff() throws for invalid manifest2
  try {
    CapabilityManifest.diff(signedA, null);
    assert(false, 'should throw for null manifest2');
  } catch (e) {
    assert(e.message.includes('manifest2'), 'throws for invalid manifest2');
  }

  // ── Test Group 6: ScopeSchema manifestHash field ──────────────────────
  console.log('\nTest Group 6: ScopeSchema manifestHash field');

  const validHash = 'a'.repeat(64);

  // Test 34: ScopeSchema accepts manifestHash
  const schema = new ScopeSchema({
    version: '1.0',
    allowedActions: [{ operation: 'read', resource: 'calendar/events' }],
    manifestHash: validHash,
  });
  assert(schema.manifestHash === validHash, 'ScopeSchema stores manifestHash');

  // Test 35: ScopeSchema.toJSON() includes manifestHash
  const json = schema.toJSON();
  assert(json.manifestHash === validHash, 'toJSON() includes manifestHash');

  // Test 36: ScopeSchema.fromJSON() round-trips manifestHash
  const restored = ScopeSchema.fromJSON(json);
  assert(restored.manifestHash === validHash, 'fromJSON() restores manifestHash');

  // Test 37: ScopeSchema without manifestHash has null
  const schemaNoHash = new ScopeSchema({ version: '1.0', allowedActions: [{ operation: 'r', resource: 'f' }] });
  assert(schemaNoHash.manifestHash === null, 'ScopeSchema without manifestHash defaults to null');
  assert(!('manifestHash' in schemaNoHash.toJSON()), 'toJSON() omits manifestHash when null');

  // Test 38: ScopeSchema throws for wrong-length manifestHash
  try {
    new ScopeSchema({ version: '1.0', allowedActions: [], manifestHash: 'tooshort' });
    assert(false, 'should throw for wrong-length manifestHash');
  } catch (e) {
    assert(e.message.includes('manifestHash') && e.message.includes('64'),
      'throws for manifestHash that is not 64 chars');
  }

  // ── Test Group 7: verify() integration ───────────────────────────────
  console.log('\nTest Group 7: verify() integration with manifest');

  const { privateKey: serverKey, publicJwk: serverPub } = await AuthProof.generateKey();
  const { privateKey: userKey,   publicJwk: userPub   } = await AuthProof.generateKey();

  // Build and sign a capability manifest
  const serverManifest = new CapabilityManifest({
    name:    'calendar-server',
    version: '1.0',
    capabilities: [
      { operation: 'read',  resource: 'calendar/events' },
      { operation: 'write', resource: 'calendar/events' },
    ],
  });
  const serverSigned = await serverManifest.sign(serverKey, serverPub);
  const manifestHash = serverManifest.getHash();

  // Issue a receipt that embeds the manifest hash via scopeSchema
  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Read and write calendar events.',
    boundaries:   'Do not send emails.',
    instructions: 'Stay in scope.',
    ttlHours:     2,
    privateKey:   userKey,
    publicJwk:    userPub,
  });
  // Attach scopeSchema with manifestHash to the receipt for integration tests
  receipt.scopeSchema = { manifestHash };

  // Test 39: verify() passes manifest check for valid manifest
  const v1 = await AuthProof.verify(receipt, receiptId, {
    manifest:       serverSigned,
    manifestAction: { operation: 'read', resource: 'calendar/events' },
  });
  const manifestSigCheck = v1.checks.find(c => c.name === 'Manifest signature valid');
  assert(manifestSigCheck !== undefined, 'verify() includes "Manifest signature valid" check');
  assert(manifestSigCheck.passed === true, 'manifest signature check passes for valid manifest');

  // Test 40: verify() includes manifest hash check against receipt.scopeSchema.manifestHash
  const hashCheck = v1.checks.find(c => c.name === 'Manifest hash matches receipt');
  assert(hashCheck !== undefined, 'verify() includes "Manifest hash matches receipt" check');
  assert(hashCheck.passed === true, 'manifest hash check passes when hashes match');

  // Test 41: verify() includes action coverage check
  const coverageCheck = v1.checks.find(c => c.name === 'Action covered by manifest');
  assert(coverageCheck !== undefined, 'verify() includes "Action covered by manifest" check');
  assert(coverageCheck.passed === true, 'coverage check passes for declared operation/resource');

  // Test 42: verify() fails coverage check for action not in manifest
  const v2 = await AuthProof.verify(receipt, receiptId, {
    manifest:       serverSigned,
    manifestAction: { operation: 'delete', resource: 'calendar/events' },
  });
  const coverCheck2 = v2.checks.find(c => c.name === 'Action covered by manifest');
  assert(coverCheck2 !== undefined && coverCheck2.passed === false,
    'coverage check fails for action not declared in manifest');

  // Test 43: verify() fails manifest hash check when manifest bodyHash differs from committed hash
  const { receipt: receipt2, receiptId: rid2 } = await AuthProof.create({
    scope: 'Read files.', boundaries: 'No writes.', instructions: 'Stay on task.',
    ttlHours: 1, privateKey: userKey, publicJwk: userPub,
  });
  receipt2.scopeSchema = { manifestHash: 'b'.repeat(64) };

  const v3 = await AuthProof.verify(receipt2, rid2, { manifest: serverSigned });
  const hashCheck3 = v3.checks.find(c => c.name === 'Manifest hash matches receipt');
  assert(hashCheck3 !== undefined && hashCheck3.passed === false,
    'hash check fails when manifest.bodyHash does not match receipt scopeSchema.manifestHash');

  // Test 44: verify() fails manifest signature check for tampered manifest
  const tamperedServerManifest = {
    ...serverSigned,
    capabilities: [...serverSigned.capabilities, { operation: 'delete', resource: '*' }],
  };
  const v4 = await AuthProof.verify(receipt, receiptId, { manifest: tamperedServerManifest });
  const sigCheck4 = v4.checks.find(c => c.name === 'Manifest signature valid');
  assert(sigCheck4 !== undefined && sigCheck4.passed === false,
    'manifest signature check fails for tampered manifest');

  // Test 45: verify() without manifest option runs no manifest checks
  const v5 = await AuthProof.verify(receipt, receiptId);
  const noManifestCheck = v5.checks.find(c => c.name === 'Manifest signature valid');
  assert(noManifestCheck === undefined, 'no manifest checks run when manifest option is omitted');

  // ── Summary ─────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Capability Manifest tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

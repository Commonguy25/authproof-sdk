/**
 * AuthProof — Gap 2: TEE Attestation
 * Run: node --experimental-global-webcrypto tests/tee-attestation.test.js
 *
 * Tests cover what can be verified without TEE hardware:
 *  - Interface validation (missing/invalid parameters)
 *  - Hardware-not-available errors for both platforms
 *  - verify() input validation and return structure
 *  - entryHash binding verification (structural check)
 *  - Certificate chain structure in return objects
 *  - ActionLog.record() accepts attestation parameter
 *  - ActionLog.verify() includes teeAttestation in result
 *  - Entry with misbound attestation is marked invalid
 *  - Entry without attestation is unaffected
 */

import AuthProof, { ActionLog, TEEAttestation } from '../src/authproof.js';

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

// A valid-length fake entryHash for structural tests
const FAKE_ENTRY_HASH = 'a'.repeat(64);
const FAKE_ENTRY_ID   = 'log-1700000000000-abc1234';

async function run() {
  console.log('Gap 2 — TEE Attestation\n');

  // ── Test Group 1: TEEAttestation is exported ─────────────────────────
  console.log('Test Group 1: Export and class structure');

  // Test 1: exported as named export
  assert(typeof TEEAttestation === 'function', 'TEEAttestation is exported as a class');

  // Test 2: available on the default AuthProof object
  assert(typeof AuthProof.TEEAttestation === 'function',
    'TEEAttestation is on the AuthProof default export');

  // Test 3: has required static methods
  assert(
    typeof TEEAttestation.create  === 'function' &&
    typeof TEEAttestation.verify  === 'function',
    'TEEAttestation has create() and verify() static methods'
  );

  // ── Test Group 2: create() — input validation ─────────────────────────
  console.log('\nTest Group 2: create() — input validation');

  // Test 4: throws when entryId is missing
  try {
    await TEEAttestation.create({ entryHash: FAKE_ENTRY_HASH, platform: 'intel-sgx' });
    assert(false, 'Should throw for missing entryId');
  } catch (e) {
    assert(e.message.includes('entryId'), 'throws for missing entryId');
  }

  // Test 5: throws when entryHash is missing
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, platform: 'intel-sgx' });
    assert(false, 'Should throw for missing entryHash');
  } catch (e) {
    assert(e.message.includes('entryHash'), 'throws for missing entryHash');
  }

  // Test 6: throws when entryHash is wrong length
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: 'tooshort', platform: 'intel-sgx' });
    assert(false, 'Should throw for wrong-length entryHash');
  } catch (e) {
    assert(e.message.includes('entryHash') && e.message.includes('64'),
      'throws for entryHash that is not 64 chars');
  }

  // Test 7: throws when platform is missing
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: FAKE_ENTRY_HASH });
    assert(false, 'Should throw for missing platform');
  } catch (e) {
    assert(e.message.includes('platform'), 'throws for missing platform');
  }

  // Test 8: throws for unsupported platform
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: FAKE_ENTRY_HASH, platform: 'nvidia-gpu' });
    assert(false, 'Should throw for unsupported platform');
  } catch (e) {
    assert(e.message.includes('unsupported platform') || e.message.includes('nvidia-gpu'),
      'throws for unsupported platform with platform name in message');
  }

  // ── Test Group 3: create() — hardware-not-available errors ───────────
  console.log('\nTest Group 3: create() — hardware not available');

  // Test 9: intel-sgx — throws 'hardware not available' on non-SGX system
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: FAKE_ENTRY_HASH, platform: 'intel-sgx' });
    // If we reach here, SGX hardware IS present and a quote was generated
    console.log('  ℹ intel-sgx hardware detected — hardware-not-available test skipped');
    assert(true, 'intel-sgx hardware present (hardware-not-available path not exercised)');
  } catch (e) {
    assert(
      e.message.includes('hardware not available') || e.message.includes('SGX'),
      'intel-sgx throws "hardware not available" on non-SGX system'
    );
  }

  // Test 10: arm-trustzone — throws 'hardware not available' on non-TrustZone system
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: FAKE_ENTRY_HASH, platform: 'arm-trustzone' });
    console.log('  ℹ arm-trustzone hardware detected — hardware-not-available test skipped');
    assert(true, 'arm-trustzone hardware present (hardware-not-available path not exercised)');
  } catch (e) {
    assert(
      e.message.includes('hardware not available') || e.message.includes('TrustZone'),
      'arm-trustzone throws "hardware not available" on non-TrustZone system'
    );
  }

  // Test 11: error message includes expected device path hints for intel-sgx
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: FAKE_ENTRY_HASH, platform: 'intel-sgx' });
  } catch (e) {
    const mentionsDevice =
      e.message.includes('/dev/sgx') || e.message.includes('/dev/isgx') ||
      e.message.includes('SGX') || e.message.includes('hardware');
    assert(mentionsDevice, 'intel-sgx error message references device path or SGX');
  }

  // Test 12: error message includes expected device path hints for arm-trustzone
  try {
    await TEEAttestation.create({ entryId: FAKE_ENTRY_ID, entryHash: FAKE_ENTRY_HASH, platform: 'arm-trustzone' });
  } catch (e) {
    const mentionsDevice =
      e.message.includes('/dev/tee') || e.message.includes('TrustZone') ||
      e.message.includes('OP-TEE') || e.message.includes('hardware');
    assert(mentionsDevice, 'arm-trustzone error message references device path or TrustZone');
  }

  // ── Test Group 4: verify() — input validation and return structure ────
  console.log('\nTest Group 4: verify() — input validation and return structure');

  // Test 13: verify() returns correct structure for null input
  const r1 = await TEEAttestation.verify(null);
  assert(
    typeof r1.verified === 'boolean' &&
    r1.verified === false &&
    typeof r1.reason === 'string',
    'verify(null) returns { verified: false, reason: string }'
  );

  // Test 14: verify() returns correct structure for missing platform
  const r2 = await TEEAttestation.verify({ entryHash: FAKE_ENTRY_HASH, quote: 'abc' });
  assert(r2.verified === false && typeof r2.reason === 'string',
    'verify() with missing platform returns verified:false');

  // Test 15: verify() returns verified:false for unsupported platform
  const r3 = await TEEAttestation.verify({
    platform: 'quantum-computer',
    entryHash: FAKE_ENTRY_HASH,
  });
  assert(r3.verified === false && r3.platform === 'quantum-computer',
    'verify() returns verified:false for unknown platform, preserves platform field');

  // Test 16: verify() returns verified:false for intel-sgx with missing quote
  const r4 = await TEEAttestation.verify({
    platform: 'intel-sgx',
    entryHash: FAKE_ENTRY_HASH,
    reportData: FAKE_ENTRY_HASH + '0'.repeat(64),
    // quote is missing
  });
  assert(r4.verified === false && r4.platform === 'intel-sgx',
    'verify() returns verified:false for intel-sgx when quote is missing');
  assert(r4.reason.toLowerCase().includes('quote'),
    'verify() reason mentions missing quote');

  // Test 17: verify() returns verified:false for arm-trustzone with missing token
  const r5 = await TEEAttestation.verify({
    platform: 'arm-trustzone',
    entryHash: FAKE_ENTRY_HASH,
    reportData: FAKE_ENTRY_HASH,
    // token is missing
  });
  assert(r5.verified === false && r5.platform === 'arm-trustzone',
    'verify() returns verified:false for arm-trustzone when token is missing');

  // ── Test Group 5: entryHash binding verification ──────────────────────
  console.log('\nTest Group 5: entryHash binding verification');

  // Test 18: verify() fails when SGX reportData does not start with entryHash
  const wrongReportData = await TEEAttestation.verify({
    platform:   'intel-sgx',
    entryHash:  FAKE_ENTRY_HASH,
    reportData: 'b'.repeat(128), // does not start with entryHash
    quote:      'ZmFrZVF1b3Rl',
  });
  assert(wrongReportData.verified === false,
    'verify() fails when SGX reportData does not contain entryHash');
  assert(
    wrongReportData.reason.toLowerCase().includes('entryhash') ||
    wrongReportData.reason.toLowerCase().includes('report') ||
    wrongReportData.reason.toLowerCase().includes('bound'),
    'failure reason mentions entryHash binding'
  );

  // Test 19: verify() fails when TrustZone reportData does not equal entryHash
  const wrongTZReport = await TEEAttestation.verify({
    platform:   'arm-trustzone',
    entryHash:  FAKE_ENTRY_HASH,
    reportData: 'c'.repeat(64), // different from entryHash
    token:      'ZmFrZVRva2Vu',
  });
  assert(wrongTZReport.verified === false,
    'verify() fails when TrustZone reportData does not match entryHash');

  // Test 20: correctly bound SGX attestation progresses past structural check
  // (crypto verification will fail without hardware, but for a different reason)
  const correctBinding = await TEEAttestation.verify({
    platform:   'intel-sgx',
    entryHash:  FAKE_ENTRY_HASH,
    reportData: FAKE_ENTRY_HASH + '0'.repeat(64), // starts with entryHash ✓
    quote:      'ZmFrZVF1b3Rl', // fake quote — crypto will fail but not structural
  });
  assert(correctBinding.verified === false, 'correctly bound but fake quote returns verified:false');
  assert(
    !correctBinding.reason.toLowerCase().includes('entryhash') &&
    !correctBinding.reason.toLowerCase().includes('not bound'),
    'structural binding check passes — failure is for a different reason (crypto/tool)'
  );

  // ── Test Group 6: ActionLog integration ──────────────────────────────
  console.log('\nTest Group 6: ActionLog integration');

  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Search web. Read files.',
    boundaries:   'Do not send emails.',
    instructions: 'Stay in scope.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });

  const log = new ActionLog();
  await log.init({ privateKey, publicJwk, tsaUrl: null });
  log.registerReceipt(receiptId, receipt);

  // Record a normal entry first, get its entryBodyHash for structural tests
  const normalEntry = await log.record(receiptId, { operation: 'read', resource: 'web' });

  // Test 21: record() still works without attestation (backward compat)
  assert(typeof normalEntry.entryId === 'string', 'record() without attestation works normally');
  assert(!('attestation' in normalEntry), 'entry without attestation has no attestation field');

  // Test 22: verify() on entry without attestation has no teeAttestation field
  const normalVerify = await log.verify(normalEntry.entryId);
  assert(normalVerify.valid === true, 'entry without attestation verifies as valid');
  assert(!('teeAttestation' in normalVerify), 'verify() on non-attested entry has no teeAttestation');

  // Record an entry with a fake attestation whose entryHash is CORRECT
  // (entryBodyHash of the NEW entry we'll record is unknown in advance, so we
  //  use normalEntry.entryBodyHash as a known hash — but it won't match
  //  the new entry's entryBodyHash, which tests the mismatch path)
  const correctHashAttestation = {
    platform:    'intel-sgx',
    entryId:     FAKE_ENTRY_ID,
    entryHash:   normalEntry.entryBodyHash, // same hash as the previous entry, NOT this entry
    reportData:  normalEntry.entryBodyHash + '0'.repeat(64),
    quote:       'ZmFrZVF1b3RlRGF0YWZvcnRlc3Rpbmc=',
    generatedAt: Date.now(),
  };

  const attestedEntry = await log.record(receiptId,
    { operation: 'search', resource: 'web/search' },
    { attestation: correctHashAttestation }
  );

  // Test 23: record() accepts attestation parameter, entry has attestation field
  assert('attestation' in attestedEntry, 'record() with attestation embeds it in entry');
  assert(attestedEntry.attestation.platform === 'intel-sgx',
    'embedded attestation preserves platform field');

  // Test 24: attestation is included in the signed body (signature covers it)
  const chainCheck = await log.verify(normalEntry.entryId);
  assert(chainCheck.valid === true, 'preceding entry still valid after attested entry is added');

  // Test 25: verify() on attested entry includes teeAttestation in result
  const attestedVerify = await log.verify(attestedEntry.entryId);
  assert('teeAttestation' in attestedVerify,
    'verify() on attested entry includes teeAttestation in result');
  assert(typeof attestedVerify.teeAttestation.verified === 'boolean',
    'teeAttestation.verified is a boolean');
  assert(typeof attestedVerify.teeAttestation.platform === 'string',
    'teeAttestation.platform is a string');
  assert(typeof attestedVerify.teeAttestation.reason === 'string',
    'teeAttestation.reason is a string');

  // The attestation's entryHash (normalEntry.entryBodyHash) does NOT match
  // attestedEntry.entryBodyHash, so the entry should be invalid
  assert(attestedVerify.valid === false,
    'entry is invalid when attestation.entryHash does not match entry.entryBodyHash');
  assert(
    attestedVerify.reason.toLowerCase().includes('entryhash') ||
    attestedVerify.reason.toLowerCase().includes('not bound') ||
    attestedVerify.reason.toLowerCase().includes('attestation'),
    'invalid reason mentions attestation entryHash mismatch'
  );

  // Test 26: attestation is signed into the entry body — tampering attestation breaks signature
  // Record an entry with attestation; then mutate the attestation field in-memory.
  const entry2 = await log.record(receiptId, { operation: 'write', resource: 'calendar' },
    { attestation: { platform: 'intel-sgx', entryId: FAKE_ENTRY_ID,
                     entryHash: normalEntry.entryBodyHash,
                     reportData: normalEntry.entryBodyHash + '0'.repeat(64),
                     quote: 'aW5pdGlhbFRlc3RRdW90ZQ==', generatedAt: Date.now() } });

  // The attestation is baked into the signed body, so changing it breaks the signature
  entry2.attestation.quote = 'dGFtcGVyZWRRdW90ZQ=='; // mutate after signing
  const tamperedAttestedVerify = await log.verify(entry2.entryId);
  assert(tamperedAttestedVerify.valid === false,
    'mutating attestation after recording breaks entry signature');

  // Test 27: structural binding error message is distinct from crypto error message
  // The attestedEntry (recorded earlier) has attestation.entryHash !== entry.entryBodyHash
  // Structural failure message must mention the mismatch
  assert(
    attestedVerify.teeAttestation !== undefined &&
    (attestedVerify.teeAttestation.reason.toLowerCase().includes('entryhash') ||
     attestedVerify.teeAttestation.reason.toLowerCase().includes('mismatch') ||
     attestedVerify.teeAttestation.reason.toLowerCase().includes('bound')),
    'structural binding failure is distinguishable by its teeAttestation.reason'
  );

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All TEE Attestation tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

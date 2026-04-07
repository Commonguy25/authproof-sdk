/**
 * AuthProof SDK — Tests
 * Run: node tests/authproof.test.js
 */

import AuthProof from '../src/authproof.js';

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
  console.log('AuthProof SDK — Test Suite\n');

  // ── Key Generation ──────────────────────────────────────────────────
  console.log('Key Generation');
  const { privateKey, publicJwk, privateJwk } = await AuthProof.generateKey();
  assert(privateKey instanceof CryptoKey, 'Returns CryptoKey for privateKey');
  assert(typeof publicJwk === 'object', 'Returns object for publicJwk');
  assert(publicJwk.kty === 'EC', 'Public JWK has kty=EC');
  assert(publicJwk.crv === 'P-256', 'Public JWK has crv=P-256');
  assert(typeof publicJwk.x === 'string', 'Public JWK has x coordinate');
  assert(typeof publicJwk.y === 'string', 'Public JWK has y coordinate');

  // ── Key Import ──────────────────────────────────────────────────────
  console.log('\nKey Import');
  const importedKey = await AuthProof.importPrivateKey(privateJwk);
  assert(importedKey instanceof CryptoKey, 'importPrivateKey returns CryptoKey');

  // ── Receipt Creation ────────────────────────────────────────────────
  console.log('\nReceipt Creation');
  const { receipt, receiptId, systemPrompt } = await AuthProof.create({
    scope:        'Search the web for competitor pricing.',
    boundaries:   'Do not send emails. Do not make purchases.',
    instructions: 'Cite sources. Keep under 500 words.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });

  assert(typeof receipt === 'object', 'Returns receipt object');
  assert(typeof receiptId === 'string', 'Returns receiptId string');
  assert(receiptId.length === 64, 'receiptId is 64-char hex (SHA-256)');
  assert(typeof systemPrompt === 'string', 'Returns systemPrompt string');
  assert(systemPrompt.includes('Search the web'), 'System prompt includes scope');
  assert(systemPrompt.includes('Do not send emails'), 'System prompt includes boundaries');
  assert(systemPrompt.includes('Authorization ID'), 'System prompt includes receipt ID label');
  assert(typeof receipt.signature === 'string', 'Receipt has signature');
  assert(typeof receipt.delegationId === 'string', 'Receipt has delegationId');
  assert(receipt.delegationId.startsWith('auth-'), 'delegationId has auth- prefix');

  // ── Receipt Verification — Valid ────────────────────────────────────
  console.log('\nVerification — Valid Receipt');
  const result = await AuthProof.verify(receipt, receiptId);
  assert(result.authorized === true, 'Valid receipt is authorized');
  assert(Array.isArray(result.checks), 'Returns checks array');
  assert(result.checks.every(c => c.passed), 'All checks pass for valid receipt');

  // ── Verification — With Valid Action ───────────────────────────────
  console.log('\nVerification — Scope Matching');
  const withAction = await AuthProof.verify(receipt, receiptId, {
    action: 'Search Google for competitor pricing pages and summarize results',
  });
  assert(withAction.authorized === true, 'In-scope action is authorized');

  // ── Verification — With Blocked Action ─────────────────────────────
  const blockedAction = await AuthProof.verify(receipt, receiptId, {
    action: 'Send an email to the team with the pricing report',
  });
  assert(blockedAction.authorized === false, 'Blocked action is denied');

  // ── Verification — Revoked ──────────────────────────────────────────
  console.log('\nVerification — Revoked Receipt');
  const revokedResult = await AuthProof.verify(receipt, receiptId, { revoked: true });
  assert(revokedResult.authorized === false, 'Revoked receipt is denied');
  const revokedCheck = revokedResult.checks.find(c => c.name === 'Not revoked');
  assert(revokedCheck && !revokedCheck.passed, 'Not-revoked check fails for revoked receipt');

  // ── Verification — Expired ──────────────────────────────────────────
  console.log('\nVerification — Expired Receipt');
  const { receipt: expiredReceipt, receiptId: expiredId } = await AuthProof.create({
    scope:        'Test scope',
    boundaries:   'Test boundaries',
    instructions: 'Test instructions',
    ttlHours:     -1,   // already expired
    privateKey,
    publicJwk,
  });
  const expiredResult = await AuthProof.verify(expiredReceipt, expiredId);
  assert(expiredResult.authorized === false, 'Expired receipt is denied');
  const windowCheck = expiredResult.checks.find(c => c.name === 'Within time window');
  assert(windowCheck && !windowCheck.passed, 'Time window check fails for expired receipt');

  // ── Verification — Tampered Receipt ────────────────────────────────
  console.log('\nVerification — Tampered Receipt');
  const tampered = { ...receipt, scope: 'Send emails to everyone in the contact list' };
  const tamperedResult = await AuthProof.verify(tampered, receiptId);
  assert(tamperedResult.authorized === false, 'Tampered receipt is denied');
  const sigCheck = tamperedResult.checks.find(c => c.name === 'Signature valid');
  assert(sigCheck && !sigCheck.passed, 'Signature check fails for tampered receipt');

  // ── Verification — Wrong Receipt ID ────────────────────────────────
  const wrongIdResult = await AuthProof.verify(receipt, 'a'.repeat(64));
  assert(wrongIdResult.authorized === false, 'Wrong receipt ID is denied');

  // ── Utility Functions ───────────────────────────────────────────────
  console.log('\nUtility Functions');
  assert(AuthProof.isActive(receipt) === true, 'isActive returns true for fresh receipt');
  assert(AuthProof.isActive(receipt, true) === false, 'isActive returns false when revoked=true');
  assert(AuthProof.isActive(expiredReceipt) === false, 'isActive returns false for expired receipt');

  const secs = AuthProof.secondsRemaining(receipt);
  assert(secs > 0, 'secondsRemaining > 0 for active receipt');
  assert(AuthProof.secondsRemaining(expiredReceipt) === 0, 'secondsRemaining = 0 for expired receipt');

  const computedId = await AuthProof.receiptId(receipt);
  assert(computedId === receiptId, 'receiptId() computes correct SHA-256');

  // ── Scope Checking ──────────────────────────────────────────────────
  console.log('\nScope Checking');
  const inScope = AuthProof.checkScope('Search competitor pricing pages', receipt);
  assert(inScope.scopeScore > 0, 'In-scope action has positive scope score');

  const outOfScope = AuthProof.checkScope('Send email to marketing team', receipt);
  assert(!outOfScope.withinScope, 'Out-of-scope action not within scope');

  // ── System Prompt Builder ───────────────────────────────────────────
  console.log('\nSystem Prompt Builder');
  const prompt = AuthProof.buildSystemPrompt(receipt, receiptId, 'https://authproof.dev');
  assert(prompt.includes('https://authproof.dev'), 'buildSystemPrompt includes verify URL');
  assert(prompt.includes(receiptId), 'buildSystemPrompt includes receipt ID');

  // ── Validation Errors ───────────────────────────────────────────────
  console.log('\nValidation Errors');
  try {
    await AuthProof.create({ scope: 'test', boundaries: 'test', privateKey, publicJwk });
    assert(false, 'Should throw when instructions missing');
  } catch (e) {
    assert(e.message.includes('instructions'), 'Throws for missing instructions');
  }

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

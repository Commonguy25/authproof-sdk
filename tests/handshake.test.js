/**
 * AuthProof — Gap 4: Cross-Agent Trust Handshake
 * Run: node tests/handshake.test.js
 *
 * Tests cover:
 *  - initiate() — produces a signed request with required fields
 *  - initiate() — validation errors for missing parameters
 *  - respond() — verifies initiator signature, produces linked response
 *  - respond() — rejects requests with invalid signatures
 *  - verify() — trusted:true for a fully valid handshake
 *  - verify() — trusted:false for each tamper / failure scenario
 *  - sharedContext structure — both signatures, scopes, scopePolicy
 *  - sharedContext is jointly provable (both sigs verifiable)
 *  - Revocation registry integration — revoked receipt fails handshake
 *  - ActionLog integration — handshake event is logged
 *  - Logging failure is non-fatal
 *  - Neither agent exceeds own receipt scope (scopePolicy field)
 */

import AuthProof, { ActionLog, AgentHandshake, RevocationRegistry } from '../src/authproof.js';

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
  console.log('Gap 4 — Cross-Agent Trust Handshake\n');

  // ── Shared setup: two agents with separate key pairs and receipts ────
  const agentA = await AuthProof.generateKey();
  const agentB = await AuthProof.generateKey();

  const { receipt: receiptA, receiptId: idA } = await AuthProof.create({
    scope:        'Read calendar events. Search the web.',
    boundaries:   'Do not send emails. Do not delete files.',
    instructions: 'Stay in scope.',
    ttlHours:     2,
    privateKey:   agentA.privateKey,
    publicJwk:    agentA.publicJwk,
  });

  const { receipt: receiptB, receiptId: idB } = await AuthProof.create({
    scope:        'Write calendar events. Read contacts.',
    boundaries:   'Do not make payments. Do not delete data.',
    instructions: 'Only act within scope.',
    ttlHours:     2,
    privateKey:   agentB.privateKey,
    publicJwk:    agentB.publicJwk,
  });

  const receipts = new Map([
    [idA, receiptA],
    [idB, receiptB],
  ]);

  // ── Test Group 1: initiate() ─────────────────────────────────────────
  console.log('Test Group 1: initiate()');

  // Test 1: returns a request object
  const { request } = await AgentHandshake.initiate({
    myReceiptHash:  idA,
    myPrivateKey:   agentA.privateKey,
    myPublicJwk:    agentA.publicJwk,
    targetPublicJwk: agentB.publicJwk,
  });
  assert(typeof request === 'object' && request !== null, 'initiate() returns a request object');

  // Test 2: request has handshakeId
  assert(typeof request.handshakeId === 'string' && request.handshakeId.startsWith('hs-'),
    'request has handshakeId with hs- prefix');

  // Test 3: request is signed
  assert(typeof request.signature === 'string' && request.signature.length > 0,
    'request has ECDSA signature');

  // Test 4: request has all required fields
  assert(
    request.initiatorReceiptHash === idA &&
    typeof request.initiatorPublicJwk === 'object' &&
    typeof request.nonce === 'string' &&
    typeof request.initiatedAt === 'number',
    'request has initiatorReceiptHash, initiatorPublicJwk, nonce, initiatedAt'
  );

  // Test 5: throws when myReceiptHash missing
  try {
    await AgentHandshake.initiate({ myPrivateKey: agentA.privateKey, myPublicJwk: agentA.publicJwk, targetPublicJwk: agentB.publicJwk });
    assert(false, 'Should throw when myReceiptHash missing');
  } catch (e) {
    assert(e.message.includes('myReceiptHash'), 'throws for missing myReceiptHash');
  }

  // Test 6: throws when myPrivateKey missing
  try {
    await AgentHandshake.initiate({ myReceiptHash: idA, myPublicJwk: agentA.publicJwk, targetPublicJwk: agentB.publicJwk });
    assert(false, 'Should throw when myPrivateKey missing');
  } catch (e) {
    assert(e.message.includes('myPrivateKey'), 'throws for missing myPrivateKey');
  }

  // Test 7: throws when targetPublicJwk missing
  try {
    await AgentHandshake.initiate({ myReceiptHash: idA, myPrivateKey: agentA.privateKey, myPublicJwk: agentA.publicJwk });
    assert(false, 'Should throw when targetPublicJwk missing');
  } catch (e) {
    assert(e.message.includes('targetPublicJwk'), 'throws for missing targetPublicJwk');
  }

  // ── Test Group 2: respond() ──────────────────────────────────────────
  console.log('\nTest Group 2: respond()');

  // Test 8: returns a response object
  const { response } = await AgentHandshake.respond({
    handshakeRequest: request,
    myReceiptHash:    idB,
    myPrivateKey:     agentB.privateKey,
    myPublicJwk:      agentB.publicJwk,
  });
  assert(typeof response === 'object' && response !== null, 'respond() returns a response object');

  // Test 9: response is signed
  assert(typeof response.signature === 'string' && response.signature.length > 0,
    'response has ECDSA signature');

  // Test 10: response links to request via handshakeId and requestHash
  assert(response.handshakeId === request.handshakeId, 'response.handshakeId matches request');
  assert(typeof response.requestHash === 'string' && response.requestHash.length === 64,
    'response has requestHash (SHA-256 of request)');

  // Test 11: response has all required fields
  assert(
    response.responderReceiptHash === idB &&
    typeof response.responderPublicJwk === 'object' &&
    typeof response.initiatorNonce === 'string' &&
    typeof response.responderNonce === 'string' &&
    typeof response.respondedAt === 'number',
    'response has responderReceiptHash, publicJwk, both nonces, respondedAt'
  );

  // Test 12: respond() rejects a tampered request
  const tamperedRequest = { ...request, initiatorReceiptHash: 'a'.repeat(64) };
  try {
    await AgentHandshake.respond({
      handshakeRequest: tamperedRequest,
      myReceiptHash:    idB,
      myPrivateKey:     agentB.privateKey,
      myPublicJwk:      agentB.publicJwk,
    });
    assert(false, 'respond() should throw for tampered request');
  } catch (e) {
    assert(e.message.includes('invalid'), 'respond() throws when initiator signature is invalid');
  }

  // ── Test Group 3: verify() — trusted path ────────────────────────────
  console.log('\nTest Group 3: verify() — trusted path');

  // Test 13: verify() returns trusted:true for a valid handshake
  const trust = await AgentHandshake.verify(request, response, { receipts });
  assert(trust.trusted === true, 'verify() returns trusted:true for a valid handshake');
  assert(typeof trust.reason === 'string', 'verify() always returns a reason string');
  assert(trust.sharedContext !== null, 'verify() returns a non-null sharedContext on success');

  // Test 14: sharedContext has both receipt hashes
  const ctx = trust.sharedContext;
  assert(ctx.initiatorReceiptHash === idA, 'sharedContext has initiator receipt hash');
  assert(ctx.responderReceiptHash === idB, 'sharedContext has responder receipt hash');

  // Test 15: sharedContext has both agents' scopes
  assert(typeof ctx.initiatorScope === 'string' && ctx.initiatorScope.length > 0,
    'sharedContext has initiatorScope');
  assert(typeof ctx.responderScope === 'string' && ctx.responderScope.length > 0,
    'sharedContext has responderScope');

  // Test 16: sharedContext has both signatures (jointly provable)
  assert(ctx.initiatorSignature === request.signature,
    'sharedContext embeds initiator signature');
  assert(ctx.responderSignature === response.signature,
    'sharedContext embeds responder signature');

  // Test 17: scopePolicy is 'each-agent-limited-to-own-receipt'
  assert(ctx.scopePolicy === 'each-agent-limited-to-own-receipt',
    'sharedContext scopePolicy prevents scope expansion');

  // Test 18: sharedContext has a SHA-256 hash of itself
  assert(typeof ctx.sharedContextHash === 'string' && ctx.sharedContextHash.length === 64,
    'sharedContext has a 64-char sharedContextHash');

  // Test 19: sharedContext has handshakeId
  assert(ctx.handshakeId === request.handshakeId, 'sharedContext has matching handshakeId');

  // ── Test Group 4: verify() — failure paths ───────────────────────────
  console.log('\nTest Group 4: verify() — failure paths');

  // Test 20: fails when initiator signature is tampered
  const badInitiatorRequest = { ...request, initiatorReceiptHash: 'b'.repeat(64) };
  const failInit = await AgentHandshake.verify(badInitiatorRequest, response, { receipts });
  assert(failInit.trusted === false, 'verify() returns trusted:false for tampered initiator sig');
  assert(failInit.sharedContext === null, 'sharedContext is null on failure');

  // Test 21: fails when responder signature is tampered
  const badResponderResponse = { ...response, responderReceiptHash: 'c'.repeat(64) };
  const failResp = await AgentHandshake.verify(request, badResponderResponse, { receipts });
  assert(failResp.trusted === false, 'verify() returns trusted:false for tampered responder sig');

  // Test 22: fails when handshake IDs don't match (spliced response)
  const { response: response2 } = await AgentHandshake.respond({
    handshakeRequest: request,
    myReceiptHash:    idB,
    myPrivateKey:     agentB.privateKey,
    myPublicJwk:      agentB.publicJwk,
  });
  // Splice handshakeId from a different handshake
  const { request: request2 } = await AgentHandshake.initiate({
    myReceiptHash:   idA,
    myPrivateKey:    agentA.privateKey,
    myPublicJwk:     agentA.publicJwk,
    targetPublicJwk: agentB.publicJwk,
  });
  const failId = await AgentHandshake.verify(request2, response, { receipts });
  assert(failId.trusted === false, 'verify() fails when handshake IDs mismatch');
  assert(failId.reason.toLowerCase().includes('mismatch'), 'failure reason mentions mismatch');

  // Test 23: fails when initiator receipt not in receipts map
  const emptyReceipts = new Map([[idB, receiptB]]);
  const failNoInitReceipt = await AgentHandshake.verify(request, response, { receipts: emptyReceipts });
  assert(failNoInitReceipt.trusted === false, 'verify() fails when initiator receipt not provided');
  assert(failNoInitReceipt.reason.toLowerCase().includes('initiator'),
    'failure reason mentions initiator');

  // Test 24: fails when responder receipt not in receipts map
  const onlyInitReceipts = new Map([[idA, receiptA]]);
  const failNoRespReceipt = await AgentHandshake.verify(request, response, { receipts: onlyInitReceipts });
  assert(failNoRespReceipt.trusted === false, 'verify() fails when responder receipt not provided');
  assert(failNoRespReceipt.reason.toLowerCase().includes('responder'),
    'failure reason mentions responder');

  // Test 25: fails when initiator receipt is expired
  const { receipt: expiredReceipt, receiptId: expiredId } = await AuthProof.create({
    scope: 'test', boundaries: 'test', instructions: 'test',
    ttlHours: -1, // already expired
    privateKey: agentA.privateKey,
    publicJwk:  agentA.publicJwk,
  });
  const { request: expiredRequest } = await AgentHandshake.initiate({
    myReceiptHash:   expiredId,
    myPrivateKey:    agentA.privateKey,
    myPublicJwk:     agentA.publicJwk,
    targetPublicJwk: agentB.publicJwk,
  });
  const { response: expiredResponse } = await AgentHandshake.respond({
    handshakeRequest: expiredRequest,
    myReceiptHash:    idB,
    myPrivateKey:     agentB.privateKey,
    myPublicJwk:      agentB.publicJwk,
  });
  const expiredReceipts = new Map([[expiredId, expiredReceipt], [idB, receiptB]]);
  const failExpired = await AgentHandshake.verify(expiredRequest, expiredResponse, { receipts: expiredReceipts });
  assert(failExpired.trusted === false, 'verify() fails when initiator receipt is expired');

  // ── Test Group 5: RevocationRegistry integration ─────────────────────
  console.log('\nTest Group 5: RevocationRegistry integration');

  const registry = new RevocationRegistry();
  await registry.init({ privateKey: agentA.privateKey, publicJwk: agentA.publicJwk });
  await registry.revoke(idA, { reason: 'agent A compromised' });

  // Test 26: verify() fails when initiator receipt is revoked
  const failRevoked = await AgentHandshake.verify(request, response, { receipts, registry });
  assert(failRevoked.trusted === false,
    'verify() fails when initiator receipt is revoked in registry');
  assert(failRevoked.reason.includes('revoked'),
    'failure reason mentions revoked');
  assert(failRevoked.reason.includes('agent A compromised'),
    'failure reason includes the revocation reason');

  // Test 27: verify() fails when RESPONDER receipt is revoked
  const registry2 = new RevocationRegistry();
  await registry2.init({ privateKey: agentB.privateKey, publicJwk: agentB.publicJwk });
  await registry2.revoke(idB, { reason: 'agent B suspended' });

  const failRespRevoked = await AgentHandshake.verify(request, response, { receipts, registry: registry2 });
  assert(failRespRevoked.trusted === false,
    'verify() fails when responder receipt is revoked');

  // ── Test Group 6: ActionLog integration ──────────────────────────────
  console.log('\nTest Group 6: ActionLog integration');

  const log = new ActionLog();
  await log.init({ privateKey: agentA.privateKey, publicJwk: agentA.publicJwk, tsaUrl: null });
  log.registerReceipt(idA, receiptA);

  // Test 28: verify() logs handshake_established event when log is provided
  const { request: req3 } = await AgentHandshake.initiate({
    myReceiptHash:   idA,
    myPrivateKey:    agentA.privateKey,
    myPublicJwk:     agentA.publicJwk,
    targetPublicJwk: agentB.publicJwk,
  });
  const { response: resp3 } = await AgentHandshake.respond({
    handshakeRequest: req3,
    myReceiptHash:    idB,
    myPrivateKey:     agentB.privateKey,
    myPublicJwk:      agentB.publicJwk,
  });
  const trustWithLog = await AgentHandshake.verify(req3, resp3, { receipts, log });
  assert(trustWithLog.trusted === true, 'verify() still succeeds when log is provided');

  const logEntries = log.getEntries(idA);
  const hsEntry = logEntries.find(e => e.action.operation === 'handshake_established');
  assert(hsEntry !== undefined, 'handshake_established entry is logged to ActionLog');
  assert(hsEntry.action.parameters.handshakeId === req3.handshakeId,
    'logged entry references the correct handshakeId');

  // Test 29: logging failure is non-fatal — log without required receipt registered
  const logNoReceipt = new ActionLog();
  await logNoReceipt.init({ privateKey: agentA.privateKey, publicJwk: agentA.publicJwk, tsaUrl: null });
  // Do NOT registerReceipt — record() will still throw, but verify() should survive
  const { request: req4 } = await AgentHandshake.initiate({
    myReceiptHash:   idA,
    myPrivateKey:    agentA.privateKey,
    myPublicJwk:     agentA.publicJwk,
    targetPublicJwk: agentB.publicJwk,
  });
  const { response: resp4 } = await AgentHandshake.respond({
    handshakeRequest: req4,
    myReceiptHash:    idB,
    myPrivateKey:     agentB.privateKey,
    myPublicJwk:      agentB.publicJwk,
  });
  const trustLogFail = await AgentHandshake.verify(req4, resp4, { receipts, log: logNoReceipt });
  assert(trustLogFail.trusted === true,
    'verify() returns trusted:true even when logging internally fails');

  // ── Test Group 7: sharedContext is verifiable by a third party ────────
  console.log('\nTest Group 7: sharedContext joint provability');

  // Test 30: a third party can verify both embedded signatures independently
  const { initiatorSignature, responderSignature } = trust.sharedContext;

  // Re-extract request body (same as during initiate)
  const { signature: _iSig, ...reqBody } = request;
  const iSigCheck = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    await crypto.subtle.importKey('jwk', { ...agentA.publicJwk, key_ops: ['verify'] },
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']),
    new Uint8Array(initiatorSignature.match(/.{2}/g).map(b => parseInt(b, 16))),
    new TextEncoder().encode(JSON.stringify(reqBody))
  );
  assert(iSigCheck === true,
    'third party can verify initiator signature embedded in sharedContext');

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Gap 4 AgentHandshake tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

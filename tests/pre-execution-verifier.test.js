/**
 * PreExecutionVerifier — Tests
 * Run: node --experimental-global-webcrypto tests/pre-execution-verifier.test.js
 */

import AuthProof, { RevocationRegistry, ScopeSchema, Canonicalizer, ActionLog } from '../src/authproof.js';
import { PreExecutionVerifier, DelegationLog } from '../src/pre-execution-verifier.js';
import { authproofMiddleware as langchainMiddleware } from '../src/middleware/langchain.js';
import { authproofMiddleware as expressMiddleware }   from '../src/middleware/express.js';
import { guardFunction }                              from '../src/middleware/generic.js';

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

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

async function makeReceipt({
  scope         = 'Read calendar events and summarize meetings',
  boundaries    = 'Do not send emails. Do not modify records.',
  instructions  = 'Summarize clearly. Stay within scope.',
  ttlHours      = 2,
  privateKey,
  publicJwk,
} = {}) {
  const { receipt, receiptId } = await AuthProof.create({
    scope, boundaries, instructions, ttlHours, privateKey, publicJwk,
  });
  return { receipt, receiptId };
}

async function makeVerifier({ requireTEE = false } = {}) {
  const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });

  const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry, requireTEE });
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });

  return { verifier, delegationLog, revocationRegistry };
}

// ─────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────

async function run() {
  console.log('PreExecutionVerifier — Test Suite\n');

  const { privateKey, publicJwk } = await AuthProof.generateKey();

  // ── DelegationLog ────────────────────────────────────────────────────
  console.log('DelegationLog');

  const dLog = new DelegationLog();
  const { receipt: r0, receiptId: rid0 } = await makeReceipt({ privateKey, publicJwk });
  dLog.add(rid0, r0);
  assert(dLog.has(rid0), 'has() returns true after add()');
  assert(dLog.getReceipt(rid0) === r0, 'getReceipt() returns the stored receipt');
  assert(dLog.getReceipt('notfound') === null, 'getReceipt() returns null for unknown hash');
  assert(typeof dLog.currentTimestamp() === 'number', 'currentTimestamp() returns a number');
  try {
    dLog.add('', r0);
    assert(false, 'add() should throw when receiptHash is empty');
  } catch (e) {
    assert(e.message.includes('receiptHash'), 'add() throws for missing receiptHash');
  }

  // ── PreExecutionVerifier — constructor ───────────────────────────────
  console.log('\nPreExecutionVerifier — constructor');

  const { verifier: v0, delegationLog: dl0, revocationRegistry: reg0 } = await makeVerifier();
  assert(v0 instanceof PreExecutionVerifier, 'PreExecutionVerifier is instantiable');

  try {
    new PreExecutionVerifier({ revocationRegistry: reg0 });
    assert(false, 'Should throw when delegationLog is missing');
  } catch (e) {
    assert(e.message.includes('delegationLog'), 'Throws when delegationLog is missing');
  }

  try {
    new PreExecutionVerifier({ delegationLog: dl0 });
    assert(false, 'Should throw when revocationRegistry is missing');
  } catch (e) {
    assert(e.message.includes('revocationRegistry'), 'Throws when revocationRegistry is missing');
  }

  // Must call init() before check()
  const { delegationLog: dl1, revocationRegistry: reg1 } = await makeVerifier();
  const uninitVerifier = new PreExecutionVerifier({ delegationLog: dl1, revocationRegistry: reg1 });
  try {
    await uninitVerifier.check({ receiptHash: rid0, action: 'read', operatorInstructions: 'x' });
    assert(false, 'Should throw when not initialized');
  } catch (e) {
    assert(e.message.includes('init()'), 'Throws when check() called before init()');
  }

  // ── Check 1: Valid receipt passes all six checks ──────────────────────
  console.log('\nCheck 1–6: Valid receipt passes all checks');

  const { verifier, delegationLog, revocationRegistry } = await makeVerifier();
  const { receipt, receiptId } = await makeReceipt({ privateKey, publicJwk });
  delegationLog.add(receiptId, receipt);

  const validResult = await verifier.check({
    receiptHash:          receiptId,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  assert(validResult.allowed === true, 'Valid receipt: allowed=true');
  assert(validResult.checks.receiptSignatureValid    === true, 'Check 1 passes: signature valid');
  assert(validResult.checks.receiptNotRevoked        === true, 'Check 2 passes: not revoked');
  assert(validResult.checks.withinTimeWindow         === true, 'Check 3 passes: within time window');
  assert(validResult.checks.actionWithinScope        === true, 'Check 4 passes: action within scope');
  assert(validResult.checks.operatorInstructionsMatch === true, 'Check 5 passes: instructions match');
  assert(validResult.blockedReason === null, 'Valid receipt: blockedReason is null');
  assert(typeof validResult.verifiedAt === 'string', 'Result has verifiedAt timestamp');
  assert(typeof validResult.verifierSignature === 'string', 'Result has verifierSignature');
  assert(typeof validResult.verifierPublicKey === 'object', 'Result has verifierPublicKey');

  // ── Block at Check 1: Invalid signature ──────────────────────────────
  console.log('\nBlock at Check 1: Invalid signature');

  const { verifier: v1, delegationLog: dl_1 } = await makeVerifier();
  const { receipt: tamperedR, receiptId: tamperedId } = await makeReceipt({ privateKey, publicJwk });
  const tampered = { ...tamperedR, scope: 'Send emails to everyone', signature: tamperedR.signature };
  // corrupt the signature
  const corruptedReceipt = { ...tampered, signature: 'a'.repeat(tamperedR.signature.length) };
  dl_1.add(tamperedId, corruptedReceipt);

  const sig1Result = await v1.check({
    receiptHash:          tamperedId,
    action:               'Read calendar',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  assert(sig1Result.allowed === false, 'Corrupted signature: allowed=false');
  assert(sig1Result.checks.receiptSignatureValid === false, 'Check 1 fails: signature invalid');
  assert(sig1Result.checks.receiptNotRevoked === false,     'Check 2 not reached after check 1 failure');
  assert(sig1Result.checks.withinTimeWindow  === false,     'Check 3 not reached after check 1 failure');
  assert(sig1Result.blockedReason !== null, 'blockedReason is set for signature failure');
  assert(sig1Result.blockedReason.toLowerCase().includes('signature'), 'blockedReason mentions signature');

  // Receipt not in log → blocked at check 1
  const notFoundResult = await v1.check({
    receiptHash:          'a'.repeat(64),
    action:               'Read calendar',
    operatorInstructions: 'x',
  });
  assert(notFoundResult.allowed === false, 'Unknown receiptHash: allowed=false');
  assert(notFoundResult.blockedReason.includes('not found'), 'blockedReason mentions not found');

  // ── Block at Check 2: Revoked receipt ────────────────────────────────
  console.log('\nBlock at Check 2: Revoked receipt');

  const { verifier: v2, delegationLog: dl2, revocationRegistry: reg2 } = await makeVerifier();
  const { receipt: r2, receiptId: rid2 } = await makeReceipt({ privateKey, publicJwk });
  dl2.add(rid2, r2);
  await reg2.revoke(rid2, { reason: 'user requested revocation' });

  const rev2Result = await v2.check({
    receiptHash:          rid2,
    action:               'Read calendar',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  assert(rev2Result.allowed === false,                           'Revoked receipt: allowed=false');
  assert(rev2Result.checks.receiptSignatureValid === true,       'Check 1 passes before revocation block');
  assert(rev2Result.checks.receiptNotRevoked     === false,      'Check 2 fails: receipt is revoked');
  assert(rev2Result.checks.withinTimeWindow      === false,      'Check 3 not reached after revocation');
  assert(rev2Result.blockedReason.includes('revoked'),           'blockedReason mentions revoked');
  assert(rev2Result.blockedReason.includes('user requested'),    'blockedReason includes revocation reason');

  // ── Block at Check 3: Expired receipt ────────────────────────────────
  console.log('\nBlock at Check 3: Expired receipt');

  const { verifier: v3, delegationLog: dl3 } = await makeVerifier();
  const { receipt: r3, receiptId: rid3 } = await makeReceipt({ privateKey, publicJwk, ttlHours: -1 });
  dl3.add(rid3, r3);

  const exp3Result = await v3.check({
    receiptHash:          rid3,
    action:               'Read calendar',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  assert(exp3Result.allowed === false,                         'Expired receipt: allowed=false');
  assert(exp3Result.checks.receiptSignatureValid === true,     'Check 1 passes before expiry block');
  assert(exp3Result.checks.receiptNotRevoked     === true,     'Check 2 passes before expiry block');
  assert(exp3Result.checks.withinTimeWindow      === false,    'Check 3 fails: receipt expired');
  assert(exp3Result.checks.actionWithinScope     === false,    'Check 4 not reached after expiry');
  assert(exp3Result.blockedReason.toLowerCase().includes('expir'), 'blockedReason mentions expiry');

  // ── Block at Check 4: Out-of-scope action ────────────────────────────
  console.log('\nBlock at Check 4: Out-of-scope action');

  // ScopeSchema path — schema registered separately in DelegationLog (not embedded in signed receipt)
  const { verifier: v4b, delegationLog: dl4b } = await makeVerifier();
  const schema4 = new ScopeSchema({
    version:        '1.0',
    allowedActions: [{ operation: 'read', resource: 'calendar' }],
    deniedActions:  [{ operation: 'delete', resource: '*' }],
  });
  const { receipt: r4c, receiptId: rid4c } = await makeReceipt({ privateKey, publicJwk });
  // Schema registered as metadata — receipt signature stays valid
  dl4b.add(rid4c, r4c, { scopeSchema: schema4 });

  const scope4Result = await v4b.check({
    receiptHash:          rid4c,
    action:               { operation: 'delete', resource: 'calendar' },
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  assert(scope4Result.allowed === false,                     'Out-of-scope action: allowed=false');
  assert(scope4Result.checks.receiptSignatureValid === true, 'Check 1 passes');
  assert(scope4Result.checks.receiptNotRevoked     === true, 'Check 2 passes');
  assert(scope4Result.checks.withinTimeWindow      === true, 'Check 3 passes');
  assert(scope4Result.checks.actionWithinScope     === false,'Check 4 fails: action out of scope');
  assert(scope4Result.checks.operatorInstructionsMatch === false, 'Check 5 not reached');
  assert(scope4Result.blockedReason.toLowerCase().includes('scope'), 'blockedReason mentions scope');

  // ScopeSchema path — allowed action passes check 4
  const { verifier: v4pass, delegationLog: dl4pass } = await makeVerifier();
  dl4pass.add(rid4c, r4c, { scopeSchema: schema4 });
  const scope4PassResult = await v4pass.check({
    receiptHash:          rid4c,
    action:               { operation: 'read', resource: 'calendar' },
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(scope4PassResult.checks.actionWithinScope === true, 'ScopeSchema allowed action passes check 4');

  // Fallback: text-based scope check on receipt without ScopeSchema
  const { verifier: v4d, delegationLog: dl4d } = await makeVerifier();
  const { receipt: r4d, receiptId: rid4d } = await makeReceipt({ privateKey, publicJwk });
  dl4d.add(rid4d, r4d);

  const scope4FallbackResult = await v4d.check({
    receiptHash:          rid4d,
    action:               'Send all purchase orders to external suppliers',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(scope4FallbackResult.allowed === false, 'Text-based out-of-scope action blocked');

  // ── Block at Check 5: Operator instruction drift ──────────────────────
  console.log('\nBlock at Check 5: Operator instruction drift');

  const { verifier: v5, delegationLog: dl5 } = await makeVerifier();
  const { receipt: r5, receiptId: rid5 } = await makeReceipt({ privateKey, publicJwk });
  dl5.add(rid5, r5);

  const drift5Result = await v5.check({
    receiptHash:          rid5,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Different instructions — send emails instead',
  });

  assert(drift5Result.allowed === false,                            'Drifted instructions: allowed=false');
  assert(drift5Result.checks.receiptSignatureValid     === true,    'Check 1 passes');
  assert(drift5Result.checks.receiptNotRevoked         === true,    'Check 2 passes');
  assert(drift5Result.checks.withinTimeWindow          === true,    'Check 3 passes');
  assert(drift5Result.checks.actionWithinScope         === true,    'Check 4 passes');
  assert(drift5Result.checks.operatorInstructionsMatch === false,   'Check 5 fails: instructions drifted');
  assert(drift5Result.blockedReason.toLowerCase().includes('operator'), 'blockedReason mentions operator');

  // Canonicalized form of identical instructions should still pass
  const { verifier: v5b, delegationLog: dl5b } = await makeVerifier();
  const { receipt: r5b, receiptId: rid5b } = await makeReceipt({ privateKey, publicJwk });
  dl5b.add(rid5b, r5b);
  const drift5PassResult = await v5b.check({
    receiptHash:          rid5b,
    action:               'Read calendar meetings and summarize',
    // Canonicalizer normalizes whitespace/case, so this should still match
    operatorInstructions: '  Summarize clearly.  Stay within scope.  ',
  });
  assert(drift5PassResult.allowed === true, 'Canonically equivalent instructions pass check 5');

  // ── Block at Check 6: Wrong program hash ─────────────────────────────
  console.log('\nBlock at Check 6: Wrong program hash');

  const { verifier: v6, delegationLog: dl6 } = await makeVerifier();
  const correctProgramHash = 'a'.repeat(64);
  const { receipt: r6base, receiptId: rid6 } = await makeReceipt({ privateKey, publicJwk });
  // executes registered as log metadata — receipt signature stays valid
  dl6.add(rid6, r6base, { executes: correctProgramHash });

  const prog6Result = await v6.check({
    receiptHash:          rid6,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
    programHash:          'b'.repeat(64),  // wrong hash
  });

  assert(prog6Result.allowed === false,                              'Wrong program hash: allowed=false');
  assert(prog6Result.checks.receiptSignatureValid      === true,     'Check 1 passes');
  assert(prog6Result.checks.receiptNotRevoked          === true,     'Check 2 passes');
  assert(prog6Result.checks.withinTimeWindow           === true,     'Check 3 passes');
  assert(prog6Result.checks.actionWithinScope          === true,     'Check 4 passes');
  assert(prog6Result.checks.operatorInstructionsMatch  === true,     'Check 5 passes');
  assert(prog6Result.checks.programHashMatch           === false,    'Check 6 fails: wrong program hash');
  assert(prog6Result.blockedReason.toLowerCase().includes('program hash') ||
         prog6Result.blockedReason.toLowerCase().includes('code substitution'),
         'blockedReason mentions program hash or code substitution');

  // Correct program hash passes check 6
  const { verifier: v6b, delegationLog: dl6b } = await makeVerifier();
  dl6b.add(rid6, r6base, { executes: correctProgramHash });
  const prog6PassResult = await v6b.check({
    receiptHash:          rid6,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
    programHash:          correctProgramHash,
  });
  assert(prog6PassResult.allowed === true,                           'Correct program hash: allowed=true');
  assert(prog6PassResult.checks.programHashMatch === true,           'Check 6 passes: program hash matches');

  // No programHash provided → programHashMatch field absent
  const { verifier: v6c, delegationLog: dl6c } = await makeVerifier();
  const { receipt: r6c, receiptId: rid6c } = await makeReceipt({ privateKey, publicJwk });
  dl6c.add(rid6c, r6c);
  const prog6AbsentResult = await v6c.check({
    receiptHash:          rid6c,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
    // no programHash
  });
  assert(!('programHashMatch' in prog6AbsentResult.checks), 'programHashMatch absent when not provided');

  // ── requireTEE: false → teeAttestationValid absent ───────────────────
  console.log('\nTEE attestation field');
  assert(!('teeAttestationValid' in validResult.checks), 'teeAttestationValid absent when requireTEE=false');

  // requireTEE: true with no attestation → blocked
  const { verifier: vTEE, delegationLog: dlTEE } = await makeVerifier({ requireTEE: true });
  const { receipt: rTEE, receiptId: ridTEE } = await makeReceipt({ privateKey, publicJwk });
  dlTEE.add(ridTEE, rTEE);
  const teeResult = await vTEE.check({
    receiptHash:          ridTEE,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(teeResult.allowed === false,                         'requireTEE=true, no attestation → blocked');
  assert(teeResult.checks.teeAttestationValid === false,      'teeAttestationValid=false when absent');
  assert(teeResult.blockedReason.toLowerCase().includes('tee'), 'blockedReason mentions TEE');

  // ── [ADVERSARIAL] Replay attack — same receipt hash used concurrently ───
  console.log('\n[ADVERSARIAL] Replay attack: same receipt hash by two concurrent agents');

  const { verifier: vReplay, delegationLog: dlReplay } = await makeVerifier();
  const { receipt: rReplay, receiptId: ridReplay } = await makeReceipt({ privateKey, publicJwk });
  dlReplay.add(ridReplay, rReplay);

  // Two concurrent check() calls with the same receipt hash.
  // JavaScript executes both synchronously until the first await — the first
  // call adds the hash to _inFlightChecks; the second finds it there and is blocked.
  const [replayResult1, replayResult2] = await Promise.all([
    vReplay.check({
      receiptHash:          ridReplay,
      action:               'Read calendar meetings and summarize',
      operatorInstructions: 'Summarize clearly. Stay within scope.',
    }),
    vReplay.check({
      receiptHash:          ridReplay,
      action:               'Read calendar meetings and summarize',
      operatorInstructions: 'Summarize clearly. Stay within scope.',
    }),
  ]);

  const replayPassing = [replayResult1, replayResult2].filter(r => r.allowed);
  const replayBlocked = [replayResult1, replayResult2].filter(r => !r.allowed);

  assert(replayPassing.length === 1,
    '[ADVERSARIAL] replay attack — exactly one concurrent check passes');
  assert(replayBlocked.length === 1,
    '[ADVERSARIAL] replay attack — second concurrent check is blocked');
  assert(
    replayBlocked[0].blockedReason.toLowerCase().includes('replay'),
    '[ADVERSARIAL] replay attack — blocked reason mentions replay'
  );

  // ── Audit log entries ─────────────────────────────────────────────────
  console.log('\nAudit log');

  const { verifier: va, delegationLog: dla } = await makeVerifier();
  const { receipt: ra, receiptId: rida } = await makeReceipt({ privateKey, publicJwk });
  dla.add(rida, ra);

  // Passing check
  await va.check({
    receiptHash:          rida,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  // Blocked check (corrupted signature)
  const { receipt: raFail, receiptId: ridaFail } = await makeReceipt({ privateKey, publicJwk });
  const raCorrupt = { ...raFail, signature: 'f'.repeat(raFail.signature.length) };
  dla.add(ridaFail, raCorrupt);
  await va.check({
    receiptHash:          ridaFail,
    action:               'Read calendar',
    operatorInstructions: 'x',
  });

  const auditPass = va.getAuditLog(rida);
  const auditFail = va.getAuditLog(ridaFail);

  assert(auditPass.length >= 1,                                      'Audit log has entry for passing check');
  assert(auditFail.length >= 1,                                      'Audit log has entry for failing check');
  assert(auditPass[0].action.operation === 'verifier_pass',          'Passing check logged as verifier_pass');
  assert(auditFail[0].action.operation === 'verifier_block',         'Blocked check logged as verifier_block');
  assert(typeof auditPass[0].action.parameters.verifierSignature === 'string',
         'Audit entry carries verifier signature');
  assert(auditPass[0].action.parameters.allowed === true,            'Audit entry records allowed=true');
  assert(auditFail[0].action.parameters.allowed === false,           'Audit entry records allowed=false');
  assert(typeof auditPass[0].entryHash === 'string',                 'Audit entry has entryHash (ActionLog chaining)');

  // ── Blocked action never reaches agent runtime ───────────────────────
  console.log('\nBlocked action never reaches runtime');

  let runtimeCalled = false;
  async function mockRuntime() { runtimeCalled = true; return 'executed'; }

  // Generic guard — blocked
  const { verifier: vg, delegationLog: dlg } = await makeVerifier();
  const { receipt: rg, receiptId: ridg } = await makeReceipt({ privateKey, publicJwk });
  const rgExpired = { ...rg };
  // use expired receipt
  const { receipt: rgExp, receiptId: ridgExp } = await makeReceipt({ privateKey, publicJwk, ttlHours: -1 });
  dlg.add(ridgExp, rgExp);

  const guardedFn = guardFunction(mockRuntime, {
    receiptHash:          ridgExp,
    verifier:             vg,
    action:               { operation: 'execute', resource: 'pipeline' },
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  runtimeCalled = false;
  try {
    await guardedFn();
    assert(false, 'Guarded function should throw on blocked check');
  } catch (e) {
    assert(e.message.includes('[AuthProof]'),   'Throws AuthProof error on block');
    assert(runtimeCalled === false,             'Runtime function never called when blocked');
    assert(e.authproofResult.allowed === false, 'Error carries authproofResult');
  }

  // Generic guard — passes
  const { verifier: vgp, delegationLog: dlgp } = await makeVerifier();
  const { receipt: rgp, receiptId: ridgp } = await makeReceipt({ privateKey, publicJwk });
  dlgp.add(ridgp, rgp);
  runtimeCalled = false;
  const guardedPass = guardFunction(mockRuntime, {
    receiptHash:          ridgp,
    verifier:             vgp,
    action:               'Read calendar meetings',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  const passReturn = await guardedPass();
  assert(runtimeCalled === true,   'Runtime called when check passes');
  assert(passReturn === 'executed', 'Return value from runtime is preserved');

  // ── LangChain middleware ─────────────────────────────────────────────
  console.log('\nLangChain middleware');

  const { verifier: vlc, delegationLog: dllc } = await makeVerifier();
  const { receipt: rlc, receiptId: ridlc } = await makeReceipt({ privateKey, publicJwk });
  dllc.add(ridlc, rlc);

  let agentInvoked = false;
  const mockAgent = {
    invoke: async (input) => { agentInvoked = true; return { output: 'agent result' }; },
    name:   'test-agent',
  };

  // Invalid setup — missing receiptHash
  try {
    langchainMiddleware(mockAgent, { verifier: vlc });
    assert(false, 'Should throw when receiptHash is missing');
  } catch (e) {
    assert(e.message.includes('receiptHash'), 'LangChain middleware throws for missing receiptHash');
  }

  // Valid agent — passes
  const guardedAgent = langchainMiddleware(mockAgent, {
    receiptHash:          ridlc,
    verifier:             vlc,
    operatorInstructions: 'Summarize clearly. Stay within scope.',
    // Custom action extractor so text-based scope check passes
    getAction: () => ({ operation: 'Read calendar meetings and summarize', resource: 'calendar' }),
  });
  agentInvoked = false;
  const agentResult = await guardedAgent.invoke('Read calendar events');
  assert(agentInvoked === true,               'LangChain agent.invoke() called when check passes');
  assert(agentResult.output === 'agent result', 'LangChain agent result passed through');

  // Blocked — expired receipt
  const { verifier: vlcB, delegationLog: dllcB } = await makeVerifier();
  const { receipt: rlcB, receiptId: ridlcB } = await makeReceipt({ privateKey, publicJwk, ttlHours: -1 });
  dllcB.add(ridlcB, rlcB);
  agentInvoked = false;
  const guardedAgentB = langchainMiddleware(mockAgent, {
    receiptHash:          ridlcB,
    verifier:             vlcB,
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  try {
    await guardedAgentB.invoke('Read calendar');
    assert(false, 'LangChain agent should throw when blocked');
  } catch (e) {
    assert(e.message.includes('[AuthProof]'), 'LangChain throws AuthProof error on block');
    assert(agentInvoked === false,             'LangChain agent never invoked when blocked');
  }

  // Non-invoke property access passes through
  assert(guardedAgent.name === 'test-agent', 'Non-intercepted property passes through proxy');

  // ── Express middleware ───────────────────────────────────────────────
  console.log('\nExpress middleware');

  const { verifier: vex, delegationLog: dlex } = await makeVerifier();
  const { receipt: rex, receiptId: ridex } = await makeReceipt({ privateKey, publicJwk });
  dlex.add(ridex, rex);

  // Invalid setup — missing verifier
  try {
    expressMiddleware({ getReceiptHash: () => ridex });
    assert(false, 'Express middleware should throw for missing verifier');
  } catch (e) {
    assert(e.message.includes('verifier'), 'Express middleware throws for missing verifier');
  }

  // Valid request — passes and calls next()
  const middleware = expressMiddleware({
    verifier:             vex,
    getReceiptHash:       (req) => req.headers['x-receipt-hash'],
    // Use a scope-compatible action string so text-based matching works
    getAction:            () => 'Read calendar meetings and summarize',
    getOperatorInstructions: () => 'Summarize clearly. Stay within scope.',
  });

  let nextCalled = false;
  const mockReq  = { headers: { 'x-receipt-hash': ridex }, method: 'GET', path: '/calendar' };
  const mockRes  = {
    status(code) { this._code = code; return this; },
    json(body)   { this._body = body; return this; },
    _code: null, _body: null,
  };
  await middleware(mockReq, mockRes, () => { nextCalled = true; });
  assert(nextCalled === true,                'Express next() called when check passes');
  assert(mockReq.authproofResult?.allowed === true, 'req.authproofResult attached on pass');

  // Blocked request — returns 403
  const { verifier: vexB, delegationLog: dlexB } = await makeVerifier();
  const { receipt: rexB, receiptId: ridexB } = await makeReceipt({ privateKey, publicJwk, ttlHours: -1 });
  dlexB.add(ridexB, rexB);
  const middlewareB = expressMiddleware({
    verifier:       vexB,
    getReceiptHash: (req) => req.headers['x-receipt-hash'],
    getOperatorInstructions: () => 'Summarize clearly. Stay within scope.',
  });
  nextCalled = false;
  const mockReqB = { headers: { 'x-receipt-hash': ridexB }, method: 'GET', path: '/calendar' };
  const mockResB = {
    status(code) { this._code = code; return this; },
    json(body)   { this._body = body; return this; },
    _code: null, _body: null,
  };
  await middlewareB(mockReqB, mockResB, () => { nextCalled = true; });
  assert(mockResB._code === 403,       'Express returns 403 when blocked');
  assert(nextCalled === false,         'Express next() NOT called when blocked');
  assert(typeof mockResB._body.blockedReason === 'string', 'Express 403 body includes blockedReason');

  // Missing receipt hash → 401
  const middlewareC = expressMiddleware({
    verifier:       vex,
    getReceiptHash: () => null,
  });
  const mockResC = {
    status(code) { this._code = code; return this; },
    json(body)   { this._body = body; return this; },
    _code: null,
  };
  await middlewareC({}, mockResC, () => {});
  assert(mockResC._code === 401, 'Express returns 401 when receipt hash missing');

  // ── Generic function wrapper ──────────────────────────────────────────
  console.log('\nGeneric function wrapper');

  // Missing fn
  try {
    guardFunction('notafunction', { receiptHash: 'x', verifier: vgp });
    assert(false, 'guardFunction should throw for non-function fn');
  } catch (e) {
    assert(e.message.includes('fn must be a function'), 'guardFunction throws for non-function fn');
  }

  // Dynamic action from args
  const { verifier: vgd, delegationLog: dlgd } = await makeVerifier();
  const { receipt: rgd, receiptId: ridgd } = await makeReceipt({ privateKey, publicJwk });
  dlgd.add(ridgd, rgd);

  let capturedArgs = null;
  async function dynamicAction(arg1) { capturedArgs = arg1; return arg1 * 2; }

  const guardedDynamic = guardFunction(dynamicAction, {
    receiptHash:          ridgd,
    verifier:             vgd,
    action:               (arg1) => ({ operation: 'read', resource: `item/${arg1}` }),
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  const dynResult = await guardedDynamic(42);
  assert(capturedArgs === 42, 'Wrapped function receives original args');
  assert(dynResult === 84,    'Wrapped function return value preserved');

  // ── ActionLog: only authorized receipts are published ────────────────
  console.log('\nActionLog: only authorized receipts are published');

  // Build an initialized ActionLog to pass as the authorization log.
  const { privateKey: alpPriv, publicJwk: alpPub } = await AuthProof.generateKey();
  const authLog = new ActionLog();
  await authLog.init({ privateKey: alpPriv, publicJwk: alpPub, tsaUrl: null });

  // Build a PreExecutionVerifier that holds this authorization log.
  const { privateKey: alpvPriv, publicJwk: alpvPub } = await AuthProof.generateKey();
  const dlAlp = new DelegationLog();
  const regAlp = new RevocationRegistry();
  const { privateKey: alpRegPriv, publicJwk: alpRegPub } = await AuthProof.generateKey();
  await regAlp.init({ privateKey: alpRegPriv, publicJwk: alpRegPub });
  const verifierAlp = new PreExecutionVerifier({
    delegationLog:      dlAlp,
    revocationRegistry: regAlp,
    actionLog:          authLog,
  });
  await verifierAlp.init({ privateKey: alpvPriv, publicJwk: alpvPub });

  // Create and register a valid receipt.
  const { receipt: rAlp, receiptId: ridAlp } = await makeReceipt({ privateKey, publicJwk });
  dlAlp.add(ridAlp, rAlp);

  // Trigger a check-5 failure: operator instructions do not match the receipt.
  const alpFailResult = await verifierAlp.check({
    receiptHash:          ridAlp,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Completely different instructions — operator drift injected',
  });

  assert(alpFailResult.allowed === false,
    'ActionLog test: check() returns allowed=false for instruction mismatch (check 5)');
  assert(alpFailResult.checks.operatorInstructionsMatch === false,
    'ActionLog test: check 5 fails — operatorInstructionsMatch is false');

  // The ActionLog must NOT contain any entry for this receipt hash.
  const alpFailEntries = authLog.getEntries(ridAlp);
  assert(alpFailEntries.length === 0,
    'ActionLog has no entry for the receipt hash when check fails — blocked receipt never published');

  // Passing check: a second receipt with correct instructions DOES get published.
  const { receipt: rAlpPass, receiptId: ridAlpPass } = await makeReceipt({ privateKey, publicJwk });
  dlAlp.add(ridAlpPass, rAlpPass);

  const alpPassResult = await verifierAlp.check({
    receiptHash:          ridAlpPass,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });

  assert(alpPassResult.allowed === true,
    'ActionLog test: passing check returns allowed=true');
  const alpPassEntries = authLog.getEntries(ridAlpPass);
  assert(alpPassEntries.length === 1,
    'ActionLog has exactly one entry after all checks pass');
  assert(alpPassEntries[0].action.operation === 'receipt_authorized',
    'ActionLog entry operation is receipt_authorized');

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All PreExecutionVerifier tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

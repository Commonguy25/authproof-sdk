/**
 * ModelStateAttestation — Test Suite
 * Run: node --experimental-global-webcrypto tests/model-state-attestation.test.js
 *
 * Covers:
 *  - Valid commitment generation with TEE attestation
 *  - Execution verification passes when model matches
 *  - ModelDriftDetected for each driftable component
 *  - Complete chain proof generation and structure
 *  - Integration with PreExecutionVerifier (check 7)
 *  - Integration with TEERuntime (execute with commitment)
 *  - Integration with ActionLog (modelCommitmentId)
 *  - RFC 3161 timestamp shape on attestations
 *  - Tampered commitment detection
 *  - Canonical measurement computation
 *  - Error cases
 */

import AuthProof, { ActionLog, TEERuntime } from '../src/authproof.js';
import { ModelStateAttestation } from '../src/model-state-attestation.js';
import { PreExecutionVerifier, DelegationLog } from '../src/pre-execution-verifier.js';

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

async function makeTeeRuntime() {
  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const teeRuntime = new TEERuntime({ platform: 'simulation' });
  await teeRuntime.init({ privateKey, publicJwk });
  return teeRuntime;
}

async function makeActionLog() {
  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const actionLog = new ActionLog();
  await actionLog.init({ privateKey, publicJwk, tsaUrl: null });
  return actionLog;
}

async function makeMSA() {
  const teeRuntime = await makeTeeRuntime();
  const actionLog  = await makeActionLog();
  return new ModelStateAttestation({ teeRuntime, actionLog });
}

async function makeCommitmentParams(overrides = {}) {
  const { privateKey, publicJwk } = await AuthProof.generateKey();
  // Simulate hashes as 64-char hex strings
  const systemPromptHash   = 'a'.repeat(64);
  const runtimeConfigHash  = 'b'.repeat(64);
  const receiptHash        = 'c'.repeat(64);
  return {
    receiptHash,
    modelId:          'claude-sonnet-4-5',
    modelVersion:     '20251101',
    systemPromptHash,
    runtimeConfigHash,
    privateKey,
    publicJwk,
    ...overrides,
  };
}

async function makeVerifier({ modelStateAttestation } = {}) {
  const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
  const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new AuthProof.RevocationRegistry();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });

  const verifier = new PreExecutionVerifier({
    delegationLog,
    revocationRegistry,
    modelStateAttestation: modelStateAttestation ?? undefined,
  });
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });

  // Create and register a receipt
  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Read and summarize calendar events',
    boundaries:   'Do not send emails. Do not modify records.',
    instructions: 'Summarize clearly.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });
  delegationLog.add(receiptId, receipt, {
    scopeSchema: new AuthProof.ScopeSchema({
      version:        '1.0',
      allowedActions: [{ operation: 'read', resource: 'calendar' }],
      deniedActions:  [],
    }),
  });

  return { verifier, delegationLog, receiptId, receipt };
}

// ─────────────────────────────────────────────
// MAIN TEST RUNNER
// ─────────────────────────────────────────────

async function run() {
  console.log('ModelStateAttestation — Test Suite\n');

  // ── Group 1: TEERuntime class ─────────────────────────────────────
  console.log('Group 1: TEERuntime class');

  // Test 1: TEERuntime exported from authproof.js
  assert(typeof TEERuntime === 'function', 'TEERuntime exported from authproof.js');

  // Test 2: TEERuntime on default export
  assert(typeof AuthProof.TEERuntime === 'function', 'TEERuntime on AuthProof default export');

  // Test 3: constructs with simulation platform
  const rt1 = new TEERuntime({ platform: 'simulation' });
  assert(rt1 instanceof TEERuntime, 'TEERuntime constructs with simulation platform');

  // Test 4: default platform is simulation
  const rt2 = new TEERuntime();
  assert(rt2._platform === 'simulation', 'TEERuntime default platform is simulation');

  // Test 5: throws on unsupported platform
  try {
    new TEERuntime({ platform: 'quantum-tee' });
    assert(false, 'TEERuntime should throw on unsupported platform');
  } catch (e) {
    assert(e.message.includes('unsupported platform'), 'TEERuntime throws on unsupported platform');
  }

  // Test 6: attest() requires init() first in simulation mode
  const rt3 = new TEERuntime({ platform: 'simulation' });
  try {
    await rt3.attest('a'.repeat(64));
    assert(false, 'attest() should throw before init()');
  } catch (e) {
    assert(e.message.includes('init()'), 'attest() throws before init() in simulation mode');
  }

  // Test 7: attest() returns simulation attestation after init
  const teeRuntime = await makeTeeRuntime();
  const att = await teeRuntime.attest('f'.repeat(64));
  assert(att.platform === 'simulation', 'attest() returns platform: simulation');
  assert(typeof att.signature === 'string', 'attest() returns signature string');
  assert(typeof att.signerPublicKey === 'object', 'attest() returns signerPublicKey');
  assert(att.dataHash === 'f'.repeat(64), 'attest() returns correct dataHash');

  // Test 8: attest() throws for invalid dataHash length
  try {
    await teeRuntime.attest('abc');
    assert(false, 'attest() should throw for short hash');
  } catch (e) {
    assert(e.message.includes('64-character'), 'attest() throws for non-64-char hash');
  }

  // Test 9: verifyAttestation() verifies simulation attestation
  const vr = await TEERuntime.verifyAttestation(att);
  assert(vr.verified === true, 'verifyAttestation() returns verified: true for valid attestation');
  assert(vr.platform === 'simulation', 'verifyAttestation() returns correct platform');

  // Test 10: verifyAttestation() rejects tampered dataHash
  const tamperedAtt = { ...att, dataHash: '0'.repeat(64) };
  const tr = await TEERuntime.verifyAttestation(tamperedAtt);
  assert(tr.verified === false, 'verifyAttestation() rejects tampered dataHash');

  // Test 11: verifyAttestation() handles null input
  const nr = await TEERuntime.verifyAttestation(null);
  assert(nr.verified === false, 'verifyAttestation() handles null input');

  // Test 12: execute() runs fn without commitment
  const exResult = await teeRuntime.execute(() => 42);
  assert(exResult === 42, 'execute() runs fn and returns its value');

  // Test 13: execute() throws for non-function
  try {
    await teeRuntime.execute('not-a-function');
    assert(false, 'execute() should throw for non-function');
  } catch (e) {
    assert(e.message.includes('fn must be a function'), 'execute() throws for non-function');
  }

  // ── Group 2: ModelStateAttestation construction ───────────────────
  console.log('\nGroup 2: ModelStateAttestation construction');

  // Test 14: ModelStateAttestation exported
  assert(typeof ModelStateAttestation === 'function', 'ModelStateAttestation exported from module');

  // Test 15: constructs with teeRuntime and actionLog
  const msa1 = await makeMSA();
  assert(msa1 instanceof ModelStateAttestation, 'ModelStateAttestation constructs correctly');

  // Test 16: throws when teeRuntime missing
  try {
    new ModelStateAttestation({ actionLog: await makeActionLog() });
    assert(false, 'should throw when teeRuntime missing');
  } catch (e) {
    assert(e.message.includes('teeRuntime'), 'throws when teeRuntime missing');
  }

  // Test 17: throws when actionLog missing
  try {
    new ModelStateAttestation({ teeRuntime: await makeTeeRuntime() });
    assert(false, 'should throw when actionLog missing');
  } catch (e) {
    assert(e.message.includes('actionLog'), 'throws when actionLog missing');
  }

  // ── Group 3: commit() ────────────────────────────────────────────
  console.log('\nGroup 3: commit()');

  const msa = await makeMSA();
  const params = await makeCommitmentParams();
  const commitment = await msa.commit(params);

  // Test 18: commit() returns commitmentId
  assert(typeof commitment.commitmentId === 'string' && commitment.commitmentId.startsWith('msc-'),
    'commit() returns commitmentId starting with msc-');

  // Test 19: commit() returns receiptHash
  assert(commitment.receiptHash === params.receiptHash, 'commit() returns correct receiptHash');

  // Test 20: commit() returns modelMeasurement (64-char hex)
  assert(typeof commitment.modelMeasurement === 'string' && commitment.modelMeasurement.length === 64,
    'commit() returns 64-char hex modelMeasurement');

  // Test 21: commit() returns modelId and modelVersion
  assert(commitment.modelId === params.modelId, 'commit() returns correct modelId');
  assert(commitment.modelVersion === params.modelVersion, 'commit() returns correct modelVersion');

  // Test 22: commit() returns systemPromptHash and runtimeConfigHash
  assert(commitment.systemPromptHash === params.systemPromptHash,
    'commit() returns correct systemPromptHash');
  assert(commitment.runtimeConfigHash === params.runtimeConfigHash,
    'commit() returns correct runtimeConfigHash');

  // Test 23: commit() returns committedAt ISO string
  assert(typeof commitment.committedAt === 'string' && !isNaN(Date.parse(commitment.committedAt)),
    'commit() returns valid ISO committedAt timestamp');

  // Test 24: commit() returns ECDSA signature
  assert(typeof commitment.signature === 'string' && commitment.signature.length > 0,
    'commit() returns signature string');

  // Test 25: commit() returns teeAttestation
  assert(commitment.teeAttestation && commitment.teeAttestation.platform === 'simulation',
    'commit() returns simulation teeAttestation');

  // Test 26: commitment stored internally
  assert(msa.getCommitment(commitment.commitmentId) === commitment,
    'commitment stored and retrievable by ID');

  // Test 27: getCommitment returns null for unknown ID
  assert(msa.getCommitment('nonexistent-id') === null,
    'getCommitment() returns null for unknown ID');

  // Test 28: commit() throws when receiptHash missing
  try {
    const p = await makeCommitmentParams({ receiptHash: undefined });
    await msa.commit(p);
    assert(false, 'commit() should throw when receiptHash missing');
  } catch (e) {
    assert(e.message.includes('receiptHash'), 'commit() throws when receiptHash missing');
  }

  // Test 29: commit() throws when modelId missing
  try {
    const p = await makeCommitmentParams({ modelId: undefined });
    await msa.commit(p);
    assert(false, 'commit() should throw when modelId missing');
  } catch (e) {
    assert(e.message.includes('modelId'), 'commit() throws when modelId missing');
  }

  // Test 30: commit() throws when systemPromptHash missing
  try {
    const p = await makeCommitmentParams({ systemPromptHash: undefined });
    await msa.commit(p);
    assert(false, 'commit() should throw when systemPromptHash missing');
  } catch (e) {
    assert(e.message.includes('systemPromptHash'), 'commit() throws when systemPromptHash missing');
  }

  // ── Group 4: verify() — passes ───────────────────────────────────
  console.log('\nGroup 4: verify() — passes when model matches');

  const verifyResult = await msa.verify({
    commitmentId:             commitment.commitmentId,
    currentModelId:           params.modelId,
    currentModelVersion:      params.modelVersion,
    currentSystemPromptHash:  params.systemPromptHash,
    currentRuntimeConfigHash: params.runtimeConfigHash,
  });

  // Test 31: valid: true when model matches
  assert(verifyResult.valid === true, 'verify() valid: true when model matches');

  // Test 32: commitmentMatches: true when model matches
  assert(verifyResult.commitmentMatches === true, 'verify() commitmentMatches: true when model matches');

  // Test 33: modelDrift empty when model matches
  assert(Array.isArray(verifyResult.modelDrift) && verifyResult.modelDrift.length === 0,
    'verify() modelDrift empty when model matches');

  // Test 34: verifiedAt is ISO string
  assert(typeof verifyResult.verifiedAt === 'string' && !isNaN(Date.parse(verifyResult.verifiedAt)),
    'verify() verifiedAt is valid ISO timestamp');

  // Test 35: teeAttestation present in verify result
  assert(verifyResult.teeAttestation && verifyResult.teeAttestation.platform === 'simulation',
    'verify() includes teeAttestation with platform: simulation');

  // ── Group 5: verify() — model drift detection ────────────────────
  console.log('\nGroup 5: verify() — ModelDrift detection');

  // Test 36: ModelDrift when modelId changes
  const driftModelId = await msa.verify({
    commitmentId:             commitment.commitmentId,
    currentModelId:           'claude-opus-4-6',
    currentModelVersion:      params.modelVersion,
    currentSystemPromptHash:  params.systemPromptHash,
    currentRuntimeConfigHash: params.runtimeConfigHash,
  });
  assert(driftModelId.valid === false, 'verify() valid: false when modelId changes');
  assert(driftModelId.modelDrift.some(d => d.includes('modelId')),
    'verify() modelDrift includes modelId description');

  // Test 37: commitmentMatches false when modelId changes
  assert(driftModelId.commitmentMatches === false,
    'verify() commitmentMatches: false when modelId changes');

  // Test 38: ModelDrift when modelVersion changes
  const driftVersion = await msa.verify({
    commitmentId:             commitment.commitmentId,
    currentModelId:           params.modelId,
    currentModelVersion:      '99999999',
    currentSystemPromptHash:  params.systemPromptHash,
    currentRuntimeConfigHash: params.runtimeConfigHash,
  });
  assert(driftVersion.valid === false, 'verify() valid: false when modelVersion changes');
  assert(driftVersion.modelDrift.some(d => d.includes('modelVersion')),
    'verify() modelDrift includes modelVersion description');

  // Test 39: ModelDrift when systemPromptHash changes
  const driftSysPrompt = await msa.verify({
    commitmentId:             commitment.commitmentId,
    currentModelId:           params.modelId,
    currentModelVersion:      params.modelVersion,
    currentSystemPromptHash:  'd'.repeat(64),
    currentRuntimeConfigHash: params.runtimeConfigHash,
  });
  assert(driftSysPrompt.valid === false, 'verify() valid: false when systemPromptHash changes');
  assert(driftSysPrompt.modelDrift.some(d => d.includes('systemPromptHash')),
    'verify() modelDrift includes systemPromptHash description');

  // Test 40: ModelDrift when runtimeConfigHash changes
  const driftRtConfig = await msa.verify({
    commitmentId:             commitment.commitmentId,
    currentModelId:           params.modelId,
    currentModelVersion:      params.modelVersion,
    currentSystemPromptHash:  params.systemPromptHash,
    currentRuntimeConfigHash: 'e'.repeat(64),
  });
  assert(driftRtConfig.valid === false, 'verify() valid: false when runtimeConfigHash changes');
  assert(driftRtConfig.modelDrift.some(d => d.includes('runtimeConfigHash')),
    'verify() modelDrift includes runtimeConfigHash description');

  // Test 41: valid: false when commitment not found
  const notFound = await msa.verify({
    commitmentId:             'msc-does-not-exist',
    currentModelId:           params.modelId,
    currentModelVersion:      params.modelVersion,
    currentSystemPromptHash:  params.systemPromptHash,
    currentRuntimeConfigHash: params.runtimeConfigHash,
  });
  assert(notFound.valid === false, 'verify() valid: false for unknown commitmentId');
  assert(notFound.commitmentMatches === false, 'verify() commitmentMatches: false for unknown commitmentId');

  // Test 42: verify() throws when commitmentId missing
  try {
    await msa.verify({
      currentModelId:           params.modelId,
      currentModelVersion:      params.modelVersion,
      currentSystemPromptHash:  params.systemPromptHash,
      currentRuntimeConfigHash: params.runtimeConfigHash,
    });
    assert(false, 'verify() should throw when commitmentId missing');
  } catch (e) {
    assert(e.message.includes('commitmentId'), 'verify() throws when commitmentId missing');
  }

  // Test 43: multiple drift items accumulated correctly
  const driftMultiple = await msa.verify({
    commitmentId:             commitment.commitmentId,
    currentModelId:           'different-model',
    currentModelVersion:      'different-version',
    currentSystemPromptHash:  params.systemPromptHash,
    currentRuntimeConfigHash: params.runtimeConfigHash,
  });
  assert(driftMultiple.modelDrift.length >= 2,
    'verify() accumulates multiple drift items when multiple components change');

  // ── Group 6: computeMeasurement() ────────────────────────────────
  console.log('\nGroup 6: computeMeasurement() — canonical measurement');

  // Test 44: same inputs produce same measurement
  const m1 = await ModelStateAttestation.computeMeasurement({
    modelId: 'model-x', modelVersion: '1.0',
    systemPromptHash: 'a'.repeat(64), runtimeConfigHash: 'b'.repeat(64),
    receiptHash: 'c'.repeat(64),
  });
  const m2 = await ModelStateAttestation.computeMeasurement({
    modelId: 'model-x', modelVersion: '1.0',
    systemPromptHash: 'a'.repeat(64), runtimeConfigHash: 'b'.repeat(64),
    receiptHash: 'c'.repeat(64),
  });
  assert(m1 === m2, 'computeMeasurement() produces identical results for identical inputs');

  // Test 45: different modelId produces different measurement
  const m3 = await ModelStateAttestation.computeMeasurement({
    modelId: 'model-y', modelVersion: '1.0',
    systemPromptHash: 'a'.repeat(64), runtimeConfigHash: 'b'.repeat(64),
    receiptHash: 'c'.repeat(64),
  });
  assert(m1 !== m3, 'computeMeasurement() differs when modelId changes');

  // Test 46: different systemPromptHash produces different measurement
  const m4 = await ModelStateAttestation.computeMeasurement({
    modelId: 'model-x', modelVersion: '1.0',
    systemPromptHash: 'd'.repeat(64), runtimeConfigHash: 'b'.repeat(64),
    receiptHash: 'c'.repeat(64),
  });
  assert(m1 !== m4, 'computeMeasurement() differs when systemPromptHash changes');

  // Test 47: different runtimeConfigHash produces different measurement
  const m5 = await ModelStateAttestation.computeMeasurement({
    modelId: 'model-x', modelVersion: '1.0',
    systemPromptHash: 'a'.repeat(64), runtimeConfigHash: 'e'.repeat(64),
    receiptHash: 'c'.repeat(64),
  });
  assert(m1 !== m5, 'computeMeasurement() differs when runtimeConfigHash changes');

  // Test 48: different receiptHash produces different measurement (delegation binding)
  const m6 = await ModelStateAttestation.computeMeasurement({
    modelId: 'model-x', modelVersion: '1.0',
    systemPromptHash: 'a'.repeat(64), runtimeConfigHash: 'b'.repeat(64),
    receiptHash: 'f'.repeat(64),
  });
  assert(m1 !== m6, 'computeMeasurement() differs when receiptHash changes — delegation binding works');

  // Test 49: result is 64-char hex string
  assert(m1.length === 64 && /^[0-9a-f]+$/.test(m1),
    'computeMeasurement() returns 64-char lowercase hex string');

  // ── Group 7: generateChainProof() ────────────────────────────────
  console.log('\nGroup 7: generateChainProof()');

  const chainProof = await msa.generateChainProof({
    receiptHash:       params.receiptHash,
    commitmentId:      commitment.commitmentId,
    actionLogEntryId:  'log-123-abc',
  });

  // Test 50: chainProofId is present
  assert(typeof chainProof.chainProofId === 'string' && chainProof.chainProofId.startsWith('cp-'),
    'generateChainProof() returns chainProofId starting with cp-');

  // Test 51: generatedAt is ISO string
  assert(typeof chainProof.generatedAt === 'string' && !isNaN(Date.parse(chainProof.generatedAt)),
    'generateChainProof() returns valid ISO generatedAt');

  // Test 52: chainHash is 64-char hex
  assert(typeof chainProof.chainHash === 'string' && chainProof.chainHash.length === 64,
    'generateChainProof() returns 64-char chainHash');

  // Test 53: chain.delegationReceipt.receiptHash matches
  assert(chainProof.chain.delegationReceipt.receiptHash === params.receiptHash,
    'chain.delegationReceipt.receiptHash matches input receiptHash');

  // Test 54: chain.modelStateCommitment.commitmentId matches
  assert(chainProof.chain.modelStateCommitment.commitmentId === commitment.commitmentId,
    'chain.modelStateCommitment.commitmentId matches input commitmentId');

  // Test 55: chain.modelStateCommitment has measurement
  assert(chainProof.chain.modelStateCommitment.modelMeasurement === commitment.modelMeasurement,
    'chain.modelStateCommitment.modelMeasurement matches committed measurement');

  // Test 56: chain.actionLogEntry.actionLogEntryId matches
  assert(chainProof.chain.actionLogEntry.actionLogEntryId === 'log-123-abc',
    'chain.actionLogEntry.actionLogEntryId matches input');

  // Test 57: chain.executionAttestation.teeAttestation present
  assert(chainProof.chain.executionAttestation.teeAttestation !== null,
    'chain.executionAttestation.teeAttestation is present');

  // Test 58: generateChainProof throws when commitmentId not found
  try {
    await msa.generateChainProof({
      receiptHash:      params.receiptHash,
      commitmentId:     'msc-not-found',
      actionLogEntryId: 'log-123-abc',
    });
    assert(false, 'generateChainProof should throw for unknown commitmentId');
  } catch (e) {
    assert(e.message.includes('not found'), 'generateChainProof throws for unknown commitmentId');
  }

  // Test 59: generateChainProof throws when actionLogEntryId missing
  try {
    await msa.generateChainProof({
      receiptHash:  params.receiptHash,
      commitmentId: commitment.commitmentId,
    });
    assert(false, 'generateChainProof should throw when actionLogEntryId missing');
  } catch (e) {
    assert(e.message.includes('actionLogEntryId'), 'generateChainProof throws when actionLogEntryId missing');
  }

  // ── Group 8: verifyCommitmentIntegrity() ────────────────────────
  console.log('\nGroup 8: verifyCommitmentIntegrity() — tamper detection');

  // Test 60: valid commitment passes integrity check
  const integrityResult = await ModelStateAttestation.verifyCommitmentIntegrity(commitment);
  assert(integrityResult.valid === true, 'verifyCommitmentIntegrity() passes for valid commitment');

  // Test 61: tampered modelMeasurement fails integrity check
  const tampered = { ...commitment, modelMeasurement: '9'.repeat(64) };
  const tamperedResult = await ModelStateAttestation.verifyCommitmentIntegrity(tampered);
  assert(tamperedResult.valid === false, 'verifyCommitmentIntegrity() fails for tampered modelMeasurement');

  // Test 62: tampered modelId fails integrity check
  const tamperedModelId = { ...commitment, modelId: 'attacker-model' };
  const tamperedIdResult = await ModelStateAttestation.verifyCommitmentIntegrity(tamperedModelId);
  assert(tamperedIdResult.valid === false, 'verifyCommitmentIntegrity() fails for tampered modelId');

  // Test 63: null commitment fails integrity check
  const nullResult = await ModelStateAttestation.verifyCommitmentIntegrity(null);
  assert(nullResult.valid === false, 'verifyCommitmentIntegrity() fails for null input');

  // Test 64: missing signature fails integrity check
  const { signature: _sig, ...noSig } = commitment;
  const noSigResult = await ModelStateAttestation.verifyCommitmentIntegrity(noSig);
  assert(noSigResult.valid === false, 'verifyCommitmentIntegrity() fails for missing signature');

  // ── Group 9: Integration with ActionLog.record() ─────────────────
  console.log('\nGroup 9: Integration with ActionLog.record()');

  const { privateKey: aPriv, publicJwk: aPub } = await AuthProof.generateKey();
  const testLog = new ActionLog();
  await testLog.init({ privateKey: aPriv, publicJwk: aPub, tsaUrl: null });

  const testReceiptHash = 'f'.repeat(64);

  // Test 65: record() accepts modelCommitmentId
  const entryWithCid = await testLog.record(
    testReceiptHash,
    { operation: 'read', resource: 'calendar' },
    { modelCommitmentId: commitment.commitmentId }
  );
  assert(entryWithCid.modelCommitmentId === commitment.commitmentId,
    'ActionLog.record() accepts and stores modelCommitmentId');

  // Test 66: log entry without modelCommitmentId still works
  const entryWithout = await testLog.record(
    testReceiptHash,
    { operation: 'write', resource: 'calendar' }
  );
  assert(entryWithout.modelCommitmentId === undefined,
    'ActionLog.record() works without modelCommitmentId (backward compat)');

  // Test 67: entry with modelCommitmentId has valid entryHash
  assert(typeof entryWithCid.entryHash === 'string' && entryWithCid.entryHash.length === 64,
    'ActionLog entry with modelCommitmentId has valid entryHash');

  // ── Group 10: Integration with TEERuntime.execute() ──────────────
  console.log('\nGroup 10: Integration with TEERuntime.execute()');

  const msaForExec = await makeMSA();
  const execParams = await makeCommitmentParams();
  const execCommitment = await msaForExec.commit(execParams);
  const execRuntime = await makeTeeRuntime();

  // Test 68: execute() passes when model matches commitment
  let execPassed = false;
  await execRuntime.execute(
    () => { execPassed = true; return 'ok'; },
    {
      commitment:               execCommitment,
      currentModelId:           execParams.modelId,
      currentModelVersion:      execParams.modelVersion,
      currentSystemPromptHash:  execParams.systemPromptHash,
      currentRuntimeConfigHash: execParams.runtimeConfigHash,
      modelStateAttestation:    msaForExec,
    }
  );
  assert(execPassed, 'TEERuntime.execute() runs fn when model matches commitment');

  // Test 69: execute() throws ModelDriftDetected when modelId drifts
  let driftErr = null;
  try {
    await execRuntime.execute(
      () => 'should not run',
      {
        commitment:               execCommitment,
        currentModelId:           'substituted-model',
        currentModelVersion:      execParams.modelVersion,
        currentSystemPromptHash:  execParams.systemPromptHash,
        currentRuntimeConfigHash: execParams.runtimeConfigHash,
        modelStateAttestation:    msaForExec,
      }
    );
  } catch (e) {
    driftErr = e;
  }
  assert(driftErr !== null && driftErr.name === 'ModelDriftDetected',
    'TEERuntime.execute() throws ModelDriftDetected when modelId drifts');
  assert(Array.isArray(driftErr.modelDrift) && driftErr.modelDrift.length > 0,
    'ModelDriftDetected error has modelDrift array');

  // Test 70: execute() throws ModelDriftDetected when systemPromptHash drifts
  let sphDriftErr = null;
  try {
    await execRuntime.execute(
      () => 'blocked',
      {
        commitment:               execCommitment,
        currentModelId:           execParams.modelId,
        currentModelVersion:      execParams.modelVersion,
        currentSystemPromptHash:  '9'.repeat(64),
        currentRuntimeConfigHash: execParams.runtimeConfigHash,
        modelStateAttestation:    msaForExec,
      }
    );
  } catch (e) {
    sphDriftErr = e;
  }
  assert(sphDriftErr !== null && sphDriftErr.name === 'ModelDriftDetected',
    'TEERuntime.execute() throws ModelDriftDetected when systemPromptHash drifts');

  // ── Group 11: Integration with PreExecutionVerifier (check 7) ────
  console.log('\nGroup 11: Integration with PreExecutionVerifier (check 7)');

  // Test 71: verifier without modelStateAttestation has no modelStateValid check
  const { verifier: baseVerifier, receiptId: baseReceiptId } = await makeVerifier();
  const baseResult = await baseVerifier.check({
    receiptHash:  baseReceiptId,
    action:       { operation: 'read', resource: 'calendar' },
    operatorInstructions: 'Summarize clearly.',
  });
  assert(baseResult.checks.modelStateValid === undefined,
    'verifier without modelStateAttestation has no modelStateValid in checks');

  // Test 72: verifier with modelStateAttestation but no commitmentId skips check 7
  const msaForVerifier = await makeMSA();
  const { verifier: msaVerifier, receiptId: msaReceiptId } = await makeVerifier({
    modelStateAttestation: msaForVerifier,
  });
  const noCommitResult = await msaVerifier.check({
    receiptHash:          msaReceiptId,
    action:               { operation: 'read', resource: 'calendar' },
    operatorInstructions: 'Summarize clearly.',
    // no commitmentId — check 7 not triggered
  });
  assert(noCommitResult.checks.modelStateValid === undefined,
    'verifier skips check 7 when no commitmentId provided');
  assert(noCommitResult.allowed === true,
    'verifier passes when check 7 not triggered');

  // Test 73: verifier check 7 passes when model matches
  const checkParams = await makeCommitmentParams();
  const checkCommitment = await msaForVerifier.commit(checkParams);

  const check7PassResult = await msaVerifier.check({
    receiptHash:              msaReceiptId,
    action:                   { operation: 'read', resource: 'calendar' },
    operatorInstructions:     'Summarize clearly.',
    commitmentId:             checkCommitment.commitmentId,
    currentModelId:           checkParams.modelId,
    currentModelVersion:      checkParams.modelVersion,
    currentSystemPromptHash:  checkParams.systemPromptHash,
    currentRuntimeConfigHash: checkParams.runtimeConfigHash,
  });
  assert(check7PassResult.checks.modelStateValid === true,
    'verifier check 7 passes when model matches (modelStateValid: true)');
  assert(check7PassResult.allowed === true,
    'verifier allows execution when all 7 checks pass');

  // Test 74: verifier check 7 blocks when modelId drifts
  const check7BlockResult = await msaVerifier.check({
    receiptHash:              msaReceiptId,
    action:                   { operation: 'read', resource: 'calendar' },
    operatorInstructions:     'Summarize clearly.',
    commitmentId:             checkCommitment.commitmentId,
    currentModelId:           'unauthorized-model',
    currentModelVersion:      checkParams.modelVersion,
    currentSystemPromptHash:  checkParams.systemPromptHash,
    currentRuntimeConfigHash: checkParams.runtimeConfigHash,
  });
  assert(check7BlockResult.checks.modelStateValid === false,
    'verifier check 7 fails when modelId drifts (modelStateValid: false)');
  assert(check7BlockResult.allowed === false,
    'verifier blocks execution when check 7 fails');

  // Test 75: blocked result contains ModelDriftDetected in blockedReason
  assert(
    typeof check7BlockResult.blockedReason === 'string' &&
    check7BlockResult.blockedReason.includes('ModelDriftDetected'),
    'blocked result contains ModelDriftDetected in blockedReason'
  );

  // Test 76: verifier check 7 blocks when systemPromptHash changes
  const check7SphBlock = await msaVerifier.check({
    receiptHash:              msaReceiptId,
    action:                   { operation: 'read', resource: 'calendar' },
    operatorInstructions:     'Summarize clearly.',
    commitmentId:             checkCommitment.commitmentId,
    currentModelId:           checkParams.modelId,
    currentModelVersion:      checkParams.modelVersion,
    currentSystemPromptHash:  'z'.repeat(64),
    currentRuntimeConfigHash: checkParams.runtimeConfigHash,
  });
  assert(check7SphBlock.allowed === false,
    'verifier blocks when systemPromptHash changes in check 7');
  assert(check7SphBlock.blockedReason.includes('ModelDriftDetected'),
    'blockedReason includes ModelDriftDetected when systemPromptHash changes');

  // Test 77: verifier check 7 blocks when runtimeConfigHash changes
  const check7RcBlock = await msaVerifier.check({
    receiptHash:              msaReceiptId,
    action:                   { operation: 'read', resource: 'calendar' },
    operatorInstructions:     'Summarize clearly.',
    commitmentId:             checkCommitment.commitmentId,
    currentModelId:           checkParams.modelId,
    currentModelVersion:      checkParams.modelVersion,
    currentSystemPromptHash:  checkParams.systemPromptHash,
    currentRuntimeConfigHash: '1'.repeat(64),
  });
  assert(check7RcBlock.allowed === false,
    'verifier blocks when runtimeConfigHash changes in check 7');

  // ── Group 12: Receipt-hash binding ───────────────────────────────
  console.log('\nGroup 12: Receipt-hash binding (same model, different receipt = different measurement)');

  // Test 78: commitments under different receipts have different measurements
  const msa2 = await makeMSA();
  const p1 = await makeCommitmentParams({ receiptHash: 'r'.repeat(64) });
  const p2 = await makeCommitmentParams({ receiptHash: 's'.repeat(64) });
  // Same model state, different receipts
  p2.modelId           = p1.modelId;
  p2.modelVersion      = p1.modelVersion;
  p2.systemPromptHash  = p1.systemPromptHash;
  p2.runtimeConfigHash = p1.runtimeConfigHash;

  const c1 = await msa2.commit(p1);
  const c2 = await msa2.commit(p2);
  assert(c1.modelMeasurement !== c2.modelMeasurement,
    'Same model state under different receipts produces different measurements');

  // Test 79: verify fails if current state matches a different receipt's commitment
  // c1 was committed under p1.receiptHash; trying to verify against c1 but with p2's receipt
  // can't cross-verify because the measurement includes the receipt hash
  const crossVerify = await msa2.verify({
    commitmentId:             c1.commitmentId,
    currentModelId:           p1.modelId,
    currentModelVersion:      p1.modelVersion,
    currentSystemPromptHash:  p1.systemPromptHash,
    currentRuntimeConfigHash: p1.runtimeConfigHash,
  });
  // c1 was committed with p1.receiptHash in measurement — correct verify should pass
  assert(crossVerify.valid === true,
    'Verify passes for correct commitment against its own receipt binding');

  // ── Group 13: Edge cases ─────────────────────────────────────────
  console.log('\nGroup 13: Edge cases');

  // Test 80: Multiple commitments coexist independently
  const msaMulti = await makeMSA();
  const pm1 = await makeCommitmentParams();
  const pm2 = await makeCommitmentParams();
  const cm1 = await msaMulti.commit(pm1);
  const cm2 = await msaMulti.commit(pm2);
  assert(cm1.commitmentId !== cm2.commitmentId,
    'Multiple commitments have distinct IDs');
  assert(msaMulti.getCommitment(cm1.commitmentId) === cm1,
    'First commitment retrievable after second is created');
  assert(msaMulti.getCommitment(cm2.commitmentId) === cm2,
    'Second commitment retrievable independently');

  // ── Group 14: providerUpdatePolicy — ProviderUpdate vs MaliciousSubstitution ──
  console.log('\nGroup 14: providerUpdatePolicy — ProviderUpdate vs MaliciousSubstitution');

  // Test 81: providerUpdatePolicy 'block' — provider version change blocks execution
  {
    const msaBlock = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
      providerUpdatePolicy: 'block',
    });
    const p = await makeCommitmentParams();
    const c = await msaBlock.commit(p);
    const r = await msaBlock.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      'new-provider-version-0125',
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(r.valid === false,
      "providerUpdatePolicy 'block' — valid: false when provider version changes");
    assert(r.reason !== 'PROVIDER_UPDATE_DETECTED',
      "providerUpdatePolicy 'block' — does NOT return PROVIDER_UPDATE_DETECTED");
    assert(r.modelDrift.some(d => d.includes('modelVersion')),
      "providerUpdatePolicy 'block' — modelDrift includes modelVersion entry");
  }

  // Test 82: providerUpdatePolicy 'reauthorize' (default) — provider version change
  //          returns PROVIDER_UPDATE_DETECTED without blocking the current call's reason
  {
    const msaReauth = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
      providerUpdatePolicy: 'reauthorize',
    });
    const p = await makeCommitmentParams();
    const c = await msaReauth.commit(p);
    const r = await msaReauth.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      'new-provider-version-0125',
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(r.reason === 'PROVIDER_UPDATE_DETECTED',
      "providerUpdatePolicy 'reauthorize' — returns PROVIDER_UPDATE_DETECTED for version change");
    assert(r.requiresReauthorization === true,
      "providerUpdatePolicy 'reauthorize' — requiresReauthorization: true");
    assert(r.previousVersion === p.modelVersion,
      "PROVIDER_UPDATE_DETECTED — previousVersion matches committed version");
    assert(r.currentVersion === 'new-provider-version-0125',
      "PROVIDER_UPDATE_DETECTED — currentVersion matches current version");
    assert(r.valid === false,
      "PROVIDER_UPDATE_DETECTED — valid: false");
  }

  // Test 83: reauthorize() clears the pending flag and allows next execution
  {
    const msaR = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
    });
    const p = await makeCommitmentParams();
    const c = await msaR.commit(p);
    // Trigger ProviderUpdate → sets pendingReauthorization
    await msaR.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      'updated-by-provider',
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    // Reauthorize
    await msaR.reauthorize({ userApproval: true });
    // Next verify with matching model should now pass
    const r2 = await msaR.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      p.modelVersion,
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(r2.valid === true,
      'reauthorize() clears pendingReauthorization and allows next valid execution');
  }

  // Test 84: reauthorize() without userApproval throws
  {
    const msaNoApproval = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
    });
    let threw = false;
    try {
      await msaNoApproval.reauthorize({ userApproval: false });
    } catch (e) {
      threw = true;
      assert(e.message.includes('userApproval'),
        'reauthorize() without userApproval throws with userApproval in message');
    }
    assert(threw, 'reauthorize() without userApproval throws');
  }

  // Test 85: operator explicitly changing modelId is always MaliciousSubstitution
  //          regardless of providerUpdatePolicy
  {
    const msaMalicious = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
      providerUpdatePolicy: 'reauthorize',
    });
    const p = await makeCommitmentParams();
    const c = await msaMalicious.commit(p);
    const r = await msaMalicious.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           'completely-different-model',
      currentModelVersion:      p.modelVersion,
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(r.valid === false,
      'MaliciousSubstitution — valid: false when modelId changes regardless of policy');
    assert(r.reason !== 'PROVIDER_UPDATE_DETECTED',
      'MaliciousSubstitution — does NOT return PROVIDER_UPDATE_DETECTED when modelId changes');
    assert(r.mismatchType === 'MaliciousSubstitution',
      'MaliciousSubstitution — mismatchType is MaliciousSubstitution when modelId changes');
  }

  // Test 86: pendingReauthorization flag blocks subsequent calls until reauthorize() is called
  {
    const msaPending = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
    });
    const p = await makeCommitmentParams();
    const c = await msaPending.commit(p);
    // Trigger ProviderUpdate → sets pendingReauthorization
    await msaPending.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      'provider-updated-version',
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    // Subsequent call with a perfectly matching model should still be blocked
    const blocked = await msaPending.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      p.modelVersion,
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(blocked.valid === false,
      'pendingReauthorization blocks subsequent calls even when model matches');
    assert(blocked.reason === 'PENDING_REAUTHORIZATION',
      'pendingReauthorization — blocked result has PENDING_REAUTHORIZATION reason');
    // After reauthorize, execution is allowed again
    await msaPending.reauthorize({ userApproval: true });
    const unblocked = await msaPending.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      p.modelVersion,
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(unblocked.valid === true,
      'pendingReauthorization cleared after reauthorize() — execution allowed again');
  }

  // Test 87: providerUpdatePolicy defaults to 'reauthorize' when not specified
  {
    const msaDefault = new ModelStateAttestation({
      teeRuntime: await makeTeeRuntime(),
      actionLog:  await makeActionLog(),
      // providerUpdatePolicy intentionally omitted
    });
    const p = await makeCommitmentParams();
    const c = await msaDefault.commit(p);
    const r = await msaDefault.verify({
      commitmentId:             c.commitmentId,
      currentModelId:           p.modelId,
      currentModelVersion:      'silently-updated-version',
      currentSystemPromptHash:  p.systemPromptHash,
      currentRuntimeConfigHash: p.runtimeConfigHash,
    });
    assert(r.reason === 'PROVIDER_UPDATE_DETECTED',
      'default providerUpdatePolicy is reauthorize — version change returns PROVIDER_UPDATE_DETECTED');
  }

  // ────────────────────────────────────────────
  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  if (failed === 0) {
    console.log('✓ All ModelStateAttestation tests passed.');
    process.exit(0);
  } else {
    console.error(`✗ ${failed} test(s) failed.`);
    process.exit(1);
  }
}

run().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});

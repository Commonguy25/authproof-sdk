/**
 * ConfidentialRuntime + TokenPreparer — TEE Enforcement Layer Tests
 * Run: node --experimental-global-webcrypto tests/confidential-runtime.test.js
 */

import AuthProof, { AuthProofClient } from '../src/authproof.js';
import { ConfidentialRuntime } from '../src/confidential-runtime.js';
import { TokenPreparer }       from '../src/token-preparer.js';

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

function makeMockVerifier({ allowed = true, blockedReason = 'denied' } = {}) {
  return {
    async check() {
      return { allowed, blockedReason };
    },
  };
}

function makeMockActionLog() {
  const log = {
    entries: [],
    async record(receiptHash, action) {
      const entry = { receiptHash, action, recordedAt: Date.now() };
      log.entries.push(entry);
      return entry;
    },
  };
  return log;
}

/** Returns a 64-char hex string filled with the given char */
function hex64(ch) {
  return ch.repeat(64);
}

async function run() {
  console.log('ConfidentialRuntime + TokenPreparer — TEE Enforcement Layer\n');

  // ── Test Group 1: AuthProofClient.delegate() teeMeasurement ──────────
  console.log('Test Group 1: AuthProofClient.delegate() — teeMeasurement field');

  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const client = new AuthProofClient();

  const verifierHash = hex64('v');
  const modelHash    = hex64('m');

  // Test 1: Receipt includes teeMeasurement when teeConfig provided
  const { receipt: receiptWithTee } = await client.delegate({
    scope: 'Read calendar events and summarize meetings',
    operatorInstructions: 'Summarize clearly.',
    expiresIn: '2h',
    privateKey,
    publicJwk,
    teeConfig: { platform: 'intel-tdx', verifierHash, modelHash },
  });
  assert(
    receiptWithTee.teeMeasurement !== undefined && receiptWithTee.teeMeasurement !== null,
    'Test 1: Receipt includes teeMeasurement when teeConfig provided'
  );

  // Test 2: Receipt without teeConfig has no teeMeasurement field
  const { receipt: receiptNoTee } = await client.delegate({
    scope: 'Read email inbox.',
    operatorInstructions: 'Summarize.',
    expiresIn: '1h',
    privateKey,
    publicJwk,
  });
  assert(
    receiptNoTee.teeMeasurement === undefined,
    'Test 2: Receipt without teeConfig has no teeMeasurement field'
  );

  // Test 3: teeMeasurement.expectedMrenclave is a valid SHA-256 hex string
  const { expectedMrenclave } = receiptWithTee.teeMeasurement;
  assert(
    typeof expectedMrenclave === 'string' &&
    expectedMrenclave.length === 64 &&
    /^[0-9a-f]{64}$/.test(expectedMrenclave),
    'Test 3: teeMeasurement.expectedMrenclave is a valid SHA-256 hex string'
  );

  // ── Test Group 2: ConfidentialRuntime instantiation ───────────────────
  console.log('\nTest Group 2: ConfidentialRuntime instantiation');

  // Test 4: Instantiates with valid platform values
  let platforms4ok = true;
  for (const p of ['intel-tdx', 'amd-sev-snp', 'auto']) {
    try {
      new ConfidentialRuntime({
        platform:  p,
        verifier:  makeMockVerifier(),
        actionLog: makeMockActionLog(),
      });
    } catch {
      platforms4ok = false;
    }
  }
  assert(platforms4ok, 'Test 4: ConfidentialRuntime instantiates with intel-tdx, amd-sev-snp, auto');

  // Test 5: Rejects unknown platform
  let threw5 = false;
  try {
    new ConfidentialRuntime({
      platform:  'fake-platform',
      verifier:  makeMockVerifier(),
      actionLog: makeMockActionLog(),
    });
  } catch (e) {
    threw5 = e.message.includes('unsupported platform');
  }
  assert(threw5, 'Test 5: ConfidentialRuntime rejects unknown platform');

  // ── Test Group 3: launch() — verifier ordering ────────────────────────
  console.log('\nTest Group 3: launch() — verifier ordering and blocking');

  // Test 6: verifier.check() is called before agentFn
  const callOrder = [];
  const orderVerifier = {
    async check() {
      callOrder.push('verifier.check');
      return { allowed: true };
    },
  };
  const orderRuntime = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  orderVerifier,
    actionLog: makeMockActionLog(),
  });
  await orderRuntime.launch({
    receiptHash:          hex64('a'),
    agentFn:              async () => { callOrder.push('agentFn'); },
    operatorInstructions: 'Test instructions',
    verifierHash,
    modelHash,
  });
  assert(
    callOrder[0] === 'verifier.check' && callOrder[1] === 'agentFn',
    'Test 6: verifier.check() is called before agentFn'
  );

  // Test 7: launch() blocks when verifier.check() returns allowed=false
  const blockedRuntime = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier({ allowed: false, blockedReason: 'receipt not registered' }),
    actionLog: makeMockActionLog(),
  });
  let threw7 = false;
  try {
    await blockedRuntime.launch({
      receiptHash:          hex64('b'),
      agentFn:              async () => 'should not run',
      operatorInstructions: 'Test',
      verifierHash,
      modelHash,
    });
  } catch (e) {
    threw7 = e.message.includes('blocked') || e.message.includes('denied');
  }
  assert(threw7, 'Test 7: launch() blocks when verifier.check() returns allowed=false');

  // ── Test Group 4: launch() — return structure ─────────────────────────
  console.log('\nTest Group 4: launch() — return structure');

  const rt = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier(),
    actionLog: makeMockActionLog(),
  });

  const launchResult = await rt.launch({
    receiptHash:          hex64('c'),
    agentFn:              async () => 'agent-output',
    operatorInstructions: 'Do something.',
    verifierHash,
    modelHash,
  });

  // Test 8: launch() returns all required fields
  assert(
    'result'         in launchResult &&
    'tdxQuote'       in launchResult &&
    'mrenclave'      in launchResult &&
    'receiptBinding' in launchResult &&
    'tokenInjected'  in launchResult &&
    'actionLogEntry' in launchResult,
    'Test 8: launch() returns tdxQuote, mrenclave, receiptBinding, tokenInjected, actionLogEntry'
  );

  // Test 9: mrenclave is deterministic SHA-256 of platform+verifierHash+modelHash
  const rt2 = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier(),
    actionLog: makeMockActionLog(),
  });
  const r2 = await rt2.launch({
    receiptHash:          hex64('d'),
    agentFn:              async () => {},
    operatorInstructions: 'Test',
    verifierHash,
    modelHash,
  });
  assert(
    launchResult.mrenclave === r2.mrenclave &&
    typeof launchResult.mrenclave === 'string' &&
    launchResult.mrenclave.length === 64 &&
    /^[0-9a-f]{64}$/.test(launchResult.mrenclave),
    'Test 9: mrenclave is a deterministic SHA-256 of platform+verifierHash+modelHash'
  );

  // Test 10: receiptBinding contains receiptHash and measurement
  assert(
    launchResult.receiptBinding.receiptHash === hex64('c') &&
    launchResult.receiptBinding.measurement === launchResult.mrenclave,
    'Test 10: receiptBinding contains receiptHash and measurement'
  );

  // Test 11: tokenInjected.status === 'PENDING_KERNEL_MODULE'
  assert(
    launchResult.tokenInjected.status === 'PENDING_KERNEL_MODULE',
    "Test 11: tokenInjected.status === 'PENDING_KERNEL_MODULE'"
  );

  // Test 12: actionLogEntry is recorded in ActionLog
  const mockLog12 = makeMockActionLog();
  const rt12 = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier(),
    actionLog: mockLog12,
  });
  await rt12.launch({
    receiptHash:          hex64('e'),
    agentFn:              async () => {},
    operatorInstructions: 'Test',
    verifierHash,
    modelHash,
  });
  assert(
    mockLog12.entries.length === 1 &&
    mockLog12.entries[0].action.operation === 'tee_execute',
    'Test 12: actionLogEntry is recorded in ActionLog'
  );

  // ── Test Group 5: azureTDXConfig() ────────────────────────────────────
  console.log('\nTest Group 5: azureTDXConfig()');

  const azureConfig = ConfidentialRuntime.azureTDXConfig({
    receiptHash:  hex64('f'),
    verifierHash,
    modelHash,
    region: 'westus',
  });

  // Test 13: vmSize is 'Standard_DC4ds_v3'
  assert(
    azureConfig.vmSize === 'Standard_DC4ds_v3',
    "Test 13: azureTDXConfig() returns vmSize 'Standard_DC4ds_v3'"
  );

  // Test 14: attestationEndpoint includes sharedeus.eus.attest.azure.net
  assert(
    typeof azureConfig.attestationEndpoint === 'string' &&
    azureConfig.attestationEndpoint.includes('sharedeus.eus.attest.azure.net'),
    'Test 14: azureTDXConfig() includes attestationEndpoint with sharedeus.eus.attest.azure.net'
  );

  // Test 15: receiptBinding contains receiptHash
  assert(
    azureConfig.receiptBinding.receiptHash === hex64('f'),
    'Test 15: azureTDXConfig() receiptBinding contains receiptHash'
  );

  // ── Test Group 6: awsNitroConfig() ────────────────────────────────────
  console.log('\nTest Group 6: awsNitroConfig()');

  const awsConfig = ConfidentialRuntime.awsNitroConfig({
    receiptHash:  hex64('g'),
    verifierHash,
    modelHash,
    region: 'us-west-2',
  });

  // Test 16: instanceType is 'c6a.xlarge'
  assert(
    awsConfig.instanceType === 'c6a.xlarge',
    "Test 16: awsNitroConfig() returns instanceType 'c6a.xlarge'"
  );

  // Test 17: enclaveOptions.enabled === true
  assert(
    awsConfig.enclaveOptions.enabled === true,
    'Test 17: awsNitroConfig() includes enclaveOptions.enabled === true'
  );

  // Test 18: includes pcr0 field
  assert(
    typeof awsConfig.pcr0 === 'string' && awsConfig.pcr0.length > 0,
    'Test 18: awsNitroConfig() includes pcr0 field'
  );

  // Test 19: receiptBinding contains receiptHash
  assert(
    awsConfig.receiptBinding.receiptHash === hex64('g'),
    'Test 19: awsNitroConfig() receiptBinding contains receiptHash'
  );

  // ── Test Group 7: kubernetesConfig() ──────────────────────────────────
  console.log('\nTest Group 7: kubernetesConfig()');

  const k8sConfig = ConfidentialRuntime.kubernetesConfig({
    receiptHash: hex64('h'),
    platform:    'intel-tdx',
    namespace:   'authproof-ns',
  });

  const k8sPod = k8sConfig.items.find(i => i.kind === 'Pod');
  const k8sSA  = k8sConfig.items.find(i => i.kind === 'ServiceAccount');
  const k8sCM  = k8sConfig.items.find(i => i.kind === 'ConfigMap');

  // Test 20: manifest spec.nodeSelector contains tdx label
  assert(
    k8sPod !== undefined &&
    Object.keys(k8sPod.spec.nodeSelector).some(k => k.toLowerCase().includes('tdx')),
    'Test 20: kubernetesConfig() manifest includes spec.nodeSelector with TDX label'
  );

  // Test 21: includes ServiceAccount
  assert(
    k8sSA !== undefined && k8sSA.kind === 'ServiceAccount',
    'Test 21: kubernetesConfig() includes ServiceAccount'
  );

  // Test 22: includes ConfigMap with receiptHash
  assert(
    k8sCM !== undefined &&
    k8sCM.data.receiptHash === hex64('h'),
    'Test 22: kubernetesConfig() includes ConfigMap with receiptHash'
  );

  // Test 23: includes attestation sidecar container
  const sidecar = k8sPod?.spec.containers.find(c => c.name === 'attestation-sidecar');
  assert(
    sidecar !== undefined,
    'Test 23: kubernetesConfig() includes attestation sidecar container'
  );

  // ── Test Group 8: TokenPreparer.prepare() ─────────────────────────────
  console.log('\nTest Group 8: TokenPreparer.prepare()');

  const { privateKey: tokenPrivKey, publicJwk: tokenPubJwk } = await AuthProof.generateKey();

  const tokenResult = await TokenPreparer.prepare({
    receiptHash:  hex64('1'),
    scopeHash:    hex64('2'),
    teeQuoteHash: hex64('3'),
    expiresAt:    Date.now() + 3_600_000,
    privateKey:   tokenPrivKey,
  });

  // Test 24: returns token, tokenHash, ebpfMapEntry
  assert(
    'token'        in tokenResult &&
    'tokenHash'    in tokenResult &&
    'ebpfMapEntry' in tokenResult,
    'Test 24: TokenPreparer.prepare() returns token, tokenHash, ebpfMapEntry'
  );

  // Test 25: status === 'PENDING_KERNEL_MODULE'
  assert(
    tokenResult.status === 'PENDING_KERNEL_MODULE',
    "Test 25: TokenPreparer status === 'PENDING_KERNEL_MODULE'"
  );

  // Test 26: tokenHash is a valid hex SHA-256
  assert(
    typeof tokenResult.tokenHash === 'string' &&
    tokenResult.tokenHash.length === 64 &&
    /^[0-9a-f]{64}$/.test(tokenResult.tokenHash),
    'Test 26: tokenHash is a valid hex SHA-256'
  );

  // Test 27: ebpfMapEntry contains receiptHash and scopeHash
  assert(
    tokenResult.ebpfMapEntry.receiptHash === hex64('1') &&
    tokenResult.ebpfMapEntry.scopeHash   === hex64('2'),
    'Test 27: ebpfMapEntry contains receiptHash and scopeHash'
  );

  // Test 28: token contains valid ECDSA signature
  const { signature: tokenSig, ...tokenBody } = tokenResult.token;
  const sigBytes = new Uint8Array(tokenSig.match(/.{2}/g).map(b => parseInt(b, 16)));
  const msgBytes = new TextEncoder().encode(JSON.stringify(tokenBody));
  const verifyKey = await crypto.subtle.importKey(
    'jwk',
    { ...tokenPubJwk, key_ops: ['verify'] },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  const sigValid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    verifyKey,
    sigBytes,
    msgBytes
  );
  assert(sigValid, 'Test 28: token contains valid ECDSA signature');

  // ── Test Group 9: Edge cases ───────────────────────────────────────────
  console.log('\nTest Group 9: Edge cases');

  // Test 29: TEE measurement mismatch in receipt vs runtime blocks launch
  const { receipt: mismatchReceipt } = await client.delegate({
    scope: 'Mismatch test scope',
    operatorInstructions: 'Mismatch test',
    expiresIn: '1h',
    privateKey,
    publicJwk,
    teeConfig: {
      platform:     'intel-tdx',
      verifierHash: hex64('v'),   // same as our verifierHash var
      modelHash:    hex64('m'),   // same as our modelHash var
    },
  });
  const mismatchRuntime = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier(),
    actionLog: makeMockActionLog(),
  });
  let threw29 = false;
  try {
    await mismatchRuntime.launch({
      receiptHash:          hex64('x'),
      agentFn:              async () => 'never runs',
      operatorInstructions: 'Mismatch test',
      verifierHash:         hex64('z'),   // DIFFERENT — mismatch
      modelHash:            hex64('y'),   // DIFFERENT — mismatch
      teeMeasurement:       mismatchReceipt.teeMeasurement,
    });
  } catch (e) {
    threw29 = e.message.includes('mismatch');
  }
  assert(threw29, 'Test 29: TEE measurement mismatch in receipt vs runtime blocks launch');

  // Test 30: launch() with agentFn that throws still records actionLogEntry
  const mockLog30 = makeMockActionLog();
  const rt30 = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier(),
    actionLog: mockLog30,
  });
  let caughtError30 = false;
  try {
    await rt30.launch({
      receiptHash:          hex64('i'),
      agentFn:              async () => { throw new Error('agent crashed'); },
      operatorInstructions: 'Test',
      verifierHash,
      modelHash,
    });
  } catch {
    caughtError30 = true;
  }
  assert(
    caughtError30 && mockLog30.entries.length === 1,
    'Test 30: launch() with agentFn that throws still records actionLogEntry'
  );

  // Test 31: 'auto' platform defaults to 'intel-tdx' behavior (same mrenclave)
  const rtAuto = new ConfidentialRuntime({
    platform:  'auto',
    verifier:  makeMockVerifier(),
    actionLog: makeMockActionLog(),
  });
  const rtTDX = new ConfidentialRuntime({
    platform:  'intel-tdx',
    verifier:  makeMockVerifier(),
    actionLog: makeMockActionLog(),
  });
  const autoResult = await rtAuto.launch({
    receiptHash:          hex64('j'),
    agentFn:              async () => {},
    operatorInstructions: 'Test',
    verifierHash,
    modelHash,
  });
  const tdxResult = await rtTDX.launch({
    receiptHash:          hex64('k'),
    agentFn:              async () => {},
    operatorInstructions: 'Test',
    verifierHash,
    modelHash,
  });
  assert(
    autoResult.mrenclave === tdxResult.mrenclave,
    "Test 31: 'auto' platform defaults to 'intel-tdx' behavior (same mrenclave)"
  );

  // ── Summary ────────────────────────────────────────────────────────────
  console.log(`\n─────────────────────────────────────────────`);
  console.log(`Total: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);

  if (failed > 0) process.exit(1);
}

run().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

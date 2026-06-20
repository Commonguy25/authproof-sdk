/**
 * Depth-isolation probe -- throwaway investigation script.
 *
 * Builds a chain where every sub-receipt is a valid strict proper subset of
 * its parent scope. If the depth check is the only thing that fires, c4
 * (depth 4, exceeds MAX_CHAIN_DEPTH=3) must be denied and c3 (depth 3,
 * exactly at limit) must be permitted.
 *
 * Do not commit this file.
 * Run: node --experimental-global-webcrypto vectors/depth-isolation-probe.js
 */

import { webcrypto } from 'node:crypto';
if (typeof globalThis.crypto === 'undefined') globalThis.crypto = webcrypto;

import AuthProof, {
  createSubReceipt,
  RevocationRegistry,
} from '../src/authproof.js';

import {
  PreExecutionVerifier,
  DelegationLog,
  MAX_CHAIN_DEPTH,
} from '../src/pre-execution-verifier.js';

async function makeVerifier(maxChainDepth) {
  const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
  const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });
  const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry, maxChainDepth });
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });
  return { verifier, delegationLog };
}

async function main() {
  console.log('Depth-isolation probe\n');
  console.log('MAX_CHAIN_DEPTH exported constant:', MAX_CHAIN_DEPTH);
  console.log('');

  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const INSTRUCTIONS = 'Read email only. Do not modify records.';

  // Root scope: 5 distinct read actions, no denied actions.
  // Each level strips exactly one action -- always a valid strict proper subset.
  const rootScope = {
    version: '1.0',
    allowedActions: [
      { operation: 'read', resource: 'alpha' },
      { operation: 'read', resource: 'beta' },
      { operation: 'read', resource: 'gamma' },
      { operation: 'read', resource: 'delta' },
      { operation: 'read', resource: 'epsilon' },
    ],
    deniedActions: [],
  };

  const { receipt: root, receiptId: rootId } = await AuthProof.create({
    scope:        'probe root scope',
    boundaries:   'none',
    instructions: INSTRUCTIONS,
    ttlHours:     24,
    privateKey,
    publicJwk,
  });

  const now    = new Date();
  const farEnd = new Date(now.getTime() + 23 * 3_600_000);

  // Attach structured scope for createSubReceipt attenuation check.
  // Stripped before storing in DelegationLog.
  root.scopeSchema = rootScope;

  // c1 = depth 1, 4 allowed actions (removes epsilon)
  const c1Scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 4), deniedActions: [] };
  const { receipt: c1, receiptId: c1Id } = await createSubReceipt({
    parentReceipt: root, parentReceiptId: rootId, parentPrivateKey: privateKey,
    scope: c1Scope,
    timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
    boundaries: 'none', instructions: INSTRUCTIONS,
  });

  // c2 = depth 2, 3 allowed actions (removes delta)
  const c2Scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 3), deniedActions: [] };
  const { receipt: c2, receiptId: c2Id } = await createSubReceipt({
    parentReceipt: c1, parentReceiptId: c1Id, parentPrivateKey: privateKey,
    scope: c2Scope,
    timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
    boundaries: 'none', instructions: INSTRUCTIONS,
  });

  // c3 = depth 3, 2 allowed actions (removes gamma) -- AT the limit
  const c3Scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 2), deniedActions: [] };
  const { receipt: c3, receiptId: c3Id } = await createSubReceipt({
    parentReceipt: c2, parentReceiptId: c2Id, parentPrivateKey: privateKey,
    scope: c3Scope,
    timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
    boundaries: 'none', instructions: INSTRUCTIONS,
  });

  // c4 = depth 4, 1 allowed action (removes beta) -- EXCEEDS limit
  const c4Scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 1), deniedActions: [] };
  const { receipt: c4, receiptId: c4Id } = await createSubReceipt({
    parentReceipt: c3, parentReceiptId: c3Id, parentPrivateKey: privateKey,
    scope: c4Scope,
    timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
    boundaries: 'none', instructions: INSTRUCTIONS,
  });

  console.log('Chain built:');
  console.log('  root (depth 0): 5 allowed actions');
  console.log('  c1   (depth 1): 4 allowed actions -- valid subset of root');
  console.log('  c2   (depth 2): 3 allowed actions -- valid subset of c1');
  console.log('  c3   (depth 3): 2 allowed actions -- valid subset of c2, AT limit');
  console.log('  c4   (depth 4): 1 allowed action  -- valid subset of c3, EXCEEDS limit');
  console.log('');

  // Register all receipts.
  // Root gets its structured scope via log metadata (not on the signed receipt body).
  const rootForLog = { ...root };
  delete rootForLog.scopeSchema;

  // --- Test A: verify c3 (depth 3, exactly at MAX_CHAIN_DEPTH) ---
  {
    const { verifier, delegationLog } = await makeVerifier(MAX_CHAIN_DEPTH);
    delegationLog.add(rootId, rootForLog, { scopeSchema: { fromJSON: undefined, ...rootScope } });
    delegationLog.add(c1Id,  c1);
    delegationLog.add(c2Id,  c2);
    delegationLog.add(c3Id,  c3);

    const result = await verifier.check({
      receiptHash:          c3Id,
      action:               { operation: 'read', resource: 'alpha' },
      operatorInstructions: INSTRUCTIONS,
    });

    console.log('Test A: c3 at depth 3 (exactly AT limit)');
    console.log('  allowed         :', result.allowed);
    console.log('  blockedReason   :', result.blockedReason);
    console.log('  parentScopeContainment:', result.checks.parentScopeContainment);
    console.log('  expected: allowed=true');
    console.log('  PASS?', result.allowed === true ? 'PASS' : 'FAIL');
    console.log('');
  }

  // --- Test B: verify c4 (depth 4, exceeds MAX_CHAIN_DEPTH) ---
  // c4->c3 scope IS a valid subset. Denial must come from the depth check only.
  {
    const { verifier, delegationLog } = await makeVerifier(MAX_CHAIN_DEPTH);
    delegationLog.add(rootId, rootForLog, { scopeSchema: { fromJSON: undefined, ...rootScope } });
    delegationLog.add(c1Id,  c1);
    delegationLog.add(c2Id,  c2);
    delegationLog.add(c3Id,  c3);
    delegationLog.add(c4Id,  c4);

    const result = await verifier.check({
      receiptHash:          c4Id,
      action:               { operation: 'read', resource: 'alpha' },
      operatorInstructions: INSTRUCTIONS,
    });

    console.log('Test B: c4 at depth 4 (EXCEEDS limit by 1)');
    console.log('  allowed         :', result.allowed);
    console.log('  blockedReason   :', result.blockedReason);
    console.log('  parentScopeContainment:', result.checks.parentScopeContainment);
    console.log('  c4->c3 scope relationship: c4=[alpha] c3=[alpha,beta] -- c4 IS a proper subset');
    console.log('  If denial is from DEPTH check, code must be PARENT_SCOPE_VIOLATION (same constant)');
    console.log('  expected: allowed=false, blockedReason=PARENT_SCOPE_VIOLATION');
    console.log('  PASS?', result.allowed === false && result.blockedReason === 'PARENT_SCOPE_VIOLATION' ? 'PASS' : 'FAIL');
    console.log('');
  }

  // --- Test C: verify c4 with a scope that also violates parent scope ---
  // This distinguishes: when BOTH depth and scope are bad, which fires first?
  // Expected: depth check fires first (it appears before scope attenuation in the code).
  {
    // Build a fresh chain. Capture timeWindow start AFTER creating root2 so the
    // child start is not before the parent start (which would throw from createSubReceipt).
    const { privateKey: pk2, publicJwk: pub2 } = await AuthProof.generateKey();

    const root2 = await AuthProof.create({
      scope: 'probe2 root', boundaries: 'none', instructions: INSTRUCTIONS,
      ttlHours: 24, privateKey: pk2, publicJwk: pub2,
    });
    root2.receipt.scopeSchema = rootScope;

    // Use root2's own timeWindow so child start is not before parent start.
    const chainStart = new Date(root2.receipt.timeWindow.start);
    const chainEnd   = new Date(root2.receipt.timeWindow.end);
    // Shrink end slightly so each child is strictly within parent.
    const chainEndMinus = new Date(chainEnd.getTime() - 60_000); // minus 1 minute

    const c1b_scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 4), deniedActions: [] };
    const c1b = await createSubReceipt({
      parentReceipt: root2.receipt, parentReceiptId: root2.receiptId, parentPrivateKey: pk2,
      scope: c1b_scope, timeWindow: { start: chainStart.toISOString(), end: chainEndMinus.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const c2b_scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 3), deniedActions: [] };
    const c2b = await createSubReceipt({
      parentReceipt: c1b.receipt, parentReceiptId: c1b.receiptId, parentPrivateKey: pk2,
      scope: c2b_scope, timeWindow: { start: chainStart.toISOString(), end: chainEndMinus.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const c3b_scope = { version: '1.0', allowedActions: rootScope.allowedActions.slice(0, 2), deniedActions: [] };
    const c3b = await createSubReceipt({
      parentReceipt: c2b.receipt, parentReceiptId: c2b.receiptId, parentPrivateKey: pk2,
      scope: c3b_scope, timeWindow: { start: chainStart.toISOString(), end: chainEndMinus.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    // c4b: hand-craft a receipt at depth 4 that ALSO claims gamma (illegal against c3b which only has alpha,beta)
    const badScope4 = {
      version: '1.0',
      allowedActions: [
        { operation: 'read', resource: 'alpha' },
        { operation: 'read', resource: 'gamma' }, // not in c3b -- scope violation!
      ],
      deniedActions: [],
    };

    // We need to manually sign since createSubReceipt would throw on scope check
    async function sha256hex(str) {
      const buf = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    async function signEcdsa(key, str) {
      const sig = await globalThis.crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(str)
      );
      return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    const body4b = {
      delegationId:         'probe-depth-and-scope-' + Date.now(),
      issuedAt:             now.toISOString(),
      scopeSchema:          badScope4,
      boundaries:           'none',
      timeWindow:           { start: now.toISOString(), end: farEnd.toISOString() },
      operatorInstructions: INSTRUCTIONS,
      instructionsHash:     await AuthProof.Canonicalizer.hash(INSTRUCTIONS),
      signerPublicKey:      pub2,
      parentReceiptId:      c3b.receiptId,
    };
    const sig4b       = await signEcdsa(pk2, JSON.stringify(body4b));
    const rec4b       = { ...body4b, signature: sig4b };
    const id4b        = await sha256hex(JSON.stringify(rec4b));
    const orchSig4b   = await signEcdsa(pk2, `orchestrator-delegation:${c3b.receiptId}:${id4b}`);
    rec4b.orchestratorSignature = orchSig4b;

    const { verifier, delegationLog } = await makeVerifier(MAX_CHAIN_DEPTH);
    const root2ForLog = { ...root2.receipt };
    delete root2ForLog.scopeSchema;
    delegationLog.add(root2.receiptId, root2ForLog, { scopeSchema: rootScope });
    delegationLog.add(c1b.receiptId,   c1b.receipt);
    delegationLog.add(c2b.receiptId,   c2b.receipt);
    delegationLog.add(c3b.receiptId,   c3b.receipt);
    delegationLog.add(id4b, rec4b);

    const result = await verifier.check({
      receiptHash:          id4b,
      action:               { operation: 'read', resource: 'alpha' },
      operatorInstructions: INSTRUCTIONS,
    });

    console.log('Test C: c4b at depth 4 AND with invalid scope (gamma not in c3b)');
    console.log('  allowed       :', result.allowed);
    console.log('  blockedReason :', result.blockedReason);
    console.log('  Both depth check (fires at line 673) and scope check (fires at line 748) would deny.');
    console.log('  Depth check runs FIRST in the code. If blockedReason is PARENT_SCOPE_VIOLATION,');
    console.log('  we cannot distinguish from this result alone which fired. But Test B already');
    console.log('  isolated that depth alone produces PARENT_SCOPE_VIOLATION.');
    console.log('  expected: allowed=false, blockedReason=PARENT_SCOPE_VIOLATION (from depth, not scope)');
    console.log('');
  }

  console.log('=== Source-code ordering summary ===');
  console.log('Line 663-671: while loop counts depth');
  console.log('Line 673-682: if (depth > maxChainDepth) -> PARENT_SCOPE_VIOLATION (EARLY RETURN)');
  console.log('Line 747-763: checkScopeAttenuation (only reached if depth is within limit)');
  console.log('');
  console.log('Conclusion: the depth check fires BEFORE the scope attenuation check.');
  console.log('Both use PARENT_SCOPE_VIOLATION. No distinct depth code exists.');
}

main().catch(err => {
  console.error('Probe error:', err);
  process.exit(1);
});

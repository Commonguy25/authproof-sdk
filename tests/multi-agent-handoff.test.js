/**
 * Multi-Agent Delegation Handoff — Tests
 *
 * Covers createSubReceipt (authproof.js) and Check 14 (PreExecutionVerifier).
 *
 * Run: node --experimental-global-webcrypto tests/multi-agent-handoff.test.js
 */

import AuthProof, {
  createSubReceipt,
  RevocationRegistry,
  ScopeSchema,
  ScopeAttenuationError,
} from '../src/authproof.js';
import { PreExecutionVerifier, DelegationLog, MAX_CHAIN_DEPTH, CHAIN_DEPTH_EXCEEDED } from '../src/pre-execution-verifier.js';

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

const PARENT_SCOPE = {
  allowedActions: [
    { operation: 'read',  resource: 'email' },
    { operation: 'read',  resource: 'calendar' },
    { operation: 'write', resource: 'calendar' },
  ],
  deniedActions: [
    { operation: 'delete', resource: '*' },
  ],
};

const CHILD_SCOPE = {
  allowedActions: [
    { operation: 'read', resource: 'email' },
  ],
  deniedActions: [
    { operation: 'delete', resource: '*' },
  ],
};

const INSTRUCTIONS = 'Read email only. Do not modify records.';
const BOUNDARIES   = 'Do not send emails. Do not delete anything.';

// crypto sign helper (mirrors authproof.js _sign)
async function _sign(key, str) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(str)
  );
  return Array.from(new Uint8Array(sig)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(x => x.toString(16).padStart(2, '0')).join('');
}

async function makeParentReceipt(privateKey, publicJwk, ttlHours = 2) {
  // The parent receipt is a plain create() receipt (text scope).
  // The structured scope (PARENT_SCOPE) is supplied to the DelegationLog as
  // metadata so it is NOT part of the signed receipt body and does not break
  // Check 14's parent-signature verification.
  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Manage email and calendar',
    boundaries:   BOUNDARIES,
    instructions: INSTRUCTIONS,
    ttlHours,
    privateKey,
    publicJwk,
  });
  return { receipt, receiptId };
}

async function makeVerifier(offlineMode = false) {
  const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });
  const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry, offlineMode });
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });
  return { verifier, delegationLog, revocationRegistry };
}

// ─────────────────────────────────────────────
// TEST SUITE
// ─────────────────────────────────────────────

async function run() {
  console.log('Multi-Agent Delegation Handoff — Test Suite\n');

  const { privateKey: orchKey, publicJwk: orchPub } = await AuthProof.generateKey();

  // ── 1. createSubReceipt produces a valid sub-receipt ──────────────────
  console.log('createSubReceipt — basic output');
  {
    const { receipt: parent, receiptId: parentId } = await makeParentReceipt(orchKey, orchPub);
    parent.scopeSchema = PARENT_SCOPE; // used only as input to createSubReceipt, not stored in log

    const now      = new Date();
    const childEnd = new Date(now.getTime() + 1 * 3_600_000);

    const { receipt, receiptId } = await createSubReceipt({
      parentReceipt:    parent,
      parentReceiptId:  parentId,
      parentPrivateKey: orchKey,
      scope:            CHILD_SCOPE,
      timeWindow:       { start: now.toISOString(), end: childEnd.toISOString() },
      boundaries:       BOUNDARIES,
      instructions:     INSTRUCTIONS,
    });

    assert(typeof receiptId === 'string' && receiptId.length === 64,
      'receiptId is a 64-char hex string');
    assert(receipt.parentReceiptId === parentId,
      'receipt.parentReceiptId matches the parent receipt id');
    assert(typeof receipt.orchestratorSignature === 'string' && receipt.orchestratorSignature.length > 0,
      'receipt.orchestratorSignature is present and non-empty');
    assert(receipt.signature !== receipt.orchestratorSignature,
      'orchestratorSignature differs from main signature');
    assert(receipt.scopeSchema === CHILD_SCOPE,
      'receipt.scopeSchema is the child scope');
  }

  // ── 2. Verifier PERMITs a valid sub-receipt with proper subset scope ──
  console.log('\nCheck 14 — PERMIT valid sub-receipt');
  {
    const { receipt: parent, receiptId: parentId } = await makeParentReceipt(orchKey, orchPub);
    // Provide structured parent scope via log metadata so the parent receipt
    // body is not mutated (which would break signature verification in Check 14).
    parent.scopeSchema = PARENT_SCOPE; // only used as input to createSubReceipt below

    const now      = new Date();
    const childEnd = new Date(now.getTime() + 1 * 3_600_000);

    const { receipt: child, receiptId: childId } = await createSubReceipt({
      parentReceipt:    parent,
      parentReceiptId:  parentId,
      parentPrivateKey: orchKey,
      scope:            CHILD_SCOPE,
      timeWindow:       { start: now.toISOString(), end: childEnd.toISOString() },
      boundaries:       BOUNDARIES,
      instructions:     INSTRUCTIONS,
    });

    // Store parent WITHOUT scopeSchema on the receipt object, but supply it as
    // DelegationLog metadata. This keeps the signed receipt body intact and lets
    // Check 14 find the parent scope via the log entry.
    const parentForLog = { ...parent };
    delete parentForLog.scopeSchema;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(parentId, parentForLog, { scopeSchema: PARENT_SCOPE });
    delegationLog.add(childId,  child);

    const result = await verifier.check({
      receiptHash:          childId,
      action:               { operation: 'read', resource: 'email' },
      operatorInstructions: INSTRUCTIONS,
    });

    assert(result.allowed === true, `result.allowed is true (blockedReason: ${result.blockedReason})`);
    assert(result.checks.parentScopeContainment === true,
      'checks.parentScopeContainment passed');
  }

  // ── 3. Verifier DENYs a sub-receipt whose scope exceeds the parent ────
  console.log('\nCheck 14 — DENY scope exceeds parent (PARENT_SCOPE_VIOLATION)');
  {
    const { receipt: parent, receiptId: parentId } = await AuthProof.create({
      scope: 'Manage email', boundaries: BOUNDARIES, instructions: INSTRUCTIONS,
      ttlHours: 2, privateKey: orchKey, publicJwk: orchPub,
    });

    const now      = new Date();
    const childEnd = new Date(now.getTime() + 1 * 3_600_000);

    // Manually craft a sub-receipt with a scope that is NOT a subset of parent
    // (contains 'send' which parent PARENT_SCOPE doesn't allow).
    const badScope = {
      allowedActions: [
        { operation: 'read', resource: 'email' },
        { operation: 'send', resource: 'email' }, // NOT in PARENT_SCOPE
      ],
      deniedActions: [{ operation: 'delete', resource: '*' }],
    };

    const childInstructions = INSTRUCTIONS;
    const childNow = new Date();
    const childEnd2 = new Date(childNow.getTime() + 1 * 3_600_000);
    const childBody = {
      delegationId:         'auth-test-bad-scope',
      issuedAt:             childNow.toISOString(),
      scopeSchema:          badScope,
      boundaries:           BOUNDARIES,
      timeWindow:           { start: childNow.toISOString(), end: childEnd2.toISOString() },
      operatorInstructions: childInstructions,
      instructionsHash:     await AuthProof.Canonicalizer.hash(childInstructions),
      signerPublicKey:      orchPub,
      parentReceiptId:      parentId,
    };
    const childSig  = await _sign(orchKey, JSON.stringify(childBody));
    const childReceipt = { ...childBody, signature: childSig };
    const childId   = await sha256hex(JSON.stringify(childReceipt));
    const orchSig   = await _sign(orchKey, `orchestrator-delegation:${parentId}:${childId}`);
    childReceipt.orchestratorSignature = orchSig;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(parentId, parent, { scopeSchema: PARENT_SCOPE });
    delegationLog.add(childId,  childReceipt);

    const result = await verifier.check({
      receiptHash:          childId,
      action:               { operation: 'read', resource: 'email' },
      operatorInstructions: childInstructions,
    });

    assert(result.allowed === false, 'result.allowed is false');
    assert(
      result.blockedReason === 'PARENT_SCOPE_VIOLATION' ||
      result.blockedReason === 'SCOPE_NOT_STRICT_SUBSET',
      `blockedReason is a scope violation (got: ${result.blockedReason})`
    );
  }

  // ── 4. Verifier DENYs a sub-receipt with time window outside parent ───
  console.log('\nCheck 14 — DENY time window outside parent (PARENT_SCOPE_VIOLATION)');
  {
    const { receipt: parent, receiptId: parentId } = await makeParentReceipt(orchKey, orchPub);
    parent.scopeSchema = PARENT_SCOPE;

    const now       = new Date();
    const farFuture = new Date(now.getTime() + 99 * 3_600_000); // beyond parent's 2h window

    let threw = false;
    try {
      await createSubReceipt({
        parentReceipt:    parent,
        parentReceiptId:  parentId,
        parentPrivateKey: orchKey,
        scope:            CHILD_SCOPE,
        timeWindow:       { start: now.toISOString(), end: farFuture.toISOString() },
        boundaries:       BOUNDARIES,
        instructions:     INSTRUCTIONS,
      });
    } catch (e) {
      threw = true;
      assert(e.message.includes('time window'),
        `createSubReceipt throws with time-window message: ${e.message}`);
    }
    assert(threw, 'createSubReceipt throws when child time window exceeds parent');

    // Also verify the verifier denies a tampered receipt that bypassed createSubReceipt
    const { receipt: parent2, receiptId: parent2Id } = await AuthProof.create({
      scope: 'email', boundaries: BOUNDARIES, instructions: INSTRUCTIONS,
      ttlHours: 2, privateKey: orchKey, publicJwk: orchPub,
    });

    const badTimeBody = {
      delegationId: 'bad-time', issuedAt: now.toISOString(),
      scopeSchema: CHILD_SCOPE, boundaries: BOUNDARIES,
      timeWindow: { start: now.toISOString(), end: farFuture.toISOString() },
      operatorInstructions: INSTRUCTIONS,
      instructionsHash: await AuthProof.Canonicalizer.hash(INSTRUCTIONS),
      signerPublicKey: orchPub, parentReceiptId: parent2Id,
    };
    const btSig     = await _sign(orchKey, JSON.stringify(badTimeBody));
    const btReceipt = { ...badTimeBody, signature: btSig };
    const btId      = await sha256hex(JSON.stringify(btReceipt));
    const btOrch    = await _sign(orchKey, `orchestrator-delegation:${parent2Id}:${btId}`);
    btReceipt.orchestratorSignature = btOrch;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(parent2Id, parent2, { scopeSchema: PARENT_SCOPE });
    delegationLog.add(btId, btReceipt);

    const result = await verifier.check({
      receiptHash:          btId,
      action:               { operation: 'read', resource: 'email' },
      operatorInstructions: INSTRUCTIONS,
    });
    assert(result.allowed === false,
      'verifier denies sub-receipt with time window outside parent');
    assert(result.blockedReason === 'PARENT_SCOPE_VIOLATION',
      `blockedReason is PARENT_SCOPE_VIOLATION (got: ${result.blockedReason})`);
  }

  // ── 5. Verifier DENYs a sub-receipt with invalid orchestratorSignature ─
  console.log('\nCheck 14 — DENY invalid orchestratorSignature (PARENT_SCOPE_VIOLATION)');
  {
    const { receipt: parent, receiptId: parentId } = await makeParentReceipt(orchKey, orchPub);
    parent.scopeSchema = PARENT_SCOPE;

    const now      = new Date();
    const childEnd = new Date(now.getTime() + 1 * 3_600_000);

    const { receipt: child, receiptId: childId } = await createSubReceipt({
      parentReceipt:    parent,
      parentReceiptId:  parentId,
      parentPrivateKey: orchKey,
      scope:            CHILD_SCOPE,
      timeWindow:       { start: now.toISOString(), end: childEnd.toISOString() },
      boundaries:       BOUNDARIES,
      instructions:     INSTRUCTIONS,
    });

    // Corrupt the orchestratorSignature by flipping the first byte
    const badOrch       = 'ff' + child.orchestratorSignature.slice(2);
    const tamperedChild = { ...child, orchestratorSignature: badOrch };

    const parentForLog = { ...parent };
    delete parentForLog.scopeSchema;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(parentId,  parentForLog, { scopeSchema: PARENT_SCOPE });
    delegationLog.add(childId,   tamperedChild);

    const result = await verifier.check({
      receiptHash:          childId,
      action:               { operation: 'read', resource: 'email' },
      operatorInstructions: INSTRUCTIONS,
    });

    assert(result.allowed === false, 'result.allowed is false');
    assert(result.blockedReason === 'PARENT_SCOPE_VIOLATION',
      `blockedReason is PARENT_SCOPE_VIOLATION (got: ${result.blockedReason})`);
  }

  // ── 6. Verifier DENYs a chain that exceeds MAX_CHAIN_DEPTH (3) ────────
  console.log('\nCheck 14 — DENY chain depth > 3 (CHAIN_DEPTH_EXCEEDED)');
  {
    // Chain: root (depth 0) -> c1 (1) -> c2 (2) -> c3 (3) -> c4 (4)
    // c4 is at depth 4, which exceeds MAX_CHAIN_DEPTH = 3 and must be denied.
    const rootScope = {
      allowedActions: [
        { operation: 'read', resource: 'a' },
        { operation: 'read', resource: 'b' },
        { operation: 'read', resource: 'c' },
        { operation: 'read', resource: 'd' },
        { operation: 'read', resource: 'e' },
      ],
      deniedActions: [],
    };

    const { receipt: root, receiptId: rootId } = await AuthProof.create({
      scope: 'root', boundaries: 'none', instructions: INSTRUCTIONS,
      ttlHours: 10, privateKey: orchKey, publicJwk: orchPub,
    });
    // rootScope is supplied via log metadata, not mutated on the receipt object.

    const now    = new Date();
    const farEnd = new Date(now.getTime() + 9 * 3_600_000);

    // Temporarily set scopeSchema on root so createSubReceipt can validate attenuation.
    // We strip it again before adding to the log.
    root.scopeSchema = rootScope;

    const { receipt: c1, receiptId: c1Id } = await createSubReceipt({
      parentReceipt: root, parentReceiptId: rootId, parentPrivateKey: orchKey,
      scope: { allowedActions: rootScope.allowedActions.slice(0, 4), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const { receipt: c2, receiptId: c2Id } = await createSubReceipt({
      parentReceipt: c1, parentReceiptId: c1Id, parentPrivateKey: orchKey,
      scope: { allowedActions: rootScope.allowedActions.slice(0, 3), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const { receipt: c3, receiptId: c3Id } = await createSubReceipt({
      parentReceipt: c2, parentReceiptId: c2Id, parentPrivateKey: orchKey,
      scope: { allowedActions: rootScope.allowedActions.slice(0, 2), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const { receipt: c4, receiptId: c4Id } = await createSubReceipt({
      parentReceipt: c3, parentReceiptId: c3Id, parentPrivateKey: orchKey,
      scope: { allowedActions: rootScope.allowedActions.slice(0, 1), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const rootForLog = { ...root };
    delete rootForLog.scopeSchema;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(rootId, rootForLog, { scopeSchema: rootScope });
    delegationLog.add(c1Id,   c1);
    delegationLog.add(c2Id,   c2);
    delegationLog.add(c3Id,   c3);
    delegationLog.add(c4Id,   c4);

    const result = await verifier.check({
      receiptHash:          c4Id,
      action:               { operation: 'read', resource: 'a' },
      operatorInstructions: INSTRUCTIONS,
    });

    assert(result.allowed === false, 'depth-4 chain denied');
    assert(result.blockedReason === CHAIN_DEPTH_EXCEEDED,
      `blockedReason is CHAIN_DEPTH_EXCEEDED (got: ${result.blockedReason})`);
  }

  // ── 7. Non-sub-receipt: Check 14 does not run, receipt is PERMITTED ───
  console.log('\nCheck 14 — non-sub-receipt passes without Check 14');
  {
    const { receipt, receiptId } = await AuthProof.create({
      scope: 'Read calendar', boundaries: BOUNDARIES, instructions: INSTRUCTIONS,
      ttlHours: 2, privateKey: orchKey, publicJwk: orchPub,
    });

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(receiptId, receipt);

    const result = await verifier.check({
      receiptHash:          receiptId,
      action:               'Read calendar',
      operatorInstructions: INSTRUCTIONS,
    });

    assert(result.checks.parentScopeContainment === undefined,
      'parentScopeContainment check key absent for root receipt');
    assert(result.allowed === true, 'root receipt is permitted');
  }

  // ── 8. Offline mode: Check 14 still runs when parent is in log ────────
  console.log('\nCheck 14 — runs in offline mode (parent supplied locally)');
  {
    const { receipt: parent, receiptId: parentId } = await makeParentReceipt(orchKey, orchPub);
    parent.scopeSchema = PARENT_SCOPE;

    const now      = new Date();
    const childEnd = new Date(now.getTime() + 1 * 3_600_000);

    const { receipt: child, receiptId: childId } = await createSubReceipt({
      parentReceipt:    parent,
      parentReceiptId:  parentId,
      parentPrivateKey: orchKey,
      scope:            CHILD_SCOPE,
      timeWindow:       { start: now.toISOString(), end: childEnd.toISOString() },
      boundaries:       BOUNDARIES,
      instructions:     INSTRUCTIONS,
    });

    const parentForLog = { ...parent };
    delete parentForLog.scopeSchema;

    const { verifier, delegationLog } = await makeVerifier(/* offlineMode */ true);
    delegationLog.add(parentId, parentForLog, { scopeSchema: PARENT_SCOPE });
    delegationLog.add(childId,  child);

    const result = await verifier.check({
      receiptHash:          childId,
      action:               { operation: 'read', resource: 'email' },
      operatorInstructions: INSTRUCTIONS,
    });

    assert(result.verificationMode === 'offline', 'verifier is in offline mode');
    assert(result.allowed === true,
      `sub-receipt permitted in offline mode when parent is in log (blockedReason: ${result.blockedReason})`);
    assert(result.checks.parentScopeContainment === true,
      'Check 14 ran and passed in offline mode');
  }

  // ── 9. Non-default maxChainDepth: verifier with maxChainDepth:1 denies depth-2 chain
  console.log('\nCheck 14 — configurable maxChainDepth: depth-2 chain denied when maxChainDepth=1');
  {
    assert(MAX_CHAIN_DEPTH === 3, 'exported MAX_CHAIN_DEPTH constant equals 3');

    const rootScope = {
      allowedActions: [
        { operation: 'read', resource: 'x' },
        { operation: 'read', resource: 'y' },
        { operation: 'read', resource: 'z' },
      ],
      deniedActions: [],
    };

    const { receipt: root, receiptId: rootId } = await AuthProof.create({
      scope: 'root', boundaries: 'none', instructions: INSTRUCTIONS,
      ttlHours: 4, privateKey: orchKey, publicJwk: orchPub,
    });

    const now    = new Date();
    const farEnd = new Date(now.getTime() + 3 * 3_600_000);

    root.scopeSchema = rootScope;

    const { receipt: c1, receiptId: c1Id } = await createSubReceipt({
      parentReceipt: root, parentReceiptId: rootId, parentPrivateKey: orchKey,
      scope: { allowedActions: rootScope.allowedActions.slice(0, 2), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const { receipt: c2, receiptId: c2Id } = await createSubReceipt({
      parentReceipt: c1, parentReceiptId: c1Id, parentPrivateKey: orchKey,
      scope: { allowedActions: rootScope.allowedActions.slice(0, 1), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const rootForLog = { ...root };
    delete rootForLog.scopeSchema;

    // Build a verifier with maxChainDepth: 1 — depth-2 receipts must be denied.
    const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
    const delegationLog      = new DelegationLog();
    const revocationRegistry = new RevocationRegistry();
    const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
    await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });
    const strictVerifier = new PreExecutionVerifier({
      delegationLog, revocationRegistry, maxChainDepth: 1,
    });
    await strictVerifier.init({ privateKey: vPriv, publicJwk: vPub });

    delegationLog.add(rootId, rootForLog, { scopeSchema: rootScope });
    delegationLog.add(c1Id,   c1);
    delegationLog.add(c2Id,   c2);

    // c1 is at depth 1 — exactly at the limit, should be permitted
    const r1 = await strictVerifier.check({
      receiptHash:          c1Id,
      action:               { operation: 'read', resource: 'x' },
      operatorInstructions: INSTRUCTIONS,
    });
    assert(r1.allowed === true,
      `depth-1 receipt permitted with maxChainDepth=1 (blockedReason: ${r1.blockedReason})`);

    // c2 is at depth 2 — exceeds maxChainDepth=1, must be denied
    const r2 = await strictVerifier.check({
      receiptHash:          c2Id,
      action:               { operation: 'read', resource: 'x' },
      operatorInstructions: INSTRUCTIONS,
    });
    assert(r2.allowed === false, 'depth-2 receipt denied with maxChainDepth=1');
    assert(r2.blockedReason === CHAIN_DEPTH_EXCEEDED,
      `blockedReason is CHAIN_DEPTH_EXCEEDED (got: ${r2.blockedReason})`);
  }

  // ── 10. CHAIN_DEPTH_EXCEEDED is distinct from PARENT_SCOPE_VIOLATION ──
  // Test A: over-deep chain where every level is a valid strict proper subset.
  // The only possible denial cause is chain depth. Confirms CHAIN_DEPTH_EXCEEDED
  // is returned and PARENT_SCOPE_VIOLATION is NOT returned.
  console.log('\nCheck 14 — CHAIN_DEPTH_EXCEEDED vs PARENT_SCOPE_VIOLATION: distinct failure classes');
  {
    const depthScope = {
      allowedActions: [
        { operation: 'read', resource: 'p' },
        { operation: 'read', resource: 'q' },
        { operation: 'read', resource: 'r' },
        { operation: 'read', resource: 's' },
        { operation: 'read', resource: 't' },
      ],
      deniedActions: [],
    };

    const { receipt: dRoot, receiptId: dRootId } = await AuthProof.create({
      scope: 'depth-test root', boundaries: 'none', instructions: INSTRUCTIONS,
      ttlHours: 10, privateKey: orchKey, publicJwk: orchPub,
    });

    const now    = new Date();
    const farEnd = new Date(now.getTime() + 9 * 3_600_000);

    dRoot.scopeSchema = depthScope;

    const { receipt: d1, receiptId: d1Id } = await createSubReceipt({
      parentReceipt: dRoot, parentReceiptId: dRootId, parentPrivateKey: orchKey,
      scope: { allowedActions: depthScope.allowedActions.slice(0, 4), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });
    const { receipt: d2, receiptId: d2Id } = await createSubReceipt({
      parentReceipt: d1, parentReceiptId: d1Id, parentPrivateKey: orchKey,
      scope: { allowedActions: depthScope.allowedActions.slice(0, 3), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });
    const { receipt: d3, receiptId: d3Id } = await createSubReceipt({
      parentReceipt: d2, parentReceiptId: d2Id, parentPrivateKey: orchKey,
      scope: { allowedActions: depthScope.allowedActions.slice(0, 2), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });
    const { receipt: d4, receiptId: d4Id } = await createSubReceipt({
      parentReceipt: d3, parentReceiptId: d3Id, parentPrivateKey: orchKey,
      scope: { allowedActions: depthScope.allowedActions.slice(0, 1), deniedActions: [] },
      timeWindow: { start: now.toISOString(), end: farEnd.toISOString() },
      boundaries: 'none', instructions: INSTRUCTIONS,
    });

    const dRootForLog = { ...dRoot };
    delete dRootForLog.scopeSchema;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(dRootId, dRootForLog, { scopeSchema: depthScope });
    delegationLog.add(d1Id, d1);
    delegationLog.add(d2Id, d2);
    delegationLog.add(d3Id, d3);
    delegationLog.add(d4Id, d4);

    const resultA = await verifier.check({
      receiptHash:          d4Id,
      action:               { operation: 'read', resource: 'p' },
      operatorInstructions: INSTRUCTIONS,
    });

    assert(resultA.allowed === false,
      'Test A: over-deep scope-valid chain is denied');
    assert(resultA.blockedReason === CHAIN_DEPTH_EXCEEDED,
      `Test A: blockedReason is CHAIN_DEPTH_EXCEEDED (got: ${resultA.blockedReason})`);
    assert(resultA.blockedReason !== 'PARENT_SCOPE_VIOLATION',
      'Test A: blockedReason is NOT PARENT_SCOPE_VIOLATION');
  }

  // Test B: scope-violating chain that is within the depth limit.
  // Depth 1, but child scope adds an action not in parent.
  // Confirms PARENT_SCOPE_VIOLATION is returned and CHAIN_DEPTH_EXCEEDED is NOT.
  {
    const { receipt: bParent, receiptId: bParentId } = await AuthProof.create({
      scope: 'scope-test parent', boundaries: 'none', instructions: INSTRUCTIONS,
      ttlHours: 2, privateKey: orchKey, publicJwk: orchPub,
    });

    const now    = new Date();
    const bEnd   = new Date(now.getTime() + 1 * 3_600_000);

    const illegalScope = {
      allowedActions: [
        { operation: 'read',  resource: 'email' },
        { operation: 'write', resource: 'files' }, // not in PARENT_SCOPE
      ],
      deniedActions: [{ operation: 'delete', resource: '*' }],
    };

    const bBody = {
      delegationId:         'test-b-scope-violation',
      issuedAt:             now.toISOString(),
      scopeSchema:          illegalScope,
      boundaries:           'none',
      timeWindow:           { start: now.toISOString(), end: bEnd.toISOString() },
      operatorInstructions: INSTRUCTIONS,
      instructionsHash:     await AuthProof.Canonicalizer.hash(INSTRUCTIONS),
      signerPublicKey:      orchPub,
      parentReceiptId:      bParentId,
    };
    const bSig     = await _sign(orchKey, JSON.stringify(bBody));
    const bReceipt = { ...bBody, signature: bSig };
    const bId      = await sha256hex(JSON.stringify(bReceipt));
    const bOrch    = await _sign(orchKey, `orchestrator-delegation:${bParentId}:${bId}`);
    bReceipt.orchestratorSignature = bOrch;

    const { verifier, delegationLog } = await makeVerifier();
    delegationLog.add(bParentId, bParent, { scopeSchema: PARENT_SCOPE });
    delegationLog.add(bId, bReceipt);

    const resultB = await verifier.check({
      receiptHash:          bId,
      action:               { operation: 'read', resource: 'email' },
      operatorInstructions: INSTRUCTIONS,
    });

    assert(resultB.allowed === false,
      'Test B: scope-violating within-depth chain is denied');
    assert(
      resultB.blockedReason === 'PARENT_SCOPE_VIOLATION' ||
      resultB.blockedReason === 'SCOPE_NOT_STRICT_SUBSET',
      `Test B: blockedReason is a scope violation code (got: ${resultB.blockedReason})`
    );
    assert(resultB.blockedReason !== CHAIN_DEPTH_EXCEEDED,
      'Test B: blockedReason is NOT CHAIN_DEPTH_EXCEEDED');
  }

  // ─────────────────────────────────────────────
  // SUMMARY
  // ─────────────────────────────────────────────
  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

run().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

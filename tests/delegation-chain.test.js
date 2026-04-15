/**
 * Fix 4 — DelegationChain
 * Run: node --experimental-global-webcrypto tests/delegation-chain.test.js
 *
 * Tests cover:
 *  - Happy path: root → child chain verifies
 *  - Happy path: root → child → grandchild chain verifies
 *  - verify() returns correct depth and scopeAttenuation array
 *  - Strict subset enforcement (equal scope rejected, broader scope rejected)
 *  - Parent denied action preservation in child
 *  - Max depth enforcement (MaxDepthExceededError)
 *  - Cascade revocation: parent → all children
 *  - Cascade revocation: grandparent → all descendants
 *  - Revoking leaf does not affect parent
 *  - verify() fails on revoked receipt in chain
 *  - Root not user-signed → throws
 *  - Root signature invalid → throws
 *  - Child signed with wrong key → verify fails
 *  - Delegation from a revoked parent is blocked
 *  - Revoking non-existent receipt throws
 *  - rootHash getter returns correct hash
 */

import { DelegationChain, ScopeAttenuationError, MaxDepthExceededError } from '../src/delegation-chain.js';
import AuthProof from '../src/authproof.js';

// ─────────────────────────────────────────────
// TEST HARNESS
// ─────────────────────────────────────────────

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

async function assertThrows(fn, errorNameOrMsg, label) {
  try {
    await fn();
    console.error(`  ✗ ${label} (expected throw, got none)`);
    failed++;
  } catch (e) {
    const matches = !errorNameOrMsg ||
      e.name === errorNameOrMsg ||
      e.message.includes(errorNameOrMsg) ||
      (typeof errorNameOrMsg === 'function' && e instanceof errorNameOrMsg);
    if (matches) {
      console.log(`  ✓ ${label}`);
      passed++;
    } else {
      console.error(`  ✗ ${label} (wrong error: ${e.name}: ${e.message})`);
      failed++;
    }
  }
}

// ─────────────────────────────────────────────
// CRYPTO HELPERS (replicate internals for test setup)
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const _fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hex(buf);
}

async function sign(privateKey, str) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, _enc(str));
  return _hex(sig);
}

/**
 * Build a signed root receipt with a structured scopeSchema.
 * Simulates what a user would sign before delegating to an agent.
 */
async function makeRootReceipt(privateKey, publicJwk, scopeSchema) {
  const body = {
    delegationId:    `root-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    issuedAt:        new Date().toISOString(),
    scopeSchema,
    signerPublicKey: publicJwk,
  };
  const signature = await sign(privateKey, JSON.stringify(body));
  return { ...body, signature };
}

// ─────────────────────────────────────────────
// SHARED SCOPE FIXTURES
// ─────────────────────────────────────────────

const ROOT_SCOPE = {
  allowedActions: [
    { operation: 'read',  resource: 'calendar' },
    { operation: 'write', resource: 'calendar' },
    { operation: 'read',  resource: 'email' },
    { operation: 'send',  resource: 'email' },
  ],
  deniedActions: [
    { operation: 'delete', resource: '*' },
  ],
};

// Proper subset of ROOT_SCOPE (2 actions removed, denied preserved)
const CHILD_SCOPE = {
  allowedActions: [
    { operation: 'read',  resource: 'calendar' },
    { operation: 'write', resource: 'calendar' },
  ],
  deniedActions: [
    { operation: 'delete', resource: '*' },
  ],
};

// Proper subset of CHILD_SCOPE (1 action removed)
const GRANDCHILD_SCOPE = {
  allowedActions: [
    { operation: 'read', resource: 'calendar' },
  ],
  deniedActions: [
    { operation: 'delete', resource: '*' },
  ],
};

// ─────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────

async function run() {
  console.log('Fix 4 — DelegationChain\n');

  const { privateKey: userKey, publicJwk: userJwk } = await AuthProof.generateKey();
  const { privateKey: agentAKey, publicJwk: agentAJwk } = await AuthProof.generateKey();
  const { privateKey: agentBKey, publicJwk: agentBJwk } = await AuthProof.generateKey();
  const { privateKey: wrongKey,  publicJwk: wrongJwk  } = await AuthProof.generateKey();

  // ── Test Group 1: Root receipt validation ────────────────────────────
  console.log('Test Group 1: Root receipt validation');

  // Test 1: Root with no signature → throws
  await assertThrows(
    async () => {
      const noSig = { delegationId: 'x', scopeSchema: ROOT_SCOPE, signerPublicKey: userJwk };
      const chain = new DelegationChain({ rootReceipt: noSig });
      await chain.verify('x');
    },
    'missing .signature',
    'root missing signature → throws on first use'
  );

  // Test 2: Root with invalid (tampered) signature → throws
  await assertThrows(
    async () => {
      const rootReceipt = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
      // Tamper the signature
      const tampered = { ...rootReceipt, signature: 'a'.repeat(rootReceipt.signature.length) };
      const chain = new DelegationChain({ rootReceipt: tampered });
      await chain.verify('x');
    },
    'invalid',
    'root with invalid signature → throws on first use'
  );

  // ── Test Group 2: Happy path — root → child ──────────────────────────
  console.log('\nTest Group 2: Happy path — root → child');

  const rootReceipt = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain = new DelegationChain({ rootReceipt });

  // Test 3: rootHash is available after first operation
  const rootHash = await sha256(JSON.stringify(rootReceipt));
  const childReceipt = await chain.delegate({
    parentReceiptHash: rootHash,
    childScope:        CHILD_SCOPE,
    childAgent:        'agent-A',
    privateKey:        agentAKey,
    publicJwk:         agentAJwk,
  });
  assert(typeof chain.rootHash === 'string' && chain.rootHash.length === 64,
    'rootHash getter returns 64-char hex hash');

  // Test 4: delegate() returns hash
  assert(typeof childReceipt.hash === 'string' && childReceipt.hash.length === 64,
    'delegate() returns receipt with .hash');

  // Test 5: delegate() returns depth = 1
  assert(childReceipt.depth === 1, 'child receipt depth is 1');

  // Test 6: delegate() returns parentHash
  assert(childReceipt.parentHash === rootHash, 'child receipt .parentHash matches root hash');

  // Test 7: delegate() returns scope
  assert(childReceipt.scope === CHILD_SCOPE, 'child receipt .scope matches childScope');

  // Test 8: delegate() returns childAgent
  assert(childReceipt.childAgent === 'agent-A', 'child receipt .childAgent matches');

  // Test 9: verify(childHash) → valid
  const childVerify = await chain.verify(childReceipt.hash);
  assert(childVerify.valid === true, 'verify(childHash) returns valid: true');

  // Test 10: verify(childHash) depth is 1
  assert(childVerify.depth === 1, 'verify(childHash) returns depth: 1');

  // ── Test Group 3: Happy path — root → child → grandchild ─────────────
  console.log('\nTest Group 3: Happy path — root → child → grandchild');

  const grandchildReceipt = await chain.delegate({
    parentReceiptHash: childReceipt.hash,
    childScope:        GRANDCHILD_SCOPE,
    childAgent:        'agent-B',
    privateKey:        agentBKey,
    publicJwk:         agentBJwk,
  });

  // Test 11: grandchild depth is 2
  assert(grandchildReceipt.depth === 2, 'grandchild receipt depth is 2');

  // Test 12: verify(grandchildHash) returns valid: true
  const gcVerify = await chain.verify(grandchildReceipt.hash);
  assert(gcVerify.valid === true, 'verify(grandchildHash) returns valid: true');

  // Test 13: verify() depth is 2 for grandchild
  assert(gcVerify.depth === 2, 'verify(grandchildHash) returns depth: 2');

  // Test 14: scopeAttenuation array length = 2 (two hops: root→child, child→grandchild)
  assert(Array.isArray(gcVerify.scopeAttenuation) && gcVerify.scopeAttenuation.length === 2,
    'verify() scopeAttenuation array has 2 entries for depth-2 chain');

  // Test 15: scopeAttenuation values correct (root→child: 4→2 = 2 dropped; child→grandchild: 2→1 = 1 dropped)
  // Array is root-to-leaf order: [2, 1]
  assert(gcVerify.scopeAttenuation[0] === 2 && gcVerify.scopeAttenuation[1] === 1,
    'verify() scopeAttenuation values are correct [2, 1]');

  // ── Test Group 4: Scope attenuation enforcement ───────────────────────
  console.log('\nTest Group 4: Scope attenuation enforcement');

  const rootReceipt2 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain2 = new DelegationChain({ rootReceipt: rootReceipt2 });
  const rootHash2 = await sha256(JSON.stringify(rootReceipt2));

  // Test 16: Equal scope rejected (same allowedActions as parent)
  await assertThrows(
    () => chain2.delegate({
      parentReceiptHash: rootHash2,
      childScope: { ...ROOT_SCOPE },    // same scope — not a proper subset
      childAgent: 'agent-X',
      privateKey: agentAKey,
      publicJwk:  agentAJwk,
    }),
    'ScopeAttenuationError',
    'equal scope → ScopeAttenuationError'
  );

  // Test 17: Broader scope (adding a new action not in parent) rejected
  await assertThrows(
    () => chain2.delegate({
      parentReceiptHash: rootHash2,
      childScope: {
        allowedActions: [
          ...ROOT_SCOPE.allowedActions,
          { operation: 'write', resource: 'files' },  // NEW — not in parent
        ],
        deniedActions: ROOT_SCOPE.deniedActions,
      },
      childAgent: 'agent-X',
      privateKey: agentAKey,
      publicJwk:  agentAJwk,
    }),
    'ScopeAttenuationError',
    'broader scope (extra action not in parent) → ScopeAttenuationError'
  );

  // Test 18: Missing parent denied action in child → ScopeAttenuationError
  await assertThrows(
    () => chain2.delegate({
      parentReceiptHash: rootHash2,
      childScope: {
        allowedActions: [
          { operation: 'read', resource: 'calendar' },
        ],
        deniedActions: [],  // parent has 'delete::*' but child drops it
      },
      childAgent: 'agent-X',
      privateKey: agentAKey,
      publicJwk:  agentAJwk,
    }),
    'ScopeAttenuationError',
    'child missing parent denied action → ScopeAttenuationError'
  );

  // Test 19: Valid proper subset is accepted (sanity check)
  const validChild = await chain2.delegate({
    parentReceiptHash: rootHash2,
    childScope: {
      allowedActions: [{ operation: 'read', resource: 'calendar' }],
      deniedActions:  ROOT_SCOPE.deniedActions,
    },
    childAgent: 'agent-X',
    privateKey: agentAKey,
    publicJwk:  agentAJwk,
  });
  assert(typeof validChild.hash === 'string', 'valid proper subset is accepted');

  // ── Test Group 5: Max depth enforcement ──────────────────────────────
  console.log('\nTest Group 5: Max depth enforcement');

  // Test 20: MaxDepthExceededError when depth would reach maxDepth
  // With default maxDepth=3: depth 0 (root), 1 (child), 2 (grandchild) OK; depth 3 throws
  const rootReceipt3 = await makeRootReceipt(userKey, userJwk, {
    allowedActions: [
      { operation: 'read',  resource: 'a' },
      { operation: 'write', resource: 'a' },
      { operation: 'read',  resource: 'b' },
      { operation: 'write', resource: 'b' },
    ],
    deniedActions: [],
  });
  const chain3 = new DelegationChain({ rootReceipt: rootReceipt3, maxDepth: 3 });
  const rh3 = await sha256(JSON.stringify(rootReceipt3));

  const c3a = await chain3.delegate({
    parentReceiptHash: rh3,
    childScope: { allowedActions: [
      { operation: 'read', resource: 'a' },
      { operation: 'write', resource: 'a' },
      { operation: 'read', resource: 'b' },
    ], deniedActions: [] },
    childAgent: 'a1', privateKey: agentAKey, publicJwk: agentAJwk,
  });
  const c3b = await chain3.delegate({
    parentReceiptHash: c3a.hash,
    childScope: { allowedActions: [
      { operation: 'read', resource: 'a' },
      { operation: 'write', resource: 'a' },
    ], deniedActions: [] },
    childAgent: 'a2', privateKey: agentAKey, publicJwk: agentAJwk,
  });
  // depth 2 was OK; depth 3 must throw
  await assertThrows(
    () => chain3.delegate({
      parentReceiptHash: c3b.hash,
      childScope: { allowedActions: [
        { operation: 'read', resource: 'a' },
      ], deniedActions: [] },
      childAgent: 'a3', privateKey: agentAKey, publicJwk: agentAJwk,
    }),
    'MaxDepthExceededError',
    'delegation at depth=maxDepth → MaxDepthExceededError'
  );

  // Test 21: Custom maxDepth=1 — even first hop throws
  const rootReceipt4 = await makeRootReceipt(userKey, userJwk, {
    allowedActions: [
      { operation: 'read',  resource: 'x' },
      { operation: 'write', resource: 'x' },
    ],
    deniedActions: [],
  });
  const chainDepth1 = new DelegationChain({ rootReceipt: rootReceipt4, maxDepth: 1 });
  const rh4 = await sha256(JSON.stringify(rootReceipt4));
  await assertThrows(
    () => chainDepth1.delegate({
      parentReceiptHash: rh4,
      childScope: { allowedActions: [{ operation: 'read', resource: 'x' }], deniedActions: [] },
      childAgent: 'x', privateKey: agentAKey, publicJwk: agentAJwk,
    }),
    'MaxDepthExceededError',
    'maxDepth=1 → MaxDepthExceededError on first delegation attempt'
  );

  // ── Test Group 6: Cascade revocation ─────────────────────────────────
  console.log('\nTest Group 6: Cascade revocation');

  const rootReceipt5 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain5 = new DelegationChain({ rootReceipt: rootReceipt5 });
  const rh5 = await sha256(JSON.stringify(rootReceipt5));

  const c5a = await chain5.delegate({
    parentReceiptHash: rh5,
    childScope:  CHILD_SCOPE,
    childAgent:  'agentA',
    privateKey:  agentAKey,
    publicJwk:   agentAJwk,
  });
  const c5b = await chain5.delegate({
    parentReceiptHash: c5a.hash,
    childScope:  GRANDCHILD_SCOPE,
    childAgent:  'agentB',
    privateKey:  agentBKey,
    publicJwk:   agentBJwk,
  });

  // Test 22: revoking parent with cascade invalidates child
  await chain5.revoke(c5a.hash, { cascadeToChildren: true });
  const parentAfterRevoke = await chain5.verify(c5a.hash);
  assert(parentAfterRevoke.valid === false && parentAfterRevoke.revocationStatus === 'revoked',
    'revoked parent returns valid: false, revocationStatus: revoked');

  // Test 23: cascaded child is also revoked
  const childAfterCascade = await chain5.verify(c5b.hash);
  assert(childAfterCascade.valid === false && childAfterCascade.revocationStatus === 'revoked',
    'cascaded child also returns valid: false, revocationStatus: revoked');

  // Test 24: Cascade from grandparent invalidates everything
  const rootReceipt6 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain6 = new DelegationChain({ rootReceipt: rootReceipt6 });
  const rh6 = await sha256(JSON.stringify(rootReceipt6));

  const c6a = await chain6.delegate({
    parentReceiptHash: rh6, childScope: CHILD_SCOPE,
    childAgent: 'a', privateKey: agentAKey, publicJwk: agentAJwk,
  });
  const c6b = await chain6.delegate({
    parentReceiptHash: c6a.hash, childScope: GRANDCHILD_SCOPE,
    childAgent: 'b', privateKey: agentBKey, publicJwk: agentBJwk,
  });

  await chain6.revoke(rh6, { cascadeToChildren: true });

  const r6root  = await chain6.verify(rh6);
  const r6child = await chain6.verify(c6a.hash);
  const r6gc    = await chain6.verify(c6b.hash);
  assert(r6root.revocationStatus === 'revoked' &&
         r6child.revocationStatus === 'revoked' &&
         r6gc.revocationStatus    === 'revoked',
    'revoking root with cascade invalidates root, child, and grandchild');

  // Test 25: Revoking leaf does NOT affect parent
  const rootReceipt7 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain7 = new DelegationChain({ rootReceipt: rootReceipt7 });
  const rh7 = await sha256(JSON.stringify(rootReceipt7));

  const c7a = await chain7.delegate({
    parentReceiptHash: rh7, childScope: CHILD_SCOPE,
    childAgent: 'a', privateKey: agentAKey, publicJwk: agentAJwk,
  });
  const c7b = await chain7.delegate({
    parentReceiptHash: c7a.hash, childScope: GRANDCHILD_SCOPE,
    childAgent: 'b', privateKey: agentBKey, publicJwk: agentBJwk,
  });

  await chain7.revoke(c7b.hash, { cascadeToChildren: true });  // leaf only

  const r7parent = await chain7.verify(c7a.hash);
  const r7leaf   = await chain7.verify(c7b.hash);
  assert(r7parent.valid === true,  'revoking leaf does not affect parent — parent still valid');
  assert(r7leaf.valid   === false, 'revoking leaf invalidates the leaf');

  // Test 26: verify() fails on revoked intermediate receipt
  const rootReceipt8 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain8 = new DelegationChain({ rootReceipt: rootReceipt8 });
  const rh8 = await sha256(JSON.stringify(rootReceipt8));

  const c8a = await chain8.delegate({
    parentReceiptHash: rh8, childScope: CHILD_SCOPE,
    childAgent: 'a', privateKey: agentAKey, publicJwk: agentAJwk,
  });
  const c8b = await chain8.delegate({
    parentReceiptHash: c8a.hash, childScope: GRANDCHILD_SCOPE,
    childAgent: 'b', privateKey: agentBKey, publicJwk: agentBJwk,
  });

  // Revoke middle link (WITHOUT cascade — just one node)
  await chain8.revoke(c8a.hash);
  const r8gc = await chain8.verify(c8b.hash);
  assert(r8gc.valid === false && r8gc.revocationStatus === 'revoked',
    'verify() fails when an intermediate link is revoked');

  // ── Test Group 7: Delegation blocked from revoked parent ──────────────
  console.log('\nTest Group 7: Delegation from revoked parent blocked');

  // Test 27: delegation from revoked parent throws
  const rootReceipt9 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain9 = new DelegationChain({ rootReceipt: rootReceipt9 });
  const rh9 = await sha256(JSON.stringify(rootReceipt9));

  const c9a = await chain9.delegate({
    parentReceiptHash: rh9, childScope: CHILD_SCOPE,
    childAgent: 'a', privateKey: agentAKey, publicJwk: agentAJwk,
  });
  await chain9.revoke(c9a.hash);

  await assertThrows(
    () => chain9.delegate({
      parentReceiptHash: c9a.hash,
      childScope: GRANDCHILD_SCOPE,
      childAgent: 'b', privateKey: agentBKey, publicJwk: agentBJwk,
    }),
    'revoked',
    'delegation from revoked parent throws'
  );

  // ── Test Group 8: Signature integrity ────────────────────────────────
  console.log('\nTest Group 8: Signature integrity');

  // Test 28: Child signed with mismatched key → verify fails
  // Pass publicJwk from wrongKey but sign with agentAKey → embedded public key won't verify sig
  const rootReceipt10 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain10 = new DelegationChain({ rootReceipt: rootReceipt10 });
  const rh10 = await sha256(JSON.stringify(rootReceipt10));

  const badChildReceipt = await chain10.delegate({
    parentReceiptHash: rh10,
    childScope:  CHILD_SCOPE,
    childAgent:  'bad-agent',
    privateKey:  agentAKey,   // signed with agentAKey
    publicJwk:   wrongJwk,    // but claims to be wrongKey → mismatch
  });
  const badChildVerify = await chain10.verify(badChildReceipt.hash);
  assert(badChildVerify.valid === false,
    'child signed with wrong key (key mismatch) → verify returns valid: false');
  assert(badChildVerify.revocationStatus === 'not-revoked',
    'failed verification due to bad signature has revocationStatus: not-revoked');

  // ── Test Group 9: Edge cases ──────────────────────────────────────────
  console.log('\nTest Group 9: Edge cases');

  // Test 29: verify() for unknown hash returns valid: false
  const chain11 = new DelegationChain({ rootReceipt: await makeRootReceipt(userKey, userJwk, ROOT_SCOPE) });
  const unknownResult = await chain11.verify('a'.repeat(64));
  assert(unknownResult.valid === false && unknownResult.revocationStatus === 'unknown',
    'verify() for unknown hash returns valid: false, revocationStatus: unknown');

  // Test 30: revoke() for non-existent hash throws
  await assertThrows(
    () => chain11.revoke('b'.repeat(64)),
    'not found',
    'revoke() on non-existent hash throws'
  );

  // Test 31: verify() root receipt directly returns valid: true
  const rootReceipt11 = await makeRootReceipt(userKey, userJwk, ROOT_SCOPE);
  const chain12 = new DelegationChain({ rootReceipt: rootReceipt11 });
  const rootHash11 = await sha256(JSON.stringify(rootReceipt11));
  // need to trigger init first
  const rootVerify = await chain12.verify(rootHash11);
  assert(rootVerify.valid === true && rootVerify.depth === 0,
    'verify() root receipt returns valid: true, depth: 0');

  // Test 32: scopeAttenuation is empty for root receipt
  assert(Array.isArray(rootVerify.scopeAttenuation) && rootVerify.scopeAttenuation.length === 0,
    'verify() root receipt returns empty scopeAttenuation array');

  // ── Summary ──────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Fix 4 DelegationChain tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

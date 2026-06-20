/**
 * VDD Phase 1 -- Authority State Attestation & reauthRequired tests
 * Run: node --experimental-global-webcrypto tests/vdd-authority-state.test.js
 */

import AuthProof, { RevocationRegistry, ScopeSchema } from '../src/authproof.js';
import { AuthorityStateAttestation } from '../src/authority-state-attestation.js';
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

async function makeKeys() {
  return AuthProof.generateKey();
}

async function makeReceipt({
  scope         = 'Read calendar events and summarize meetings',
  boundaries    = 'Do not send emails. Do not modify records.',
  instructions  = 'Summarize clearly. Stay within scope.',
  ttlHours      = 2,
  privateKey,
  publicJwk,
  authorityState,
  reauthPolicy,
} = {}) {
  return AuthProof.create({
    scope, boundaries, instructions, ttlHours,
    privateKey, publicJwk, authorityState, reauthPolicy,
  });
}

async function makeVerifier({ sessionState } = {}) {
  const { privateKey: vPriv, publicJwk: vPub } = await makeKeys();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  const { privateKey: rPriv, publicJwk: rPub } = await makeKeys();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });

  const verifier = new PreExecutionVerifier({
    delegationLog,
    revocationRegistry,
    sessionState: sessionState ?? null,
  });
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });
  return { verifier, delegationLog, revocationRegistry };
}

// ─────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────

async function run() {
  console.log('VDD Phase 1 -- Authority State Attestation\n');

  const { privateKey, publicJwk } = await makeKeys();

  // ── 1. Deterministic commit ───────────────────────────────────────────
  console.log('AuthorityStateAttestation.commit');

  const state1 = { roles: ['admin'], groups: ['engineering'], entitlements: ['pii:read'] };
  const h1a = await AuthorityStateAttestation.commit(state1);
  const h1b = await AuthorityStateAttestation.commit(state1);
  assert(h1a === h1b, 'Same input produces the same commitment (deterministic)');
  assert(typeof h1a === 'string' && h1a.length === 64, 'Commitment is a 64-char hex string');

  // Key order must not matter
  const stateReordered = { entitlements: ['pii:read'], roles: ['admin'], groups: ['engineering'] };
  const h1c = await AuthorityStateAttestation.commit(stateReordered);
  assert(h1a === h1c, 'Key order does not affect the commitment');

  // ── 2. Different inputs produce different commitments ─────────────────
  console.log('\nDifferent inputs');

  const state2 = { roles: ['viewer'], groups: ['engineering'] };
  const h2 = await AuthorityStateAttestation.commit(state2);
  assert(h1a !== h2, 'Different authority states produce different commitments');

  const stateEmpty = {};
  const hEmpty = await AuthorityStateAttestation.commit(stateEmpty);
  assert(h1a !== hEmpty, 'Empty state produces a different commitment than populated state');

  // ── 3. PERMIT with matching state — reauthRequired false ──────────────
  console.log('\nCheck 15: matching state -> PERMIT, reauthRequired false');

  const { verifier: v3, delegationLog: dl3 } = await makeVerifier();
  const authorityState3 = { roles: ['admin'], groups: ['ops'] };
  const { receipt: r3, receiptId: rid3 } = await makeReceipt({
    privateKey, publicJwk, authorityState: authorityState3,
  });
  dl3.add(rid3, r3);

  const res3 = await v3.check({
    receiptHash:          rid3,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
    currentAuthorityState: authorityState3,
  });
  assert(res3.allowed === true,         'Matching authority state: allowed=true');
  assert(res3.reauthRequired === false,  'Matching authority state: reauthRequired=false');
  assert('reauthRequired' in res3,       'reauthRequired field is present on PERMIT result');

  // ── 4. PERMIT with drifted state, policy='reauth' ─────────────────────
  console.log('\nCheck 15: drifted state, policy=reauth -> PERMIT, reauthRequired true');

  const { verifier: v4, delegationLog: dl4 } = await makeVerifier();
  const authorityState4 = { roles: ['admin'], groups: ['ops'] };
  const driftedState4   = { roles: ['viewer'], groups: ['ops'] };
  const { receipt: r4, receiptId: rid4 } = await makeReceipt({
    privateKey, publicJwk,
    authorityState: authorityState4,
    reauthPolicy:   { onAuthorityStateDrift: 'reauth' },
  });
  dl4.add(rid4, r4);

  const res4 = await v4.check({
    receiptHash:           rid4,
    action:                'Read calendar meetings and summarize',
    operatorInstructions:  'Summarize clearly. Stay within scope.',
    currentAuthorityState: driftedState4,
  });
  assert(res4.allowed === true,        'Drifted state (reauth policy): allowed=true (not blocked)');
  assert(res4.reauthRequired === true,  'Drifted state (reauth policy): reauthRequired=true');

  // ── 5. DENY with drifted state, policy='block' ────────────────────────
  console.log('\nCheck 15: drifted state, policy=block -> DENY, AUTHORITY_STATE_DRIFT');

  const { verifier: v5, delegationLog: dl5 } = await makeVerifier();
  const authorityState5 = { roles: ['admin'] };
  const driftedState5   = { roles: ['viewer'] };
  const { receipt: r5, receiptId: rid5 } = await makeReceipt({
    privateKey, publicJwk,
    authorityState: authorityState5,
    reauthPolicy:   { onAuthorityStateDrift: 'block' },
  });
  dl5.add(rid5, r5);

  const res5 = await v5.check({
    receiptHash:           rid5,
    action:                'Read calendar meetings and summarize',
    operatorInstructions:  'Summarize clearly. Stay within scope.',
    currentAuthorityState: driftedState5,
  });
  assert(res5.allowed === false,                                    'Drifted state (block policy): allowed=false');
  assert(res5.blockedReason === 'AUTHORITY_STATE_DRIFT',            'DENY has blockedReason AUTHORITY_STATE_DRIFT');
  assert(res5.reauthRequired === false,                             'DENY from block policy: reauthRequired=false');
  assert('reauthRequired' in res5,                                  'reauthRequired field present on DENY result');

  // ── 6. Receipt expiring within 300 seconds — reauthRequired true ──────
  console.log('\nreauthRequired: receipt expiring soon');

  const { verifier: v6, delegationLog: dl6 } = await makeVerifier();
  // ttlHours=0.04 gives ~144 seconds, within the 300s default threshold
  const { receipt: r6, receiptId: rid6 } = await makeReceipt({
    privateKey, publicJwk, ttlHours: 0.04,
  });
  dl6.add(rid6, r6);

  const res6 = await v6.check({
    receiptHash:          rid6,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(res6.allowed === true,        'Short-lived receipt: allowed=true (not expired)');
  assert(res6.reauthRequired === true,  'Short-lived receipt: reauthRequired=true (expiring within 300s)');

  // A long-lived receipt (2 hours) should not trigger expiry reauth
  const { verifier: v6b, delegationLog: dl6b } = await makeVerifier();
  const { receipt: r6b, receiptId: rid6b } = await makeReceipt({
    privateKey, publicJwk, ttlHours: 2,
  });
  dl6b.add(rid6b, r6b);
  const res6b = await v6b.check({
    receiptHash:          rid6b,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(res6b.reauthRequired === false, 'Long-lived receipt: reauthRequired=false');

  // ── 7. Session riskScore below trustScoreBelow threshold ──────────────
  console.log('\nreauthRequired: low trust score');

  // Mock SessionState whose evaluate() returns riskScore=20, which is below
  // the default trustScoreBelow=50. Per spec: riskScore < trustScoreBelow => reauth.
  const mockSessionLowTrust = {
    evaluate: async () => ({
      decision:  'ALLOW',
      riskScore: 20,
      reasons:   [],
    }),
  };

  const { verifier: v7, delegationLog: dl7 } = await makeVerifier({ sessionState: mockSessionLowTrust });
  const { receipt: r7, receiptId: rid7 } = await makeReceipt({ privateKey, publicJwk });
  dl7.add(rid7, r7);

  const res7 = await v7.check({
    receiptHash:          rid7,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(res7.allowed === true,        'Low trust score: allowed=true (not blocked)');
  assert(res7.reauthRequired === true,  'Low trust score: reauthRequired=true');

  // High risk score (above threshold) should not trigger reauthRequired from this condition
  const mockSessionHighTrust = {
    evaluate: async () => ({
      decision:  'ALLOW',
      riskScore: 80,
      reasons:   [],
    }),
  };
  const { verifier: v7b, delegationLog: dl7b } = await makeVerifier({ sessionState: mockSessionHighTrust });
  const { receipt: r7b, receiptId: rid7b } = await makeReceipt({ privateKey, publicJwk });
  dl7b.add(rid7b, r7b);
  const res7b = await v7b.check({
    receiptHash:          rid7b,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(res7b.reauthRequired === false, 'High riskScore (above trustScoreBelow): reauthRequired=false');

  // ── 8. Old-style receipt with no authorityState — unchanged behavior ───
  console.log('\nBackward compatibility: no authorityState');

  const { verifier: v8, delegationLog: dl8 } = await makeVerifier();
  const { receipt: r8, receiptId: rid8 } = await makeReceipt({ privateKey, publicJwk });
  dl8.add(rid8, r8);

  const res8 = await v8.check({
    receiptHash:          rid8,
    action:               'Read calendar meetings and summarize',
    operatorInstructions: 'Summarize clearly. Stay within scope.',
  });
  assert(res8.allowed === true,          'Old-style receipt: allowed=true (unchanged)');
  assert(res8.reauthRequired === false,  'Old-style receipt: reauthRequired=false (no drift, not expiring)');
  assert(res8.blockedReason === null,    'Old-style receipt: blockedReason=null (unchanged)');

  // currentAuthorityState passed but receipt has no commitment -> no drift check
  const res8b = await v8.check({
    receiptHash:           rid8,
    action:                'Read calendar meetings and summarize',
    operatorInstructions:  'Summarize clearly. Stay within scope.',
    currentAuthorityState: { roles: ['anyone'] },
  });
  assert(res8b.allowed === true,         'No commitment in receipt: passing currentAuthorityState is harmless');
  assert(res8b.reauthRequired === false,  'No commitment in receipt: reauthRequired=false');

  // ── Summary ────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All VDD authority state tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

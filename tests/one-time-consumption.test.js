/**
 * One-Time Consumption -- Test Suite
 * Run: node --experimental-global-webcrypto tests/one-time-consumption.test.js
 *
 * Covers:
 *   1. InMemoryConsumptionStore: atomicity, terminal refusal
 *   2. oneTimeUse receipt + durable store: first PERMIT, second DENY RECEIPT_ALREADY_CONSUMED
 *   3. oneTimeUse receipt + no durable store: DENY CONSUMPTION_STORE_REQUIRED (fail closed)
 *   4. Non-oneTimeUse receipt: unaffected, consume() never called
 *   5. Concurrency: Promise.all on same key -- exactly one true, one false
 *   6. Redis adapter: mocked client -- SET NX used atomically, no prior GET
 */

import AuthProof, { RevocationRegistry } from '../src/authproof.js';
import {
  PreExecutionVerifier,
  DelegationLog,
  RECEIPT_ALREADY_CONSUMED,
  CONSUMPTION_STORE_REQUIRED,
} from '../src/pre-execution-verifier.js';
import { ConsumptionStore, InMemoryConsumptionStore } from '../src/consumption-store.js';
import { RedisConsumptionStore } from '../src/redis-consumption-store.js';

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  v ${label}`);
    passed++;
  } else {
    console.error(`  x ${label}`);
    failed++;
  }
}

// -------------------------------------------------------
// HELPERS
// -------------------------------------------------------

async function makeReceipt({ privateKey, publicJwk, oneTimeUse } = {}) {
  return AuthProof.create({
    scope:        'Read calendar events',
    boundaries:   'Do not send emails',
    instructions: 'Stay within scope',
    ttlHours:     2,
    privateKey,
    publicJwk,
    ...(oneTimeUse !== undefined ? { oneTimeUse } : {}),
  });
}

async function makeVerifier({ consumptionStore } = {}) {
  const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });

  const opts = { delegationLog, revocationRegistry };
  if (consumptionStore !== undefined) opts.consumptionStore = consumptionStore;

  const verifier = new PreExecutionVerifier(opts);
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });
  return { verifier, delegationLog };
}

// -------------------------------------------------------
// TEST RUNNER
// -------------------------------------------------------

async function run() {
  console.log('One-Time Consumption -- Test Suite\n');

  const { privateKey, publicJwk } = await AuthProof.generateKey();

  // -------------------------------------------------------
  // Section 1: InMemoryConsumptionStore basics
  // -------------------------------------------------------
  console.log('Section 1: InMemoryConsumptionStore');

  const memStore = new InMemoryConsumptionStore();

  const first = await memStore.consume('key-a');
  assert(first === true,  'First consume of a key returns true (allow)');

  const second = await memStore.consume('key-a');
  assert(second === false, 'Second consume of same key returns false (already consumed)');

  const third = await memStore.consume('key-a');
  assert(third === false,  'Third consume -- refusal is terminal, still returns false');

  assert(await memStore.has('key-a') === true,  'has() returns true for a consumed key');
  assert(await memStore.has('key-b') === false, 'has() returns false for an unconsumed key');

  // Different key is independent
  const diffKey = await memStore.consume('key-b');
  assert(diffKey === true, 'Consuming a different key returns true (independent slot)');

  // -------------------------------------------------------
  // Section 2: oneTimeUse receipt with a durable store
  // -------------------------------------------------------
  console.log('\nSection 2: oneTimeUse receipt with durable store');

  const durableStore = new InMemoryConsumptionStore();
  const { verifier: v2, delegationLog: dl2 } = await makeVerifier({ consumptionStore: durableStore });
  const { receipt: r2, receiptId: rid2 } = await makeReceipt({ privateKey, publicJwk, oneTimeUse: true });
  dl2.add(rid2, r2);

  const result2a = await v2.check({
    receiptHash:          rid2,
    action:               'Read calendar events',
    operatorInstructions: 'Stay within scope',
  });
  assert(result2a.allowed === true,
    'First verification of oneTimeUse receipt: PERMIT');

  const result2b = await v2.check({
    receiptHash:          rid2,
    action:               'Read calendar events',
    operatorInstructions: 'Stay within scope',
  });
  assert(result2b.allowed === false,
    'Second verification of same oneTimeUse receipt: DENY');
  assert(result2b.blockedReason === RECEIPT_ALREADY_CONSUMED,
    'Second verification: blockedReason is RECEIPT_ALREADY_CONSUMED');

  // Consumed state is terminal -- a third call also denies
  const result2c = await v2.check({
    receiptHash:          rid2,
    action:               'Read calendar events',
    operatorInstructions: 'Stay within scope',
  });
  assert(result2c.allowed === false && result2c.blockedReason === RECEIPT_ALREADY_CONSUMED,
    'Third verification: still DENY RECEIPT_ALREADY_CONSUMED (terminal)');

  // -------------------------------------------------------
  // Section 3: oneTimeUse with no durable store -- fail closed
  // -------------------------------------------------------
  console.log('\nSection 3: oneTimeUse with no durable store (fail closed)');

  const { verifier: v3, delegationLog: dl3 } = await makeVerifier();
  const { receipt: r3, receiptId: rid3 } = await makeReceipt({ privateKey, publicJwk, oneTimeUse: true });
  dl3.add(rid3, r3);

  const result3 = await v3.check({
    receiptHash:          rid3,
    action:               'Read calendar events',
    operatorInstructions: 'Stay within scope',
  });
  assert(result3.allowed === false,
    'oneTimeUse receipt with no durable store: DENY (fail closed)');
  assert(result3.blockedReason === CONSUMPTION_STORE_REQUIRED,
    'Fail-closed denial code is CONSUMPTION_STORE_REQUIRED');

  // -------------------------------------------------------
  // Section 4: Non-oneTimeUse receipt -- consumption not checked
  // -------------------------------------------------------
  console.log('\nSection 4: Non-oneTimeUse receipt is unaffected');

  let consumeCalled = false;
  const trackingStore = {
    consume: async (_key) => { consumeCalled = true; return true; },
    has:     async (_key) => false,
  };

  const { verifier: v4, delegationLog: dl4 } = await makeVerifier({ consumptionStore: trackingStore });
  const { receipt: r4, receiptId: rid4 } = await makeReceipt({ privateKey, publicJwk });
  dl4.add(rid4, r4);

  const result4 = await v4.check({
    receiptHash:          rid4,
    action:               'Read calendar events',
    operatorInstructions: 'Stay within scope',
  });
  assert(result4.allowed === true,  'Non-oneTimeUse receipt: PERMIT');
  assert(consumeCalled   === false, 'Non-oneTimeUse receipt: consume() never called on store');

  // -------------------------------------------------------
  // Section 5: Concurrency -- atomicity within a single process
  // -------------------------------------------------------
  console.log('\nSection 5: Concurrency atomicity');

  const concStore = new InMemoryConsumptionStore();

  // Promise.all issues both calls in the same microtask batch. JavaScript is
  // single-threaded so consume() for the first call runs to completion (the
  // synchronous Map.has + Map.set) before the second call starts. Exactly one
  // must return true and one must return false.
  const [concA, concB] = await Promise.all([
    concStore.consume('concurrent-key'),
    concStore.consume('concurrent-key'),
  ]);
  const successes = [concA, concB].filter(v => v === true);
  const failures  = [concA, concB].filter(v => v === false);
  assert(successes.length === 1, 'Concurrent consume: exactly one call returns true');
  assert(failures.length  === 1, 'Concurrent consume: exactly one call returns false');

  // Follow-up call on the same key is also false (terminal)
  const concC = await concStore.consume('concurrent-key');
  assert(concC === false, 'Post-concurrency consume: also false (terminal)');

  // -------------------------------------------------------
  // Section 6: Redis adapter -- mock client, verify atomic SET NX
  // -------------------------------------------------------
  console.log('\nSection 6: Redis adapter (mocked client)');

  const setCalls = [];
  const getCalls = [];
  // totalSetInvocations tracks the absolute call count independent of array resets.
  // The mock returns 'OK' only on the very first invocation (key does not exist);
  // all subsequent invocations return null (key already exists, SET NX rejected).
  let totalSetInvocations = 0;
  const mockRedisClient = {
    set: async (key, value, opts) => {
      setCalls.push({ key, value, opts });
      totalSetInvocations++;
      // First invocation: SET NX succeeds -> 'OK'
      // Any later invocation: key already exists, SET NX rejected -> null
      return totalSetInvocations === 1 ? 'OK' : null;
    },
    get: async (key) => {
      getCalls.push({ key });
      return null;
    },
  };

  const redisStore = new RedisConsumptionStore({ client: mockRedisClient });

  // First consume
  const redisFirst = await redisStore.consume('receipt-abc');
  assert(redisFirst === true,    'Redis adapter: first consume returns true');
  assert(setCalls.length === 1,  'Redis adapter: set() called exactly once for first consume');
  assert(getCalls.length === 0,  'Redis adapter: get() NOT called before set() -- no GET+SET race');
  assert(
    setCalls[0].opts != null && setCalls[0].opts.NX === true,
    'Redis adapter: SET called with NX: true (atomic check-and-set)'
  );

  // Reset call-tracking arrays for the second consume (totalSetInvocations stays at 1).
  setCalls.length = 0;
  getCalls.length = 0;

  // Second consume -- mock returns null (key already exists)
  const redisSecond = await redisStore.consume('receipt-abc');
  assert(redisSecond === false,  'Redis adapter: second consume returns false (mock returns null)');
  assert(setCalls.length === 1,  'Redis adapter: set() called once for second attempt');
  assert(getCalls.length === 0,  'Redis adapter: get() still NOT called -- only SET NX used');
  assert(
    setCalls[0].opts != null && setCalls[0].opts.NX === true,
    'Redis adapter: second attempt also uses SET NX, not GET then SET'
  );

  // has() is allowed to use GET (read-only check, not the atomic consume path)
  const redisHas = await redisStore.has('receipt-abc');
  assert(getCalls.length === 1,
    'Redis adapter: has() uses GET (read-only path is separate from consume)');

  // -------------------------------------------------------
  // Summary
  // -------------------------------------------------------
  console.log(`\n${'='.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\nAll one-time consumption tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

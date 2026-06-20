/**
 * CAEPEventAdapter -- Tests
 * Run: node --experimental-global-webcrypto tests/caep-event-adapter.test.js
 */

import AuthProof, { RevocationRegistry } from '../src/authproof.js';
import { CAEPEventAdapter } from '../src/caep-event-adapter.js';

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

async function makeRegistry() {
  const registry = new RevocationRegistry();
  const { privateKey, publicJwk } = await AuthProof.generateKey();
  await registry.init({ privateKey, publicJwk });
  return registry;
}

// ─────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────

async function run() {
  console.log('CAEPEventAdapter -- Test Suite\n');

  // ── Constructor validation ─────────────────────────────────────────────
  console.log('Constructor');

  try {
    new CAEPEventAdapter({});
    assert(false, 'Should throw when revocationRegistry is missing');
  } catch (e) {
    assert(e.message.includes('revocationRegistry'), 'Throws when revocationRegistry is missing');
  }

  const registry = await makeRegistry();
  const adapter  = new CAEPEventAdapter({ revocationRegistry: registry });
  assert(adapter instanceof CAEPEventAdapter, 'CAEPEventAdapter is instantiable');

  // ── 1. session.terminated -> revocation ───────────────────────────────
  console.log('\nsession.terminated');

  const registry1 = await makeRegistry();
  const adapter1  = new CAEPEventAdapter({ revocationRegistry: registry1 });
  const receiptId1 = 'a'.repeat(64);

  const result1 = await adapter1.handleEvent({
    type:    'session.terminated',
    subject: { receiptId: receiptId1 },
  });

  assert(result1.handled === true,                'session.terminated: handled=true');
  assert(result1.type === 'session.terminated',   'session.terminated: type matches');
  assert(result1.receiptId === receiptId1,        'session.terminated: receiptId returned');

  const status1 = await registry1.check(receiptId1);
  assert(status1.revoked === true,                'session.terminated: receipt is revoked in registry');
  assert(status1.reason === 'CAEP:session.terminated', 'session.terminated: reason is CAEP:session.terminated');

  // ── 2. credential.change -> revocation ────────────────────────────────
  console.log('\ncredential.change');

  const registry2 = await makeRegistry();
  const adapter2  = new CAEPEventAdapter({ revocationRegistry: registry2 });
  const receiptId2 = 'b'.repeat(64);

  const result2 = await adapter2.handleEvent({
    type:    'credential.change',
    subject: { receiptId: receiptId2 },
  });

  assert(result2.handled === true,               'credential.change: handled=true');
  assert(result2.type === 'credential.change',   'credential.change: type matches');

  const status2 = await registry2.check(receiptId2);
  assert(status2.revoked === true,               'credential.change: receipt is revoked in registry');
  assert(status2.reason === 'CAEP:credential.change', 'credential.change: reason is CAEP:credential.change');

  // ── 3. Unknown event type -- no throw, no revocation, handled=false ────
  console.log('\nUnknown event type');

  const registry3 = await makeRegistry();
  const adapter3  = new CAEPEventAdapter({ revocationRegistry: registry3 });
  const receiptId3 = 'c'.repeat(64);

  let threw3 = false;
  let result3;
  try {
    result3 = await adapter3.handleEvent({
      type:    'token.revoked',
      subject: { receiptId: receiptId3 },
    });
  } catch {
    threw3 = true;
  }

  assert(threw3 === false,          'Unknown event type: does not throw');
  assert(result3.handled === false, 'Unknown event type: handled=false');

  const status3 = await registry3.check(receiptId3);
  assert(status3.revoked === false, 'Unknown event type: no revocation recorded');

  // ── 4. Missing receiptId in subject -- handled=false, no throw ─────────
  console.log('\nMissing receiptId');

  const registry4 = await makeRegistry();
  const adapter4  = new CAEPEventAdapter({ revocationRegistry: registry4 });

  let threw4 = false;
  let result4a;
  try {
    result4a = await adapter4.handleEvent({
      type:    'session.terminated',
      subject: {},
    });
  } catch {
    threw4 = true;
  }
  assert(threw4 === false,            'Missing receiptId (empty subject): does not throw');
  assert(result4a.handled === false,  'Missing receiptId (empty subject): handled=false');
  assert(result4a.reason !== undefined, 'Missing receiptId: reason field is present');

  let threw4b = false;
  let result4b;
  try {
    result4b = await adapter4.handleEvent({
      type: 'credential.change',
      // no subject at all
    });
  } catch {
    threw4b = true;
  }
  assert(threw4b === false,           'Missing subject entirely: does not throw');
  assert(result4b.handled === false,  'Missing subject entirely: handled=false');

  // ── 5. Alternate subject shapes ──────────────────────────────────────
  console.log('\nAlternate subject shapes');

  const registry5 = await makeRegistry();
  const adapter5  = new CAEPEventAdapter({ revocationRegistry: registry5 });
  const receiptId5 = 'd'.repeat(64);

  // subject.identifier shape
  const result5a = await adapter5.handleEvent({
    type:    'session.terminated',
    subject: { identifier: receiptId5 },
  });
  assert(result5a.handled === true,          'subject.identifier shape: handled=true');
  assert(result5a.receiptId === receiptId5,  'subject.identifier shape: receiptId extracted correctly');

  const registry5b = await makeRegistry();
  const adapter5b  = new CAEPEventAdapter({ revocationRegistry: registry5b });
  const receiptId5b = 'e'.repeat(64);

  // top-level receiptId shape
  const result5b = await adapter5b.handleEvent({
    type:      'credential.change',
    receiptId: receiptId5b,
  });
  assert(result5b.handled === true,           'Top-level receiptId shape: handled=true');
  assert(result5b.receiptId === receiptId5b,  'Top-level receiptId shape: receiptId extracted correctly');

  // ── 6. Handler map is extensible ─────────────────────────────────────
  console.log('\nExtensible handler map');

  const registry6 = await makeRegistry();
  const adapter6  = new CAEPEventAdapter({ revocationRegistry: registry6 });
  const receiptId6 = 'f'.repeat(64);

  let customCalled = false;
  adapter6._handlers['custom.event'] = async (event) => {
    customCalled = true;
    const id = event?.subject?.receiptId ?? null;
    if (id) await registry6.revoke(id, { reason: 'CAEP:custom.event' });
    return { handled: true, type: 'custom.event', receiptId: id };
  };

  const result6 = await adapter6.handleEvent({
    type:    'custom.event',
    subject: { receiptId: receiptId6 },
  });
  assert(customCalled === true,      'Custom handler is called for new event type');
  assert(result6.handled === true,   'Custom event type: handled=true');

  const status6 = await registry6.check(receiptId6);
  assert(status6.revoked === true,   'Custom event type: receipt revoked via custom handler');

  // ── Summary ────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All CAEPEventAdapter tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

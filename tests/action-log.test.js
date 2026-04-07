/**
 * AuthProof ActionLog — Tests
 * Run: node tests/action-log.test.js
 */

import AuthProof, { ActionLog } from '../src/authproof.js';

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
  console.log('AuthProof ActionLog — Test Suite\n');

  // ── Setup: shared key pair and receipt ─────────────────────────────
  const { privateKey, publicJwk } = await AuthProof.generateKey();

  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Search the web for competitor pricing. Read calendar events.',
    boundaries:   'Do not send emails. Do not make purchases. Do not delete files.',
    instructions: 'Cite sources. Stay within the authorized scope.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });

  // ── Test 1: Recording a valid action under a valid receipt ──────────
  console.log('Test 1: Record a valid action under a valid receipt');

  const log = new ActionLog();
  await log.init({ privateKey, publicJwk });
  log.registerReceipt(receiptId, receipt);

  const entry = await log.record(receiptId, {
    operation:  'Search competitor pricing',
    resource:   'web/search',
    parameters: { query: 'rival.com pricing 2024' },
  });

  assert(typeof entry === 'object',          'record() returns an entry object');
  assert(typeof entry.entryId === 'string',  'entry has entryId');
  assert(entry.entryId.startsWith('log-'),   'entryId starts with log-');
  assert(entry.receiptHash === receiptId,    'entry.receiptHash matches receiptId');
  assert(entry.action.operation === 'Search competitor pricing', 'entry.action.operation is set');
  assert(entry.action.resource === 'web/search',                 'entry.action.resource is set');
  assert(typeof entry.signature === 'string' && entry.signature.length > 0, 'entry has signature');
  assert(typeof entry.entryHash === 'string' && entry.entryHash.length === 64, 'entry has 64-char entryHash');
  assert(entry.prevHash === '0'.repeat(64),  'first entry prevHash is genesis hash');
  assert(typeof entry.timestamp === 'number' && entry.timestamp > 0, 'entry has timestamp');

  // Verify the first entry is valid
  const v1 = await log.verify(entry.entryId);
  assert(v1.valid === true, 'First recorded entry verifies as valid');

  // Record a second entry and verify chain links correctly
  const entry2 = await log.record(receiptId, {
    operation:  'Read calendar events',
    resource:   'calendar/events',
  });
  assert(entry2.prevHash === entry.entryHash, 'Second entry prevHash equals first entry entryHash');

  const v2 = await log.verify(entry2.entryId);
  assert(v2.valid === true, 'Second entry verifies as valid');

  // getEntries returns in order
  const entries = log.getEntries(receiptId);
  assert(entries.length === 2, 'getEntries returns both entries');
  assert(entries[0].entryId === entry.entryId,  'First entry is in chronological position');
  assert(entries[1].entryId === entry2.entryId, 'Second entry is in chronological position');

  // ── Test 2: Detecting a scope violation in diff() ──────────────────
  console.log('\nTest 2: Detect a scope violation in diff()');

  // Use a receipt with an explicit allowedActions list for precise diff
  const { receipt: strictReceipt, receiptId: strictId } = await AuthProof.create({
    scope:        'Search the web for competitor pricing.',
    boundaries:   'Do not send emails. Do not delete files.',
    instructions: 'Stay within scope.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });
  // Add an explicit allowedActions array for exact matching
  strictReceipt.allowedActions = ['web_search', 'read_calendar'];

  const log2 = new ActionLog();
  await log2.init({ privateKey, publicJwk });
  log2.registerReceipt(strictId, strictReceipt);

  // Record one compliant action and one violation
  await log2.record(strictId, { operation: 'web_search',   resource: 'web',    parameters: { query: 'test' } });
  await log2.record(strictId, { operation: 'send_email',   resource: 'email',  parameters: { to: 'evil@example.com' } });
  await log2.record(strictId, { operation: 'read_calendar', resource: 'calendar' });

  const diffResult = log2.diff(strictId);

  assert(diffResult.totalEntries === 3,      'diff sees all 3 entries');
  assert(diffResult.compliant.length === 2,  'diff finds 2 compliant actions');
  assert(diffResult.violations.length === 1, 'diff finds 1 violation');
  assert(diffResult.clean === false,         'diff.clean is false when violations exist');

  const violation = diffResult.violations[0];
  assert(violation.entry.action.operation === 'send_email', 'Violation is the send_email operation');
  assert(violation.reason.includes('not in allowedActions'),  'Violation reason mentions allowedActions');

  const compliantOps = diffResult.compliant.map(c => c.entry.action.operation);
  assert(compliantOps.includes('web_search'),    'web_search is compliant');
  assert(compliantOps.includes('read_calendar'), 'read_calendar is compliant');

  // A clean diff
  const log3 = new ActionLog();
  await log3.init({ privateKey, publicJwk });
  log3.registerReceipt(strictId, strictReceipt);
  await log3.record(strictId, { operation: 'web_search', resource: 'web' });
  const cleanDiff = log3.diff(strictId);
  assert(cleanDiff.clean === true, 'diff.clean is true when no violations');

  // ── Test 3: Verifying chain integrity ──────────────────────────────
  console.log('\nTest 3: Verify chain integrity across multiple entries');

  const log4 = new ActionLog();
  await log4.init({ privateKey, publicJwk });
  log4.registerReceipt(receiptId, receipt);

  const e1 = await log4.record(receiptId, { operation: 'Search web', resource: 'web' });
  const e2 = await log4.record(receiptId, { operation: 'Read file',  resource: 'filesystem/docs' });
  const e3 = await log4.record(receiptId, { operation: 'Search web', resource: 'web/images' });

  // Verify the chain is intact entry by entry
  const r1 = await log4.verify(e1.entryId);
  const r2 = await log4.verify(e2.entryId);
  const r3 = await log4.verify(e3.entryId);

  assert(r1.valid === true, 'Entry 1 chain integrity valid');
  assert(r2.valid === true, 'Entry 2 chain integrity valid');
  assert(r3.valid === true, 'Entry 3 chain integrity valid');

  // Verify the prevHash chain manually
  assert(e1.prevHash === '0'.repeat(64), 'Entry 1 prevHash is genesis');
  assert(e2.prevHash === e1.entryHash,   'Entry 2 prevHash === entry 1 entryHash');
  assert(e3.prevHash === e2.entryHash,   'Entry 3 prevHash === entry 2 entryHash');

  // Verify unknown entry returns invalid
  const missing = await log4.verify('log-0000000-nonexistent');
  assert(missing.valid === false,                  'Unknown entryId returns invalid');
  assert(missing.reason === 'Entry not found',     'Correct reason for missing entry');

  // ── Test 4: Detecting tampering with a log entry ───────────────────
  console.log('\nTest 4: Detect tampering with a log entry');

  const log5 = new ActionLog();
  await log5.init({ privateKey, publicJwk });
  log5.registerReceipt(receiptId, receipt);

  const original = await log5.record(receiptId, {
    operation:  'Search competitor pricing',
    resource:   'web/search',
    parameters: { query: 'legit query' },
  });

  // Verify it's valid before tampering
  const beforeTamper = await log5.verify(original.entryId);
  assert(beforeTamper.valid === true, 'Entry is valid before any tampering');

  // Simulate tampering: mutate action.operation in-place
  // (getEntries returns references to the same objects stored in the Map)
  const entries5 = log5.getEntries(receiptId);
  entries5[0].action.operation = 'delete_all_files';  // TAMPER

  // Verify should now fail — signature was computed over the original operation
  const afterTamper = await log5.verify(original.entryId);
  assert(afterTamper.valid === false,   'Tampered entry fails verification');
  assert(
    afterTamper.reason.includes('Signature verification failed') ||
    afterTamper.reason.includes('hash mismatch'),
    'Tamper reason mentions signature or hash failure'
  );

  // Simulate tampering of a different field: receiptHash
  const log6 = new ActionLog();
  await log6.init({ privateKey, publicJwk });
  log6.registerReceipt(receiptId, receipt);

  const original2 = await log6.record(receiptId, {
    operation: 'Search web',
    resource:  'web',
  });
  const entries6 = log6.getEntries(receiptId);
  entries6[0].receiptHash = 'a'.repeat(64);  // TAMPER

  const tamperReceipt = await log6.verify(original2.entryId);
  assert(tamperReceipt.valid === false, 'Tampering receiptHash fails verification');

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All ActionLog tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

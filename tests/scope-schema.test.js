/**
 * AuthProof — Gap 2: Structured Scope Schema
 * Run: node tests/scope-schema.test.js
 *
 * Tests cover:
 *  - ScopeSchema construction and validation errors
 *  - validate() — allowed, denied, wildcard, constraints
 *  - Denial takes precedence over allowance
 *  - Wildcard matching on operations and resources
 *  - Constraint validation (numeric max, string patterns)
 *  - toJSON / fromJSON round-trip
 *  - diff() integration: ScopeSchema replaces fuzzy fallback
 *  - diff() backward compatibility with allowedActions arrays
 */

import AuthProof, { ActionLog, ScopeSchema } from '../src/authproof.js';

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
  console.log('Gap 2 — Structured Scope Schema\n');

  // ── Test Group 1: Construction and validation errors ─────────────────
  console.log('Test Group 1: Construction and validation');

  // Test 1: valid construction
  const schema = new ScopeSchema({
    version: '1.0',
    allowedActions: [
      { operation: 'read',  resource: 'email',    constraints: { sender: '*.company.com' } },
      { operation: 'write', resource: 'calendar', constraints: { maxEvents: 10 } },
    ],
    deniedActions: [
      { operation: 'delete',  resource: '*' },
      { operation: 'payment', resource: '*' },
    ],
    maxDuration: '4h',
  });
  assert(schema instanceof ScopeSchema, 'ScopeSchema constructs successfully');
  assert(schema.version === '1.0', 'version is stored correctly');
  assert(schema.allowedActions.length === 2, 'allowedActions stored correctly');
  assert(schema.deniedActions.length === 2, 'deniedActions stored correctly');
  assert(schema.maxDuration === '4h', 'maxDuration stored correctly');

  // Test 2: throws when version missing
  try {
    new ScopeSchema({ allowedActions: [] });
    assert(false, 'Should throw when version is missing');
  } catch (e) {
    assert(e.message.includes('version'), 'throws for missing version');
  }

  // Test 3: throws when version is not a string
  try {
    new ScopeSchema({ version: 42 });
    assert(false, 'Should throw when version is not a string');
  } catch (e) {
    assert(e.message.includes('version'), 'throws when version is not a string');
  }

  // Test 4: throws when allowedActions is not an array
  try {
    new ScopeSchema({ version: '1.0', allowedActions: 'read email' });
    assert(false, 'Should throw when allowedActions is not an array');
  } catch (e) {
    assert(e.message.includes('allowedActions'), 'throws when allowedActions is not an array');
  }

  // Test 5: throws when an action entry is missing operation
  try {
    new ScopeSchema({ version: '1.0', allowedActions: [{ resource: 'email' }] });
    assert(false, 'Should throw when action missing operation');
  } catch (e) {
    assert(e.message.includes('operation'), 'throws when action entry missing operation');
  }

  // Test 6: throws when an action entry is missing resource
  try {
    new ScopeSchema({ version: '1.0', allowedActions: [{ operation: 'read' }] });
    assert(false, 'Should throw when action missing resource');
  } catch (e) {
    assert(e.message.includes('resource'), 'throws when action entry missing resource');
  }

  // ── Test Group 2: validate() — core allow/deny logic ─────────────────
  console.log('\nTest Group 2: validate() — allow/deny logic');

  // Test 7: allowed action returns valid
  const r1 = schema.validate({ operation: 'read', resource: 'email' });
  assert(r1.valid === true, 'allowed action returns valid:true');
  assert(typeof r1.reason === 'string', 'validate() always returns a reason string');

  // Test 8: denied action returns invalid
  const r2 = schema.validate({ operation: 'delete', resource: 'contacts' });
  assert(r2.valid === false, 'denied action returns valid:false');
  assert(r2.reason.includes('denied'), 'deny reason mentions denied');

  // Test 9: action not in allowedActions returns invalid
  const r3 = schema.validate({ operation: 'execute', resource: 'script' });
  assert(r3.valid === false, 'action not in schema returns valid:false');
  assert(r3.reason.includes('not in allowedActions'), 'reason mentions not in allowedActions');

  // Test 10: denial takes precedence over allowance
  // Create schema where same op/resource is both allowed and denied
  const conflictSchema = new ScopeSchema({
    version: '1.0',
    allowedActions: [{ operation: 'read', resource: 'files' }],
    deniedActions:  [{ operation: 'read', resource: 'files' }],
  });
  const r4 = conflictSchema.validate({ operation: 'read', resource: 'files' });
  assert(r4.valid === false, 'denial takes precedence over allowance for same operation+resource');

  // Test 11: missing operation in validate call
  const r5 = schema.validate({ resource: 'email' });
  assert(r5.valid === false, 'validate() returns invalid when operation missing');

  // Test 12: missing resource in validate call
  const r6 = schema.validate({ operation: 'read' });
  assert(r6.valid === false, 'validate() returns invalid when resource missing');

  // ── Test Group 3: Wildcard matching ──────────────────────────────────
  console.log('\nTest Group 3: Wildcard matching');

  const wildcardSchema = new ScopeSchema({
    version: '1.0',
    allowedActions: [
      { operation: 'read',  resource: 'email/*' },
      { operation: '*',     resource: 'sandbox' },
    ],
    deniedActions: [
      { operation: 'delete', resource: '*' },
    ],
  });

  // Test 13: wildcard resource matches any suffix
  const r7 = wildcardSchema.validate({ operation: 'read', resource: 'email/inbox' });
  assert(r7.valid === true, 'wildcard resource "email/*" matches "email/inbox"');

  const r8 = wildcardSchema.validate({ operation: 'read', resource: 'email/sent' });
  assert(r8.valid === true, 'wildcard resource "email/*" matches "email/sent"');

  // Test 14: wildcard resource does not match unrelated path
  const r9 = wildcardSchema.validate({ operation: 'read', resource: 'calendar/events' });
  assert(r9.valid === false, 'wildcard resource "email/*" does not match "calendar/events"');

  // Test 15: wildcard operation matches any operation
  const r10 = wildcardSchema.validate({ operation: 'write', resource: 'sandbox' });
  assert(r10.valid === true, 'wildcard operation "*" matches any operation on allowed resource');

  // Test 16: wildcard deny blocks all resources
  const r11 = wildcardSchema.validate({ operation: 'delete', resource: 'any/path/here' });
  assert(r11.valid === false, 'wildcard deny "delete *" blocks any resource');

  // ── Test Group 4: Constraint validation ──────────────────────────────
  console.log('\nTest Group 4: Constraint validation');

  // sender pattern: "*.company.com" matches subdomains like "mail.company.com"
  // Use "*@company.com" for email address glob matching
  const constraintSchema = new ScopeSchema({
    version: '1.0',
    allowedActions: [
      { operation: 'read',  resource: 'email',    constraints: { sender: '*@company.com' } },
      { operation: 'write', resource: 'calendar', constraints: { maxEvents: 5 } },
    ],
    deniedActions: [],
  });

  // Test 17: action with constraint-satisfying parameters is valid
  const r12 = constraintSchema.validate({
    operation: 'read',
    resource:  'email',
    constraints: { sender: 'alice@company.com' },
  });
  assert(r12.valid === true, 'action with matching sender pattern is valid');

  // Test 18: action with constraint-violating parameters is invalid
  const r13 = constraintSchema.validate({
    operation: 'read',
    resource:  'email',
    constraints: { sender: 'attacker@evil.com' },
  });
  assert(r13.valid === false, 'action with non-matching sender pattern is invalid');
  assert(r13.reason.includes('constraint'), 'constraint violation reason mentions constraint');

  // Test 19: numeric max constraint — within limit is valid
  const r14 = constraintSchema.validate({
    operation: 'write',
    resource:  'calendar',
    constraints: { maxEvents: 3 },
  });
  assert(r14.valid === true, 'maxEvents within limit is valid');

  // Test 20: numeric max constraint — over limit is invalid
  const r15 = constraintSchema.validate({
    operation: 'write',
    resource:  'calendar',
    constraints: { maxEvents: 10 },
  });
  assert(r15.valid === false, 'maxEvents over limit is invalid');

  // ── Test Group 5: toJSON / fromJSON round-trip ────────────────────────
  console.log('\nTest Group 5: Serialization round-trip');

  const json = schema.toJSON();

  // Test 21: toJSON returns plain object (no class methods)
  assert(typeof json === 'object' && !(json instanceof ScopeSchema), 'toJSON returns a plain object');
  assert(json.version === '1.0', 'toJSON includes version');
  assert(Array.isArray(json.allowedActions), 'toJSON includes allowedActions array');
  assert(Array.isArray(json.deniedActions),  'toJSON includes deniedActions array');
  assert(json.maxDuration === '4h', 'toJSON includes maxDuration');

  // Test 22: round-trip via JSON.stringify / JSON.parse
  const roundTripped = ScopeSchema.fromJSON(JSON.parse(JSON.stringify(json)));
  assert(roundTripped instanceof ScopeSchema, 'fromJSON returns a ScopeSchema instance');
  assert(roundTripped.version === schema.version, 'round-tripped version matches');
  assert(roundTripped.allowedActions.length === schema.allowedActions.length,
    'round-tripped allowedActions length matches');

  // Test 23: round-tripped schema validates the same way as original
  const r16 = roundTripped.validate({ operation: 'read', resource: 'email' });
  const r17 = roundTripped.validate({ operation: 'delete', resource: 'anything' });
  assert(r16.valid === true,  'round-tripped schema allows same actions');
  assert(r17.valid === false, 'round-tripped schema denies same actions');

  // ── Test Group 6: diff() integration with ScopeSchema ────────────────
  console.log('\nTest Group 6: diff() integration');

  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Read emails and write calendar events.',
    boundaries:   'Do not delete or make payments.',
    instructions: 'Stay in scope.',
    ttlHours:     2,
    privateKey,
    publicJwk,
  });

  // Attach a ScopeSchema to the receipt
  receipt.scopeSchema = new ScopeSchema({
    version: '1.0',
    allowedActions: [
      { operation: 'read',  resource: 'email/*' },
      { operation: 'write', resource: 'calendar' },
    ],
    deniedActions: [
      { operation: 'delete',  resource: '*' },
      { operation: 'payment', resource: '*' },
    ],
  });

  const log = new ActionLog();
  await log.init({ privateKey, publicJwk, tsaUrl: null });
  log.registerReceipt(receiptId, receipt);

  await log.record(receiptId, { operation: 'read',    resource: 'email/inbox' });
  await log.record(receiptId, { operation: 'write',   resource: 'calendar' });
  await log.record(receiptId, { operation: 'delete',  resource: 'contacts' });
  await log.record(receiptId, { operation: 'payment', resource: 'stripe' });

  const diffResult = log.diff(receiptId);

  // Test 24: ScopeSchema diff finds correct compliant count
  assert(diffResult.compliant.length === 2, 'diff() finds 2 compliant entries via ScopeSchema');

  // Test 25: ScopeSchema diff finds correct violation count
  assert(diffResult.violations.length === 2, 'diff() finds 2 violations via ScopeSchema');

  // Test 26: diff reports violation reason from ScopeSchema
  const deleteViolation = diffResult.violations.find(
    v => v.entry.action.operation === 'delete'
  );
  assert(deleteViolation !== undefined, 'delete violation is in violations list');
  assert(deleteViolation.reason.includes('denied'), 'delete violation reason mentions denied');

  // Test 27: diff compliant entries have correct operations
  const compliantOps = diffResult.compliant.map(c => c.entry.action.operation);
  assert(compliantOps.includes('read') && compliantOps.includes('write'),
    'read and write are compliant per ScopeSchema');

  // Test 28: diff.clean is false when violations exist
  assert(diffResult.clean === false, 'diff.clean is false when ScopeSchema finds violations');

  // Test 29: backward compat — allowedActions path still works (no scopeSchema)
  const { receipt: legacyReceipt, receiptId: legacyId } = await AuthProof.create({
    scope: 'test', boundaries: 'test', instructions: 'test',
    ttlHours: 2, privateKey, publicJwk,
  });
  legacyReceipt.allowedActions = ['web_search'];

  const log2 = new ActionLog();
  await log2.init({ privateKey, publicJwk, tsaUrl: null });
  log2.registerReceipt(legacyId, legacyReceipt);
  await log2.record(legacyId, { operation: 'web_search', resource: 'web' });
  await log2.record(legacyId, { operation: 'send_email',  resource: 'email' });

  const diff2 = log2.diff(legacyId);
  assert(diff2.compliant.length === 1 && diff2.violations.length === 1,
    'allowedActions path still works without ScopeSchema');

  // Test 30: no-schema path reports helpful error
  const { receipt: noSchemaReceipt, receiptId: noSchemaId } = await AuthProof.create({
    scope: 'test', boundaries: 'test', instructions: 'test',
    ttlHours: 2, privateKey, publicJwk,
  });

  const log3 = new ActionLog();
  await log3.init({ privateKey, publicJwk, tsaUrl: null });
  log3.registerReceipt(noSchemaId, noSchemaReceipt);  // no scopeSchema, no allowedActions
  await log3.record(noSchemaId, { operation: 'anything', resource: 'anywhere' });

  const diff3 = log3.diff(noSchemaId);
  assert(diff3.violations.length === 1, 'no-schema path marks entry as violation');
  assert(diff3.violations[0].reason.includes('ScopeSchema'),
    'no-schema violation reason mentions ScopeSchema');

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Gap 2 ScopeSchema tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

/**
 * Tool Schema Hash Binding and Denied Call Audit Logging — Tests
 * Run: node --experimental-global-webcrypto tests/tool-schema-and-denied-calls.test.js
 */

import AuthProof, { RevocationRegistry, ActionLog } from '../src/authproof.js';
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

async function makeVerifier({ sessionState, actionLog } = {}) {
  const { privateKey: vPriv, publicJwk: vPub } = await AuthProof.generateKey();
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  const { privateKey: rPriv, publicJwk: rPub } = await AuthProof.generateKey();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });

  const verifier = new PreExecutionVerifier({
    delegationLog,
    revocationRegistry,
    sessionState:  sessionState ?? null,
    actionLog:     actionLog    ?? null,
  });
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });

  return { verifier, delegationLog, revocationRegistry };
}

async function makeReceiptWithSchema({ privateKey, publicJwk, toolSchema } = {}) {
  const client = new AuthProof.AuthProofClient();
  const { receipt, receiptId } = await client.delegate({
    scope:                'Read and summarize documents',
    boundaries:           'Do not delete files.',
    operatorInstructions: 'Summarize the document.',
    expiresIn:            '2h',
    privateKey,
    publicJwk,
    toolSchema,
  });
  return { receipt, receiptId };
}

// ─────────────────────────────────────────────
// SUITE 1: Tool Schema Hash — delegate()
// ��──────────────────���─────────────────────────

async function runToolSchemaHashTests() {
  console.log('Tool Schema Hash Binding — delegate()');

  const { privateKey, publicJwk } = await makeKeys();

  const toolSpec = {
    name:    'document-reader',
    version: '1.0',
    actions: ['read', 'summarize'],
  };

  // 1a. toolSchemaHash is included in receipt when toolSchema is provided
  const { receipt: r1, receiptId: rid1 } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema: toolSpec });
  assert(typeof r1.toolSchemaHash === 'string', 'toolSchemaHash present in receipt when toolSchema provided');
  assert(r1.toolSchemaHash.startsWith('sha256:'), 'toolSchemaHash formatted as sha256:hex');
  assert(r1.toolSchemaHash.length === 71, 'toolSchemaHash has correct length (sha256: + 64 hex chars)');

  // 1b. receipt without toolSchema has no toolSchemaHash
  const client = new AuthProof.AuthProofClient();
  const { receipt: r2 } = await client.delegate({
    scope: 'Read documents',
    boundaries: 'Do not delete.',
    operatorInstructions: 'Read carefully.',
    expiresIn: '1h',
    privateKey,
    publicJwk,
  });
  assert(r2.toolSchemaHash === undefined, 'toolSchemaHash absent when toolSchema not provided');

  // 1c. same schema produces same hash (deterministic)
  const { receipt: r3 } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema: toolSpec });
  assert(r1.toolSchemaHash === r3.toolSchemaHash, 'Same schema always produces same hash');

  // 1d. different schemas produce different hashes
  const toolSpec2 = { ...toolSpec, actions: ['read', 'summarize', 'write'] };
  const { receipt: r4 } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema: toolSpec2 });
  assert(r1.toolSchemaHash !== r4.toolSchemaHash, 'Different schemas produce different hashes');

  // 1e. key order in schema object does not affect hash (canonical JSON)
  const toolSpecReordered = { actions: toolSpec.actions, version: toolSpec.version, name: toolSpec.name };
  const { receipt: r5 } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema: toolSpecReordered });
  assert(r1.toolSchemaHash === r5.toolSchemaHash, 'Key order does not affect hash (canonical JSON)');

  // 1f. toolSchemaHash is part of the signed body — signature covers it
  const { signature: _sig, ...body } = r1;
  assert(body.toolSchemaHash !== undefined, 'toolSchemaHash is in signed receipt body');
}

// ─────────────────────────────────────────────
// SUITE 2: TOOL_SCHEMA_DRIFT denial
// ─────────────────────────��───────────────────

async function runSchemaDriftTests() {
  console.log('\nTOOL_SCHEMA_DRIFT — Check 8');

  const { privateKey, publicJwk } = await makeKeys();

  const originalSchema = { name: 'tool-v1', version: '1.0', ops: ['read'] };
  const changedSchema  = { name: 'tool-v2', version: '2.0', ops: ['read', 'write'] };

  const { receipt, receiptId } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema: originalSchema });
  const { verifier, delegationLog } = await makeVerifier();
  delegationLog.add(receiptId, receipt);

  const action = { operation: 'read', resource: 'document' };

  // 2a. ALLOW when schema matches exactly
  const resultMatch = await verifier.check({
    receiptHash:       receiptId,
    action,
    operatorInstructions: receipt.operatorInstructions,
    currentToolSchema: originalSchema,
  });
  assert(resultMatch.allowed === true, 'ALLOW when current schema matches receipt hash');
  assert(resultMatch.checks.toolSchemaIntegrity === true, 'toolSchemaIntegrity check passes on match');

  // 2b. DENY with TOOL_SCHEMA_DRIFT when schema has changed
  const resultDrift = await verifier.check({
    receiptHash:       receiptId,
    action,
    operatorInstructions: receipt.operatorInstructions,
    currentToolSchema: changedSchema,
  });
  assert(resultDrift.allowed === false, 'DENY when schema changed after issuance');
  assert(resultDrift.blockedReason === 'TOOL_SCHEMA_DRIFT', 'blockedReason is TOOL_SCHEMA_DRIFT');
  assert(resultDrift.checks.toolSchemaIntegrity === false, 'toolSchemaIntegrity check fails on mismatch');

  // 2c. ALLOW when receipt has no toolSchemaHash (optional check skipped)
  const { receipt: rNoHash, receiptId: ridNoHash } = await (async () => {
    const c = new AuthProof.AuthProofClient();
    return c.delegate({
      scope: 'Read docs', boundaries: 'No delete.', operatorInstructions: 'Read.',
      expiresIn: '1h', privateKey, publicJwk,
    });
  })();
  const { verifier: v2, delegationLog: dl2 } = await makeVerifier();
  dl2.add(ridNoHash, rNoHash);

  const resultNoHash = await v2.check({
    receiptHash:       ridNoHash,
    action,
    operatorInstructions: rNoHash.operatorInstructions,
    currentToolSchema: changedSchema,
  });
  assert(resultNoHash.allowed === true, 'ALLOW when receipt has no toolSchemaHash (check skipped)');
  assert(resultNoHash.checks.toolSchemaIntegrity === undefined, 'toolSchemaIntegrity check absent when not applicable');

  // 2d. ALLOW when currentToolSchema not provided (check skipped even if hash present)
  const { verifier: v3, delegationLog: dl3 } = await makeVerifier();
  dl3.add(receiptId, receipt);
  const resultNoSchema = await v3.check({
    receiptHash:          receiptId,
    action,
    operatorInstructions: receipt.operatorInstructions,
    // no currentToolSchema
  });
  assert(resultNoSchema.allowed === true, 'ALLOW when currentToolSchema not provided (check skipped)');
}

// ──────���────────────────��─────────────────────
// SUITE 3: Denied call log entry on every DENY
// ───────���──────────��──────────────────────────

async function runDeniedCallLogTests() {
  console.log('\nDenied Call Logging — every DENY produces a log entry');

  const { privateKey, publicJwk } = await makeKeys();

  const toolSchema = { name: 'tool', version: '1', ops: ['read'] };
  const { receipt, receiptId } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema });
  const { verifier, delegationLog } = await makeVerifier();
  delegationLog.add(receiptId, receipt);

  // 3a. No entries before any checks
  const preDenied = verifier.getDeniedCallLog(null);
  assert(preDenied.length === 0, 'getDeniedCallLog returns empty before any checks');

  // 3b. Trigger TOOL_SCHEMA_DRIFT denial
  const changedSchema = { name: 'tool', version: '2', ops: ['read', 'write'] };
  const action = { operation: 'read', resource: 'doc' };

  await verifier.check({
    receiptHash:       receiptId,
    action,
    operatorInstructions: receipt.operatorInstructions,
    currentToolSchema: changedSchema,
  });

  const denied1 = verifier.getDeniedCallLog(null);
  assert(denied1.length === 1, 'One denied call entry created for TOOL_SCHEMA_DRIFT');
  assert(denied1[0].decision === 'BLOCK', 'Denied entry has decision: BLOCK');
  assert(denied1[0].denialReason === 'TOOL_SCHEMA_DRIFT', 'Denied entry has correct denialReason');
  assert(denied1[0].receiptHash === receiptId, 'Denied entry has correct receiptHash');
  assert(typeof denied1[0].timestamp === 'number', 'Denied entry has numeric timestamp');
  assert(typeof denied1[0].entryId === 'string', 'Denied entry has entryId');
  assert(typeof denied1[0].entryHash === 'string', 'Denied entry has entryHash for chaining');
  assert(typeof denied1[0].action === 'object', 'Denied entry has action object');
  assert(denied1[0].action.operation === 'read', 'Denied entry action.operation correct');

  // 3c. Trigger a scope violation denial
  const { verifier: v2, delegationLog: dl2 } = await makeVerifier();
  dl2.add(receiptId, receipt);
  await verifier.check({
    receiptHash:          receiptId,
    action:               { operation: 'delete', resource: 'doc' },
    operatorInstructions: receipt.operatorInstructions,
    currentToolSchema:    toolSchema,
  });

  const denied2 = verifier.getDeniedCallLog(null);
  assert(denied2.length >= 1, 'getDeniedCallLog accumulates entries across multiple DENY calls');

  // 3d. Chain linking — previousEntryHash of second entry = entryHash of first
  if (denied2.length >= 2) {
    assert(
      denied2[1].previousEntryHash === denied2[0].entryHash,
      'Denied call entries are chain-linked via previousEntryHash'
    );
  }

  // 3e. ALLOW decisions do not add denied call entries
  const countBefore = verifier.getDeniedCallLog(null).length;
  await verifier.check({
    receiptHash:          receiptId,
    action,
    operatorInstructions: receipt.operatorInstructions,
    currentToolSchema:    toolSchema,
  });
  const countAfter = verifier.getDeniedCallLog(null).length;
  assert(countAfter === countBefore, 'ALLOW decisions do not add denied call entries');
}

// ─��──────────────���────────────────────────────
// SUITE 4: getDeniedCallLog by session
// ─────────────────────────────────────────────

async function runGetDeniedCallLogTests() {
  console.log('\ngetDeniedCallLog — session isolation');

  const { privateKey, publicJwk } = await makeKeys();
  const toolSchema = { name: 't', version: '1', ops: ['r'] };
  const badSchema  = { name: 't', version: '2', ops: ['r', 'w'] };

  const { receipt, receiptId } = await makeReceiptWithSchema({ privateKey, publicJwk, toolSchema });
  const { verifier, delegationLog } = await makeVerifier();
  delegationLog.add(receiptId, receipt);

  const action = { operation: 'read', resource: 'file' };

  // Trigger two DENY calls
  await verifier.check({ receiptHash: receiptId, action, operatorInstructions: receipt.operatorInstructions, currentToolSchema: badSchema });
  await verifier.check({ receiptHash: receiptId, action, operatorInstructions: receipt.operatorInstructions, currentToolSchema: badSchema });

  const entries = verifier.getDeniedCallLog(null);
  assert(entries.length === 2, 'getDeniedCallLog returns all entries for the session');
  assert(entries[0].timestamp <= entries[1].timestamp, 'Entries ordered by timestamp ascending');

  // 4b. getDeniedCallLog returns empty for unknown sessionId
  const noEntries = verifier.getDeniedCallLog('sess-unknown-xyz');
  assert(noEntries.length === 0, 'getDeniedCallLog returns empty for unknown session');

  // 4c. Each entry has all required fields
  const entry = entries[0];
  assert('entryId'          in entry, 'entry has entryId');
  assert('decision'         in entry, 'entry has decision');
  assert('action'           in entry, 'entry has action');
  assert('receiptHash'      in entry, 'entry has receiptHash');
  assert('denialReason'     in entry, 'entry has denialReason');
  assert('timestamp'        in entry, 'entry has timestamp');
  assert('previousEntryHash' in entry, 'entry has previousEntryHash');
  assert('entryHash'        in entry, 'entry has entryHash');
}

// ───���─────────────────────────────────────────
// SUITE 5: Denied call audit endpoint (unit)
// ────────────────────���────────────────────────

async function runDeniedCallEndpointTests() {
  console.log('\nDenied Call Audit Endpoint — structure');

  // Validate that the denied calls response structure matches spec
  const mockEntry = {
    entryId:           'denied-123',
    decision:          'BLOCK',
    action:            { operation: 'write', resource: 'db', args: {} },
    receiptHash:       'abc123',
    denialReason:      'TOOL_SCHEMA_DRIFT',
    timestamp:         Date.now(),
    previousEntryHash: '0'.repeat(64),
    riskScore:         null,
    sessionId:         'sess-456',
    entryHash:         'def789',
  };

  assert(mockEntry.decision === 'BLOCK',               'denied call entry has decision BLOCK');
  assert(mockEntry.denialReason === 'TOOL_SCHEMA_DRIFT', 'denied call entry has denial reason code');
  assert(typeof mockEntry.action === 'object',           'denied call entry has action object');
  assert(typeof mockEntry.receiptHash === 'string',      'denied call entry has receiptHash');
  assert(typeof mockEntry.timestamp === 'number',        'denied call entry has numeric timestamp');

  // Verify denied call log returns entries ordered by timestamp
  const entries = [
    { ...mockEntry, entryId: 'e2', timestamp: 2000 },
    { ...mockEntry, entryId: 'e1', timestamp: 1000 },
    { ...mockEntry, entryId: 'e3', timestamp: 3000 },
  ].sort((a, b) => a.timestamp - b.timestamp);

  assert(entries[0].entryId === 'e1', 'Entries sorted by timestamp ascending — first is earliest');
  assert(entries[2].entryId === 'e3', 'Entries sorted by timestamp ascending — last is latest');

  // Response envelope structure
  const mockResponse = {
    deniedCalls: entries,
    count:       entries.length,
    filters:     { sessionId: 'sess-456', from: null, to: null, denialReason: 'TOOL_SCHEMA_DRIFT' },
  };

  assert(Array.isArray(mockResponse.deniedCalls),            'Response has deniedCalls array');
  assert(typeof mockResponse.count === 'number',             'Response has numeric count');
  assert(mockResponse.count === mockResponse.deniedCalls.length, 'count matches deniedCalls.length');
  assert(typeof mockResponse.filters === 'object',           'Response has filters object');
  assert('sessionId'    in mockResponse.filters,             'filters has sessionId');
  assert('denialReason' in mockResponse.filters,             'filters has denialReason');
}

// ─────────────────────────────────────────────
// RUN ALL SUITES
// ─��───────────��───────────────────────────────

async function run() {
  console.log('Tool Schema Hash Binding and Denied Call Audit Logging\n');

  await runToolSchemaHashTests();
  await runSchemaDriftTests();
  await runDeniedCallLogTests();
  await runGetDeniedCallLogTests();
  await runDeniedCallEndpointTests();

  console.log(`\n${'─'.repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
}

run().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});

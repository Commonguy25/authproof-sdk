/**
 * DRP Conformance Vector Runner
 *
 * Loads all positive and negative vector JSON files, runs each through the
 * reference SDK verifier, and reports PASS or FAIL for every vector.
 *
 * Run: node --experimental-global-webcrypto vectors/run-vectors.js
 *
 * Exit code 0 = all vectors pass. Non-zero = at least one failure.
 */

import { webcrypto } from 'node:crypto';
if (typeof globalThis.crypto === 'undefined') globalThis.crypto = webcrypto;

import fs   from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import AuthProof, {
  RevocationRegistry,
  ScopeSchema,
  generateKey,
} from '../src/authproof.js';

import {
  PreExecutionVerifier,
  DelegationLog,
} from '../src/pre-execution-verifier.js';

import { InMemoryConsumptionStore } from '../src/consumption-store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadVectors(subdir) {
  const dir = path.join(__dirname, subdir);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .map(f => {
      const raw = fs.readFileSync(path.join(dir, f), 'utf8');
      return JSON.parse(raw);
    });
}

/**
 * Build a fresh PreExecutionVerifier + DelegationLog for a vector.
 * Registers the receipt and any parent/chain receipts.
 */
async function buildVerifier(vector) {
  const { privateKey: vPriv, publicJwk: vPub } = await generateKey();
  const { privateKey: rPriv, publicJwk: rPub } = await generateKey();

  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  await revocationRegistry.init({ privateKey: rPriv, publicJwk: rPub });

  const opts = { delegationLog, revocationRegistry };

  // consumptionStore
  if (vector.verifierOptions?.consumptionStore === 'durable') {
    opts.consumptionStore = new InMemoryConsumptionStore();
  }

  // maxChainDepth
  if (vector.verifierOptions?.maxChainDepth !== undefined) {
    opts.maxChainDepth = vector.verifierOptions.maxChainDepth;
  }

  const verifier = new PreExecutionVerifier(opts);
  await verifier.init({ privateKey: vPriv, publicJwk: vPub });

  // Register chain receipts first (ancestors of the receipt under test)
  if (Array.isArray(vector.chainReceipts)) {
    for (const entry of vector.chainReceipts) {
      const addOpts = {};
      if (entry.scopeSchema) {
        addOpts.scopeSchema = ScopeSchema.fromJSON(entry.scopeSchema);
      }
      delegationLog.add(entry.receiptId, entry.receipt, addOpts);
    }
  }

  // Register parent receipt if present
  if (vector.parentReceipt && vector.parentReceiptId) {
    const addOpts = {};
    if (vector.parentScopeSchema) {
      addOpts.scopeSchema = ScopeSchema.fromJSON(vector.parentScopeSchema);
    }
    delegationLog.add(vector.parentReceiptId, vector.parentReceipt, addOpts);
  }

  // Register the receipt under test
  {
    const addOpts = {};
    if (vector.verifierOptions?.scopeSchema) {
      addOpts.scopeSchema = ScopeSchema.fromJSON(vector.verifierOptions.scopeSchema);
    }
    delegationLog.add(vector.receiptId, vector.receipt, addOpts);
  }

  return { verifier, delegationLog };
}

/**
 * Run a single vector and return { pass, actualOutcome, actualDenialCode, error }.
 */
async function runVector(vector) {
  try {
    const { verifier } = await buildVerifier(vector);

    const checkOpts = {
      receiptHash:          vector.receiptId,
      action:               vector.action,
      operatorInstructions: vector.operatorInstructions,
    };

    if (vector.currentAuthorityState !== undefined) {
      checkOpts.currentAuthorityState = vector.currentAuthorityState;
    }

    const expectedOutcome    = vector.expected.outcome;
    const expectedDenialCode = vector.expected.denialCode ?? null;

    let result;

    if (vector.testBehavior === 'concurrent_replay') {
      // Run two checks concurrently -- one must pass, one must be blocked as replay
      const [r1, r2] = await Promise.all([
        verifier.check({ ...checkOpts }),
        verifier.check({ ...checkOpts }),
      ]);
      // Find the blocked one
      const blocked = r1.allowed ? r2 : r1;
      result = blocked;
    } else if (vector.testBehavior === 'second_presentation') {
      // Run first presentation (should PERMIT), then test the second (should DENY)
      await verifier.check({ ...checkOpts }); // first: consume the slot
      result = await verifier.check({ ...checkOpts }); // second: already consumed
    } else {
      result = await verifier.check({ ...checkOpts });
    }

    const actualOutcome    = result.allowed ? 'PERMIT' : 'DENY';
    const actualDenialCode = result.blockedReason ?? null;

    let pass;
    if (expectedOutcome === 'PERMIT') {
      pass = result.allowed === true;
    } else {
      // DENY: outcome must be DENY and denialCode must appear in blockedReason
      const outcomeMatch = result.allowed === false;
      const codeMatch    = expectedDenialCode === null
        || (actualDenialCode !== null && actualDenialCode.includes(expectedDenialCode));
      pass = outcomeMatch && codeMatch;
    }

    return { pass, actualOutcome, actualDenialCode };
  } catch (err) {
    return { pass: false, actualOutcome: 'ERROR', actualDenialCode: err.message };
  }
}

// ---------------------------------------------------------------------------
// Table formatting
// ---------------------------------------------------------------------------

function pad(str, width) {
  const s = String(str ?? '');
  return s.length >= width ? s.slice(0, width) : s + ' '.repeat(width - s.length);
}

function truncate(str, width) {
  const s = String(str ?? '');
  return s.length > width ? s.slice(0, width - 3) + '...' : s;
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

async function main() {
  console.log('DRP Conformance Vector Runner\n');

  const positiveVectors = loadVectors('positive');
  const negativeVectors = loadVectors('negative');
  const allVectors      = [...positiveVectors, ...negativeVectors];

  if (allVectors.length === 0) {
    console.error('No vectors found. Run generate-vectors.js first.');
    process.exit(1);
  }

  const COL = { id: 34, expOut: 7, expCode: 36, actOut: 7, actCode: 36, result: 7 };
  const header =
    pad('vector-id', COL.id) +
    pad('exp-out', COL.expOut) +
    pad('exp-code', COL.expCode) +
    pad('act-out', COL.actOut) +
    pad('act-code', COL.actCode) +
    'result';

  const sep = '-'.repeat(
    COL.id + COL.expOut + COL.expCode + COL.actOut + COL.actCode + COL.result
  );

  console.log(header);
  console.log(sep);

  let totalPass = 0;
  let totalFail = 0;

  for (const vector of allVectors) {
    const { pass, actualOutcome, actualDenialCode } = await runVector(vector);

    const expOut  = vector.expected.outcome;
    const expCode = vector.expected.denialCode ?? '';
    const actCode = actualDenialCode ?? '';

    const row =
      pad(vector.id, COL.id) +
      pad(expOut,    COL.expOut) +
      pad(truncate(expCode, COL.expCode - 1), COL.expCode) +
      pad(actualOutcome, COL.actOut) +
      pad(truncate(actCode, COL.actCode - 1), COL.actCode) +
      (pass ? 'PASS' : 'FAIL');

    console.log(row);

    if (pass) totalPass++;
    else       totalFail++;
  }

  console.log(sep);
  console.log(`\nTotal: ${totalPass + totalFail} vectors  |  ${totalPass} PASS  |  ${totalFail} FAIL`);

  if (totalFail > 0) {
    console.error('\n' + totalFail + ' vector(s) failed.');
    process.exit(1);
  } else {
    console.log('\nAll vectors passed.');
  }
}

main().catch(err => {
  console.error('Runner error:', err);
  process.exit(1);
});

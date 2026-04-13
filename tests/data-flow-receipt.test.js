/**
 * AuthProof — Feature 1: Data Flow Receipt
 * Run: node --experimental-global-webcrypto tests/data-flow-receipt.test.js
 *
 * Tests cover:
 *  - DataTagger: constructor, tag(), getManifest(), inspect()
 *  - TaintTracker: constructor, recordOutput(), getEgressLog()
 *  - DataFlowReceipt: generate(), verify()
 *  - ActionLog integration
 *  - End-to-end flow
 */

import AuthProof, { DataTagger, TaintTracker, DataFlowReceipt, ActionLog } from '../src/authproof.js';

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
  console.log('Feature 1 — Data Flow Receipt\n');

  // ── Shared key pair ─────────────────────────────────────────────────
  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const receiptHash = 'a'.repeat(64); // representative receipt hash

  // ── Test Group 1: DataTagger constructor validation ──────────────────
  console.log('Test Group 1: DataTagger constructor validation');

  // Test 1: throws for missing receiptHash
  try {
    new DataTagger({});
    assert(false, 'should throw for missing receiptHash');
  } catch (e) {
    assert(e.message.includes('receiptHash'), 'throws for missing receiptHash');
  }

  // Test 2: constructs successfully
  const tagger = new DataTagger({ receiptHash });
  assert(tagger instanceof DataTagger, 'constructs a DataTagger instance');

  // Test 3: manifest is empty on construction
  assert(tagger.getManifest().length === 0, 'manifest is empty on construction');

  // ── Test Group 2: DataTagger.tag() ──────────────────────────────────
  console.log('\nTest Group 2: DataTagger.tag()');

  const now = Date.now();

  // Test 4: throws for missing source
  try {
    await tagger.tag('some data', { sensitivity: 'PII', accessedAt: now });
    assert(false, 'should throw for missing source');
  } catch (e) {
    assert(e.message.includes('source'), 'throws for missing source');
  }

  // Test 5: throws for missing sensitivity
  try {
    await tagger.tag('some data', { source: 'email', accessedAt: now });
    assert(false, 'should throw for missing sensitivity');
  } catch (e) {
    assert(e.message.includes('sensitivity'), 'throws for missing sensitivity');
  }

  // Test 6: throws for missing accessedAt
  try {
    await tagger.tag('some data', { source: 'email', sensitivity: 'PII' });
    assert(false, 'should throw for missing accessedAt');
  } catch (e) {
    assert(e.message.includes('accessedAt'), 'throws for missing accessedAt');
  }

  // Test 7: returns correct tag structure
  const tag1 = await tagger.tag('user@example.com', { source: 'email-inbox', sensitivity: 'PII', accessedAt: now });
  assert(typeof tag1.tagId === 'string' && tag1.tagId.length === 64, 'tagId is 64-char hex');
  assert(typeof tag1.dataHash === 'string' && tag1.dataHash.length === 64, 'dataHash is 64-char hex');
  assert(tag1.receiptHash === receiptHash, 'tag contains correct receiptHash');
  assert(tag1.source === 'email-inbox', 'tag contains correct source');
  assert(tag1.sensitivity === 'PII', 'tag contains correct sensitivity');
  assert(tag1.accessedAt === now, 'tag contains correct accessedAt');

  // Test 8: raw data is NOT stored in the tag
  assert(!JSON.stringify(tag1).includes('user@example.com'), 'raw data not stored in tag entry');

  // Test 9: tagId = SHA-256(dataHash + receiptHash + accessedAt)
  const expectedTagId = await (async () => {
    const enc = s => new TextEncoder().encode(s);
    const hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2,'0')).join('');
    const h = s => crypto.subtle.digest('SHA-256', enc(s)).then(hex);
    const dh = await h('user@example.com');
    return h(dh + receiptHash + String(now));
  })();
  assert(tag1.tagId === expectedTagId, 'tagId computed as SHA-256(dataHash + receiptHash + accessedAt)');

  // ── Test Group 3: DataTagger.getManifest() ───────────────────────────
  console.log('\nTest Group 3: DataTagger.getManifest()');

  // Test 10: manifest grows after tag()
  const tag2 = await tagger.tag('John Doe', { source: 'user-profile', sensitivity: 'PII', accessedAt: now });
  const manifest = tagger.getManifest();
  assert(manifest.length === 2, 'manifest has 2 entries after 2 tags');

  // Test 11: manifest is append-only — returned copy cannot mutate internal state
  manifest.push({ fake: true });
  assert(tagger.getManifest().length === 2, 'manifest is append-only (mutation of returned copy has no effect)');

  // Test 12: manifest entries have correct shape
  assert(manifest[0].tagId === tag1.tagId, 'first manifest entry matches first tag');

  // ── Test Group 4: DataTagger.inspect() — exact hash matching ─────────
  console.log('\nTest Group 4: DataTagger.inspect() — exact hash matching');

  // Test 13: inspect of clean output returns clean:true
  const clean = await tagger.inspect('This is a totally clean output with no sensitive data.');
  assert(clean.clean === true, 'clean output returns clean:true');
  assert(clean.foundTags.length === 0, 'clean output has no foundTags');

  // Test 14: inspect of exact tagged data returns clean:false with exact-hash match
  const exactMatch = await tagger.inspect('user@example.com');
  assert(exactMatch.clean === false, 'exact tagged data returns clean:false');
  const hashTag = exactMatch.foundTags.find(t => t.matchType === 'exact-hash');
  assert(hashTag !== undefined, 'exact-hash match detected');
  assert(hashTag.source === 'email-inbox', 'exact-hash match has correct source');

  // Test 15: inspect result has reason string
  assert(typeof exactMatch.reason === 'string' && exactMatch.reason.length > 0, 'inspect result has reason string');

  // Test 16: inspect of unseen data returns clean
  const unseen = await tagger.inspect('completely unrelated content xyz123');
  assert(unseen.clean === true, 'unseen data returns clean:true');

  // ── Test Group 5: DataTagger.inspect() — PII pattern detection ───────
  console.log('\nTest Group 5: DataTagger.inspect() — PII pattern detection');

  const freshTagger = new DataTagger({ receiptHash }); // clean tagger, no tags

  // Test 17: detects email address pattern
  const emailResult = await freshTagger.inspect('Contact us at support@company.com for help.');
  assert(emailResult.clean === false, 'email address in output → clean:false');
  const piiEntry = emailResult.foundTags.find(t => t.matchType === 'pii-pattern');
  assert(piiEntry !== undefined, 'pii-pattern entry present for email');
  assert(piiEntry.patterns.some(p => p.type === 'email'), 'email pattern identified');

  // Test 18: detects phone number pattern
  const phoneResult = await freshTagger.inspect('Call us at 555-867-5309 for support.');
  assert(phoneResult.clean === false, 'phone number in output → clean:false');
  assert(phoneResult.foundTags.find(t => t.matchType === 'pii-pattern')?.patterns.some(p => p.type === 'phone'),
    'phone pattern identified');

  // Test 19: detects SSN pattern
  const ssnResult = await freshTagger.inspect('SSN on file: 123-45-6789');
  assert(ssnResult.clean === false, 'SSN in output → clean:false');
  assert(ssnResult.foundTags.find(t => t.matchType === 'pii-pattern')?.patterns.some(p => p.type === 'ssn'),
    'SSN pattern identified');

  // Test 20: detects credit card pattern
  const ccResult = await freshTagger.inspect('Card ending in 4111111111111111 was charged.');
  assert(ccResult.clean === false, 'credit card in output → clean:false');
  assert(ccResult.foundTags.find(t => t.matchType === 'pii-pattern')?.patterns.some(p => p.type === 'credit-card'),
    'credit card pattern identified');

  // Test 21: output with no PII patterns returns clean
  const noPii = await freshTagger.inspect('The weather today is sunny with a high of 72.');
  assert(noPii.clean === true, 'non-PII output returns clean:true');

  // ── Test Group 6: inspect() — combined matching ───────────────────────
  console.log('\nTest Group 6: inspect() — combined matching');

  // Test 22: output containing both exact tagged data and additional PII
  const taggerCombo = new DataTagger({ receiptHash });
  await taggerCombo.tag('secret-document-abc', { source: 'vault', sensitivity: 'CONFIDENTIAL', accessedAt: now });
  const comboResult = await taggerCombo.inspect('secret-document-abc contact admin@corp.com');
  // This won't exact-hash match (different string) but will match PII
  assert(comboResult.clean === false, 'combined output with PII → clean:false');

  // Test 23: reason string mentions detected findings
  assert(typeof comboResult.reason === 'string', 'inspect reason is a string');

  // Test 24: inspect() handles null/undefined gracefully
  const nullResult = await freshTagger.inspect(null);
  assert(typeof nullResult.clean === 'boolean', 'inspect(null) returns a result without throwing');

  // ── Test Group 7: TaintTracker constructor validation ────────────────
  console.log('\nTest Group 7: TaintTracker constructor validation');

  // Test 25: throws when tagger is missing
  try {
    new TaintTracker({ receiptHash });
    assert(false, 'should throw for missing tagger');
  } catch (e) {
    assert(e.message.includes('tagger'), 'throws for missing tagger');
  }

  // Test 26: throws when tagger is not a DataTagger instance
  try {
    new TaintTracker({ tagger: { inspect: () => {} }, receiptHash });
    assert(false, 'should throw for non-DataTagger tagger');
  } catch (e) {
    assert(e.message.includes('DataTagger'), 'throws for non-DataTagger tagger');
  }

  // Test 27: throws for missing receiptHash
  try {
    new TaintTracker({ tagger });
    assert(false, 'should throw for missing receiptHash');
  } catch (e) {
    assert(e.message.includes('receiptHash'), 'throws for missing receiptHash');
  }

  const tracker = new TaintTracker({ tagger, receiptHash });
  assert(tracker instanceof TaintTracker, 'constructs a TaintTracker instance');

  // ── Test Group 8: TaintTracker.recordOutput() — clean outputs ────────
  console.log('\nTest Group 8: TaintTracker.recordOutput() — clean outputs');

  // Test 28: throws for missing destination
  try {
    await tracker.recordOutput({ output: 'text', outputType: 'response' });
    assert(false, 'should throw for missing destination');
  } catch (e) {
    assert(e.message.includes('destination'), 'throws for missing destination');
  }

  // Test 29: throws for missing outputType
  try {
    await tracker.recordOutput({ output: 'text', destination: 'user' });
    assert(false, 'should throw for missing outputType');
  } catch (e) {
    assert(e.message.includes('outputType'), 'throws for missing outputType');
  }

  // Test 30: clean output to user returns clean:true, no violation
  const cleanResult = await tracker.recordOutput({
    output: 'Here is a summary of your calendar.',
    destination: 'user',
    outputType: 'response',
  });
  assert(cleanResult.clean === true, 'clean output → clean:true');
  assert(cleanResult.policyViolation === false, 'clean output → no policy violation');
  assert(typeof cleanResult.outputHash === 'string' && cleanResult.outputHash.length === 64,
    'recordOutput has 64-char outputHash');
  assert(cleanResult.destination === 'user', 'destination recorded correctly');

  // Test 31: every output logged regardless of clean status
  assert(tracker.getEgressLog().length === 1, 'first output appended to egress log');

  // ── Test Group 9: TaintTracker.recordOutput() — tainted outputs ──────
  console.log('\nTest Group 9: TaintTracker.recordOutput() — tainted outputs');

  // Test 32: tainted output to user (not high-risk) — no policy violation
  const taintedToUser = await tracker.recordOutput({
    output: 'user@example.com',  // matches tagged hash from earlier
    destination: 'user',
    outputType: 'response',
  });
  assert(taintedToUser.clean === false, 'exact-tagged output to user → clean:false');
  assert(taintedToUser.policyViolation === false,
    'tagged PII output to user destination → no policy violation');
  assert(taintedToUser.taintedTags.length > 0, 'taintedTags populated');

  // Test 33: tainted output logged regardless
  assert(tracker.getEgressLog().length === 2, 'tainted output appended to egress log');

  // Test 34: output with PII pattern to log — no violation (log is not high-risk)
  const piiToLog = await tracker.recordOutput({
    output: 'Processing request from admin@corp.com',
    destination: 'log',
    outputType: 'log-entry',
  });
  assert(piiToLog.policyViolation === false, 'PII to log destination → no policy violation');
  assert(piiToLog.clean === false, 'PII to log → clean:false');

  // ── Test Group 10: TaintTracker.recordOutput() — policy violations ───
  console.log('\nTest Group 10: TaintTracker.recordOutput() — policy violations');

  // Test 35: PII to external-api → policy violation
  const piiToApi = await tracker.recordOutput({
    output: 'user@example.com',  // exact hash match tagged as PII
    destination: 'external-api',
    outputType: 'api-call',
  });
  assert(piiToApi.policyViolation === true, 'PII tagged data to external-api → policy violation');
  assert(typeof piiToApi.reason === 'string' && piiToApi.reason.includes('Policy violation'),
    'policy violation reason mentions "Policy violation"');

  // Test 36: PII pattern to file → policy violation
  const piiToFile = await tracker.recordOutput({
    output: 'Customer SSN: 123-45-6789',
    destination: 'file',
    outputType: 'file-write',
  });
  assert(piiToFile.policyViolation === true, 'PII pattern to file → policy violation');

  // Test 37: clean data to external-api → no violation (data not tainted)
  const cleanToApi = await tracker.recordOutput({
    output: 'Total items processed: 42',
    destination: 'external-api',
    outputType: 'api-call',
  });
  assert(cleanToApi.policyViolation === false, 'clean data to external-api → no policy violation');

  // Test 38: non-PII sensitivity tagged data to external-api — no violation if not flagged as PII
  const bizTagger = new DataTagger({ receiptHash });
  await bizTagger.tag('internal-report-data', { source: 'reports', sensitivity: 'INTERNAL', accessedAt: now });
  const bizTracker = new TaintTracker({ tagger: bizTagger, receiptHash });
  const internalToApi = await bizTracker.recordOutput({
    output: 'internal-report-data',
    destination: 'external-api',
    outputType: 'api-call',
  });
  // Tainted (exact hash match) and external-api, but sensitivity is INTERNAL not PII — behavior per policy
  assert(typeof internalToApi.policyViolation === 'boolean', 'non-PII sensitivity policy violation is boolean');

  // Test 39: multiple violations accumulate in egress log
  const violations = tracker.getEgressLog().filter(e => e.policyViolation);
  assert(violations.length >= 2, 'multiple violations accumulated in egress log');

  // ── Test Group 11: TaintTracker.getEgressLog() ────────────────────────
  console.log('\nTest Group 11: TaintTracker.getEgressLog()');

  // Test 40: egress log is append-only
  const logCopy = tracker.getEgressLog();
  logCopy.push({ fake: true });
  assert(tracker.getEgressLog().length === logCopy.length - 1, 'egress log is append-only (copy cannot mutate internal)');

  // Test 41: all entries have required fields
  for (const entry of tracker.getEgressLog()) {
    assert(
      typeof entry.outputHash === 'string' &&
      typeof entry.destination === 'string' &&
      typeof entry.policyViolation === 'boolean' &&
      typeof entry.clean === 'boolean' &&
      typeof entry.loggedAt === 'number',
      `egress log entry has required fields (destination: ${entry.destination})`
    );
  }

  // Test 42: egress log preserves insertion order
  const log = tracker.getEgressLog();
  assert(log[0].destination === 'user' && log[0].clean === true, 'egress log preserves insertion order');

  // ── Test Group 12: DataFlowReceipt.generate() — validation ───────────
  console.log('\nTest Group 12: DataFlowReceipt.generate() — validation');

  // Test 43: throws for missing delegationReceiptHash
  try {
    await DataFlowReceipt.generate({ tagger, tracker, privateKey, publicJwk });
    assert(false, 'should throw for missing delegationReceiptHash');
  } catch (e) {
    assert(e.message.includes('delegationReceiptHash'), 'throws for missing delegationReceiptHash');
  }

  // Test 44: throws when tagger is not a DataTagger
  try {
    await DataFlowReceipt.generate({ delegationReceiptHash: receiptHash, tagger: {}, tracker, privateKey, publicJwk });
    assert(false, 'should throw for invalid tagger');
  } catch (e) {
    assert(e.message.includes('DataTagger'), 'throws for invalid tagger');
  }

  // Test 45: throws when tracker is not a TaintTracker
  try {
    await DataFlowReceipt.generate({ delegationReceiptHash: receiptHash, tagger, tracker: {}, privateKey, publicJwk });
    assert(false, 'should throw for invalid tracker');
  } catch (e) {
    assert(e.message.includes('TaintTracker'), 'throws for invalid tracker');
  }

  // Test 46: throws for missing privateKey
  try {
    await DataFlowReceipt.generate({ delegationReceiptHash: receiptHash, tagger, tracker, publicJwk });
    assert(false, 'should throw for missing privateKey');
  } catch (e) {
    assert(e.message.includes('privateKey'), 'throws for missing privateKey');
  }

  // ── Test Group 13: DataFlowReceipt.generate() — content ──────────────
  console.log('\nTest Group 13: DataFlowReceipt.generate() — content');

  const dfr = await DataFlowReceipt.generate({
    delegationReceiptHash: receiptHash,
    tagger,
    tracker,
    privateKey,
    publicJwk,
  });

  // Test 47: generated receipt has required fields
  assert(typeof dfr.bodyHash === 'string' && dfr.bodyHash.length === 64, 'receipt has 64-char bodyHash');
  assert(typeof dfr.signature === 'string', 'receipt has signature');
  assert(typeof dfr.signerPublicKey === 'object', 'receipt has signerPublicKey');
  assert(typeof dfr.generatedAt === 'string', 'receipt has generatedAt timestamp');
  assert(Array.isArray(dfr.dataManifest), 'receipt has dataManifest array');
  assert(Array.isArray(dfr.egressLog), 'receipt has egressLog array');
  assert(Array.isArray(dfr.violations), 'receipt has violations array');
  assert(typeof dfr.clean === 'boolean', 'receipt has clean flag');

  // Test 48: dataManifest reflects tagger state
  assert(dfr.dataManifest.length === tagger.getManifest().length,
    'dataManifest length matches tagger manifest length');

  // Test 49: violations array contains only policy-violating entries
  assert(dfr.violations.every(v => v.policyViolation === true),
    'violations array contains only policy-violating entries');

  // Test 50: clean flag is false when there are violations
  const hasViolations = tracker.getEgressLog().some(e => e.policyViolation);
  assert(dfr.clean === !hasViolations, 'clean flag correctly reflects absence of violations');

  // Test 51: timestampType is set
  assert(dfr.timestampType === 'RFC3161' || dfr.timestampType === 'UNVERIFIED_TIMESTAMP',
    'timestampType is RFC3161 or UNVERIFIED_TIMESTAMP');

  // ── Test Group 14: DataFlowReceipt.verify() ──────────────────────────
  console.log('\nTest Group 14: DataFlowReceipt.verify()');

  // Test 52: verify() returns valid:true for correct receipt
  const verifyResult = await DataFlowReceipt.verify(dfr);
  assert(verifyResult.valid === true, 'verify() returns valid:true for correct receipt');
  assert(typeof verifyResult.reason === 'string', 'verify() result has reason string');

  // Test 53: verify(null) returns valid:false
  const nullVerify = await DataFlowReceipt.verify(null);
  assert(nullVerify.valid === false, 'verify(null) returns valid:false');

  // Test 54: verify() returns valid:false for missing signature
  const noSig = { ...dfr, signature: undefined };
  assert((await DataFlowReceipt.verify(noSig)).valid === false, 'missing signature → valid:false');

  // Test 55: verify() detects body tampering (modified clean flag)
  const tampered = { ...dfr, clean: !dfr.clean };
  const tamperedResult = await DataFlowReceipt.verify(tampered);
  assert(tamperedResult.valid === false, 'tampered body → valid:false');
  assert(tamperedResult.reason.toLowerCase().includes('tampered') || tamperedResult.reason.includes('mismatch'),
    'tamper detected via bodyHash mismatch');

  // Test 56: verify() returns valid:false for wrong signer key
  const { publicJwk: otherPub } = await AuthProof.generateKey();
  const wrongKey = { ...dfr, signerPublicKey: otherPub };
  assert((await DataFlowReceipt.verify(wrongKey)).valid === false, 'wrong signer key → valid:false');

  // ── Test Group 15: ActionLog integration ─────────────────────────────
  console.log('\nTest Group 15: ActionLog integration');

  const { privateKey: logKey, publicJwk: logPub } = await AuthProof.generateKey();
  const actionLog = new ActionLog();
  await actionLog.init({ privateKey: logKey, publicJwk: logPub, tsaUrl: null });

  const logReceiptHash = 'b'.repeat(64);
  const logTagger  = new DataTagger({ receiptHash: logReceiptHash });
  await logTagger.tag('sensitive-user-data', { source: 'db', sensitivity: 'PII', accessedAt: Date.now() });
  const logTracker = new TaintTracker({ tagger: logTagger, receiptHash: logReceiptHash });

  // Test 57: record() with output + taintTracker runs taint check automatically
  const entry = await actionLog.record(
    logReceiptHash,
    { operation: 'read', resource: 'database' },
    { output: 'sensitive-user-data', taintTracker: logTracker }
  );
  assert('taintResult' in entry, 'entry includes taintResult when output provided');
  assert(typeof entry.taintResult.outputHash === 'string', 'taintResult has outputHash');

  // Test 58: taint result on entry reflects inspection of provided output
  assert(entry.taintResult.clean === false, 'taintResult.clean:false for tagged output');
  assert(entry.taintResult.destination === 'log', 'taintResult destination is "log"');
  assert(entry.taintResult.outputType === 'log-entry', 'taintResult outputType is "log-entry"');

  // Test 59: egress log updated after ActionLog.record() with output
  assert(logTracker.getEgressLog().length === 1, 'egress log has 1 entry after ActionLog.record()');

  // Test 60: record() without output/taintTracker still works (backward compat)
  const plainEntry = await actionLog.record(
    logReceiptHash,
    { operation: 'write', resource: 'calendar' }
  );
  assert(!('taintResult' in plainEntry), 'entry without output has no taintResult field');

  // ── Test Group 16: End-to-end flow ────────────────────────────────────
  console.log('\nTest Group 16: End-to-end flow');

  // Test 61: full cycle — tag, track, generate receipt, verify
  const e2eReceiptHash = 'c'.repeat(64);
  const e2eTagger  = new DataTagger({ receiptHash: e2eReceiptHash });
  const e2eTracker = new TaintTracker({ tagger: e2eTagger, receiptHash: e2eReceiptHash });

  await e2eTagger.tag('alice@corp.com', { source: 'email-inbox', sensitivity: 'PII', accessedAt: Date.now() });
  await e2eTracker.recordOutput({ output: 'Summary report generated.', destination: 'user', outputType: 'response' });
  await e2eTracker.recordOutput({ output: 'alice@corp.com', destination: 'user', outputType: 'response' });

  const e2eReceipt = await DataFlowReceipt.generate({
    delegationReceiptHash: e2eReceiptHash,
    tagger: e2eTagger,
    tracker: e2eTracker,
    privateKey,
    publicJwk,
  });

  assert((await DataFlowReceipt.verify(e2eReceipt)).valid === true,
    'end-to-end: generated receipt verifies successfully');

  // Test 62: clean execution produces clean receipt
  const cleanHash    = 'd'.repeat(64);
  const cleanTagger  = new DataTagger({ receiptHash: cleanHash });
  const cleanTracker = new TaintTracker({ tagger: cleanTagger, receiptHash: cleanHash });
  await cleanTracker.recordOutput({ output: 'No PII here.', destination: 'user', outputType: 'response' });

  const cleanDFR = await DataFlowReceipt.generate({
    delegationReceiptHash: cleanHash,
    tagger: cleanTagger,
    tracker: cleanTracker,
    privateKey,
    publicJwk,
  });

  assert(cleanDFR.clean === true, 'clean execution produces receipt with clean:true');
  assert(cleanDFR.violations.length === 0, 'clean execution has zero violations');

  // Test 63: exports accessible on AuthProof default export
  assert(typeof AuthProof.DataTagger === 'function', 'DataTagger exported on AuthProof');
  assert(typeof AuthProof.TaintTracker === 'function', 'TaintTracker exported on AuthProof');
  assert(typeof AuthProof.DataFlowReceipt === 'function', 'DataFlowReceipt exported on AuthProof');

  // ── Summary ──────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Data Flow Receipt tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

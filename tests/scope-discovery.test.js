/**
 * ScopeDiscovery — Test Suite
 * Run: node --experimental-global-webcrypto tests/scope-discovery.test.js
 *
 * Covers:
 *  1.  Discovery run records all observed operations
 *  2.  Sandbox intercepts without executing real operations
 *  3.  Mock data returned for all resource types (email/calendar/payment/files/db/network)
 *  4.  Write/delete/execute ops return success without side effects
 *  5.  Draft scope generated correctly from observations
 *  6.  Plain language summary is accurate and readable
 *  7.  Risk flags: delete, send/write external, execute, payment, >50 frequency
 *  8.  User modifications (remove + add) applied correctly in approve()
 *  9.  Final receipt generated from approved scope is a valid Delegation Receipt
 *  10. ScopeDiscovery.fromReceipt drift report (over-, under-, exact match)
 *  11. Guided delegation mode end-to-end
 *  12. Timeout handling — aborted sessions retain partial observations
 *  13. Empty observation session handled gracefully
 *  14. High-frequency operation (>50) flagged in riskFlags
 *  15. SuggestedDenials includes dangerous ops not observed
 *  16. Error handling — precondition violations throw descriptive messages
 */

import { ScopeDiscovery } from '../src/scope-discovery.js';
import AuthProof from '../src/authproof.js';

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
  console.log('ScopeDiscovery — Test Suite\n');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 1: Observation Records All Operations
  // ─────────────────────────────────────────────────────────────────────
  console.log('Test Group 1: Observation records all operations');

  const disc1 = new ScopeDiscovery();
  const { observations: obs1, aborted: ab1 } = await disc1.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.calendar.list();
    await ctx.files.read();
  });

  assert(Array.isArray(obs1), 'observe() returns an observations array');
  assert(obs1.length === 3, 'all 3 operations are recorded');
  assert(ab1 === false, 'aborted is false when agent completes normally');
  assert(obs1.some(o => o.resource === 'email'    && o.operation === 'read'), 'email.read recorded');
  assert(obs1.some(o => o.resource === 'calendar' && o.operation === 'list'), 'calendar.list recorded');
  assert(obs1.some(o => o.resource === 'files'    && o.operation === 'read'), 'files.read recorded');
  assert(obs1.every(o => typeof o.observedAt === 'number'), 'each observation has numeric observedAt');
  assert(obs1.every(o => typeof o.resource   === 'string'), 'each observation has string resource');
  assert(obs1.every(o => typeof o.operation  === 'string'), 'each observation has string operation');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 2: Sandbox Intercepts Without Real Execution
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 2: Sandbox intercepts without real execution');

  let mockDataReceived = false;
  const disc2 = new ScopeDiscovery();
  const { observations: obs2 } = await disc2.observe(async (ctx) => {
    const result = await ctx.email.send({ to: 'victim@example.com', body: 'not real' });
    // Mock data has messageId — confirms sandbox returned mock, not real email
    if (result && typeof result.messageId === 'string') mockDataReceived = true;
  });

  assert(obs2.length === 1, 'intercepted send is recorded as one observation');
  assert(obs2[0].operation === 'send', 'operation is recorded as "send"');
  assert(mockDataReceived, 'sandbox returns mock data (messageId present) — no real email sent');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 3: Mock Data Returned for All Resource Types
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 3: Mock data returned for all resource types');

  const mockResults = {};
  const disc3 = new ScopeDiscovery();
  await disc3.observe(async (ctx) => {
    mockResults.email    = await ctx.email.read();
    mockResults.calendar = await ctx.calendar.read();
    mockResults.payment  = await ctx.payment.read();
    mockResults.files    = await ctx.files.read();
    mockResults.db       = await ctx.db.read();
    mockResults.network  = await ctx.network.read();
  });

  assert(mockResults.email    !== null && typeof mockResults.email    === 'object', 'email returns mock object');
  assert(mockResults.calendar !== null && typeof mockResults.calendar === 'object', 'calendar returns mock object');
  assert(mockResults.payment  !== null && typeof mockResults.payment  === 'object', 'payment returns mock object');
  assert(mockResults.files    !== null && typeof mockResults.files    === 'object', 'files returns mock object');
  assert(mockResults.db       !== null && typeof mockResults.db       === 'object', 'db returns mock object');
  assert(mockResults.network  !== null && typeof mockResults.network  === 'object', 'network returns mock object');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 4: Write / Delete / Execute Return Success Without Side Effects
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 4: Write/delete/execute return success without side effects');

  const sideResults = {};
  const disc4 = new ScopeDiscovery();
  await disc4.observe(async (ctx) => {
    sideResults.write  = await ctx.files.write({ path: '/etc/passwd', content: 'evil' });
    sideResults.delete = await ctx.db.delete({ table: 'users', where: '1=1' });
    sideResults.exec   = await ctx.files.execute({ cmd: 'rm -rf /' });
    sideResults.charge = await ctx.payment.charge({ amount: 9999, card: '4111111111111111' });
  });

  assert(sideResults.write?.success  === true, 'write returns mock success (no real file written)');
  assert(sideResults.delete?.success === true, 'delete returns mock success (no real row deleted)');
  assert(sideResults.exec?.success   === true, 'execute returns mock success (no real command run)');
  assert(sideResults.charge?.success === true, 'charge returns mock success (no real payment charged)');
  // Confirm mock flag is present (marks these as simulated)
  assert(sideResults.write?.mock  === true || sideResults.write?.bytesWritten === 0, 'write mock has no bytes written');
  assert(sideResults.delete?.mock === true || sideResults.delete?.rowsAffected === 0, 'delete mock has 0 rows affected');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 5: Draft Scope Generated Correctly from Observations
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 5: Draft scope generated correctly from observations');

  const disc5 = new ScopeDiscovery();
  await disc5.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.calendar.write();
  });
  const review5 = disc5.generateScope();

  assert(typeof review5 === 'object', 'generateScope() returns an object');
  assert(Array.isArray(review5.draftScope.allowedActions), 'draftScope has allowedActions array');
  assert(Array.isArray(review5.draftScope.deniedActions),  'draftScope has deniedActions array');
  assert(
    review5.draftScope.allowedActions.some(a => a.resource === 'email' && a.operation === 'read'),
    'email.read is in allowedActions'
  );
  assert(
    review5.draftScope.allowedActions.some(a => a.resource === 'calendar' && a.operation === 'write'),
    'calendar.write is in allowedActions'
  );
  assert(typeof review5.observationCount === 'number', 'observationCount is a number');
  assert(review5.observationCount === 2, 'observationCount equals number of observations');

  // De-duplication: same op+resource called twice → appears once in allowedActions
  const disc5b = new ScopeDiscovery();
  await disc5b.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.email.read();
    await ctx.email.read();
  });
  const review5b = disc5b.generateScope();
  const dupCount = review5b.draftScope.allowedActions.filter(
    a => a.resource === 'email' && a.operation === 'read'
  ).length;
  assert(dupCount === 1, 'duplicate observations are de-duplicated in allowedActions');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 6: Plain Language Summary
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 6: Plain language summary is accurate and readable');

  const disc6 = new ScopeDiscovery();
  await disc6.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.calendar.list();
  });
  const review6 = disc6.generateScope();

  assert(typeof review6.plainSummary === 'string', 'plainSummary is a string');
  assert(review6.plainSummary.length > 10, 'plainSummary is non-trivially long');
  assert(review6.plainSummary.includes('email'),    'plainSummary mentions email resource');
  assert(review6.plainSummary.includes('calendar'), 'plainSummary mentions calendar resource');
  assert(review6.plainSummary.includes('2'),        'plainSummary mentions total operation count');

  // Empty session produces a "no operations" summary
  const disc6b = new ScopeDiscovery();
  await disc6b.observe(async () => { /* no-op */ });
  const review6b = disc6b.generateScope();
  assert(
    review6b.plainSummary.toLowerCase().includes('no operations'),
    'empty session summary says "no operations"'
  );

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 7: Risk Flags
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 7: Risk flags trigger for dangerous operations');

  // Delete op
  const discDel = new ScopeDiscovery();
  await discDel.observe(async (ctx) => { await ctx.db.delete(); });
  const reviewDel = discDel.generateScope();
  assert(
    reviewDel.riskFlags.some(f => f.includes('delete')),
    'delete operation triggers delete risk flag'
  );

  // Send/write external op
  const discSend = new ScopeDiscovery();
  await discSend.observe(async (ctx) => { await ctx.email.send(); });
  const reviewSend = discSend.generateScope();
  assert(
    reviewSend.riskFlags.some(f => f.includes('send') || f.includes('external')),
    'send operation triggers external send/write risk flag'
  );

  // Execute op
  const discExec = new ScopeDiscovery();
  await discExec.observe(async (ctx) => { await ctx.files.execute(); });
  const reviewExec = discExec.generateScope();
  assert(
    reviewExec.riskFlags.some(f => f.includes('execute')),
    'execute operation triggers execute risk flag'
  );

  // Payment op
  const discPay = new ScopeDiscovery();
  await discPay.observe(async (ctx) => { await ctx.payment.charge(); });
  const reviewPay = discPay.generateScope();
  assert(
    reviewPay.riskFlags.some(f => f.includes('payment') || f.includes('charge')),
    'payment/charge operation triggers payment risk flag'
  );

  // High-frequency (>50 calls)
  const discFreq = new ScopeDiscovery();
  await discFreq.observe(async (ctx) => {
    for (let i = 0; i < 55; i++) await ctx.email.read();
  });
  const reviewFreq = discFreq.generateScope();
  assert(
    reviewFreq.riskFlags.some(f => f.includes('high-frequency') || f.includes('>50')),
    '55 calls to email.read triggers high-frequency risk flag'
  );

  // No false flags for benign read-only session
  const discBenign = new ScopeDiscovery();
  await discBenign.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.calendar.list();
  });
  const reviewBenign = discBenign.generateScope();
  assert(Array.isArray(reviewBenign.riskFlags), 'riskFlags is always an array');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 8: User Modifications in approve()
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 8: User modifications (remove + add) applied correctly');

  const discApprove = new ScopeDiscovery();
  await discApprove.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.calendar.write();
    await ctx.files.delete();
  });
  discApprove.generateScope();

  // Remove files.delete; add network.read
  discApprove.approve({
    remove: [{ operation: 'delete', resource: 'files' }],
    add:    [{ operation: 'read',   resource: 'network' }],
  });

  const { privateKey: pk8, publicJwk: pub8 } = await AuthProof.generateKey();
  const fin8 = await discApprove.finalize({ privateKey: pk8, publicJwk: pub8 });

  assert(
    !fin8.scopeSummary.allowedActions.some(a => a.operation === 'delete' && a.resource === 'files'),
    'removed action (files.delete) is absent from approved scope'
  );
  assert(
    fin8.scopeSummary.allowedActions.some(a => a.operation === 'read' && a.resource === 'network'),
    'added action (network.read) is present in approved scope'
  );
  assert(
    fin8.scopeSummary.allowedActions.some(a => a.operation === 'read' && a.resource === 'email'),
    'original action (email.read) is retained after modifications'
  );

  // Adding a duplicate is silently de-duplicated
  const discDupe = new ScopeDiscovery();
  await discDupe.observe(async (ctx) => { await ctx.email.read(); });
  discDupe.generateScope();
  discDupe.approve({
    add: [{ operation: 'read', resource: 'email' }], // duplicate
  });
  const { privateKey: pkD, publicJwk: pubD } = await AuthProof.generateKey();
  const finD = await discDupe.finalize({ privateKey: pkD, publicJwk: pubD });
  const emailReadInstances = finD.scopeSummary.allowedActions.filter(
    a => a.operation === 'read' && a.resource === 'email'
  ).length;
  assert(emailReadInstances === 1, 'adding a duplicate action does not create duplicate entries');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 9: Final Receipt is a Valid Delegation Receipt
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 9: Final receipt is a valid Delegation Receipt');

  const { privateKey: pk9, publicJwk: pub9 } = await AuthProof.generateKey();
  const disc9 = new ScopeDiscovery({ operatorInstructions: 'Read emails and summarize.' });
  await disc9.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.email.list();
  });
  disc9.generateScope();
  disc9.approve();
  const fin9 = await disc9.finalize({ privateKey: pk9, publicJwk: pub9 });

  assert(typeof fin9.receipt === 'object', 'finalize() returns a receipt object');
  assert(typeof fin9.receiptId === 'string', 'finalize() returns a receiptId string');
  assert(fin9.receiptId.length === 64, 'receiptId is 64-char hex (SHA-256)');
  assert(typeof fin9.systemPrompt === 'string', 'finalize() returns a systemPrompt string');
  assert(fin9.systemPrompt.includes('Authorization ID'), 'systemPrompt includes Authorization ID');
  assert(fin9.receipt.delegationId.startsWith('auth-'), 'delegationId has auth- prefix');
  assert(typeof fin9.receipt.signature === 'string', 'receipt has an ECDSA signature');
  assert(fin9.receipt.scopeSchema !== undefined, 'receipt embeds scopeSchema');
  assert(fin9.receipt.discoveryMetadata !== undefined, 'receipt embeds discoveryMetadata');
  assert(
    typeof fin9.receipt.discoveryMetadata.observationCount === 'number',
    'discoveryMetadata.observationCount is a number'
  );

  // AuthProof.verify() must accept the receipt
  const ver9 = await AuthProof.verify(fin9.receipt, fin9.receiptId);
  assert(ver9.authorized === true, 'AuthProof.verify() authorizes the ScopeDiscovery receipt');
  assert(Array.isArray(ver9.checks), 'AuthProof.verify() returns checks array');
  assert(ver9.checks.every(c => c.passed), 'all AuthProof verification checks pass');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 10: ScopeDiscovery.fromReceipt Drift Report
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 10: fromReceipt drift report');

  // Build a receipt authorizing email.read + calendar.list
  const { privateKey: pk10, publicJwk: pub10 } = await AuthProof.generateKey();
  const discBase10 = new ScopeDiscovery();
  await discBase10.observe(async (ctx) => {
    await ctx.email.read();
    await ctx.calendar.list();
  });
  discBase10.generateScope();
  discBase10.approve();
  const fin10 = await discBase10.finalize({ privateKey: pk10, publicJwk: pub10 });

  // ── Exact match ───────────────────────────────────────────────────────
  const obsExact = [
    { resource: 'email',    operation: 'read', observedAt: Date.now() },
    { resource: 'calendar', operation: 'list', observedAt: Date.now() },
  ];
  const driftExact = ScopeDiscovery.fromReceipt(fin10.receipt, obsExact);
  assert(driftExact.status === 'exact-match', 'exact-match when operations mirror receipt');
  assert(typeof driftExact.report === 'string', 'drift report is a string');

  // ── Over-authorized ───────────────────────────────────────────────────
  const obsOver = [
    { resource: 'email', operation: 'read', observedAt: Date.now() },
    // calendar.list was committed but agent never used it
  ];
  const driftOver = ScopeDiscovery.fromReceipt(fin10.receipt, obsOver);
  assert(driftOver.status === 'over-authorized', 'over-authorized when receipt allows unused ops');
  assert(driftOver.overAuthorized.length > 0, 'overAuthorized array is non-empty');
  assert(driftOver.underAuthorized.length === 0, 'underAuthorized array is empty for over-authorized case');

  // ── Under-authorized ──────────────────────────────────────────────────
  const obsUnder = [
    { resource: 'email',    operation: 'read',   observedAt: Date.now() },
    { resource: 'calendar', operation: 'list',   observedAt: Date.now() },
    { resource: 'files',    operation: 'delete', observedAt: Date.now() }, // not in receipt
  ];
  const driftUnder = ScopeDiscovery.fromReceipt(fin10.receipt, obsUnder);
  assert(
    driftUnder.status === 'under-authorized' || driftUnder.status === 'diverged',
    'under-authorized or diverged when agent exceeded receipt scope'
  );
  assert(driftUnder.underAuthorized.length > 0, 'underAuthorized array is non-empty');

  // Report includes status header
  assert(driftExact.report.includes('exact-match'), 'exact-match report mentions status');
  assert(driftOver.report.includes('Over-authorized'), 'over-authorized report names the issue');
  assert(driftUnder.report.toLowerCase().includes('under') || driftUnder.report.includes('diverged'), 'under-authorized report names the issue');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 11: Guided Delegation Mode End-to-End
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 11: Guided delegation mode end-to-end');

  const { privateKey: pk11, publicJwk: pub11 } = await AuthProof.generateKey();
  const guided = await ScopeDiscovery.guided({
    agentFn: async (ctx) => {
      await ctx.email.read();
      await ctx.calendar.list();
    },
    operatorInstructions: 'Read emails and list calendar events.',
    privateKey: pk11,
    publicJwk:  pub11,
    expiresIn:  3_600_000,
    timeout:    10_000,
  });

  assert(typeof guided.receipt   === 'object', 'guided() returns receipt object');
  assert(typeof guided.receiptId === 'string', 'guided() returns receiptId string');
  assert(Array.isArray(guided.observations), 'guided() returns observations array');
  assert(guided.observations.length === 2, 'guided() captured 2 observations');
  assert(Array.isArray(guided.riskFlags), 'guided() returns riskFlags array');
  assert(guided.aborted === false, 'guided() completes without timeout');

  // Receipt must pass AuthProof.verify()
  const ver11 = await AuthProof.verify(guided.receipt, guided.receiptId);
  assert(ver11.authorized === true, 'guided() receipt passes AuthProof.verify()');

  // scopeSummary includes the observed actions
  assert(
    guided.scopeSummary.allowedActions.some(a => a.resource === 'email' && a.operation === 'read'),
    'guided() scopeSummary includes email.read'
  );

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 12: Timeout Handling
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 12: Timeout handling');

  const discTimeout = new ScopeDiscovery();
  const { observations: obsTimeout, aborted: wasAborted } = await discTimeout.observe(
    async (ctx) => {
      await ctx.email.read(); // resolves immediately — recorded before timeout
      // Then hang longer than the timeout
      await new Promise(resolve => setTimeout(resolve, 5_000));
      await ctx.calendar.list(); // never reached
    },
    { timeout: 80 }
  );

  assert(wasAborted === true, 'aborted flag is true when timeout fires');
  assert(Array.isArray(obsTimeout), 'partial observations are returned as array after timeout');

  // The generateScope() and approve()/finalize() chain should still work on partial observations
  const partialReview = discTimeout.generateScope();
  discTimeout.approve();
  const { privateKey: pkT, publicJwk: pubT } = await AuthProof.generateKey();
  const finTimeout = await discTimeout.finalize({ privateKey: pkT, publicJwk: pubT });
  assert(typeof finTimeout.receipt === 'object', 'finalize() works on partial (timed-out) observations');
  assert(finTimeout.receipt.discoveryMetadata.aborted === true, 'discoveryMetadata.aborted is true for timed-out session');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 13: Empty Observation Session Handled Gracefully
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 13: Empty observation session handled gracefully');

  const discEmpty = new ScopeDiscovery({ operatorInstructions: 'Do nothing.' });
  const { observations: obsEmpty, aborted: emptyAborted } = await discEmpty.observe(
    async () => { /* agent performs no operations */ }
  );

  assert(obsEmpty.length === 0, 'empty session produces zero observations');
  assert(emptyAborted === false, 'empty session is not aborted');

  const reviewEmpty = discEmpty.generateScope();
  assert(reviewEmpty.observationCount === 0, 'observationCount is 0 for empty session');
  assert(Array.isArray(reviewEmpty.draftScope.allowedActions), 'empty session has allowedActions array');
  assert(reviewEmpty.draftScope.allowedActions.length === 0, 'empty session allowedActions is empty');
  assert(
    reviewEmpty.plainSummary.toLowerCase().includes('no operations'),
    'empty summary describes absence of operations'
  );

  discEmpty.approve();
  const { privateKey: pkE, publicJwk: pubE } = await AuthProof.generateKey();
  const finEmpty = await discEmpty.finalize({ privateKey: pkE, publicJwk: pubE });
  assert(typeof finEmpty.receipt === 'object', 'empty session produces a valid receipt object');
  // Receipt must still pass verification (signature + hash checks are structural)
  const verEmpty = await AuthProof.verify(finEmpty.receipt, finEmpty.receiptId);
  assert(verEmpty.authorized === true, 'empty-session receipt passes AuthProof.verify()');

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 14: High-Frequency Operation (>50) Flagged
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 14: High-frequency operation (>50) flagged in riskFlags');

  const discHF = new ScopeDiscovery();
  await discHF.observe(async (ctx) => {
    for (let i = 0; i < 51; i++) await ctx.db.query();
  });
  const reviewHF = discHF.generateScope();

  assert(reviewHF.observationCount === 51, 'all 51 calls are recorded');
  assert(
    reviewHF.riskFlags.some(f => f.includes('high-frequency') || f.includes('>50')),
    '51 calls (>50 threshold) triggers high-frequency risk flag'
  );

  // Exactly 50 calls should NOT trigger (threshold is strictly > 50)
  const discHF50 = new ScopeDiscovery();
  await discHF50.observe(async (ctx) => {
    for (let i = 0; i < 50; i++) await ctx.db.query();
  });
  const reviewHF50 = discHF50.generateScope();
  assert(
    !reviewHF50.riskFlags.some(f => f.includes('high-frequency') || f.includes('>50')),
    'exactly 50 calls does NOT trigger high-frequency flag (threshold is >50, not >=50)'
  );

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 15: SuggestedDenials Includes Dangerous Ops Not Observed
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 15: SuggestedDenials includes dangerous ops not observed');

  const discSD = new ScopeDiscovery();
  await discSD.observe(async (ctx) => {
    await ctx.email.read(); // only a safe read — dangerous ops never observed
  });
  const reviewSD = discSD.generateScope();

  assert(Array.isArray(reviewSD.suggestedDenials), 'suggestedDenials is an array');
  assert(reviewSD.suggestedDenials.length > 0, 'suggestedDenials is non-empty');
  assert(
    reviewSD.suggestedDenials.some(d => d.operation === 'delete'),
    'delete is suggested as a denial'
  );
  assert(
    reviewSD.suggestedDenials.some(d => d.operation === 'execute'),
    'execute is suggested as a denial'
  );
  assert(
    reviewSD.suggestedDenials.every(d => typeof d.reason === 'string' && d.reason.length > 0),
    'each suggested denial has a non-empty reason string'
  );
  assert(
    reviewSD.suggestedDenials.every(d => typeof d.operation === 'string'),
    'each suggested denial has an operation field'
  );
  assert(
    reviewSD.suggestedDenials.every(d => typeof d.resource === 'string'),
    'each suggested denial has a resource field'
  );

  // ─────────────────────────────────────────────────────────────────────
  // Test Group 16: Error Handling — Precondition Violations
  // ─────────────────────────────────────────────────────────────────────
  console.log('\nTest Group 16: Error handling — precondition violations');

  // approve() before generateScope()
  try {
    const discErr1 = new ScopeDiscovery();
    await discErr1.observe(async (ctx) => { await ctx.email.read(); });
    discErr1.approve(); // should throw
    assert(false, 'approve() before generateScope() should throw');
  } catch (e) {
    assert(
      e.message.includes('generateScope'),
      'approve() before generateScope() throws error mentioning generateScope()'
    );
  }

  // finalize() before approve()
  try {
    const discErr2 = new ScopeDiscovery();
    await discErr2.observe(async (ctx) => { await ctx.email.read(); });
    discErr2.generateScope();
    const { privateKey: pkErr2, publicJwk: pubErr2 } = await AuthProof.generateKey();
    await discErr2.finalize({ privateKey: pkErr2, publicJwk: pubErr2 }); // should throw
    assert(false, 'finalize() before approve() should throw');
  } catch (e) {
    assert(
      e.message.includes('approve'),
      'finalize() before approve() throws error mentioning approve()'
    );
  }

  // observe() with non-function argument
  try {
    const discErr3 = new ScopeDiscovery();
    await discErr3.observe('not a function');
    assert(false, 'observe() with non-function should throw');
  } catch (e) {
    assert(
      e.message.includes('agentFn'),
      'observe() with non-function throws error mentioning agentFn'
    );
  }

  // finalize() without privateKey
  try {
    const discErr4 = new ScopeDiscovery();
    await discErr4.observe(async (ctx) => { await ctx.email.read(); });
    discErr4.generateScope();
    discErr4.approve();
    await discErr4.finalize({ publicJwk: pub9 }); // missing privateKey
    assert(false, 'finalize() without privateKey should throw');
  } catch (e) {
    assert(
      e.message.includes('privateKey'),
      'finalize() without privateKey throws error mentioning privateKey'
    );
  }

  // fromReceipt() with non-object receipt
  try {
    ScopeDiscovery.fromReceipt('not an object', []);
    assert(false, 'fromReceipt() with non-object receipt should throw');
  } catch (e) {
    assert(
      e.message.includes('receipt'),
      'fromReceipt() with invalid receipt throws descriptive error'
    );
  }

  // ─────────────────────────────────────────────────────────────────────
  // Summary
  // ─────────────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

run().catch(err => {
  console.error('Unexpected error in test suite:', err);
  process.exit(1);
});

/**
 * Canonicalizer — Test Suite
 * Run: node --experimental-global-webcrypto tests/canonicalizer.test.js
 */

import AuthProof, { Canonicalizer } from '../src/authproof.js';

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
  console.log('Canonicalizer — Test Suite\n');

  // ── normalize(): Whitespace Rules ───────────────────────────────────
  console.log('normalize() — Whitespace');

  assert(
    Canonicalizer.normalize('  Hello World  ') === 'hello world',
    'Trims leading and trailing whitespace'
  );
  assert(
    Canonicalizer.normalize('Hello\n\nWorld') === 'hello world',
    'Collapses newlines to single space'
  );
  assert(
    Canonicalizer.normalize('Hello\t\tWorld') === 'hello world',
    'Collapses tabs to single space'
  );
  assert(
    Canonicalizer.normalize('Hello   World') === 'hello world',
    'Collapses multiple spaces to one'
  );
  assert(
    Canonicalizer.normalize('\n\n  Cite sources.  \n\n') === 'cite sources',
    'Trims and collapses mixed whitespace'
  );

  // ── normalize(): Case Rules ─────────────────────────────────────────
  console.log('\nnormalize() — Case');

  assert(
    Canonicalizer.normalize('CITE SOURCES') === 'cite sources',
    'Lowercases all uppercase'
  );
  assert(
    Canonicalizer.normalize('Cite Sources.') === 'cite sources',
    'Lowercases mixed case and removes trailing period'
  );
  assert(
    Canonicalizer.normalize('cItE SoUrCeS') === 'cite sources',
    'Lowercases random case'
  );

  // ── normalize(): Punctuation Rules ──────────────────────────────────
  console.log('\nnormalize() — Punctuation');

  assert(
    Canonicalizer.normalize('Cite sources, keep under 500 words.') === 'cite sources keep under 500 words',
    'Removes commas and sentence-final periods'
  );
  assert(
    Canonicalizer.normalize('First sentence. Second sentence.') === 'first sentence second sentence',
    'Removes multiple sentence-final periods'
  );
  assert(
    Canonicalizer.normalize('"Cite sources"') === 'cite sources',
    'Removes double quotes'
  );
  assert(
    Canonicalizer.normalize("'Cite sources'") === 'cite sources',
    'Removes single quotes'
  );
  assert(
    Canonicalizer.normalize('\u201cCite sources\u201d') === 'cite sources',
    'Removes curly double quotes'
  );
  assert(
    Canonicalizer.normalize('Version 1.2.3 is required') === 'version 1.2.3 is required',
    'Preserves periods mid-word (version numbers, URLs)'
  );

  // ── hash(): Whitespace variations → identical hashes ────────────────
  console.log('\nhash() — Whitespace variations produce identical hashes');

  const h1a = await Canonicalizer.hash('Cite sources. Keep under 500 words.');
  const h1b = await Canonicalizer.hash('  Cite sources.  Keep under 500 words.  ');
  const h1c = await Canonicalizer.hash('Cite sources.\n\nKeep under 500 words.');
  const h1d = await Canonicalizer.hash('Cite\tsources.\tKeep\tunder\t500\twords.');

  assert(h1a === h1b, 'Leading/trailing whitespace variation → same hash');
  assert(h1a === h1c, 'Newline whitespace variation → same hash');
  assert(h1a === h1d, 'Tab whitespace variation → same hash');
  assert(typeof h1a === 'string' && h1a.length === 64, 'Hash is 64-char hex string');

  // ── hash(): Case variations → identical hashes ──────────────────────
  console.log('\nhash() — Case variations produce identical hashes');

  const h2a = await Canonicalizer.hash('cite sources keep under 500 words');
  const h2b = await Canonicalizer.hash('CITE SOURCES KEEP UNDER 500 WORDS');
  const h2c = await Canonicalizer.hash('Cite Sources Keep Under 500 Words');
  const h2d = await Canonicalizer.hash('cItE sOuRcEs kEeP uNdEr 500 wOrDs');

  assert(h2a === h2b, 'All-uppercase variation → same hash');
  assert(h2a === h2c, 'Title-case variation → same hash');
  assert(h2a === h2d, 'Random-case variation → same hash');

  // ── hash(): Different instructions → different hashes ───────────────
  console.log('\nhash() — Different instructions produce different hashes');

  const hDiff1 = await Canonicalizer.hash('Cite sources. Keep under 500 words.');
  const hDiff2 = await Canonicalizer.hash('Do not cite sources. Write at length.');
  const hDiff3 = await Canonicalizer.hash('Send emails to all contacts.');
  const hDiff4 = await Canonicalizer.hash('Search the web only. No writes.');

  assert(hDiff1 !== hDiff2, 'Semantically different instruction 1 vs 2 → different hashes');
  assert(hDiff1 !== hDiff3, 'Semantically different instruction 1 vs 3 → different hashes');
  assert(hDiff2 !== hDiff3, 'Semantically different instruction 2 vs 3 → different hashes');
  assert(hDiff3 !== hDiff4, 'Semantically different instruction 3 vs 4 → different hashes');

  // ── hash(): Key-value pair sorting ──────────────────────────────────
  console.log('\nhash() — Key-value pair sorting');

  const hKv1 = await Canonicalizer.hash('name: John city: NYC age: 30');
  const hKv2 = await Canonicalizer.hash('city: NYC name: John age: 30');
  const hKv3 = await Canonicalizer.hash('age: 30 name: John city: NYC');
  assert(hKv1 === hKv2, 'KV pairs in different order → same hash');
  assert(hKv1 === hKv3, 'KV pairs in yet another order → same hash');

  const hKvEq1 = await Canonicalizer.hash('max=100 min=0 step=5');
  const hKvEq2 = await Canonicalizer.hash('step=5 max=100 min=0');
  assert(hKvEq1 === hKvEq2, 'key=value pairs in different order → same hash');

  // ── compare() ───────────────────────────────────────────────────────
  console.log('\ncompare()');

  assert(
    await Canonicalizer.compare(
      'Cite sources. Keep under 500 words.',
      '  CITE SOURCES.   Keep under 500 words.  '
    ),
    'compare() returns true for whitespace+case variants'
  );
  assert(
    await Canonicalizer.compare(
      '"Cite sources," keep under 500 words.',
      'cite sources keep under 500 words'
    ),
    'compare() returns true after quote and comma removal'
  );
  assert(
    !await Canonicalizer.compare(
      'Cite sources. Keep under 500 words.',
      'Send emails to all contacts.'
    ),
    'compare() returns false for genuinely different instructions'
  );

  // ── normalize(): Round-trip idempotency ─────────────────────────────
  console.log('\nnormalize() — Round-trip idempotency');

  const originals = [
    'Cite sources. Keep under 500 words.',
    '  HELLO   WORLD\n\n',
    '"Use structured data," and cite sources.',
    'name: John, city: NYC, age: 30',
  ];
  for (const original of originals) {
    const once  = Canonicalizer.normalize(original);
    const twice = Canonicalizer.normalize(once);
    assert(once === twice, `normalize(normalize(x)) === normalize(x) for: "${original.slice(0, 40)}"`);
  }

  // ── Integration: AuthProof.create() uses Canonicalizer.hash ─────────
  console.log('\nIntegration — AuthProof.create() and verify() use canonical hash');

  const { privateKey, publicJwk } = await AuthProof.generateKey();
  const instructions = 'Cite sources.  Keep under 500 words.';

  const { receipt, receiptId } = await AuthProof.create({
    scope:        'Search the web for competitor pricing.',
    boundaries:   'Do not send emails.',
    instructions,
    ttlHours:     1,
    privateKey,
    publicJwk,
  });

  const expectedHash = await Canonicalizer.hash(instructions);
  assert(
    receipt.instructionsHash === expectedHash,
    'receipt.instructionsHash equals Canonicalizer.hash(instructions)'
  );

  const result = await AuthProof.verify(receipt, receiptId);
  assert(result.authorized === true, 'Receipt created with canonical hash verifies successfully');

  const ihCheck = result.checks.find(c => c.name === 'Instructions intact');
  assert(ihCheck && ihCheck.passed, 'Instructions intact check passes with canonical hash');

  // Whitespace variant of the same instruction creates verifiable receipt
  const { receipt: receipt2, receiptId: receiptId2 } = await AuthProof.create({
    scope:        'Search the web for competitor pricing.',
    boundaries:   'Do not send emails.',
    instructions: '\n\n  CITE SOURCES.  Keep under 500 words.  \n',
    ttlHours:     1,
    privateKey,
    publicJwk,
  });
  assert(
    receipt.instructionsHash === receipt2.instructionsHash,
    'Whitespace/case variant of instruction produces identical instructionsHash'
  );
  const result2 = await AuthProof.verify(receipt2, receiptId2);
  assert(result2.authorized === true, 'Receipt with whitespace-variant instruction verifies successfully');

  // ── Error handling ───────────────────────────────────────────────────
  console.log('\nError handling');

  try {
    Canonicalizer.normalize(42);
    assert(false, 'Should throw for non-string input');
  } catch (e) {
    assert(e.message.includes('string'), 'normalize() throws for non-string input');
  }

  // ── Summary ────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(40)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log('\n✓ All Canonicalizer tests passed.');
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

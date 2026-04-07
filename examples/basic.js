/**
 * AuthProof — Basic Usage Example
 * Run: node examples/basic.js
 */

import AuthProof from '../src/authproof.js';

async function main() {
  console.log('AuthProof SDK — Basic Example\n');

  // ── 1. Generate a signing key pair ─────────────────────────────────
  // In production: persist privateJwk securely (env var, secrets manager, etc.)
  // The publicJwk is safe to store anywhere — it's only used for verification.
  console.log('1. Generating key pair...');
  const { privateKey, publicJwk, privateJwk } = await AuthProof.generateKey();
  console.log('   ✓ Key pair generated');
  console.log('   Public key ID:', publicJwk.x.slice(0, 12) + '...\n');

  // ── 2. Create a delegation receipt ─────────────────────────────────
  console.log('2. Creating delegation receipt...');
  const { receipt, receiptId, systemPrompt } = await AuthProof.create({
    scope: 'Search the web for publicly available information about competitor pricing. Summarize findings into a structured comparison report.',
    boundaries: 'Do not access internal company documents. Do not send emails or messages. Do not make purchases or submit forms.',
    instructions: 'Only use publicly listed sources. Cite every claim. Flag anything uncertain. Keep the report under 500 words.',
    ttlHours: 4,
    privateKey,
    publicJwk,
  });

  console.log('   ✓ Receipt created');
  console.log('   Receipt ID:', receiptId);
  console.log('   Expires:', new Date(receipt.timeWindow.end).toLocaleString(), '\n');

  // ── 3. System prompt ────────────────────────────────────────────────
  console.log('3. System prompt (paste into any AI):');
  console.log('─'.repeat(60));
  console.log(systemPrompt);
  console.log('─'.repeat(60) + '\n');

  // ── 4. Verify the receipt ───────────────────────────────────────────
  console.log('4. Verifying receipt...');
  const result = await AuthProof.verify(receipt, receiptId, {
    action: 'Search Google for iPhone 15 pricing on competitor websites and write a comparison table',
  });

  console.log('   Authorized:', result.authorized);
  console.log('   Checks:');
  result.checks.forEach(c => {
    console.log(`     ${c.passed ? '✓' : '✗'} ${c.name}: ${c.detail}`);
  });

  // ── 5. Scope check a different action ──────────────────────────────
  console.log('\n5. Testing a blocked action...');
  const blockedResult = await AuthProof.verify(receipt, receiptId, {
    action: 'Send an email to the marketing team with the findings',
  });
  console.log('   Authorized:', blockedResult.authorized);
  blockedResult.checks
    .filter(c => !c.passed)
    .forEach(c => console.log(`   ✗ Failed: ${c.name} — ${c.detail}`));

  // ── 6. Utility helpers ──────────────────────────────────────────────
  console.log('\n6. Utility helpers:');
  console.log('   isActive:', AuthProof.isActive(receipt));
  console.log('   secondsRemaining:', AuthProof.secondsRemaining(receipt), 'seconds');

  console.log('\n✓ Done. See README for agent framework integration examples.');
}

main().catch(console.error);

/**
 * Authproof + Cursor / Claude Code agent — minimal integration example
 * Run: node authproof-cloud/templates/cursor-claude-template.js
 * Shows one PERMIT (read calendar) and one DENY (send email).
 */
import AuthProof from '../../src/authproof.js';

async function main() {
  // Step 1: Generate a signing key pair.
  // In production: save privateJwk to an env var or secrets manager.
  const { privateKey, publicJwk } = await AuthProof.generateKey();

  // Step 2: Create a receipt — defines exactly what this agent can and cannot do.
  const { receipt, receiptId, systemPrompt } = await AuthProof.create({
    scope:        'Read the user\'s calendar. Check availability and find free time slots.',
    boundaries:   'Never send emails. Never delete calendar events. Never access contacts.',
    instructions: 'Confirm with the user before making any changes. Show free/busy only.',
    ttlHours: 1,
    privateKey,
    publicJwk,
  });
  console.log('Receipt created:', receiptId.slice(0, 16) + '...');
  console.log('Expires:', new Date(receipt.timeWindow.end).toLocaleTimeString(), '\n');

  // Step 3: PERMIT — agent reads calendar (matches scope).
  const permit = await AuthProof.verify(receipt, receiptId, {
    action: 'Read calendar to check available time slots on Monday afternoon',
  });
  console.log('✓ PERMIT — read calendar');
  console.log('  Authorized:', permit.authorized, '\n');

  // Step 4: DENY — agent tries to send email (not in scope, hits boundary).
  const deny = await AuthProof.verify(receipt, receiptId, {
    action: 'Send a confirmation email to all meeting attendees',
  });
  console.log('✗ DENY — send email');
  console.log('  Authorized:', deny.authorized);
  deny.checks.filter(c => !c.passed).forEach(c =>
    console.log('  Failed check:', c.name, '—', c.detail)
  );

  // Step 5: Paste systemPrompt into your Cursor or Claude Code agent system prompt.
  console.log('\n── System prompt (paste into your agent) ──');
  console.log(systemPrompt.slice(0, 250) + '…');
}

main().catch(console.error);

/**
 * AuthProof — LangChain Delegation Receipt Example
 * Run: node examples/langchain-example.js
 *
 * Shows how to wrap a LangChain agent (or any object with invoke()) with
 * authproofMiddleware so every invocation is gated by PreExecutionVerifier.
 * Uses a local mock agent — no LangChain install required to run this demo.
 */

import AuthProof from '../src/authproof.js';
import { PreExecutionVerifier, DelegationLog } from '../src/pre-execution-verifier.js';
import { RevocationRegistry } from '../src/authproof.js';
import { authproofMiddleware } from '../src/middleware/langchain.js';

async function main() {
  console.log('AuthProof SDK — LangChain Middleware Example\n');

  // ── 1. Generate key pairs ────────────────────────────────────────────
  console.log('1. Generating key pairs...');
  const { privateKey: userKey,     publicJwk: userPub }     = await AuthProof.generateKey();
  const { privateKey: verifierKey, publicJwk: verifierPub } = await AuthProof.generateKey();
  console.log('   ✓ User key pair generated');
  console.log('   ✓ Verifier key pair generated\n');

  // ── 2. Issue a delegation receipt ───────────────────────────────────
  console.log('2. Issuing delegation receipt...');
  const { receipt, receiptId, systemPrompt } = await AuthProof.create({
    scope:        'Read the user\'s calendar for the next 7 days. Identify scheduling conflicts.',
    boundaries:   'Do not create, edit, or delete calendar events. Do not read emails or contacts.',
    instructions: 'Present the 3 best available time slots. Explain why each works.',
    ttlHours:     1,
    privateKey:   userKey,
    publicJwk:    userPub,
  });

  console.log('   ✓ Receipt ID:', receiptId);
  console.log('   ✓ Expires:', new Date(receipt.timeWindow.end).toLocaleString(), '\n');

  // ── 3. Set up the PreExecutionVerifier ──────────────────────────────
  console.log('3. Setting up PreExecutionVerifier...');
  const delegationLog      = new DelegationLog();
  const revocationRegistry = new RevocationRegistry();
  await revocationRegistry.init({ privateKey: verifierKey, publicJwk: verifierPub });

  const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry });
  await verifier.init({ privateKey: verifierKey, publicJwk: verifierPub });

  delegationLog.add(receiptId, receipt);
  console.log('   ✓ Verifier ready\n');

  // ── 4. Create a mock LangChain-style agent ───────────────────────────
  // In production: replace with your real LangChain agent instance.
  const mockAgent = {
    name: 'calendar-agent',
    async invoke(input) {
      return { result: `[mock response to: "${input}"]` };
    },
  };

  // ── 5. Wrap the agent with authproofMiddleware ───────────────────────
  console.log('4. Wrapping agent with authproofMiddleware...');
  const guardedAgent = authproofMiddleware(mockAgent, {
    receiptHash:          receiptId,
    verifier,
    operatorInstructions: receipt.operatorInstructions,
  });
  console.log('   ✓ Agent is now gated by PreExecutionVerifier\n');

  // ── 6. Call 1: PERMIT — read calendar events (in-scope action) ──────
  console.log('5. Call 1: action read calendar (should PERMIT)...');
  try {
    const response = await guardedAgent.invoke(
      'Read my calendar events for the next 7 days and identify scheduling conflicts.'
    );
    console.log('   ✓ PERMIT. Response:', response.result, '\n');
  } catch (err) {
    console.log('   ✗ Blocked:', err.message, '\n');
  }

  // ── 7. Call 2: DENY — send on email/outbox ──────────────────────────
  // Denied: email operations are completely outside the authorized calendar read scope.
  console.log('6. Call 2: action send on email/outbox (should DENY)...');
  {
    const result = await verifier.check({
      receiptHash:          receiptId,
      action:               { operation: 'send', resource: 'email/outbox' },
      operatorInstructions: receipt.operatorInstructions,
    });
    if (result.allowed) {
      console.log('   ✓ PERMIT (unexpected)\n');
    } else {
      const failedCheck = Object.entries(result.checks).find(([, v]) => !v);
      console.log('   ✗ DENY');
      console.log('   Blocked at check:', failedCheck?.[0] ?? 'unknown');
      console.log('   Reason:', result.blockedReason);
      console.log('   Why: send on email/outbox is outside the authorized calendar read scope\n');
    }
  }

  // ── 8. Call 3: DENY — delete on calendar/events ─────────────────────
  // Denied: 'delete' is explicitly prohibited by the receipt boundaries
  // ("Do not create, edit, or delete calendar events.").
  console.log('7. Call 3: action delete on calendar/events (should DENY)...');
  {
    const result = await verifier.check({
      receiptHash:          receiptId,
      action:               { operation: 'delete', resource: 'calendar/events' },
      operatorInstructions: receipt.operatorInstructions,
    });
    if (result.allowed) {
      console.log('   ✓ PERMIT (unexpected)\n');
    } else {
      const failedCheck = Object.entries(result.checks).find(([, v]) => !v);
      console.log('   ✗ DENY');
      console.log('   Blocked at check:', failedCheck?.[0] ?? 'unknown');
      console.log('   Reason:', result.blockedReason);
      console.log('   Why: delete is explicitly denied in the receipt boundaries\n');
    }
  }

  // ── 9. System prompt (for use with real LangChain agents) ────────────
  console.log('8. System prompt to inject into your real LangChain agent:');
  console.log('─'.repeat(60));
  console.log(systemPrompt.slice(0, 300) + (systemPrompt.length > 300 ? '\n   [...]' : ''));
  console.log('─'.repeat(60) + '\n');

  console.log('Usage with a real LangChain agent:');
  console.log(`
  import { ChatOpenAI } from '@langchain/openai'
  import { createOpenAIFunctionsAgent, AgentExecutor } from 'langchain/agents'

  const llm     = new ChatOpenAI({ model: 'gpt-4o' })
  const agent   = await createOpenAIFunctionsAgent({ llm, tools, prompt })
  const executor = new AgentExecutor({ agent, tools })

  const guardedExecutor = authproofMiddleware(executor, {
    receiptHash:          receiptId,
    verifier,
    operatorInstructions: receipt.operatorInstructions,
  })

  // System prompt goes into your agent's initial messages
  const result = await guardedExecutor.invoke({
    input: 'Read my calendar events for the next 7 days and identify scheduling conflicts.',
    chat_history: [{ role: 'system', content: systemPrompt }],
  })
  `);

  console.log('✓ Done. See README for full middleware documentation.');
}

main().catch(console.error);

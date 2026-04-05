/**
 * AuthProof — Agent Framework Integration Examples
 *
 * Shows how to use AuthProof with:
 *  - LangChain / LangGraph agents
 *  - n8n (system prompt injection)
 *  - Any OpenAI-compatible API
 *  - Express.js verify middleware
 */

import AuthProof from '../src/authproof.js';

// ════════════════════════════════════════════════════════════
// EXAMPLE 1: LangChain / LangGraph
// Inject the system prompt into your agent's initial messages
// ════════════════════════════════════════════════════════════
export async function langchainExample(privateKey, publicJwk) {
  const { receipt, receiptId, systemPrompt } = await AuthProof.create({
    scope: 'Read the user\'s calendar for the next 7 days. Identify scheduling conflicts.',
    boundaries: 'Do not create, edit, or delete calendar events. Do not read emails or contacts.',
    instructions: 'Present the 3 best available time slots. Explain why each works.',
    ttlHours: 1,
    privateKey,
    publicJwk,
  });

  // LangChain: pass as SystemMessage
  const messages = [
    { role: 'system', content: systemPrompt },
    { role: 'user',   content: 'Find me a good time for a 1-hour meeting next week.' },
  ];

  // LangGraph: inject into state
  const agentState = {
    messages,
    receiptId,     // store for audit trail
    receipt,       // store for later verification
  };

  return agentState;
}

// ════════════════════════════════════════════════════════════
// EXAMPLE 2: OpenAI-compatible API (works with Claude, GPT, etc.)
// ════════════════════════════════════════════════════════════
export async function openaiExample(privateKey, publicJwk, apiKey, baseUrl = 'https://api.openai.com/v1') {
  const { systemPrompt, receiptId } = await AuthProof.create({
    scope: 'Summarize the top 5 HackerNews stories today into bullet points.',
    boundaries: 'Do not click any links. Do not submit any forms. Do not access paid content.',
    instructions: 'Keep each summary under 2 sentences. Include the story score.',
    ttlHours: 1,
    privateKey,
    publicJwk,
  });

  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type':  'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: 'gpt-4o',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: 'Go ahead.' },
      ],
    }),
  });

  const data = await response.json();
  return { receiptId, response: data };
}

// ════════════════════════════════════════════════════════════
// EXAMPLE 3: Express.js verify middleware
// Drop this into any API that AI agents call — verify the
// receipt before allowing the agent to take action.
// ════════════════════════════════════════════════════════════
export function authproofMiddleware(receiptStore) {
  /**
   * receiptStore: object with .get(receiptId) => { receipt, revoked }
   * Returns an Express middleware function.
   */
  return async (req, res, next) => {
    const receiptId = req.headers['x-authproof-receipt-id'];
    const action    = req.headers['x-authproof-action'] || req.body?.action;

    if (!receiptId) {
      return res.status(401).json({ error: 'Missing X-AuthProof-Receipt-Id header' });
    }

    const stored = await receiptStore.get(receiptId);
    if (!stored) {
      return res.status(404).json({ error: 'Receipt not found' });
    }

    const result = await AuthProof.verify(stored.receipt, receiptId, {
      revoked: stored.revoked,
      action,
    });

    if (!result.authorized) {
      return res.status(403).json({
        error:   'Authorization denied',
        checks:  result.checks,
      });
    }

    // Attach receipt context to the request for downstream use
    req.authproof = {
      receiptId,
      receiptContext: result.receiptContext,
      checks: result.checks,
    };

    next();
  };
}

// ════════════════════════════════════════════════════════════
// EXAMPLE 4: n8n — Code node snippet
// Paste this into an n8n "Code" node that runs before your
// AI node. It injects the system prompt into the workflow.
// ════════════════════════════════════════════════════════════
export const n8nCodeNodeSnippet = `
// AuthProof — n8n Code Node
// Add this before your AI/LLM node.
// Requires: authproof npm package OR copy src/authproof.js into your n8n instance.

const { create, generateKey } = require('authproof');

// Load your key from n8n credentials / environment
const privateJwk = JSON.parse($env.AUTHPROOF_PRIVATE_JWK);
const publicJwk  = JSON.parse($env.AUTHPROOF_PUBLIC_JWK);

const privateKey = await importPrivateKey(privateJwk);

const { systemPrompt, receiptId } = await create({
  scope:        $input.item.json.scope       || 'Perform the requested task.',
  boundaries:   $input.item.json.boundaries  || 'Do not take actions outside the described task.',
  instructions: $input.item.json.instructions || 'Complete the task accurately and concisely.',
  ttlHours:     1,
  privateKey,
  publicJwk,
});

return [{
  json: {
    ...$input.item.json,
    systemPrompt,
    receiptId,
  }
}];
`;

// ════════════════════════════════════════════════════════════
// EXAMPLE 5: Supabase Edge Function — verify endpoint
// Deploy this as a Supabase Edge Function at /functions/v1/verify
// ════════════════════════════════════════════════════════════
export const supabaseVerifyFunction = `
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import AuthProof from 'https://esm.sh/authproof@1';

const supabase = createClient(
  Deno.env.get('SUPABASE_URL'),
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
);

Deno.serve(async (req) => {
  const { hash, proposed_action } = await req.json();

  const { data, error } = await supabase
    .from('receipts')
    .select('*')
    .eq('hash', hash)
    .single();

  if (error || !data) {
    return new Response(JSON.stringify({
      authorized: false,
      result: 'Receipt not found',
      checks: [{ name: 'Found', passed: false, detail: 'No receipt with that ID' }]
    }), { headers: { 'Content-Type': 'application/json' } });
  }

  // Reconstruct receipt object from DB columns
  const receipt = {
    delegationId:         data.delegation_id,
    issuedAt:             data.issued_at,
    scope:                data.scope,
    boundaries:           data.boundaries,
    timeWindow:           { start: data.time_window_start, end: data.time_window_end },
    operatorInstructions: data.operator_instructions,
    instructionsHash:     data.instructions_hash,
    signerPublicKey:      data.signer_public_key,
    signature:            data.signature,
  };

  const result = await AuthProof.verify(receipt, hash, {
    revoked: data.revoked,
    action:  proposed_action,
  });

  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
});
`;

#!/usr/bin/env node
// DRP MCP Server
// Exposes two tools to Claude Code agents:
//   • issue_delegation_receipt  — creates and stores a signed receipt
//   • verify_action             — checks whether an action is authorized under a receipt
//
// Transport: stdio (standard MCP pattern)
// Requires: SUPABASE_URL and SUPABASE_ANON_KEY environment variables
//
// Add to Claude Code config (~/.claude/claude_desktop_config.json):
//   {
//     "mcpServers": {
//       "drp": {
//         "command": "node",
//         "args": ["/absolute/path/to/drp-infrastructure/mcp-server.js"],
//         "env": {
//           "SUPABASE_URL": "https://YOUR_PROJECT.supabase.co",
//           "SUPABASE_ANON_KEY": "YOUR_ANON_KEY"
//         }
//       }
//     }
//   }

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// ─── Config ──────────────────────────────────────────────────────────────────

const SUPABASE_URL     = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  process.stderr.write(
    'ERROR: SUPABASE_URL and SUPABASE_ANON_KEY environment variables are required.\n',
  );
  process.exit(1);
}

// ─── Crypto helpers (Node 18+ built-in Web Crypto) ──────────────────────────

function hexOf(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return hexOf(buf);
}

async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
}

async function ecSign(signingKey, message) {
  const buf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingKey,
    new TextEncoder().encode(message),
  );
  return hexOf(buf);
}

// ─── Generate a one-time signing key for this server session ─────────────────
// For production, persist this key; for now a fresh key per server start is fine
// as the public key is embedded in every receipt.

const { privateKey, publicKey } = await generateKeyPair();
const pubJwk = await crypto.subtle.exportKey('jwk', publicKey);
const { kty, crv, x, y } = pubJwk;

// ─── REST helpers ─────────────────────────────────────────────────────────────

async function supabaseFetch(path, opts = {}) {
  const res = await fetch(`${SUPABASE_URL}/functions/v1${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
      ...(opts.headers || {}),
    },
  });
  return res.json();
}

async function insertReceipt(receipt, hash) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/receipts`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
      'Prefer': 'return=minimal',
    },
    body: JSON.stringify({
      hash,
      delegation_id:         receipt.delegationId,
      scope:                 receipt.scope,
      boundaries:            receipt.boundaries,
      time_window_start:     receipt.timeWindow.start,
      time_window_end:       receipt.timeWindow.end,
      operator_instructions: receipt.operatorInstructions,
      instructions_hash:     receipt.instructionsHash,
      signer_public_key:     receipt.signerPublicKey,
      signature:             receipt.signature,
      issued_at:             receipt.issuedAt,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`DB insert failed: ${text}`);
  }
}

// ─── Tool: issue_delegation_receipt ──────────────────────────────────────────

async function issueDelegationReceipt({ scope, boundaries, time_window_hours, operator_instructions }) {
  const now    = new Date();
  const end    = new Date(now.getTime() + (time_window_hours || 24) * 3600 * 1000);
  const delegationId   = `drp-${now.getTime()}-${Math.random().toString(36).slice(2, 8)}`;
  const instructionsHash = await sha256(operator_instructions);

  const obj = {
    delegationId,
    issuedAt:             now.toISOString(),
    scope,
    boundaries,
    timeWindow:           { start: now.toISOString(), end: end.toISOString() },
    operatorInstructions: operator_instructions,
    instructionsHash,
    signerPublicKey:      { kty, crv, x, y },
  };

  const payload   = JSON.stringify(obj);
  const signature = await ecSign(privateKey, payload);
  const receipt   = { ...obj, signature };
  const hash      = await sha256(JSON.stringify(receipt));

  await insertReceipt(receipt, hash);

  return {
    success: true,
    hash,
    receipt,
    verify_url: `${SUPABASE_URL}/functions/v1/verify`,
    share_url:  `https://your-drp-app.com/?receipt=${hash}`, // update with your deployment URL
  };
}

// ─── Tool: verify_action ──────────────────────────────────────────────────────

async function verifyAction({ receipt_hash, proposed_action }) {
  return await supabaseFetch('/verify', {
    method: 'POST',
    body: JSON.stringify({ hash: receipt_hash, proposed_action }),
  });
}

// ─── MCP Server setup ────────────────────────────────────────────────────────

const server = new Server(
  { name: 'drp-server', version: '1.0.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'issue_delegation_receipt',
      description:
        'Issue a cryptographically signed delegation receipt that authorizes an AI agent to act within defined boundaries. ' +
        'Returns a receipt hash that can be verified by other agents or systems.',
      inputSchema: {
        type: 'object',
        properties: {
          scope: {
            type: 'string',
            description: 'What the agent is authorized to do (plain English description of permitted actions)',
          },
          boundaries: {
            type: 'string',
            description: 'What the agent must NOT do (constraints, off-limits actions)',
          },
          time_window_hours: {
            type: 'number',
            description: 'How long the receipt is valid, in hours (default: 24)',
            default: 24,
          },
          operator_instructions: {
            type: 'string',
            description: 'Specific instructions from the human operator to the agent',
          },
        },
        required: ['scope', 'boundaries', 'operator_instructions'],
      },
    },
    {
      name: 'verify_action',
      description:
        'Verify whether a proposed action is authorized under a given delegation receipt. ' +
        'Checks the receipt signature, time window, revocation status, and scope alignment.',
      inputSchema: {
        type: 'object',
        properties: {
          receipt_hash: {
            type: 'string',
            description: 'The SHA-256 hash of the delegation receipt to verify against',
          },
          proposed_action: {
            type: 'string',
            description: 'Description of the action the agent wants to take (used for scope alignment check)',
          },
        },
        required: ['receipt_hash', 'proposed_action'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result;

    if (name === 'issue_delegation_receipt') {
      result = await issueDelegationReceipt(args);
    } else if (name === 'verify_action') {
      result = await verifyAction(args);
    } else {
      throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (err) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${err.message}`,
        },
      ],
      isError: true,
    };
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write('DRP MCP server running (stdio)\n');

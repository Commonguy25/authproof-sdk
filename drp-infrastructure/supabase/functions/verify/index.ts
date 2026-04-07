// DRP Edge Function — POST /verify
// Verifies a delegation receipt and checks whether a proposed action is authorized.
//
// Request body:
//   { hash: string, proposed_action?: string }
//
// Response:
//   { authorized: boolean, result: string, checks: Check[], receipt_context?: object }
//
// Deno / Supabase Edge Function runtime

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, handleOptions, jsonResponse, errorResponse } from '../_shared/cors.ts';

// ─── Types ───────────────────────────────────────────────────────────────────

interface Check {
  name: string;
  passed: boolean;
  detail: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function sha256hex(s: string): Promise<string> {
  const encoded = new TextEncoder().encode(s);
  const buf = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Import an ECDSA P-256 public key from JWK { kty, crv, x, y }
async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'jwk',
    { ...jwk, key_ops: ['verify'] },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

async function verifySignature(
  pubKeyJwk: JsonWebKey,
  payload: string,
  sigHex: string,
): Promise<boolean> {
  try {
    const pubKey = await importPublicKey(pubKeyJwk);
    const sigBytes = hexToBytes(sigHex);
    const msgBytes = new TextEncoder().encode(payload);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pubKey,
      sigBytes,
      msgBytes,
    );
  } catch {
    return false;
  }
}

// Simple keyword tokenizer — strips stopwords, lowercases, filters short words
const STOPWORDS = new Set([
  'the','a','an','and','or','but','in','on','at','to','for','of','with','by',
  'from','is','are','was','were','be','been','being','have','has','had','do',
  'does','did','will','would','could','should','may','might','shall','can',
  'not','no','nor','so','yet','both','either','neither','this','that','these',
  'those','i','you','he','she','it','we','they','what','which','who','whom',
  'how','when','where','why','all','any','each','every','some','such','only',
  'own','same','than','too','very','just','as','if','then','else','up','out',
]);

function tokenize(text: string): Set<string> {
  return new Set(
    text.toLowerCase()
      .split(/[\s,;:.()\[\]{}'"""]+/)
      .filter(w => w.length > 3 && !STOPWORDS.has(w)),
  );
}

function keywordOverlap(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  let hits = 0;
  for (const w of ta) if (tb.has(w)) hits++;
  return ta.size === 0 ? 0 : hits / ta.size;
}

// ─── Main handler ─────────────────────────────────────────────────────────────

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return handleOptions();
  if (req.method !== 'POST') return errorResponse('Method not allowed', 405);

  let body: { hash?: string; proposed_action?: string };
  try {
    body = await req.json();
  } catch {
    return errorResponse('Invalid JSON body');
  }

  const { hash, proposed_action } = body;
  if (!hash) return errorResponse('Missing required field: hash');

  // ── Fetch receipt from DB ──────────────────────────────────────────────────

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );

  const { data: row, error: dbErr } = await supabase
    .from('receipts')
    .select('*')
    .eq('hash', hash)
    .single();

  if (dbErr || !row) {
    return jsonResponse({
      authorized: false,
      result: 'Receipt not found',
      checks: [{ name: 'Receipt exists', passed: false, detail: 'No receipt with that hash in the database' }],
    });
  }

  const checks: Check[] = [];

  // ── Check 1: Receipt exists ───────────────────────────────────────────────
  checks.push({ name: 'Receipt exists', passed: true, detail: `Found receipt ${row.delegation_id}` });

  // ── Check 2: Not revoked ──────────────────────────────────────────────────
  const notRevoked = !row.revoked;
  checks.push({
    name: 'Not revoked',
    passed: notRevoked,
    detail: notRevoked
      ? 'Receipt is active'
      : `Revoked at ${row.revoked_at}`,
  });

  // ── Check 3: Time window ──────────────────────────────────────────────────
  const now = new Date();
  const windowStart = new Date(row.time_window_start);
  const windowEnd = new Date(row.time_window_end);
  const inWindow = now >= windowStart && now <= windowEnd;
  checks.push({
    name: 'Time window',
    passed: inWindow,
    detail: inWindow
      ? `Valid from ${windowStart.toISOString()} to ${windowEnd.toISOString()}`
      : `Current time ${now.toISOString()} is outside window ${windowStart.toISOString()} – ${windowEnd.toISOString()}`,
  });

  // ── Check 4: Signature ────────────────────────────────────────────────────
  // Reconstruct canonical payload (must match exact key order from the client)
  const canonicalObj = {
    delegationId:         row.delegation_id,
    issuedAt:             new Date(row.issued_at).toISOString(),
    scope:                row.scope,
    boundaries:           row.boundaries,
    timeWindow: {
      start: new Date(row.time_window_start).toISOString(),
      end:   new Date(row.time_window_end).toISOString(),
    },
    operatorInstructions: row.operator_instructions,
    instructionsHash:     row.instructions_hash,
    signerPublicKey:      row.signer_public_key,
  };
  const payload = JSON.stringify(canonicalObj);
  const sigValid = await verifySignature(row.signer_public_key as JsonWebKey, payload, row.signature);
  checks.push({
    name: 'Signature valid',
    passed: sigValid,
    detail: sigValid
      ? 'ECDSA P-256 signature verified against embedded public key'
      : 'Signature verification failed — receipt may be tampered',
  });

  // ── Check 5: Hash integrity ───────────────────────────────────────────────
  const receiptObj = { ...canonicalObj, signature: row.signature };
  const recomputedHash = await sha256hex(JSON.stringify(receiptObj));
  const hashMatch = recomputedHash === hash;
  checks.push({
    name: 'Hash integrity',
    passed: hashMatch,
    detail: hashMatch
      ? 'Recomputed hash matches stored hash'
      : `Hash mismatch: expected ${hash}, got ${recomputedHash}`,
  });

  // ── Check 6 (optional): Scope alignment with proposed action ─────────────
  if (proposed_action) {
    const scopeOverlap = keywordOverlap(proposed_action, row.scope);
    const boundaryOverlap = keywordOverlap(proposed_action, row.boundaries);
    const inScope = scopeOverlap >= 0.3; // ≥30% of action words appear in scope
    const notBlocked = boundaryOverlap < 0.5; // <50% overlap with boundaries = not blocked
    checks.push({
      name: 'Scope alignment',
      passed: inScope,
      detail: `Action keyword overlap with scope: ${Math.round(scopeOverlap * 100)}% (need ≥30%)`,
    });
    checks.push({
      name: 'Boundary check',
      passed: notBlocked,
      detail: notBlocked
        ? `Action keyword overlap with boundaries: ${Math.round(boundaryOverlap * 100)}% (need <50%)`
        : `Action appears to conflict with stated boundaries (${Math.round(boundaryOverlap * 100)}% overlap)`,
    });
  }

  // ── Final verdict ─────────────────────────────────────────────────────────
  const authorized = checks.every(c => c.passed);
  const failedChecks = checks.filter(c => !c.passed).map(c => c.name);
  const result = authorized
    ? 'Action is authorized under this delegation receipt'
    : `Authorization denied — failed: ${failedChecks.join(', ')}`;

  return jsonResponse({
    authorized,
    result,
    checks,
    receipt_context: {
      delegationId:         row.delegation_id,
      scope:                row.scope,
      boundaries:           row.boundaries,
      timeWindow: {
        start: new Date(row.time_window_start).toISOString(),
        end:   new Date(row.time_window_end).toISOString(),
      },
      operatorInstructions: row.operator_instructions,
      issuedAt:             new Date(row.issued_at).toISOString(),
      revoked:              row.revoked,
    },
  });
});

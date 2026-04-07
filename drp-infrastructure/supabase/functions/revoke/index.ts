// DRP Edge Function — POST /revoke
// Marks a receipt as revoked in the database.
//
// Request body:
//   { hash: string }
//
// Response:
//   { success: boolean, message: string }
//
// Note: Uses the service role key so it can bypass RLS update restriction.
// Only call this from trusted contexts (the issuing device or an admin UI).

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { corsHeaders, handleOptions, jsonResponse, errorResponse } from '../_shared/cors.ts';

serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return handleOptions();
  if (req.method !== 'POST') return errorResponse('Method not allowed', 405);

  let body: { hash?: string };
  try {
    body = await req.json();
  } catch {
    return errorResponse('Invalid JSON body');
  }

  const { hash } = body;
  if (!hash) return errorResponse('Missing required field: hash');

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );

  // Confirm the receipt exists first
  const { data: existing, error: fetchErr } = await supabase
    .from('receipts')
    .select('id, revoked, delegation_id')
    .eq('hash', hash)
    .single();

  if (fetchErr || !existing) {
    return jsonResponse({ success: false, message: 'Receipt not found' }, 404);
  }

  if (existing.revoked) {
    return jsonResponse({
      success: false,
      message: `Receipt ${existing.delegation_id} is already revoked`,
    });
  }

  // Mark as revoked
  const { error: updateErr } = await supabase
    .from('receipts')
    .update({ revoked: true, revoked_at: new Date().toISOString() })
    .eq('hash', hash);

  if (updateErr) {
    return errorResponse(`Database error: ${updateErr.message}`, 500);
  }

  return jsonResponse({
    success: true,
    message: `Receipt ${existing.delegation_id} has been revoked`,
  });
});

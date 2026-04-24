const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const app = express();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Use env var if set (avoids runtime Stripe API calls on cold start)
let proPriceId = process.env.STRIPE_PRO_PRICE_ID || null;
let stripeReady = null;

// Stripe webhooks need raw body; everything else gets JSON
app.use((req, res, next) => {
  if (req.originalUrl === '/webhooks/stripe') {
    express.raw({ type: 'application/json' })(req, res, next);
  } else {
    express.json()(req, res, next);
  }
});

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' }
});

// ─── helpers ────────────────────────────────────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
}

async function logCustodyEvent(legalHoldId, action, actor, details = null) {
  await supabaseAdmin.from('legal_hold_custody_log').insert({
    legal_hold_id: legalHoldId,
    action,
    actor,
    details,
  });
}

async function requireApiKey(req, res, next) {
  const auth = req.headers.authorization;
  const apiKey = auth?.startsWith('Bearer ') ? auth.slice(7) : req.query.apiKey;
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  const { data: account, error } = await supabaseAdmin
    .from('accounts')
    .select('*')
    .eq('api_key', apiKey)
    .single();
  if (error || !account) return res.status(401).json({ error: 'Invalid API key' });
  req.account = account;
  next();
}

function requireEnterprise(req, res, next) {
  if (req.account.plan !== 'enterprise') {
    return res.status(403).json({
      error: 'Legal Hold is available on Enterprise plans only. Contact ryan@authproof.dev to upgrade.',
    });
  }
  next();
}

// ─── auth ────────────────────────────────────────────────────────────────────

app.post('/auth/signup', authLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const { data: authData, error: authError } = await supabase.auth.signUp({ email, password });
  if (authError) return res.status(400).json({ error: authError.message });

  const { data: account, error: accountError } = await supabaseAdmin
    .from('accounts')
    .insert({ email })
    .select()
    .single();

  if (accountError) {
    await supabaseAdmin.auth.admin.deleteUser(authData.user.id);
    return res.status(400).json({ error: accountError.message });
  }

  res.status(201).json({
    apiKey: account.api_key,
    accountId: account.id,
    plan: account.plan,
    monthlyLimit: account.monthly_limit,
  });
});

// ── password reset helpers ───────────────────────────────────────────────────

function makeResetToken(email) {
  const payload = Buffer.from(JSON.stringify({ email, exp: Date.now() + 3600000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.SUPABASE_SERVICE_KEY).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifyResetToken(token) {
  try {
    const [payload, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', process.env.SUPABASE_SERVICE_KEY).update(payload).digest('base64url');
    if (sig !== expected) return null;
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (Date.now() > data.exp) return null;
    return data;
  } catch { return null; }
}

async function sendResetEmail(email, resetLink) {
  const resendKey = process.env.RESEND_API_KEY;
  if (!resendKey) return;
  const https = require('https');
  const body = JSON.stringify({
    // authproof.dev must be verified as a Resend sending domain before this address works
    from: 'Authproof Cloud <noreply@authproof.dev>',
    to: [email],
    subject: 'Reset your Authproof Cloud password',
    html: `
      <div style="font-family:system-ui,sans-serif;max-width:480px;margin:0 auto;padding:40px 24px;background:#fff">
        <h1 style="font-size:20px;font-weight:700;margin-bottom:8px;color:#000">Reset your password</h1>
        <p style="color:#555;font-size:14px;margin-bottom:28px;line-height:1.6">
          Click the button below to set a new password for your Authproof Cloud account.
          This link expires in 1 hour.
        </p>
        <a href="${resetLink}"
           style="display:inline-block;background:#1a56db;color:#ffffff;font-weight:700;font-size:14px;
                  padding:14px 28px;text-decoration:none;border-radius:980px;letter-spacing:0.02em">
          Reset password
        </a>
        <p style="color:#999;font-size:12px;margin-top:28px;line-height:1.6">
          If you didn't request this, ignore this email — your password won't change.<br>
          Or copy: <a href="${resetLink}" style="color:#00cc33">${resetLink}</a>
        </p>
      </div>
    `,
  });
  await new Promise((resolve) => {
    const r2 = https.request({
      hostname: 'api.resend.com', path: '/emails', method: 'POST',
      headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (r) => { let raw=''; r.on('data', c => raw+=c); r.on('end', () => { console.log('[Resend]', r.statusCode, raw); resolve(); }); });
    r2.on('error', (e) => { console.error('[Resend] error:', e.message); resolve(); });
    r2.write(body); r2.end();
  });
}

app.post('/auth/forgot-password', authLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email is required' });

  try {
    // Check account exists (don't reveal if it doesn't)
    const { data: account } = await supabaseAdmin
      .from('accounts').select('email').eq('email', email).single();

    if (account) {
      const token = makeResetToken(email);
      const resetLink = `https://cloud.authproof.dev/reset-password?token=${encodeURIComponent(token)}`;
      await sendResetEmail(email, resetLink);
    }
  } catch (err) {
    console.error('Forgot password error:', err.message);
  }

  res.json({ success: true });
});

app.post('/auth/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'token and password are required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const data = verifyResetToken(token);
  if (!data) return res.status(400).json({ error: 'Reset link is invalid or has expired' });

  const { data: accountRow, error: accountError } = await supabaseAdmin
    .from('accounts')
    .select('user_id')
    .eq('email', data.email)
    .single();

  if (accountError || !accountRow) return res.status(400).json({ error: 'Account not found' });

  const { error: updateErr } = await supabaseAdmin.auth.admin.updateUserById(accountRow.user_id, { password });
  if (updateErr) return res.status(500).json({ error: updateErr.message });

  res.json({ success: true });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: error.message });

  const { data: account } = await supabaseAdmin
    .from('accounts')
    .select('api_key, plan')
    .eq('email', email)
    .single();

  res.json({
    token: data.session.access_token,
    apiKey: account?.api_key,
    plan: account?.plan,
  });
});

// ─── receipts ────────────────────────────────────────────────────────────────

app.post('/receipts', requireApiKey, async (req, res) => {
  const { receiptHash, receiptData, expiresAt } = req.body || {};
  if (!receiptHash || !receiptData) {
    return res.status(400).json({ error: 'receiptHash and receiptData are required' });
  }

  const { account } = req;
  if (account.plan === 'free' && account.receipt_count >= account.monthly_limit) {
    return res.status(429).json({
      error: 'Monthly receipt limit reached. Upgrade to Pro for unlimited receipts.',
    });
  }

  const scopeHash = receiptData.scope ? sha256(receiptData.scope) : null;
  const operatorInstructionsHash = receiptData.operatorInstructions
    ? sha256(receiptData.operatorInstructions)
    : null;

  const { data: receipt, error } = await supabaseAdmin
    .from('receipts')
    .insert({
      account_id: account.id,
      receipt_hash: receiptHash,
      receipt_data: receiptData,
      scope_hash: scopeHash,
      operator_instructions_hash: operatorInstructionsHash,
      expires_at: expiresAt || null,
    })
    .select()
    .single();

  if (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'Receipt hash already exists' });
    return res.status(400).json({ error: error.message });
  }

  await supabaseAdmin
    .from('accounts')
    .update({ receipt_count: account.receipt_count + 1, last_seen_at: new Date().toISOString() })
    .eq('id', account.id);

  res.status(201).json({
    id: receipt.id,
    receiptHash: receipt.receipt_hash,
    storedAt: receipt.created_at,
  });
});

app.get('/receipts/:hash', requireApiKey, async (req, res) => {
  const { data: receipt, error } = await supabaseAdmin
    .from('receipts')
    .select('*')
    .eq('receipt_hash', req.params.hash)
    .eq('account_id', req.account.id)
    .single();

  if (error || !receipt) return res.status(404).json({ error: 'Receipt not found' });
  res.json(receipt);
});

app.post('/receipts/:hash/revoke', requireApiKey, async (req, res) => {
  const { data: existing } = await supabaseAdmin
    .from('receipts')
    .select('on_legal_hold')
    .eq('receipt_hash', req.params.hash)
    .eq('account_id', req.account.id)
    .single();

  if (existing?.on_legal_hold) {
    return res.status(423).json({ error: 'Receipt is subject to legal hold and cannot be revoked.' });
  }

  const { data: receipt, error } = await supabaseAdmin
    .from('receipts')
    .update({ revoked: true, revoked_at: new Date().toISOString() })
    .eq('receipt_hash', req.params.hash)
    .eq('account_id', req.account.id)
    .select()
    .single();

  if (error || !receipt) return res.status(404).json({ error: 'Receipt not found' });
  res.json({ success: true, revokedAt: receipt.revoked_at });
});

app.get('/receipts/:hash/verify', requireApiKey, async (req, res) => {
  // Accept action/operatorInstructions from body or query string
  const rawAction = req.body?.action ?? req.query.action;
  const rawInstructions = req.body?.operatorInstructions ?? req.query.operatorInstructions;

  let action = null;
  let operatorInstructions = null;

  try {
    if (rawAction) action = typeof rawAction === 'string' ? JSON.parse(rawAction) : rawAction;
    if (rawInstructions)
      operatorInstructions =
        typeof rawInstructions === 'string' ? JSON.parse(rawInstructions) : rawInstructions;
  } catch {
    return res.status(400).json({ error: 'action and operatorInstructions must be valid JSON' });
  }

  const { data: receipt } = await supabaseAdmin
    .from('receipts')
    .select('*')
    .eq('receipt_hash', req.params.hash)
    .single();

  const now = new Date();

  const checks = {
    receipt_exists: !!receipt,
    not_revoked: receipt ? !receipt.revoked : false,
    not_expired: receipt
      ? !receipt.expires_at || new Date(receipt.expires_at) > now
      : false,
    scope_valid: receipt ? checkScopeMatch(action, receipt.receipt_data?.scope) : false,
    operator_instructions_match: receipt
      ? checkOperatorInstructionsMatch(operatorInstructions, receipt)
      : false,
    action_within_bounds: receipt ? checkActionBounds(action, receipt.receipt_data) : false,
    no_anomalies: receipt ? checkNoAnomalies(action, receipt.receipt_data) : false,
  };

  const passed = Object.values(checks).filter(Boolean).length;
  const riskScore = parseFloat(((7 - passed) / 7).toFixed(3));

  const criticalFailed =
    !checks.receipt_exists || !checks.not_revoked || !checks.not_expired;
  const decision = criticalFailed ? 'deny' : riskScore > 0.4 ? 'review' : 'allow';

  const reasons = [];
  if (!checks.receipt_exists) reasons.push('Receipt not found');
  if (!checks.not_revoked) reasons.push('Receipt has been revoked');
  if (!checks.not_expired) reasons.push('Receipt has expired');
  if (!checks.scope_valid) reasons.push('Action does not match declared scope');
  if (!checks.operator_instructions_match)
    reasons.push('Operator instructions hash mismatch');
  if (!checks.action_within_bounds) reasons.push('Action exceeds authorized bounds');
  if (!checks.no_anomalies) reasons.push('Anomalous action patterns detected');

  await supabaseAdmin.from('verifications').insert({
    account_id: req.account.id,
    receipt_hash: req.params.hash,
    action,
    decision,
    risk_score: riskScore,
    reasons,
  });

  res.json({ decision, riskScore, reasons, checks });
});

// ─── verification helpers ────────────────────────────────────────────────────

function checkScopeMatch(action, scope) {
  if (!action || !scope) return true;
  if (typeof scope === 'string') {
    return action.type === scope || action.operation === scope;
  }
  if (Array.isArray(scope)) {
    return scope.includes(action.type) || scope.includes(action.operation);
  }
  if (scope.allowedOperations && action.operation) {
    if (!scope.allowedOperations.includes(action.operation)) return false;
  }
  if (scope.resource && action.resource) {
    if (scope.resource !== action.resource && scope.resource !== '*') return false;
  }
  if (scope.methods && action.method) {
    if (!scope.methods.includes(action.method)) return false;
  }
  return true;
}

function checkOperatorInstructionsMatch(instructions, receipt) {
  if (!instructions || !receipt.operator_instructions_hash) return true;
  return sha256(instructions) === receipt.operator_instructions_hash;
}

function checkActionBounds(action, receiptData) {
  if (!action || !receiptData) return true;
  if (receiptData.maxAmount != null && action.amount != null) {
    if (action.amount > receiptData.maxAmount) return false;
  }
  if (receiptData.allowedResources && action.resource) {
    if (!receiptData.allowedResources.includes(action.resource)) return false;
  }
  if (receiptData.allowedEndpoints && action.endpoint) {
    if (!receiptData.allowedEndpoints.includes(action.endpoint)) return false;
  }
  return true;
}

function checkNoAnomalies(action, receiptData) {
  if (!action || !receiptData) return true;
  if (action.bulk === true && !receiptData.scope?.allowBulk) return false;
  const scopeMax = receiptData.scope?.maxAmount ?? receiptData.maxAmount;
  if (scopeMax != null && action.amount != null && action.amount > scopeMax * 10) return false;
  if (action.externalSystem && receiptData.scope?.allowedSystems) {
    if (!receiptData.scope.allowedSystems.includes(action.externalSystem)) return false;
  }
  return true;
}

// ─── tool calls ───────────────────────────────────────────────────────────────

app.post('/tool-calls', requireApiKey, async (req, res) => {
  const {
    tool_name, arguments: args, result, decision,
    session_id, receipt_hash, risk_score, duration_ms,
  } = req.body || {};

  if (!tool_name) return res.status(400).json({ error: 'tool_name is required' });
  if (!['allowed', 'blocked', 'flagged'].includes(decision)) {
    return res.status(400).json({ error: 'decision must be "allowed", "blocked", or "flagged"' });
  }

  const arguments_hash = sha256(args);
  const result_hash = result !== undefined && result !== null ? sha256(result) : null;

  let arguments_preview = null;
  try {
    const s = JSON.stringify(args);
    arguments_preview = s.length <= 512 ? args : { _preview: s.slice(0, 509) + '...' };
  } catch {}

  let result_preview = null;
  try {
    if (result !== undefined && result !== null) {
      const s = JSON.stringify(result);
      result_preview = s.length <= 512 ? result : { _preview: s.slice(0, 509) + '...' };
    }
  } catch {}

  const { data: toolCall, error } = await supabaseAdmin
    .from('tool_calls')
    .insert({
      account_id: req.account.id,
      session_id: session_id || null,
      receipt_hash: receipt_hash || null,
      tool_name,
      arguments_hash,
      arguments_preview,
      result_hash,
      result_preview,
      decision,
      risk_score: risk_score ?? null,
      duration_ms: duration_ms ?? null,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });

  res.status(201).json({
    id: toolCall.id,
    tool_name: toolCall.tool_name,
    arguments_hash: toolCall.arguments_hash,
    result_hash: toolCall.result_hash,
    decision: toolCall.decision,
    created_at: toolCall.created_at,
  });
});

app.get('/tool-calls', requireApiKey, async (req, res) => {
  const { session_id, decision } = req.query;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;

  let query = supabaseAdmin
    .from('tool_calls')
    .select('*')
    .eq('account_id', req.account.id)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (session_id) query = query.eq('session_id', session_id);
  if (decision) query = query.eq('decision', decision);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });

  res.json(data || []);
});

// ─── account ─────────────────────────────────────────────────────────────────

app.get('/account', requireApiKey, async (req, res) => {
  const { account } = req;
  const isPro = account.plan === 'pro';
  const usagePercent = isPro
    ? 0
    : parseFloat(((account.receipt_count / account.monthly_limit) * 100).toFixed(1));

  res.json({
    plan: account.plan,
    receiptCount: account.receipt_count,
    monthlyLimit: isPro ? null : account.monthly_limit,
    usagePercent: isPro ? null : usagePercent,
  });
});

// ─── billing ─────────────────────────────────────────────────────────────────

app.get('/billing/checkout', requireApiKey, async (req, res) => {
  try {
    // Resolve the price ID inline — don't depend on background init
    if (!proPriceId) {
      const products = await stripe.products.list({ limit: 100 });
      let proProduct = products.data.find(p => p.metadata?.authproof === 'pro');
      if (!proProduct) {
        proProduct = await stripe.products.create({
          name: 'Authproof Cloud Pro',
          description: 'Unlimited delegation receipts, priority support, and SLA guarantee.',
          metadata: { authproof: 'pro' },
        });
      }
      const prices = await stripe.prices.list({ product: proProduct.id, limit: 20 });
      let proPrice = prices.data.find(
        p => p.unit_amount === 4900 && p.recurring?.interval === 'month' && p.active
      );
      if (!proPrice) {
        proPrice = await stripe.prices.create({
          product: proProduct.id,
          unit_amount: 4900,
          currency: 'usd',
          recurring: { interval: 'month' },
        });
      }
      proPriceId = proPrice.id;
    }

    const { account } = req;
    let customerId = account.stripe_customer_id;

    // Verify the stored customer ID exists in this Stripe environment
    // (test-mode IDs are invalid in live mode and vice versa)
    if (customerId) {
      try {
        await stripe.customers.retrieve(customerId);
      } catch (e) {
        // Customer not found in this environment — create a new one
        customerId = null;
      }
    }

    if (!customerId) {
      const customer = await stripe.customers.create({ email: account.email });
      customerId = customer.id;
      await supabaseAdmin
        .from('accounts')
        .update({ stripe_customer_id: customerId })
        .eq('id', account.id);
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: proPriceId, quantity: 1 }],
      success_url: `${process.env.BASE_URL || 'https://cloud.authproof.dev'}/dashboard?upgraded=true`,
      cancel_url: `${process.env.BASE_URL || 'https://cloud.authproof.dev'}/dashboard?canceled=true`,
    });

    res.json({ checkoutUrl: session.url });
  } catch (err) {
    console.error('Checkout error:', err.message);
    res.status(500).json({ error: err.message || 'Could not create checkout session' });
  }
});

app.get('/billing/portal', requireApiKey, async (req, res) => {
  const { account } = req;
  if (!account.stripe_customer_id) {
    return res.status(400).json({ error: 'No billing account found. Upgrade to Pro first.' });
  }

  const session = await stripe.billingPortal.sessions.create({
    customer: account.stripe_customer_id,
    return_url: process.env.BASE_URL || 'https://cloud.authproof.dev',
  });

  res.json({ portalUrl: session.url });
});

// ─── stripe webhook ───────────────────────────────────────────────────────────

app.post('/webhooks/stripe', async (req, res) => {
  const sig = req.headers['stripe-signature'];

  if (!process.env.STRIPE_WEBHOOK_SECRET) {
    return res.status(400).json({ error: 'Webhook secret not configured' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).json({ error: `Webhook verification failed: ${err.message}` });
  }

  const obj = event.data.object;

  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated': {
      const isActive = ['active', 'trialing'].includes(obj.status);
      await supabaseAdmin
        .from('accounts')
        .update({
          plan: isActive ? 'pro' : 'free',
          monthly_limit: isActive ? 2147483647 : 1000,
          stripe_subscription_id: obj.id,
        })
        .eq('stripe_customer_id', obj.customer);
      break;
    }
    case 'customer.subscription.deleted': {
      await supabaseAdmin
        .from('accounts')
        .update({ plan: 'free', monthly_limit: 1000, stripe_subscription_id: null })
        .eq('stripe_customer_id', obj.customer);
      break;
    }
  }

  res.json({ received: true });
});

// ─── dashboard ────────────────────────────────────────────────────────────────

app.get('/api/dashboard', requireApiKey, async (req, res) => {
  const { account } = req;

  const [receiptsResult, verificationsResult, toolCallsResult, toolCallDecisionsResult] = await Promise.all([
    supabaseAdmin
      .from('receipts')
      .select('*')
      .eq('account_id', account.id)
      .order('created_at', { ascending: false })
      .limit(20),
    supabaseAdmin
      .from('verifications')
      .select('*')
      .eq('account_id', account.id)
      .order('created_at', { ascending: false })
      .limit(20),
    supabaseAdmin
      .from('tool_calls')
      .select('*')
      .eq('account_id', account.id)
      .order('created_at', { ascending: false })
      .limit(10),
    supabaseAdmin
      .from('tool_calls')
      .select('decision')
      .eq('account_id', account.id),
  ]);

  const isPro = account.plan === 'pro';
  const usagePercent = isPro
    ? 0
    : parseFloat(((account.receipt_count / account.monthly_limit) * 100).toFixed(1));

  const decisions = toolCallDecisionsResult.data || [];
  const toolCallStats = {
    total: decisions.length,
    allowed: decisions.filter(r => r.decision === 'allowed').length,
    blocked: decisions.filter(r => r.decision === 'blocked').length,
    flagged: decisions.filter(r => r.decision === 'flagged').length,
  };

  res.json({
    account: {
      email: account.email,
      plan: account.plan,
      receiptCount: account.receipt_count,
      monthlyLimit: isPro ? null : account.monthly_limit,
      usagePercent: isPro ? null : usagePercent,
    },
    recentReceipts: receiptsResult.data || [],
    recentVerifications: verificationsResult.data || [],
    recentToolCalls: toolCallsResult.data || [],
    toolCallStats,
  });
});

// ─── audit ────────────────────────────────────────────────────────────────────

app.get('/audit/export', requireApiKey, async (req, res) => {
  const { format = 'json', from, to, session_id } = req.query;
  const { account } = req;

  let receiptsQuery = supabaseAdmin
    .from('receipts')
    .select('*')
    .eq('account_id', account.id)
    .order('created_at', { ascending: true });

  let toolCallsQuery = supabaseAdmin
    .from('tool_calls')
    .select('*')
    .eq('account_id', account.id)
    .order('created_at', { ascending: true });

  if (from) {
    receiptsQuery = receiptsQuery.gte('created_at', from);
    toolCallsQuery = toolCallsQuery.gte('created_at', from);
  }
  if (to) {
    receiptsQuery = receiptsQuery.lte('created_at', to);
    toolCallsQuery = toolCallsQuery.lte('created_at', to);
  }
  if (session_id) {
    toolCallsQuery = toolCallsQuery.eq('session_id', session_id);
  }

  const [{ data: receipts }, { data: toolCalls }] = await Promise.all([
    receiptsQuery,
    toolCallsQuery,
  ]);

  const payload = {
    exported_at: new Date().toISOString(),
    account_id: account.id,
    receipts: receipts || [],
    tool_calls: toolCalls || [],
  };

  const signature = crypto
    .createHmac('sha256', account.api_key)
    .update(JSON.stringify(payload))
    .digest('hex');

  res.setHeader('X-Audit-Signature', signature);

  if (format === 'csv') {
    function csvEscape(val) {
      if (val == null) return '""';
      return '"' + String(val).replace(/"/g, '""') + '"';
    }

    const lines = [];
    lines.push('type,id,receipt_hash,created_at,revoked,expires_at,tool_name,decision,risk_score,session_id');
    for (const r of payload.receipts) {
      lines.push([
        csvEscape('receipt'), csvEscape(r.id), csvEscape(r.receipt_hash),
        csvEscape(r.created_at), csvEscape(r.revoked), csvEscape(r.expires_at),
        csvEscape(''), csvEscape(''), csvEscape(''), csvEscape(''),
      ].join(','));
    }
    for (const t of payload.tool_calls) {
      lines.push([
        csvEscape('tool_call'), csvEscape(t.id), csvEscape(''),
        csvEscape(t.created_at), csvEscape(''), csvEscape(''),
        csvEscape(t.tool_name), csvEscape(t.decision), csvEscape(t.risk_score), csvEscape(t.session_id),
      ].join(','));
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="audit-export.csv"');
    return res.send(lines.join('\n'));
  }

  res.json({ ...payload, signature });
});

app.get('/audit/report', requireApiKey, async (req, res) => {
  const { from, to, session_id } = req.query;
  const { account } = req;

  let receiptsQuery = supabaseAdmin
    .from('receipts')
    .select('*')
    .eq('account_id', account.id)
    .order('created_at', { ascending: false });

  let toolCallsQuery = supabaseAdmin
    .from('tool_calls')
    .select('*')
    .eq('account_id', account.id)
    .order('created_at', { ascending: false });

  if (from) {
    receiptsQuery = receiptsQuery.gte('created_at', from);
    toolCallsQuery = toolCallsQuery.gte('created_at', from);
  }
  if (to) {
    receiptsQuery = receiptsQuery.lte('created_at', to);
    toolCallsQuery = toolCallsQuery.lte('created_at', to);
  }
  if (session_id) toolCallsQuery = toolCallsQuery.eq('session_id', session_id);

  const [{ data: receipts }, { data: toolCalls }] = await Promise.all([
    receiptsQuery,
    toolCallsQuery,
  ]);

  const r = receipts || [];
  const t = toolCalls || [];

  const blocked = t.filter(c => c.decision === 'blocked').length;
  const flagged = t.filter(c => c.decision === 'flagged').length;
  const exportedAt = new Date().toISOString();

  const payload = { exported_at: exportedAt, account_id: account.id, receipts: r, tool_calls: t };
  const signature = crypto
    .createHmac('sha256', account.api_key)
    .update(JSON.stringify(payload))
    .digest('hex');

  const receiptRows = r.map(rec => `
    <tr>
      <td>${new Date(rec.created_at).toLocaleString()}</td>
      <td style="font-family:monospace;font-size:12px">${rec.receipt_hash?.slice(0, 16)}…</td>
      <td>${rec.revoked ? '<span style="color:#c00">Revoked</span>' : '<span style="color:#060">Active</span>'}</td>
      <td>${rec.expires_at ? new Date(rec.expires_at).toLocaleDateString() : '—'}</td>
    </tr>`).join('') || '<tr><td colspan="4" style="text-align:center;color:#999">No receipts</td></tr>';

  const toolCallRows = t.map(tc => {
    const decisionColor = tc.decision === 'allowed' ? '#060' : tc.decision === 'blocked' ? '#c00' : '#a60';
    return `
    <tr>
      <td>${new Date(tc.created_at).toLocaleString()}</td>
      <td style="font-family:monospace">${tc.tool_name}</td>
      <td style="color:${decisionColor};font-weight:600">${tc.decision}</td>
      <td>${tc.risk_score != null ? tc.risk_score.toFixed(2) : '—'}</td>
      <td style="font-family:monospace;font-size:12px">${tc.session_id || '—'}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="5" style="text-align:center;color:#999">No tool calls</td></tr>';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Authproof Cloud — Audit Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; font-size: 13px; color: #111; background: #fff; padding: 40px; }
    h1 { font-size: 22px; margin-bottom: 4px; }
    .meta { color: #666; font-size: 12px; margin-bottom: 32px; }
    .stats { display: flex; gap: 24px; margin-bottom: 32px; }
    .stat { border: 1px solid #ddd; padding: 16px 24px; }
    .stat-n { font-size: 28px; font-weight: 700; }
    .stat-l { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
    h2 { font-size: 15px; margin-bottom: 12px; margin-top: 32px; border-bottom: 1px solid #eee; padding-bottom: 6px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { text-align: left; padding: 8px 10px; background: #f5f5f5; border-bottom: 2px solid #ddd; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
    td { padding: 8px 10px; border-bottom: 1px solid #eee; }
    footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #eee; font-size: 11px; color: #999; }
    @media print { body { padding: 24px; } .stats { flex-wrap: wrap; } }
  </style>
</head>
<body>
  <h1>Authproof Cloud — Audit Report</h1>
  <div class="meta">Account: ${account.email} &nbsp;·&nbsp; Generated: ${exportedAt}${from ? ' &nbsp;·&nbsp; From: ' + from : ''}${to ? ' &nbsp;·&nbsp; To: ' + to : ''}</div>

  <div class="stats">
    <div class="stat"><div class="stat-n">${r.length}</div><div class="stat-l">Receipts</div></div>
    <div class="stat"><div class="stat-n">${t.length}</div><div class="stat-l">Tool Calls</div></div>
    <div class="stat"><div class="stat-n" style="color:#c00">${blocked}</div><div class="stat-l">Blocked</div></div>
    <div class="stat"><div class="stat-n" style="color:#a60">${flagged}</div><div class="stat-l">Flagged</div></div>
  </div>

  <h2>Receipts</h2>
  <table>
    <thead><tr><th>Time</th><th>Hash</th><th>Status</th><th>Expires</th></tr></thead>
    <tbody>${receiptRows}</tbody>
  </table>

  <h2>Tool Calls</h2>
  <table>
    <thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Risk</th><th>Session</th></tr></thead>
    <tbody>${toolCallRows}</tbody>
  </table>

  <footer>
    <p>HMAC-SHA256 Signature: <span style="font-family:monospace">${signature}</span></p>
    <p style="margin-top:4px">Verify: <code>crypto.createHmac('sha256', YOUR_API_KEY).update(JSON.stringify(payload)).digest('hex')</code></p>
  </footer>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html');
  res.setHeader('X-Audit-Signature', signature);
  res.send(html);
});

// ─── legal holds ─────────────────────────────────────────────────────────────

app.post('/legal-holds', requireApiKey, requireEnterprise, async (req, res) => {
  const { name, description, organizationId, expiresAt } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });

  const { data: hold, error } = await supabaseAdmin
    .from('legal_holds')
    .insert({
      account_id: req.account.id,
      organization_id: organizationId || null,
      name,
      description: description || null,
      status: 'active',
      created_by: req.account.email || req.account.id,
      expires_at: expiresAt || null,
    })
    .select()
    .single();

  if (error) return res.status(400).json({ error: error.message });

  await logCustodyEvent(hold.id, 'hold_created', req.account.email || req.account.id, {
    name,
    description: description || null,
    organization_id: organizationId || null,
    expires_at: expiresAt || null,
  });

  res.status(201).json({ id: hold.id, name: hold.name, status: hold.status, createdAt: hold.created_at });
});

app.get('/legal-holds', requireApiKey, requireEnterprise, async (req, res) => {
  const { data: holds, error } = await supabaseAdmin
    .from('legal_holds')
    .select('*')
    .eq('account_id', req.account.id)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(holds || []);
});

app.get('/legal-holds/:id', requireApiKey, requireEnterprise, async (req, res) => {
  const { data: hold, error } = await supabaseAdmin
    .from('legal_holds')
    .select('*')
    .eq('id', req.params.id)
    .eq('account_id', req.account.id)
    .single();

  if (error || !hold) return res.status(404).json({ error: 'Legal hold not found' });

  const [{ data: items }, { data: custodyLog }] = await Promise.all([
    supabaseAdmin
      .from('legal_hold_items')
      .select('*')
      .eq('legal_hold_id', hold.id)
      .order('added_at', { ascending: false }),
    supabaseAdmin
      .from('legal_hold_custody_log')
      .select('*')
      .eq('legal_hold_id', hold.id)
      .order('occurred_at', { ascending: true }),
  ]);

  res.json({ ...hold, items: items || [], chain_of_custody: custodyLog || [] });
});

app.post('/legal-holds/:id/items', requireApiKey, requireEnterprise, async (req, res) => {
  const { receiptHashes, addedBy } = req.body || {};
  if (!receiptHashes?.length) return res.status(400).json({ error: 'receiptHashes is required' });
  if (!addedBy) return res.status(400).json({ error: 'addedBy is required' });

  const { data: hold } = await supabaseAdmin
    .from('legal_holds')
    .select('id, status, receipt_count')
    .eq('id', req.params.id)
    .eq('account_id', req.account.id)
    .single();

  if (!hold) return res.status(404).json({ error: 'Legal hold not found' });
  if (hold.status !== 'active') return res.status(409).json({ error: 'Legal hold is not active' });

  const added = [];
  for (const hash of receiptHashes) {
    const { data: receipt } = await supabaseAdmin
      .from('receipts')
      .select('id, receipt_hash')
      .eq('receipt_hash', hash)
      .eq('account_id', req.account.id)
      .single();

    if (!receipt) continue;

    await supabaseAdmin
      .from('receipts')
      .update({ on_legal_hold: true, legal_hold_id: hold.id })
      .eq('id', receipt.id);

    await supabaseAdmin
      .from('verifications')
      .update({ on_legal_hold: true })
      .eq('receipt_hash', hash)
      .eq('account_id', req.account.id);

    await supabaseAdmin
      .from('tool_calls')
      .update({ on_legal_hold: true })
      .eq('receipt_hash', hash)
      .eq('account_id', req.account.id);

    await supabaseAdmin.from('legal_hold_items').insert({
      legal_hold_id: hold.id,
      item_type: 'receipt',
      item_id: receipt.id,
      receipt_hash: hash,
      added_by: addedBy,
    });

    added.push(hash);
  }

  if (added.length) {
    await supabaseAdmin
      .from('legal_holds')
      .update({ receipt_count: hold.receipt_count + added.length })
      .eq('id', hold.id);

    await logCustodyEvent(hold.id, 'items_added', addedBy, {
      count: added.length,
      receipt_hashes: added,
    });
  }

  res.json({ added: added.length, receiptHashes: added });
});

app.post('/legal-holds/:id/items/bulk', requireApiKey, requireEnterprise, async (req, res) => {
  const { from, to, organizationId } = req.body || {};
  if (!from || !to) return res.status(400).json({ error: 'from and to are required' });

  const { data: hold } = await supabaseAdmin
    .from('legal_holds')
    .select('id, status, receipt_count')
    .eq('id', req.params.id)
    .eq('account_id', req.account.id)
    .single();

  if (!hold) return res.status(404).json({ error: 'Legal hold not found' });
  if (hold.status !== 'active') return res.status(409).json({ error: 'Legal hold is not active' });

  const { data: receipts } = await supabaseAdmin
    .from('receipts')
    .select('id, receipt_hash')
    .eq('account_id', req.account.id)
    .eq('on_legal_hold', false)
    .gte('created_at', from)
    .lte('created_at', to);

  if (!receipts?.length) return res.json({ added: 0 });

  const addedBy = req.account.email || req.account.id;

  await supabaseAdmin.from('legal_hold_items').insert(
    receipts.map(r => ({
      legal_hold_id: hold.id,
      item_type: 'receipt',
      item_id: r.id,
      receipt_hash: r.receipt_hash,
      added_by: addedBy,
    }))
  );

  const ids = receipts.map(r => r.id);
  const hashes = receipts.map(r => r.receipt_hash);

  await supabaseAdmin
    .from('receipts')
    .update({ on_legal_hold: true, legal_hold_id: hold.id })
    .in('id', ids);

  await supabaseAdmin
    .from('verifications')
    .update({ on_legal_hold: true })
    .in('receipt_hash', hashes)
    .eq('account_id', req.account.id);

  await supabaseAdmin
    .from('tool_calls')
    .update({ on_legal_hold: true })
    .in('receipt_hash', hashes)
    .eq('account_id', req.account.id);

  await supabaseAdmin
    .from('legal_holds')
    .update({ receipt_count: hold.receipt_count + receipts.length })
    .eq('id', hold.id);

  await logCustodyEvent(hold.id, 'items_added_bulk', addedBy, {
    count: receipts.length,
    from,
    to,
    organization_id: organizationId || null,
  });

  res.json({ added: receipts.length });
});

app.post('/legal-holds/:id/release', requireApiKey, requireEnterprise, async (req, res) => {
  const { releasedBy, reason } = req.body || {};
  if (!releasedBy) return res.status(400).json({ error: 'releasedBy is required' });
  if (!reason) return res.status(400).json({ error: 'reason is required' });

  const { data: hold } = await supabaseAdmin
    .from('legal_holds')
    .select('id, status')
    .eq('id', req.params.id)
    .eq('account_id', req.account.id)
    .single();

  if (!hold) return res.status(404).json({ error: 'Legal hold not found' });
  if (hold.status !== 'active') return res.status(409).json({ error: 'Legal hold is already released' });

  const releasedAt = new Date().toISOString();

  await supabaseAdmin
    .from('legal_holds')
    .update({ status: 'released', released_at: releasedAt, released_by: releasedBy, release_reason: reason })
    .eq('id', hold.id);

  const { data: items } = await supabaseAdmin
    .from('legal_hold_items')
    .select('item_id, receipt_hash')
    .eq('legal_hold_id', hold.id);

  if (items?.length) {
    const ids = items.map(i => i.item_id);
    const hashes = items.map(i => i.receipt_hash).filter(Boolean);

    await supabaseAdmin.from('receipts').update({ on_legal_hold: false }).in('id', ids);

    if (hashes.length) {
      await supabaseAdmin
        .from('verifications')
        .update({ on_legal_hold: false })
        .in('receipt_hash', hashes)
        .eq('account_id', req.account.id);

      await supabaseAdmin
        .from('tool_calls')
        .update({ on_legal_hold: false })
        .in('receipt_hash', hashes)
        .eq('account_id', req.account.id);
    }
  }

  await logCustodyEvent(hold.id, 'hold_released', releasedBy, {
    reason,
    released_at: releasedAt,
    items_released: items?.length || 0,
  });

  res.json({ success: true, releasedAt, releasedBy, reason });
});

app.get('/legal-holds/:id/export', requireApiKey, requireEnterprise, async (req, res) => {
  const { data: hold } = await supabaseAdmin
    .from('legal_holds')
    .select('*')
    .eq('id', req.params.id)
    .eq('account_id', req.account.id)
    .single();

  if (!hold) return res.status(404).json({ error: 'Legal hold not found' });

  const [{ data: items }, { data: custodyLog }] = await Promise.all([
    supabaseAdmin.from('legal_hold_items').select('*').eq('legal_hold_id', hold.id),
    supabaseAdmin
      .from('legal_hold_custody_log')
      .select('*')
      .eq('legal_hold_id', hold.id)
      .order('occurred_at', { ascending: true }),
  ]);

  const receiptHashes = (items || []).map(i => i.receipt_hash).filter(Boolean);

  let verifications = [];
  let toolCalls = [];
  if (receiptHashes.length) {
    const [{ data: v }, { data: tc }] = await Promise.all([
      supabaseAdmin
        .from('verifications')
        .select('*')
        .eq('account_id', req.account.id)
        .in('receipt_hash', receiptHashes),
      supabaseAdmin
        .from('tool_calls')
        .select('*')
        .eq('account_id', req.account.id)
        .in('receipt_hash', receiptHashes),
    ]);
    verifications = v || [];
    toolCalls = tc || [];
  }

  const exportedAt = new Date().toISOString();
  const payload = {
    exported_at: exportedAt,
    hold: {
      id: hold.id,
      name: hold.name,
      description: hold.description,
      status: hold.status,
      created_by: hold.created_by,
      created_at: hold.created_at,
      expires_at: hold.expires_at,
      released_at: hold.released_at,
      released_by: hold.released_by,
      release_reason: hold.release_reason,
    },
    receipt_hashes: receiptHashes,
    items: items || [],
    verifications,
    tool_calls: toolCalls,
    chain_of_custody: custodyLog || [],
  };

  const signature = crypto
    .createHmac('sha256', req.account.api_key)
    .update(JSON.stringify(payload))
    .digest('hex');

  const exportPackage = { ...payload, export_hash: signature };

  await logCustodyEvent(hold.id, 'export_generated', req.account.email || req.account.id, {
    exported_at: exportedAt,
    export_hash: signature,
  });

  res.setHeader('Content-Disposition', `attachment; filename="legal-hold-${hold.id}-export.json"`);
  res.json(exportPackage);
});

// ─── misc ─────────────────────────────────────────────────────────────────────

app.post('/account/regenerate-key', requireApiKey, async (req, res) => {
  const newKey = crypto.randomBytes(32).toString('hex');
  await supabaseAdmin
    .from('accounts')
    .update({ api_key: newKey })
    .eq('id', req.account.id);
  res.json({ apiKey: newKey });
});

app.post('/auth/logout', (req, res) => {
  res.json({ ok: true });
});

// ─── retention cleanup ────────────────────────────────────────────────────────
// Schedule externally (e.g. pg_cron, Supabase Edge Function, or Vercel cron).
// Receipts with on_legal_hold = true are always skipped regardless of expires_at.
async function runRetentionCleanup() {
  const now = new Date().toISOString();
  const { data: expired, error } = await supabaseAdmin
    .from('receipts')
    .select('id, receipt_hash')
    .eq('on_legal_hold', false)
    .eq('revoked', false)
    .not('expires_at', 'is', null)
    .lt('expires_at', now);

  if (error) { console.error('[retention] Query error:', error.message); return; }
  if (!expired?.length) { console.log('[retention] No expired receipts.'); return; }

  await supabaseAdmin
    .from('receipts')
    .update({ revoked: true, revoked_at: now })
    .in('id', expired.map(r => r.id));

  console.log(`[retention] Expired ${expired.length} receipts.`);
}

// ─── startup ──────────────────────────────────────────────────────────────────

async function initStripe() {
  stripeReady = (async () => { try {
    const products = await stripe.products.list({ limit: 100 });
    let proProduct = products.data.find((p) => p.metadata?.authproof === 'pro');

    if (!proProduct) {
      proProduct = await stripe.products.create({
        name: 'Authproof Cloud Pro',
        description: 'Unlimited delegation receipts, priority support, and SLA guarantee.',
        metadata: { authproof: 'pro' },
      });
      console.log('Created Authproof Pro product:', proProduct.id);
    }

    const prices = await stripe.prices.list({ product: proProduct.id, limit: 20 });
    let proPrice = prices.data.find(
      (p) => p.unit_amount === 4900 && p.recurring?.interval === 'month' && p.active
    );

    if (!proPrice) {
      proPrice = await stripe.prices.create({
        product: proProduct.id,
        unit_amount: 4900,
        currency: 'usd',
        recurring: { interval: 'month' },
      });
      console.log('Created Pro price:', proPrice.id);
    }

    proPriceId = proPrice.id;
    console.log('Stripe ready. Pro price ID:', proPriceId);
  } catch (err) {
    console.error('Stripe init failed:', err.message);
  } })();
}

initStripe();

const PORT = process.env.PORT || 3000;
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => console.log(`Authproof Cloud API on http://localhost:${PORT}`));
}

module.exports = app;
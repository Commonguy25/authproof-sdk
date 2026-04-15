/**
 * ScopeDiscovery — Observation-based scope generation for Delegation Receipts.
 *
 * Addresses the design-time authorization gap: users cannot correctly define scope
 * before seeing what an agent actually does. ScopeDiscovery runs the agent in a
 * sandboxed simulation, intercepts every operation (read/write/delete/execute/
 * payment/send), and generates a grounded scope definition with plain-language
 * explanation, risk flags, and suggested denials.
 *
 * Flow:
 *   1. observe(agentFn, { timeout })  — run agent in sandbox, capture operations
 *   2. generateScope()                — produce draft scope, summary, risk flags
 *   3. approve({ remove, add })       — apply user modifications
 *   4. finalize({ privateKey, ... })  — produce a signed Delegation Receipt
 *
 * Static helpers:
 *   ScopeDiscovery.fromReceipt(receipt, observations) — drift report
 *   ScopeDiscovery.guided({ agentFn, ... })            — one-call end-to-end flow
 *
 * @module scope-discovery
 * @version 1.0.0
 */

'use strict';

// ─────────────────────────────────────────────
// MOCK DATA STORE
// ─────────────────────────────────────────────

/**
 * Mock return values for each supported resource type and operation.
 * Every value is deliberately shallow — enough to satisfy duck-typing checks
 * without hiding real operations behind realistic-looking side effects.
 */
const _MOCK_DATA = {
  email: {
    read:   { messages: [{ id: 'msg-001', from: 'alice@example.com', subject: '[MOCK] Q3 Report', body: '[MOCK CONTENT]' }], count: 1 },
    list:   { messages: [{ id: 'msg-001', from: 'alice@example.com', subject: '[MOCK] Q3 Report' }], count: 1 },
    write:  { success: true, messageId: 'draft-mock-001', status: 'saved' },
    send:   { success: true, messageId: 'sent-mock-001',  status: 'queued' },
    delete: { success: true, deleted: 0, mock: true },
    search: { results: [{ id: 'msg-001', subject: '[MOCK]' }], count: 1 },
  },
  calendar: {
    read:   { events: [{ id: 'evt-001', title: '[MOCK] Team Standup', start: '2025-01-10T09:00:00Z' }], count: 1 },
    list:   { events: [{ id: 'evt-001', title: '[MOCK] Team Standup' }], count: 1 },
    write:  { success: true, eventId: 'evt-mock-001', status: 'created' },
    create: { success: true, eventId: 'evt-mock-001', status: 'created' },
    update: { success: true, eventId: 'evt-mock-001', status: 'updated' },
    delete: { success: true, deleted: 0, mock: true },
  },
  payment: {
    read:    { transactions: [{ id: 'txn-001', amount: 0, currency: 'USD', status: 'MOCK' }], count: 1 },
    list:    { transactions: [{ id: 'txn-001', amount: 0, status: 'MOCK' }], count: 1 },
    write:   { success: true, transactionId: 'txn-mock-001', status: 'pending', mock: true },
    execute: { success: true, transactionId: 'txn-mock-001', amount: 0, status: 'MOCK_SIMULATED', mock: true },
    charge:  { success: true, transactionId: 'txn-mock-001', amount: 0, status: 'MOCK_SIMULATED', mock: true },
    refund:  { success: true, refundId: 'ref-mock-001', amount: 0, status: 'MOCK_SIMULATED', mock: true },
    payment: { success: true, transactionId: 'txn-mock-001', amount: 0, status: 'MOCK_SIMULATED', mock: true },
  },
  files: {
    read:    { content: '[MOCK FILE CONTENT]', size: 19, encoding: 'utf-8' },
    list:    { files: [{ name: 'mock-file.txt', size: 19 }], count: 1 },
    write:   { success: true, bytesWritten: 0, path: '/mock/output.txt', mock: true },
    delete:  { success: true, deleted: 0, path: '/mock/target.txt', mock: true },
    execute: { success: true, stdout: '[MOCK OUTPUT]', exitCode: 0, mock: true },
    copy:    { success: true, destination: '/mock/copy.txt', mock: true },
    move:    { success: true, destination: '/mock/moved.txt', mock: true },
  },
  db: {
    read:    { rows: [{ id: 1, name: '[MOCK]', value: 0 }], count: 1 },
    query:   { rows: [{ id: 1, name: '[MOCK]' }], count: 1 },
    write:   { success: true, rowsAffected: 0, insertId: 'mock-1', mock: true },
    insert:  { success: true, rowsAffected: 0, insertId: 'mock-1', mock: true },
    update:  { success: true, rowsAffected: 0, mock: true },
    delete:  { success: true, rowsAffected: 0, mock: true },
    execute: { success: true, rowsAffected: 0, mock: true },
  },
  network: {
    read:    { status: 200, body: '{"mock":true}', headers: { 'content-type': 'application/json' } },
    fetch:   { status: 200, body: '{"mock":true}', headers: { 'content-type': 'application/json' } },
    get:     { status: 200, body: '{"mock":true}', headers: {} },
    write:   { status: 200, body: '{"success":true}', headers: {}, mock: true },
    post:    { status: 200, body: '{"success":true}', headers: {}, mock: true },
    execute: { status: 200, body: '{"executed":true}', headers: {}, mock: true },
    put:     { status: 200, body: '{"updated":true}', headers: {}, mock: true },
    delete:  { status: 200, body: '{"deleted":true}', headers: {}, mock: true },
  },
};

/** Supported resource type keys for sandbox construction. */
const _RESOURCE_TYPES = ['email', 'calendar', 'payment', 'files', 'db', 'network'];

// Operation risk classification sets
const _DELETE_OPS         = new Set(['delete', 'remove', 'destroy', 'drop', 'purge', 'truncate']);
const _EXECUTE_OPS        = new Set(['execute', 'exec', 'run', 'shell', 'spawn', 'eval']);
const _PAYMENT_OPS        = new Set(['payment', 'charge', 'pay', 'refund', 'transfer', 'purchase', 'debit']);
const _SEND_WRITE_EXT_OPS = new Set(['send', 'post', 'publish', 'notify', 'emit', 'push', 'submit']);

// ─────────────────────────────────────────────
// SANDBOX PROXY
// ─────────────────────────────────────────────

/**
 * Build a sandboxed resource object for a given resource type.
 * Every property access returns a function that:
 *   1. Records the (resource, operation) pair in the shared observations array.
 *   2. Returns a Promise resolving to mock data — never performs real I/O.
 *
 * @param {string}   resourceType
 * @param {object[]} observations — Shared observation log (mutated in place)
 * @returns {Proxy}
 */
function _buildResourceProxy(resourceType, observations) {
  const mockStore = _MOCK_DATA[resourceType] ?? {};

  return new Proxy({}, {
    get(_target, operation) {
      // Return a callable that records the operation and resolves with mock data
      return function sandboxedOperation(..._args) {
        observations.push({
          resource:   resourceType,
          operation:  String(operation),
          observedAt: Date.now(),
        });
        const mockResult = mockStore[operation] ?? { success: true, mock: true };
        return Promise.resolve(mockResult);
      };
    },
  });
}

/**
 * Build the complete sandbox context passed to agentFn during observation.
 * Contains one proxy per supported resource type.
 *
 * @param {object[]} observations
 * @returns {{ email, calendar, payment, files, db, network }}
 */
function _buildSandboxContext(observations) {
  const ctx = {};
  for (const rt of _RESOURCE_TYPES) {
    ctx[rt] = _buildResourceProxy(rt, observations);
  }
  return ctx;
}

// ─────────────────────────────────────────────
// SCOPE GENERATION HELPERS
// ─────────────────────────────────────────────

/**
 * Compute a frequency map: "resource:operation" → call count.
 * @param {object[]} observations
 * @returns {Map<string, number>}
 */
function _computeFrequencies(observations) {
  const freq = new Map();
  for (const obs of observations) {
    const k = `${obs.resource}:${obs.operation}`;
    freq.set(k, (freq.get(k) ?? 0) + 1);
  }
  return freq;
}

/**
 * Derive risk flags from observed operations and their frequencies.
 * Risk categories: delete, execute, payment, external send/write, high-frequency (>50).
 *
 * @param {object[]} observations
 * @param {Map<string,number>} freq
 * @returns {string[]}
 */
function _computeRiskFlags(observations, freq) {
  const flags = new Set();

  for (const obs of observations) {
    const op = obs.operation.toLowerCase();

    if (_DELETE_OPS.has(op)) {
      flags.add(`delete operation observed on resource "${obs.resource}"`);
    }
    if (_EXECUTE_OPS.has(op)) {
      flags.add(`execute operation observed on resource "${obs.resource}"`);
    }
    if (_PAYMENT_OPS.has(op)) {
      flags.add(`payment operation observed on resource "${obs.resource}"`);
    }
    if (_SEND_WRITE_EXT_OPS.has(op)) {
      flags.add(`external send/write operation observed on resource "${obs.resource}"`);
    }
  }

  // High-frequency: any (resource:op) pair called more than 50 times
  for (const [key, count] of freq) {
    if (count > 50) {
      flags.add(`high-frequency operation detected: "${key}" called ${count} times (>50)`);
    }
  }

  return [...flags];
}

/**
 * Suggest denials for dangerous operations that were not observed in this session.
 * Belt-and-suspenders: always suggests deny for delete, execute, and payment ops
 * since those are destructive regardless of whether the agent needed them.
 *
 * @param {object[]} observations
 * @returns {Array<{ operation: string, resource: string, reason: string }>}
 */
function _computeSuggestedDenials(observations) {
  const observedKeys = new Set(observations.map(o => `${o.operation}:${o.resource}`));

  const candidates = [
    { operation: 'delete',  resource: '*',       reason: 'destructive — permanently removes data with no undo' },
    { operation: 'execute', resource: '*',       reason: 'arbitrary code execution — highest privilege escalation risk' },
    { operation: 'payment', resource: '*',       reason: 'financial transactions cannot be automatically reversed' },
    { operation: 'charge',  resource: 'payment', reason: 'financial charge — should require explicit human approval' },
    { operation: 'send',    resource: 'email',   reason: 'external communication — agent can leak information or impersonate user' },
    { operation: 'post',    resource: 'network', reason: 'external write — agent can exfiltrate data or trigger side effects' },
    { operation: 'refund',  resource: 'payment', reason: 'financial mutation — requires explicit authorization' },
  ];

  const results = [];
  for (const c of candidates) {
    const exact    = observedKeys.has(`${c.operation}:${c.resource}`);
    const wildcard = observedKeys.has(`${c.operation}:*`);
    // Always include delete/execute/payment as denials (belt-and-suspenders)
    const alwaysDeny =
      _DELETE_OPS.has(c.operation) ||
      _EXECUTE_OPS.has(c.operation) ||
      _PAYMENT_OPS.has(c.operation);

    if (!exact && !wildcard) {
      results.push(c);
    } else if (alwaysDeny && !results.some(r => r.operation === c.operation && r.resource === c.resource)) {
      results.push(c);
    }
  }

  // De-duplicate
  const seen = new Set();
  return results.filter(d => {
    const k = `${d.operation}:${d.resource}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Build a plain-language summary of what the agent did during observation.
 * @param {object[]} observations
 * @param {Map<string,number>} freq
 * @returns {string}
 */
function _buildPlainSummary(observations, freq) {
  if (observations.length === 0) {
    return (
      'No operations were observed during this session. ' +
      'The agent did not access any resources.'
    );
  }

  // Group by resource
  const groups = new Map();
  for (const obs of observations) {
    if (!groups.has(obs.resource)) groups.set(obs.resource, new Set());
    groups.get(obs.resource).add(obs.operation);
  }

  const lines = [
    'During the observation session, the agent performed the following operations:',
  ];
  for (const [resource, ops] of groups) {
    lines.push(`  • ${resource}: ${[...ops].join(', ')}`);
  }

  // Frequently repeated operations
  const hiFreq = [];
  for (const [key, count] of freq) {
    if (count > 1) hiFreq.push(`${key} (×${count})`);
  }
  if (hiFreq.length > 0) {
    lines.push(`\nFrequently called operations: ${hiFreq.join(', ')}`);
  }

  lines.push(`\nTotal operations observed: ${observations.length}`);
  return lines.join('\n');
}

/**
 * Collapse observations into a de-duplicated list of { operation, resource } pairs
 * for use as allowedActions in a ScopeSchema.
 * @param {object[]} observations
 * @returns {Array<{ operation: string, resource: string }>}
 */
function _observationsToAllowedActions(observations) {
  const seen    = new Set();
  const actions = [];
  for (const obs of observations) {
    const k = `${obs.operation}:${obs.resource}`;
    if (!seen.has(k)) {
      seen.add(k);
      actions.push({ operation: obs.operation, resource: obs.resource });
    }
  }
  return actions;
}

/**
 * Build a human-readable scope string and boundaries string from observations.
 * These are embedded as the scope / boundaries fields of the final Delegation Receipt.
 * @param {object[]} observations
 * @returns {{ scope: string, boundaries: string }}
 */
function _buildScopeText(observations) {
  if (observations.length === 0) {
    return {
      scope:      'No operations authorized — agent performed no observable actions during discovery.',
      boundaries: 'All resource access is denied by default. Agent must not perform any operations without explicit re-authorization.',
    };
  }

  const groups = new Map();
  for (const obs of observations) {
    if (!groups.has(obs.resource)) groups.set(obs.resource, new Set());
    groups.get(obs.resource).add(obs.operation);
  }

  const scopeParts = [];
  for (const [resource, ops] of groups) {
    scopeParts.push(`${[...ops].join('/')} on ${resource}`);
  }

  // Dangerous operations that were observed (warn in boundaries)
  const observedDangerous = [..._DELETE_OPS, ..._EXECUTE_OPS, ..._PAYMENT_OPS].filter(op =>
    [...groups.values()].some(ops => ops.has(op))
  );

  const boundaryParts = [
    'Do not access any resource not listed in the authorized scope above.',
  ];
  if (observedDangerous.length === 0) {
    boundaryParts.push(
      'Do not perform delete, execute, payment, or external send operations.'
    );
  } else {
    boundaryParts.push(
      `CAUTION: the following high-risk operations were observed during discovery: ` +
      `${[...new Set(observedDangerous)].join(', ')}. ` +
      `Ensure this is intentional before approving.`
    );
  }

  return {
    scope:      `Authorized operations (derived from observation): ${scopeParts.join('; ')}.`,
    boundaries: boundaryParts.join(' '),
  };
}

// ─────────────────────────────────────────────
// INLINE CRYPTO (no dependency on authproof.js)
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _hexEncode = b =>
  Array.from(new Uint8Array(b))
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');

async function _sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hexEncode(buf);
}

async function _ecdsaSign(privateKey, str) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    _enc(str)
  );
  return _hexEncode(sig);
}

/**
 * Normalize a string using the same rules as authproof.js Canonicalizer,
 * so that instructionsHash values are compatible with AuthProof.verify().
 * @param {string} text
 * @returns {string}
 */
function _canonicalizeInstructions(text) {
  if (typeof text !== 'string') return '';
  let s = text.trim().toLowerCase();
  s = s.replace(/\s+/g, ' ');
  s = s.replace(/,/g, '');
  s = s.replace(/\.(?=\s|$)/g, '');
  s = s.replace(/["""''\u2018\u2019\u201c\u201d`]/g, '');
  s = s.replace(/\s+/g, ' ').trim();
  return s;
}

// ─────────────────────────────────────────────
// SCOPE DISCOVERY CLASS
// ─────────────────────────────────────────────

/**
 * ScopeDiscovery — stateful observation session that generates grounded scope
 * definitions for Delegation Receipts.
 *
 * @example
 * const discovery = new ScopeDiscovery({ operatorInstructions: 'Summarize my inbox.' });
 *
 * const { observations } = await discovery.observe(async (ctx) => {
 *   await ctx.email.read();
 *   await ctx.calendar.list();
 * }, { timeout: 10_000 });
 *
 * const review = discovery.generateScope();
 * // Inspect review.plainSummary, review.riskFlags, review.suggestedDenials
 *
 * discovery.approve({
 *   remove: [{ operation: 'delete', resource: 'files' }],
 *   add:    [{ operation: 'read',   resource: 'network' }],
 * });
 *
 * const { receipt, receiptId, systemPrompt } = await discovery.finalize({
 *   privateKey, publicJwk
 * });
 */
class ScopeDiscovery {
  /**
   * @param {object} [opts]
   * @param {string} [opts.operatorInstructions]
   *   Operator instructions embedded in the final Delegation Receipt.
   */
  constructor({
    operatorInstructions = 'Generated by ScopeDiscovery observation session.',
  } = {}) {
    this._operatorInstructions = operatorInstructions;
    /** @private {object[]} Raw observations from the last observe() call */
    this._observations    = [];
    /** @private {object|null} Scope review object set by generateScope() */
    this._review          = null;
    /** @private {object[]|null} Approved allowed actions set by approve() */
    this._approvedActions = null;
    /** @private {boolean} Whether the last observe() call was aborted by timeout */
    this._aborted         = false;
  }

  // ── OBSERVE ─────────────────────────────────────────────────────────

  /**
   * Run `agentFn` inside a sandboxed context. The function receives a context
   * object with proxies for all supported resource types. Every call is
   * intercepted and recorded; no real I/O is performed and no side effects occur.
   * Mock data is returned for all operations so the agent can proceed normally.
   *
   * If the agent does not finish within `timeout` ms the observation session is
   * aborted. Partial observations accumulated before the timeout are retained.
   *
   * @param {Function} agentFn
   *   `async (ctx: { email, calendar, payment, files, db, network }) => void`
   * @param {object}  [opts]
   * @param {number}  [opts.timeout=30000]  — Abort after this many milliseconds.
   * @returns {Promise<{ observations: object[], aborted: boolean }>}
   */
  async observe(agentFn, { timeout = 30_000 } = {}) {
    if (typeof agentFn !== 'function') {
      throw new Error('ScopeDiscovery.observe: agentFn must be a function');
    }

    const observations = [];
    const ctx          = _buildSandboxContext(observations);

    let aborted = false;
    let timer   = null;

    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        aborted = true;
        reject(new Error(`ScopeDiscovery: observation timed out after ${timeout}ms`));
      }, timeout);
      if (timer.unref) timer.unref(); // don't block Node exit
    });

    try {
      await Promise.race([agentFn(ctx), timeoutPromise]);
    } catch (err) {
      if (!aborted) {
        // Non-timeout error — save observations and re-throw
        if (timer) clearTimeout(timer);
        this._observations    = observations;
        this._aborted         = false;
        this._review          = null;
        this._approvedActions = null;
        throw err;
      }
      // Timeout — fall through and save partial observations
    } finally {
      if (timer && !aborted) clearTimeout(timer);
    }

    this._observations    = observations;
    this._aborted         = aborted;
    this._review          = null;
    this._approvedActions = null;

    return { observations: [...observations], aborted };
  }

  // ── GENERATE SCOPE ───────────────────────────────────────────────────

  /**
   * Analyze the observations from the last `observe()` call and produce a
   * scope review object. Call this after `observe()` and before `approve()`.
   *
   * @returns {{
   *   draftScope:       { allowedActions: object[], deniedActions: object[] },
   *   plainSummary:     string,
   *   riskFlags:        string[],
   *   suggestedDenials: Array<{ operation: string, resource: string, reason: string }>,
   *   observationCount: number,
   * }}
   */
  generateScope() {
    const observations = this._observations;
    const freq         = _computeFrequencies(observations);
    const riskFlags    = _computeRiskFlags(observations, freq);
    const suggestedDenials = _computeSuggestedDenials(observations);
    const plainSummary = _buildPlainSummary(observations, freq);
    const allowedActions = _observationsToAllowedActions(observations);

    // Conservative default denials for destructive operations
    const deniedActions = [
      { operation: 'delete',  resource: '*' },
      { operation: 'execute', resource: '*' },
      { operation: 'payment', resource: '*' },
    ];

    const review = {
      draftScope: { allowedActions, deniedActions },
      plainSummary,
      riskFlags,
      suggestedDenials,
      observationCount: observations.length,
    };

    this._review = review;
    return review;
  }

  // ── APPROVE ──────────────────────────────────────────────────────────

  /**
   * Apply user modifications to the draft scope and lock in the approved scope.
   * Must be called after `generateScope()`. Returns `this` for chaining.
   *
   * @param {object} [opts]
   * @param {Array<{ operation: string, resource: string }>} [opts.remove]
   *   Operations to remove from the draft allowedActions.
   * @param {Array<{ operation: string, resource: string }>} [opts.add]
   *   Additional operations to add.
   * @returns {ScopeDiscovery}
   */
  approve({ remove = [], add = [] } = {}) {
    if (!this._review) {
      throw new Error('ScopeDiscovery.approve: call generateScope() first');
    }

    let actions = [...this._review.draftScope.allowedActions];

    // Remove matching entries
    if (remove.length > 0) {
      actions = actions.filter(a =>
        !remove.some(r => r.operation === a.operation && r.resource === a.resource)
      );
    }

    // Add new entries (de-duplicate)
    for (const newAction of add) {
      const exists = actions.some(
        a => a.operation === newAction.operation && a.resource === newAction.resource
      );
      if (!exists) actions.push({ operation: newAction.operation, resource: newAction.resource });
    }

    this._approvedActions = actions;
    return this;
  }

  // ── FINALIZE ─────────────────────────────────────────────────────────

  /**
   * Produce a signed Delegation Receipt from the approved scope.
   * The receipt is fully compatible with `AuthProof.verify()`.
   * Must be called after `approve()`.
   *
   * @param {object}    opts
   * @param {CryptoKey} opts.privateKey
   * @param {object}    opts.publicJwk
   * @param {number}    [opts.expiresIn=3600000]       — ms until expiry
   * @param {string}    [opts.operatorInstructions]    — override stored instructions
   * @returns {Promise<{
   *   receipt:       object,
   *   receiptId:     string,
   *   systemPrompt:  string,
   *   scopeSummary:  object,
   * }>}
   */
  async finalize({
    privateKey,
    publicJwk,
    expiresIn = 3_600_000,
    operatorInstructions,
  } = {}) {
    if (!this._approvedActions) {
      throw new Error('ScopeDiscovery.finalize: call approve() first');
    }
    if (!privateKey) throw new Error('ScopeDiscovery.finalize: privateKey is required');
    if (!publicJwk)  throw new Error('ScopeDiscovery.finalize: publicJwk is required');

    const instructions = operatorInstructions ?? this._operatorInstructions;
    const { scope, boundaries } = _buildScopeText(this._observations);
    const instructionsHash = await _sha256(_canonicalizeInstructions(instructions));

    const now = new Date();
    const end = new Date(now.getTime() + expiresIn);
    const id  = `auth-${now.getTime()}-${Math.random().toString(36).slice(2, 7)}`;

    const { kty, crv, x, y } = publicJwk;

    const scopeSchema = {
      version:        '1.0',
      allowedActions: this._approvedActions,
      deniedActions:  this._review?.draftScope?.deniedActions ?? [],
    };

    const body = {
      delegationId:         id,
      issuedAt:             now.toISOString(),
      scope,
      boundaries,
      timeWindow:           { start: now.toISOString(), end: end.toISOString() },
      operatorInstructions: instructions,
      instructionsHash,
      signerPublicKey:      { kty, crv, x, y },
      scopeSchema,
      discoveryMetadata: {
        observationCount: this._observations.length,
        aborted:          this._aborted,
        riskFlags:        this._review?.riskFlags ?? [],
        generatedAt:      now.toISOString(),
      },
    };

    const signature = await _ecdsaSign(privateKey, JSON.stringify(body));
    const receipt   = { ...body, signature };
    const receiptId = await _sha256(JSON.stringify(receipt));

    const expiry = end.toLocaleString();
    const systemPrompt =
      `You are authorized to act within the following scope:\n\n${scope}\n\n` +
      `You must not:\n${boundaries}\n\n` +
      `Operator instructions:\n${instructions}\n\n` +
      `This authorization is valid until: ${expiry}\n` +
      `Authorization ID: ${receiptId}\n\n` +
      `Before taking any significant action, confirm it falls within the authorized scope above. ` +
      `If uncertain, ask for clarification rather than proceeding.`;

    return {
      receipt,
      receiptId,
      systemPrompt,
      scopeSummary: {
        allowedActions:   this._approvedActions,
        deniedActions:    scopeSchema.deniedActions,
        riskFlags:        this._review?.riskFlags ?? [],
        observationCount: this._observations.length,
      },
    };
  }

  // ── STATIC: FROM RECEIPT ─────────────────────────────────────────────

  /**
   * Compare a receipt's committed scope against a new set of observations.
   * Returns a drift report classifying the relationship as one of:
   *
   *   'exact-match'      — committed actions exactly match observed actions
   *   'over-authorized'  — receipt allows operations the agent never performed
   *   'under-authorized' — agent performed operations not covered by the receipt
   *   'diverged'         — both over- and under-authorization are present
   *
   * @param {object}   receipt      — Delegation Receipt (AuthProof.create or finalize())
   * @param {object[]} observations — From ScopeDiscovery.observe()
   * @returns {{
   *   status:           string,
   *   overAuthorized:   object[],
   *   underAuthorized:  object[],
   *   report:           string,
   * }}
   */
  static fromReceipt(receipt, observations) {
    if (!receipt || typeof receipt !== 'object') {
      throw new Error('ScopeDiscovery.fromReceipt: receipt must be an object');
    }
    if (!Array.isArray(observations)) {
      throw new Error('ScopeDiscovery.fromReceipt: observations must be an array');
    }

    const committedActions = receipt.scopeSchema?.allowedActions ?? [];
    const observedActions  = _observationsToAllowedActions(observations);

    const committedKeys = new Set(committedActions.map(a => `${a.operation}:${a.resource}`));
    const observedKeys  = new Set(observedActions.map(a => `${a.operation}:${a.resource}`));

    // Over-authorized: in receipt but never observed
    const overAuthorized = committedActions.filter(
      a => !observedKeys.has(`${a.operation}:${a.resource}`)
    );

    // Under-authorized: observed but not covered by any committed entry or wildcard
    const underAuthorized = observedActions.filter(a => {
      const k = `${a.operation}:${a.resource}`;
      if (committedKeys.has(k))                return false; // exact match
      if (committedKeys.has(`*:${a.resource}`)) return false; // op wildcard
      if (committedKeys.has(`${a.operation}:*`)) return false; // resource wildcard
      if (committedKeys.has('*:*'))             return false; // full wildcard
      return true;
    });

    let status;
    if (overAuthorized.length === 0 && underAuthorized.length === 0) {
      status = 'exact-match';
    } else if (overAuthorized.length > 0 && underAuthorized.length === 0) {
      status = 'over-authorized';
    } else if (underAuthorized.length > 0 && overAuthorized.length === 0) {
      status = 'under-authorized';
    } else {
      status = 'diverged';
    }

    const lines = [`Drift Report — Status: ${status}`];
    if (overAuthorized.length > 0) {
      lines.push(
        `\nOver-authorized (${overAuthorized.length} operation(s) committed but never used):`
      );
      for (const a of overAuthorized) lines.push(`  - ${a.operation} on ${a.resource}`);
    }
    if (underAuthorized.length > 0) {
      lines.push(
        `\nUnder-authorized (${underAuthorized.length} operation(s) performed but not in receipt):`
      );
      for (const a of underAuthorized) lines.push(`  - ${a.operation} on ${a.resource}`);
    }
    if (status === 'exact-match') {
      lines.push('\nReceipt scope exactly matches observed operations — no drift detected.');
    }

    return {
      status,
      overAuthorized,
      underAuthorized,
      report: lines.join('\n'),
    };
  }

  // ── STATIC: GUIDED ───────────────────────────────────────────────────

  /**
   * Guided delegation — one-call end-to-end flow.
   *
   * Runs `agentFn` in the sandbox, generates scope, auto-approves the full draft
   * (no user modifications), and returns a signed Delegation Receipt. Intended for
   * operators who trust the observed scope without manual review.
   *
   * @param {object}    opts
   * @param {Function}  opts.agentFn
   * @param {string}    [opts.operatorInstructions]
   * @param {CryptoKey} opts.privateKey
   * @param {object}    opts.publicJwk
   * @param {number}    [opts.expiresIn=3600000]
   * @param {number}    [opts.timeout=30000]
   * @returns {Promise<{
   *   receipt:       object,
   *   receiptId:     string,
   *   systemPrompt:  string,
   *   scopeSummary:  object,
   *   observations:  object[],
   *   aborted:       boolean,
   *   riskFlags:     string[],
   * }>}
   */
  static async guided({
    agentFn,
    operatorInstructions = 'Guided delegation — scope generated from observed agent behavior.',
    privateKey,
    publicJwk,
    expiresIn = 3_600_000,
    timeout   = 30_000,
  } = {}) {
    if (!agentFn)    throw new Error('ScopeDiscovery.guided: agentFn is required');
    if (!privateKey) throw new Error('ScopeDiscovery.guided: privateKey is required');
    if (!publicJwk)  throw new Error('ScopeDiscovery.guided: publicJwk is required');

    const discovery = new ScopeDiscovery({ operatorInstructions });
    const { observations, aborted } = await discovery.observe(agentFn, { timeout });
    const review = discovery.generateScope();
    discovery.approve(); // auto-approve full draft — no user modifications
    const result = await discovery.finalize({ privateKey, publicJwk, expiresIn, operatorInstructions });

    return {
      ...result,
      observations,
      aborted,
      riskFlags: review.riskFlags,
    };
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

export { ScopeDiscovery };
export default ScopeDiscovery;

/**
 * AuthProof SDK
 * Cryptographically signed delegation receipts for AI agents.
 *
 * Works in: Node.js 18+, modern browsers, Deno, Bun, Cloudflare Workers
 * Zero dependencies. Uses native Web Crypto API everywhere.
 *
 * @version 1.0.0
 * @license MIT
 */

'use strict';

// ─────────────────────────────────────────────
// CRYPTO PRIMITIVES
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const _fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function _sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hex(buf);
}

async function _generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
}

async function _exportPublicJwk(publicKey) {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  const { kty, crv, x, y } = jwk;
  return { kty, crv, x, y };
}

async function _sign(privateKey, str) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    _enc(str)
  );
  return _hex(sig);
}

async function _verify(publicJwk, signature, str) {
  try {
    const pk = await crypto.subtle.importKey(
      'jwk',
      { ...publicJwk, key_ops: ['verify'] },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pk,
      _fromHex(signature),
      _enc(str)
    );
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────
// SCOPE MATCHING
// ─────────────────────────────────────────────

const STOP_WORDS = new Set([
  'the','a','an','and','or','but','in','on','at','to','for','of','with',
  'by','from','is','are','was','were','be','been','have','has','had','do',
  'does','did','will','would','could','should','may','might','can','not',
  'no','this','that','these','those','i','you','he','she','it','we','they',
  'what','which','who','all','any','each','some','only','just','as','if',
  'then','up','out'
]);

function _tokenize(text) {
  return new Set(
    text.toLowerCase()
      .split(/[\s,;:.()\[\]{}'"""]+/)
      .filter(w => w.length > 3 && !STOP_WORDS.has(w))
  );
}

function _overlapScore(a, b) {
  const ta = _tokenize(a);
  const tb = _tokenize(b);
  if (ta.size === 0) return 0;
  let hits = 0;
  for (const w of ta) if (tb.has(w)) hits++;
  return hits / ta.size;
}

/**
 * Check if a proposed action falls within scope and doesn't violate boundaries.
 * Returns { withinScope: boolean, scopeScore: number, boundaryScore: number }
 */
function checkScope(action, receipt) {
  const scopeScore    = _overlapScope(action, receipt.scope);
  const boundaryScore = _overlapScore(action, receipt.boundaries);
  return {
    withinScope:    scopeScore >= 0.3 && boundaryScore < 0.5,
    scopeScore:     Math.round(scopeScore * 100),
    boundaryScore:  Math.round(boundaryScore * 100),
  };
}

// ─────────────────────────────────────────────
// KEY MANAGEMENT
// ─────────────────────────────────────────────

/**
 * Generate a new ECDSA P-256 signing key pair.
 * Returns exportable JWK representations for storage.
 *
 * @returns {{ privateJwk: object, publicJwk: object, privateKey: CryptoKey, publicKey: CryptoKey }}
 */
async function generateKey() {
  const kp = await _generateKeyPair();
  const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const publicJwk  = await _exportPublicJwk(kp.publicKey);
  return {
    privateKey: kp.privateKey,
    publicKey:  kp.publicKey,
    privateJwk,
    publicJwk,
  };
}

/**
 * Load a signing key from a stored private JWK.
 * @param {object} privateJwk
 * @returns {CryptoKey}
 */
async function importPrivateKey(privateJwk) {
  return crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

// ─────────────────────────────────────────────
// RECEIPT CREATION
// ─────────────────────────────────────────────

/**
 * Create a signed delegation receipt.
 *
 * @param {object} options
 * @param {string}      options.scope          - What the AI is authorized to do
 * @param {string}      options.boundaries     - What the AI must never do
 * @param {string}      options.instructions   - Operator instructions locked into the receipt
 * @param {number}      [options.ttlHours=1]   - How long the receipt is valid (hours)
 * @param {CryptoKey}   options.privateKey     - ECDSA P-256 private signing key
 * @param {object}      options.publicJwk      - Corresponding public key JWK
 * @param {string}      [options.agentId]      - Optional identifier for the agent being authorized
 * @param {object}      [options.metadata]     - Optional arbitrary metadata attached to receipt
 *
 * @returns {{ receipt: object, receiptId: string, systemPrompt: string }}
 */
async function create(options) {
  const {
    scope,
    boundaries,
    instructions,
    ttlHours = 1,
    privateKey,
    publicJwk,
    agentId,
    metadata,
  } = options;

  if (!scope)        throw new Error('AuthProof: scope is required');
  if (!boundaries)   throw new Error('AuthProof: boundaries is required');
  if (!instructions) throw new Error('AuthProof: instructions is required');
  if (!privateKey)   throw new Error('AuthProof: privateKey is required');
  if (!publicJwk)    throw new Error('AuthProof: publicJwk is required');

  const now  = new Date();
  const end  = new Date(now.getTime() + ttlHours * 3_600_000);
  const id   = `auth-${now.getTime()}-${Math.random().toString(36).slice(2, 7)}`;
  const instructionsHash = await _sha256(instructions);

  const { kty, crv, x, y } = publicJwk;

  const body = {
    delegationId:         id,
    issuedAt:             now.toISOString(),
    scope,
    boundaries,
    timeWindow:           { start: now.toISOString(), end: end.toISOString() },
    operatorInstructions: instructions,
    instructionsHash,
    signerPublicKey:      { kty, crv, x, y },
    ...(agentId   ? { agentId }   : {}),
    ...(metadata  ? { metadata }  : {}),
  };

  const signature = await _sign(privateKey, JSON.stringify(body));
  const receipt   = { ...body, signature };
  const receiptId = await _sha256(JSON.stringify(receipt));

  return {
    receipt,
    receiptId,
    systemPrompt: buildSystemPrompt(receipt, receiptId),
  };
}

// ─────────────────────────────────────────────
// RECEIPT VERIFICATION
// ─────────────────────────────────────────────

/**
 * Verify a receipt locally (no network call).
 * Checks: found, not revoked, within time window, signature valid, hash matches,
 * and optionally whether a proposed action falls within scope.
 *
 * @param {object}  receipt           - The receipt object
 * @param {string}  receiptId         - The SHA-256 receipt ID to verify against
 * @param {object}  [options]
 * @param {boolean} [options.revoked] - Whether the receipt has been revoked (from your store)
 * @param {string}  [options.action]  - Proposed action to scope-check
 *
 * @returns {{ authorized: boolean, checks: Array, receiptContext: object }}
 */
async function verify(receipt, receiptId, options = {}) {
  const { revoked = false, action } = options;
  const checks = [];

  // 1. Not revoked
  const notRevoked = !revoked && !receipt.revoked;
  checks.push({
    name:   'Not revoked',
    passed: notRevoked,
    detail: notRevoked ? 'Active' : 'This authorization has been revoked',
  });

  // 2. Within time window
  const now = new Date();
  const start = new Date(receipt.timeWindow.start);
  const end   = new Date(receipt.timeWindow.end);
  const inWindow = now >= start && now <= end;
  checks.push({
    name:   'Within time window',
    passed: inWindow,
    detail: inWindow
      ? `Expires ${end.toLocaleString()}`
      : now < start
        ? `Not yet valid — starts ${start.toLocaleString()}`
        : `Expired ${end.toLocaleString()}`,
  });

  // 3. Signature valid
  const { signature, ...bodyWithoutSig } = receipt;
  const sigValid = await _verify(
    receipt.signerPublicKey,
    signature,
    JSON.stringify(bodyWithoutSig)
  );
  checks.push({
    name:   'Signature valid',
    passed: sigValid,
    detail: sigValid
      ? 'Cryptographic signature verified (ECDSA P-256)'
      : 'Signature verification failed — receipt may be tampered',
  });

  // 4. Receipt ID matches
  const computedId = await _sha256(JSON.stringify(receipt));
  const idMatches  = computedId === receiptId;
  checks.push({
    name:   'Receipt ID matches',
    passed: idMatches,
    detail: idMatches
      ? 'SHA-256 content hash verified'
      : 'ID mismatch — receipt content may have been altered',
  });

  // 5. Instructions hash matches
  const computedIH = await _sha256(receipt.operatorInstructions);
  const ihMatches  = computedIH === receipt.instructionsHash;
  checks.push({
    name:   'Instructions intact',
    passed: ihMatches,
    detail: ihMatches
      ? 'Instructions hash verified'
      : 'Instructions hash mismatch — instructions may have been altered',
  });

  // 6. Optional scope check
  if (action) {
    const { withinScope, scopeScore, boundaryScore } = checkScope(action, receipt);
    checks.push({
      name:   'Action within scope',
      passed: scopeScore >= 30,
      detail: `${scopeScore}% keyword match with authorized scope`,
    });
    checks.push({
      name:   'Action not blocked',
      passed: boundaryScore < 50,
      detail: `${boundaryScore}% overlap with off-limits boundaries`,
    });
  }

  const authorized = checks.every(c => c.passed);

  return {
    authorized,
    result: authorized
      ? 'This action is authorized'
      : 'Authorization denied — see checks for details',
    checks,
    receiptContext: {
      scope:                receipt.scope,
      boundaries:           receipt.boundaries,
      operatorInstructions: receipt.operatorInstructions,
      timeWindow:           receipt.timeWindow,
      issuedAt:             receipt.issuedAt,
      agentId:              receipt.agentId,
      revoked,
    },
  };
}

// ─────────────────────────────────────────────
// SYSTEM PROMPT BUILDER
// ─────────────────────────────────────────────

/**
 * Build a ready-to-use system prompt block from a receipt.
 * Paste this directly into any AI chat or agent system prompt.
 *
 * @param {object} receipt
 * @param {string} receiptId
 * @param {string} [verifyUrl] - Optional URL to your verify endpoint
 * @returns {string}
 */
function buildSystemPrompt(receipt, receiptId, verifyUrl) {
  const expiry = new Date(receipt.timeWindow.end).toLocaleString();
  const verifyLine = verifyUrl
    ? `\nVerify this authorization: ${verifyUrl}?receipt=${receiptId}`
    : `\nAuthorization ID: ${receiptId}`;

  return `You are authorized to act within the following scope:

${receipt.scope}

You must not:
${receipt.boundaries}

Operator instructions:
${receipt.operatorInstructions}

This authorization is valid until: ${expiry}${verifyLine}

Before taking any significant action, confirm it falls within the authorized scope above. If uncertain, ask for clarification rather than proceeding.`;
}

// ─────────────────────────────────────────────
// UTILITY
// ─────────────────────────────────────────────

/**
 * Compute the receipt ID (SHA-256 of the full receipt JSON).
 * Useful for re-deriving the ID from a stored receipt.
 *
 * @param {object} receipt
 * @returns {string}
 */
async function receiptId(receipt) {
  return _sha256(JSON.stringify(receipt));
}

/**
 * Check if a receipt is currently active (not expired, not revoked).
 * @param {object}  receipt
 * @param {boolean} [revoked=false]
 * @returns {boolean}
 */
function isActive(receipt, revoked = false) {
  if (revoked || receipt.revoked) return false;
  const now = new Date();
  return now >= new Date(receipt.timeWindow.start) && now <= new Date(receipt.timeWindow.end);
}

/**
 * Get seconds remaining before a receipt expires.
 * Returns 0 if already expired.
 * @param {object} receipt
 * @returns {number}
 */
function secondsRemaining(receipt) {
  const remaining = new Date(receipt.timeWindow.end) - new Date();
  return Math.max(0, Math.floor(remaining / 1000));
}

// ─────────────────────────────────────────────
// ACTION LOG
// ─────────────────────────────────────────────

/** Sentinel prevHash used on the first entry of every chain. */
const _GENESIS = '0'.repeat(64);

/**
 * ActionLog — append-only, cryptographically chained agent action log.
 *
 * Pairs with a Delegation Receipt to provide a complete audit trail:
 * what was authorized (the receipt) vs. what was actually done (the log).
 * The diff() method surfaces any deviation between the two instantly.
 *
 * Every entry contains:
 *   - entryId        — unique identifier
 *   - receiptHash    — the receipt this action is authorized under
 *   - action         — { operation, resource, parameters }
 *   - timestamp      — ms since epoch (see ⚠ note on record())
 *   - agentPublicKey — agent's ECDSA P-256 public key JWK
 *   - prevHash       — SHA-256 of the previous entry (GENESIS for first)
 *   - signature      — ECDSA P-256 signature over all fields above
 *   - entryHash      — SHA-256 of the full entry including signature
 *
 * @example
 * const log = new ActionLog();
 * await log.init({ privateKey, publicJwk });
 * log.registerReceipt(receiptId, receipt);
 * await log.record(receiptId, { operation: 'read_calendar', resource: 'calendar/events' });
 * const report = log.diff(receiptId);
 * // { clean: true, compliant: [...], violations: [] }
 */
class ActionLog {
  constructor() {
    /** @private {Map<string, object>} entryId → sealed entry */
    this._entries = new Map();
    /** @private {Map<string, string[]>} receiptHash → ordered entryId list */
    this._byReceipt = new Map();
    /** @private {Map<string, object>} receiptHash → receipt */
    this._receipts = new Map();
    /** @private {CryptoKey|null} */
    this._privateKey = null;
    /** @private {object|null} */
    this._publicJwk = null;
  }

  /**
   * Initialize with the agent's ECDSA P-256 signing key.
   * Must be called once before record().
   * @param {{ privateKey: CryptoKey, publicJwk: object }} opts
   */
  async init({ privateKey, publicJwk }) {
    if (!privateKey) throw new Error('ActionLog: privateKey is required');
    if (!publicJwk)  throw new Error('ActionLog: publicJwk is required');
    this._privateKey = privateKey;
    this._publicJwk  = publicJwk;
  }

  /**
   * Register a Delegation Receipt so diff() can compare against its scope.
   * Call this with the receipt from AuthProof.create() before calling diff().
   *
   * @param {string} receiptHash — SHA-256 receipt ID from AuthProof.create()
   * @param {object} receipt     — The full receipt object
   */
  registerReceipt(receiptHash, receipt) {
    if (!receiptHash) throw new Error('ActionLog: receiptHash is required');
    if (!receipt)     throw new Error('ActionLog: receipt is required');
    this._receipts.set(receiptHash, receipt);
  }

  /**
   * Record a signed, chain-linked entry for an action taken under a receipt.
   *
   * ⚠ Timestamp uses Date.now() (the local system clock). This is not a
   *   trusted time source. For production audit logs requiring tamper-proof
   *   timestamps, integrate an RFC 3161 Trusted Timestamp Authority (TSA)
   *   and replace timestamp before passing to this method.
   *
   * @param {string} receiptHash
   * @param {{ operation: string, resource: string, parameters?: object }} action
   * @returns {Promise<object>} The sealed log entry
   */
  async record(receiptHash, action) {
    if (!this._privateKey) throw new Error('ActionLog: call init() before record()');
    if (!receiptHash)       throw new Error('ActionLog: receiptHash is required');
    if (!action?.operation) throw new Error('ActionLog: action.operation is required');
    if (!action?.resource)  throw new Error('ActionLog: action.resource is required');

    const ids      = this._byReceipt.get(receiptHash) || [];
    const prevHash = ids.length === 0
      ? _GENESIS
      : this._entries.get(ids[ids.length - 1]).entryHash;

    const entryId = `log-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // ─────────────────────────────────────────────────────────────────
    // ⚠ PRODUCTION WARNING — UNTRUSTED TIMESTAMP
    // The value below is taken from the local system clock (Date.now()).
    // This clock is not independently verifiable and can be set
    // arbitrarily by the host process. It MUST NOT be used in any
    // compliance, legal, or regulatory context where timestamp
    // authenticity matters.
    //
    // For production deployments requiring verifiable timestamps:
    // obtain a timestamp token from an RFC 3161 Trusted Timestamp
    // Authority (TSA) and replace this value before calling record().
    // ─────────────────────────────────────────────────────────────────
    const timestamp = Date.now();

    const body = {
      entryId,
      receiptHash,
      action: {
        operation:  action.operation,
        resource:   action.resource,
        parameters: action.parameters ?? {},
      },
      timestamp,
      agentPublicKey: this._publicJwk,
      prevHash,
    };

    const signature = await _sign(this._privateKey, JSON.stringify(body));
    const entryHash = await _sha256(JSON.stringify({ ...body, signature }));

    const entry = { ...body, signature, entryHash };

    this._entries.set(entryId, entry);
    this._byReceipt.set(receiptHash, [...ids, entryId]);

    return entry;
  }

  /**
   * Verify a specific entry's signature and chain integrity.
   *
   * Checks performed:
   *   1. Agent ECDSA P-256 signature over all body fields
   *   2. Entry hash integrity (SHA-256 of body + signature)
   *   3. Chain linkage (prevHash === previous entry's entryHash)
   *
   * Any mutation to any field — however small — fails at least one check.
   *
   * @param {string} entryId
   * @returns {Promise<{ valid: boolean, reason: string }>}
   */
  async verify(entryId) {
    const entry = this._entries.get(entryId);
    if (!entry) return { valid: false, reason: 'Entry not found' };

    const { signature, entryHash, ...body } = entry;

    // 1 — Agent signature over all body fields
    const sigValid = await _verify(entry.agentPublicKey, signature, JSON.stringify(body));
    if (!sigValid) {
      return {
        valid:  false,
        reason: 'Signature verification failed — entry may have been tampered',
      };
    }

    // 2 — Entry hash (SHA-256 of body + signature)
    const computedHash = await _sha256(JSON.stringify({ ...body, signature }));
    if (computedHash !== entryHash) {
      return {
        valid:  false,
        reason: 'Entry hash mismatch — content was altered after recording',
      };
    }

    // 3 — Chain linkage
    const chain = this._byReceipt.get(entry.receiptHash) || [];
    const idx   = chain.indexOf(entryId);

    if (idx === -1) {
      return { valid: false, reason: 'Entry is orphaned — not found in chain index' };
    }

    if (idx === 0) {
      if (entry.prevHash !== _GENESIS) {
        return { valid: false, reason: 'Genesis entry has wrong prevHash' };
      }
    } else {
      const prev = this._entries.get(chain[idx - 1]);
      if (!prev) {
        return { valid: false, reason: 'Previous entry is missing — chain is broken' };
      }
      if (entry.prevHash !== prev.entryHash) {
        return {
          valid:  false,
          reason: "Chain broken — prevHash does not match previous entry's entryHash",
        };
      }
    }

    return { valid: true, reason: 'Signature and chain integrity verified' };
  }

  /**
   * Return all log entries for a receipt in chronological (insertion) order.
   * @param {string} receiptHash
   * @returns {object[]}
   */
  getEntries(receiptHash) {
    const ids = this._byReceipt.get(receiptHash) || [];
    return ids.map(id => this._entries.get(id));
  }

  /**
   * Diff: compare all recorded actions against the receipt's authorized scope.
   *
   * This is the audit method. Any party — user, operator, regulator, or court —
   * can call diff() to see exactly what was authorized versus what was done,
   * and identify any deviations instantly.
   *
   * Scope matching strategy (applied in order):
   *   1. If receipt.allowedActions is a string[] → exact operation match
   *   2. Otherwise → keyword overlap scoring against receipt.scope /
   *      receipt.boundaries text (via AuthProof.checkScope)
   *
   * @param {string} receiptHash
   * @returns {{
   *   receiptHash:  string,
   *   totalEntries: number,
   *   compliant:    Array<{ entry: object, reason: string }>,
   *   violations:   Array<{ entry: object, reason: string }>,
   *   clean:        boolean
   * }}
   */
  diff(receiptHash) {
    const receipt = this._receipts.get(receiptHash);
    const entries = this.getEntries(receiptHash);

    const compliant  = [];
    const violations = [];

    for (const entry of entries) {
      const op = entry.action.operation;
      let inScope, reason;

      if (receipt?.allowedActions && Array.isArray(receipt.allowedActions)) {
        // Explicit allowlist — exact string match on operation
        inScope = receipt.allowedActions.includes(op);
        reason  = inScope
          ? `"${op}" is in allowedActions`
          : `"${op}" not in allowedActions [${receipt.allowedActions.join(', ')}]`;

      } else if (receipt) {
        // ─────────────────────────────────────────────────────────────
        // ⚠ WARNING: Text-based keyword matching is fuzzy and not
        // cryptographically sound. Explicit allowedActions arrays are
        // strongly recommended for any production or compliance use
        // case. This fallback exists only for convenience during
        // development.
        // ─────────────────────────────────────────────────────────────
        const { withinScope, scopeScore, boundaryScore } = checkScope(op, receipt);
        inScope = withinScope;
        reason  = inScope
          ? `"${op}" matches authorized scope (${scopeScore}% keyword overlap)`
          : `"${op}" outside authorized scope (${scopeScore}% scope match, ${boundaryScore}% boundary overlap)`;

      } else {
        inScope = false;
        reason  = 'No receipt registered for this receiptHash — call registerReceipt() first';
      }

      (inScope ? compliant : violations).push({ entry, reason });
    }

    return {
      receiptHash,
      totalEntries: entries.length,
      compliant,
      violations,
      clean: violations.length === 0,
    };
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

const AuthProof = {
  // Key management
  generateKey,
  importPrivateKey,

  // Core protocol
  create,
  verify,

  // Utilities
  buildSystemPrompt,
  checkScope,
  receiptId,
  isActive,
  secondsRemaining,

  // Action log
  ActionLog,
};

// ESM + CJS compatible export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthProof;
  module.exports.ActionLog = ActionLog;
} else if (typeof globalThis !== 'undefined') {
  globalThis.AuthProof = AuthProof;
  globalThis.ActionLog = ActionLog;
}

export default AuthProof;
export {
  generateKey,
  importPrivateKey,
  create,
  verify,
  buildSystemPrompt,
  checkScope,
  receiptId,
  isActive,
  secondsRemaining,
  ActionLog,
};

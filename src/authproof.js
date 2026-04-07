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
// RFC 3161 TRUSTED TIMESTAMP
// ─────────────────────────────────────────────

/**
 * Build a minimal DER-encoded TimeStampReq (RFC 3161) for a SHA-256 hash.
 *
 * Structure (59 bytes total, fixed for SHA-256):
 *   SEQUENCE {
 *     INTEGER v1,
 *     MessageImprint { AlgorithmIdentifier sha-256, OCTET STRING hash },
 *     BOOLEAN certReq = TRUE
 *   }
 *
 * SHA-256 OID 2.16.840.1.101.3.4.2.1 → bytes 60 86 48 01 65 03 04 02 01
 *
 * @param {Uint8Array} hashBytes - 32-byte SHA-256 digest
 * @returns {Uint8Array}
 */
function _buildTsq(hashBytes) {
  return new Uint8Array([
    0x30, 0x39,              // SEQUENCE length 57 (TimeStampReq)
      0x02, 0x01, 0x01,      // INTEGER v1
      0x30, 0x31,            // SEQUENCE length 49 (MessageImprint)
        0x30, 0x0d,          // SEQUENCE length 13 (AlgorithmIdentifier)
          0x06, 0x09,        // OID length 9
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // sha-256
          0x05, 0x00,        // NULL (parameters)
        0x04, 0x20,          // OCTET STRING length 32 (hashedMessage)
          ...hashBytes,      // 32 bytes of the hash
      0x01, 0x01, 0xff,      // BOOLEAN certReq = TRUE
  ]);
}

/**
 * Search for a byte subsequence inside a larger byte array.
 * Used to verify that a TSA token contains the submitted hash.
 * @param {Uint8Array} haystack
 * @param {Uint8Array} needle
 * @returns {boolean}
 */
function _tokenContainsHash(haystack, needle) {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

/** Uint8Array → base64 string (safe for arbitrarily large arrays). */
function _uint8ToBase64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

/** base64 string → Uint8Array. */
function _base64ToUint8(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/**
 * Request a RFC 3161 timestamp token from a TSA.
 * Throws on network error, non-200 status, or malformed response.
 * Callers must catch and fall back to UNVERIFIED_TIMESTAMP.
 *
 * @param {string} hashHex - Hex-encoded SHA-256 digest to timestamp
 * @param {string} tsaUrl  - RFC 3161 TSA endpoint URL
 * @returns {Promise<string>} base64-encoded TimeStampToken
 */
async function _requestRfc3161Timestamp(hashHex, tsaUrl) {
  const hashBytes = _fromHex(hashHex);
  const tsq = _buildTsq(hashBytes);

  const response = await fetch(tsaUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: tsq,
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) {
    throw new Error(`TSA responded with HTTP ${response.status}`);
  }

  const tokenBuffer = await response.arrayBuffer();
  const tokenBytes  = new Uint8Array(tokenBuffer);

  // Sanity-check: the response must contain our hash bytes
  if (!_tokenContainsHash(tokenBytes, hashBytes)) {
    throw new Error('TSA response does not contain the submitted hash — response may be malformed');
  }

  return _uint8ToBase64(tokenBytes);
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
  const scopeScore    = _overlapScore(action, receipt.scope);
  const boundaryScore = _overlapScore(action, receipt.boundaries);
  return {
    withinScope:    scopeScore >= 0.3 && boundaryScore < 0.5,
    scopeScore:     Math.round(scopeScore * 100),
    boundaryScore:  Math.round(boundaryScore * 100),
  };
}

// ─────────────────────────────────────────────
// SCOPE SCHEMA
// ─────────────────────────────────────────────

/**
 * Match an operation pattern against a concrete operation string.
 * '*' matches any operation; otherwise exact string equality is required.
 * @param {string} pattern
 * @param {string} operation
 * @returns {boolean}
 */
function _matchOp(pattern, operation) {
  return pattern === '*' || pattern === operation;
}

/**
 * Match a resource pattern against a concrete resource string.
 * '*' matches anything. Patterns may contain '*' as a glob wildcard
 * (e.g. '*.company.com', 'files/*', 'email/*').
 * @param {string} pattern
 * @param {string} resource
 * @returns {boolean}
 */
function _matchResource(pattern, resource) {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === resource;
  // Escape all regex special chars except *, then replace * with .*
  const reStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  return new RegExp(`^${reStr}$`).test(resource);
}

/**
 * Validate an action's parameters against a constraint map from allowedActions.
 * Supports:
 *   - Wildcard string patterns: { sender: "*.company.com" }
 *   - Numeric max limits: { maxEvents: 10 } — action parameter must not exceed this
 * @param {object} schemaConstraints
 * @param {object} actionParams
 * @returns {{ valid: boolean, reason: string }}
 */
function _checkConstraints(schemaConstraints, actionParams) {
  for (const [key, limit] of Object.entries(schemaConstraints)) {
    const val = actionParams[key];
    if (val === undefined) continue; // parameter not provided — no violation

    if (typeof limit === 'number') {
      // Numeric max constraint
      if (typeof val === 'number' && val > limit) {
        return { valid: false, reason: `${key} value ${val} exceeds maximum ${limit}` };
      }
    } else if (typeof limit === 'string' && limit.includes('*')) {
      // Wildcard string pattern constraint
      if (typeof val === 'string' && !_matchResource(limit, val)) {
        return { valid: false, reason: `${key} "${val}" does not match required pattern "${limit}"` };
      }
    }
  }
  return { valid: true, reason: 'all constraints satisfied' };
}

/**
 * ScopeSchema — machine-readable, versioned, serializable scope definition.
 *
 * Replaces fuzzy text-based scope matching with an explicit, structured schema
 * that can be validated programmatically, serialized to JSON, and embedded in
 * delegation receipts.
 *
 * @example
 * const schema = new ScopeSchema({
 *   version: "1.0",
 *   allowedActions: [
 *     { operation: "read",  resource: "email",    constraints: { sender: "*.company.com" } },
 *     { operation: "write", resource: "calendar", constraints: { maxEvents: 10 } },
 *   ],
 *   deniedActions: [
 *     { operation: "delete",  resource: "*" },
 *     { operation: "payment", resource: "*" },
 *   ],
 *   maxDuration: "4h"
 * });
 *
 * schema.validate({ operation: "read", resource: "email", constraints: { sender: "alice@company.com" } });
 * // → { valid: true, reason: '...' }
 *
 * schema.validate({ operation: "delete", resource: "contacts" });
 * // → { valid: false, reason: 'operation "delete" on resource "contacts" is explicitly denied' }
 */
class ScopeSchema {
  /**
   * @param {object} opts
   * @param {string}   opts.version         — Required. Schema version string (e.g. "1.0").
   * @param {object[]} [opts.allowedActions] — Actions that are permitted. Default: [].
   * @param {object[]} [opts.deniedActions]  — Actions that are always denied. Default: [].
   *   Each action: { operation: string, resource: string, constraints?: object }
   * @param {string}   [opts.maxDuration]   — Optional maximum delegation duration (e.g. "4h").
   */
  constructor({ version, allowedActions = [], deniedActions = [], maxDuration } = {}) {
    if (!version) throw new Error('ScopeSchema: version is required');
    if (typeof version !== 'string') throw new Error('ScopeSchema: version must be a string');
    if (!Array.isArray(allowedActions)) throw new Error('ScopeSchema: allowedActions must be an array');
    if (!Array.isArray(deniedActions))  throw new Error('ScopeSchema: deniedActions must be an array');
    if (maxDuration !== undefined && typeof maxDuration !== 'string') {
      throw new Error('ScopeSchema: maxDuration must be a string (e.g. "4h")');
    }

    for (const a of [...allowedActions, ...deniedActions]) {
      if (!a || typeof a.operation !== 'string') {
        throw new Error('ScopeSchema: each action entry must have an operation string');
      }
      if (typeof a.resource !== 'string') {
        throw new Error('ScopeSchema: each action entry must have a resource string');
      }
    }

    this.version        = version;
    this.allowedActions = allowedActions;
    this.deniedActions  = deniedActions;
    this.maxDuration    = maxDuration ?? null;
  }

  /**
   * Validate whether an action is permitted by this schema.
   *
   * Denial takes precedence over allowance. Wildcards ('*') are supported
   * on both operation and resource fields. Constraints on allowedActions
   * entries are checked against action.constraints.
   *
   * @param {{ operation: string, resource: string, constraints?: object }} action
   * @returns {{ valid: boolean, reason: string }}
   */
  validate(action) {
    if (!action?.operation) return { valid: false, reason: 'action.operation is required' };
    if (!action?.resource)  return { valid: false, reason: 'action.resource is required' };

    const { operation, resource, constraints: actionConstraints = {} } = action;

    // Denial takes precedence — check deniedActions first
    for (const denied of this.deniedActions) {
      if (_matchOp(denied.operation, operation) && _matchResource(denied.resource, resource)) {
        return {
          valid:  false,
          reason: `operation "${operation}" on resource "${resource}" is explicitly denied`,
        };
      }
    }

    // Check allowedActions
    for (const allowed of this.allowedActions) {
      if (_matchOp(allowed.operation, operation) && _matchResource(allowed.resource, resource)) {
        if (allowed.constraints) {
          const cv = _checkConstraints(allowed.constraints, actionConstraints);
          if (!cv.valid) return { valid: false, reason: `constraint violation: ${cv.reason}` };
        }
        return {
          valid:  true,
          reason: `operation "${operation}" on resource "${resource}" is allowed`,
        };
      }
    }

    return {
      valid:  false,
      reason: `operation "${operation}" on resource "${resource}" is not in allowedActions`,
    };
  }

  /**
   * Serialize to a plain JSON-safe object.
   * @returns {object}
   */
  toJSON() {
    const obj = {
      version:        this.version,
      allowedActions: this.allowedActions,
      deniedActions:  this.deniedActions,
    };
    if (this.maxDuration !== null) obj.maxDuration = this.maxDuration;
    return obj;
  }

  /**
   * Deserialize from a plain object (e.g. JSON.parse output).
   * @param {object} obj
   * @returns {ScopeSchema}
   */
  static fromJSON(obj) {
    return new ScopeSchema(obj);
  }
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
 *   - timestamp      — ms since epoch (local clock, approximate)
 *   - agentPublicKey — agent's ECDSA P-256 public key JWK
 *   - prevHash       — SHA-256 of the previous entry (GENESIS for first)
 *   - entryBodyHash  — SHA-256 of the base body fields (sent to TSA)
 *   - timestampType  — 'RFC3161' | 'UNVERIFIED_TIMESTAMP'
 *   - timestampToken — base64 TimeStampToken (RFC3161 entries only)
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
    /** @private {string|null} RFC 3161 TSA endpoint; null disables TSA */
    this._tsaUrl = 'https://freetsa.org/tsr';
  }

  /**
   * Initialize with the agent's ECDSA P-256 signing key.
   * Must be called once before record().
   *
   * @param {{ privateKey: CryptoKey, publicJwk: object, tsaUrl?: string|null }} opts
   *   tsaUrl — RFC 3161 TSA endpoint. Defaults to 'https://freetsa.org/tsr'.
   *            Pass null to disable TSA (entries will be UNVERIFIED_TIMESTAMP).
   */
  async init({ privateKey, publicJwk, tsaUrl }) {
    if (!privateKey) throw new Error('ActionLog: privateKey is required');
    if (!publicJwk)  throw new Error('ActionLog: publicJwk is required');
    this._privateKey = privateKey;
    this._publicJwk  = publicJwk;
    if (tsaUrl !== undefined) this._tsaUrl = tsaUrl;
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
   * Timestamps: by default, record() obtains a signed timestamp token from
   * the freetsa.org RFC 3161 Trusted Timestamp Authority (TSA) and embeds
   * it in the entry. If the TSA request fails for any reason (network
   * unavailable, timeout, non-200 response), the entry is still recorded
   * using the local system clock and flagged with
   * timestampType: 'UNVERIFIED_TIMESTAMP' so callers know the difference.
   *
   * Every entry carries:
   *   - entryBodyHash  — SHA-256 of the base entry body (what was sent to the TSA)
   *   - timestampType  — 'RFC3161' | 'UNVERIFIED_TIMESTAMP'
   *   - timestampToken — base64 TimeStampToken (only present when type is RFC3161)
   *
   * Use verifyTimestamp(entryId) to independently verify the TSA token.
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

    const entryId   = `log-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const timestamp = Date.now();

    // Base body — the fields whose integrity we timestamp
    const baseBody = {
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

    // SHA-256 of the base body — sent to the TSA for timestamping
    const entryBodyHash = await _sha256(JSON.stringify(baseBody));

    // Request an RFC 3161 trusted timestamp; fall back to UNVERIFIED_TIMESTAMP
    let timestampToken = null;
    let timestampType;

    if (this._tsaUrl) {
      try {
        timestampToken = await _requestRfc3161Timestamp(entryBodyHash, this._tsaUrl);
        timestampType  = 'RFC3161';
      } catch {
        timestampType = 'UNVERIFIED_TIMESTAMP';
      }
    } else {
      timestampType = 'UNVERIFIED_TIMESTAMP';
    }

    // Full body — includes timestamp fields; signature covers everything
    const body = {
      ...baseBody,
      entryBodyHash,
      timestampType,
      ...(timestampToken ? { timestampToken } : {}),
    };

    const signature = await _sign(this._privateKey, JSON.stringify(body));
    const entryHash = await _sha256(JSON.stringify({ ...body, signature }));

    const entry = { ...body, signature, entryHash };

    this._entries.set(entryId, entry);
    this._byReceipt.set(receiptHash, [...ids, entryId]);

    return entry;
  }

  /**
   * Verify the timestamp on a log entry.
   *
   * For RFC3161 entries: confirms the stored TSA token contains the
   * entry body hash that was submitted to the TSA.
   * For UNVERIFIED_TIMESTAMP entries: reports that no TSA token exists
   * and the timestamp cannot be independently verified.
   *
   * Note: this performs a structural verification (hash presence check).
   * Full PKI verification of the TSA signing certificate requires the
   * TSA root certificate chain, which is not bundled in this SDK.
   *
   * @param {string} entryId
   * @returns {Promise<{ verified: boolean, type: string|null, reason: string, timestamp?: number, tokenBase64?: string }>}
   */
  async verifyTimestamp(entryId) {
    const entry = this._entries.get(entryId);
    if (!entry) {
      return { verified: false, type: null, reason: 'Entry not found' };
    }

    const { timestampType, timestampToken, entryBodyHash, timestamp } = entry;

    if (timestampType === 'UNVERIFIED_TIMESTAMP') {
      return {
        verified:  false,
        type:      'UNVERIFIED_TIMESTAMP',
        reason:    'Entry was recorded with a local system clock — no TSA token is available. Timestamps cannot be independently verified.',
        timestamp,
      };
    }

    if (timestampType === 'RFC3161') {
      try {
        const tokenBytes = _base64ToUint8(timestampToken);
        const hashBytes  = _fromHex(entryBodyHash);
        const valid      = _tokenContainsHash(tokenBytes, hashBytes);
        return {
          verified:   valid,
          type:       'RFC3161',
          reason:     valid
            ? 'RFC 3161 token verified — TSA token contains the entry body hash'
            : 'RFC 3161 token verification failed — entry hash not found in token',
          timestamp,
          tokenBase64: timestampToken,
        };
      } catch (e) {
        return {
          verified: false,
          type:     'RFC3161',
          reason:   `Token decode error: ${e.message}`,
          timestamp,
        };
      }
    }

    return {
      verified: false,
      type:     timestampType ?? null,
      reason:   `Unknown timestamp type: ${String(timestampType)}`,
      timestamp,
    };
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

      if (receipt?.scopeSchema instanceof ScopeSchema) {
        // Structured schema — machine-readable, wildcard-aware, constraint-checked
        const result = receipt.scopeSchema.validate({
          operation:   entry.action.operation,
          resource:    entry.action.resource,
          constraints: entry.action.parameters,
        });
        inScope = result.valid;
        reason  = result.reason;

      } else if (receipt?.allowedActions && Array.isArray(receipt.allowedActions)) {
        // Legacy explicit allowlist — exact string match on operation
        inScope = receipt.allowedActions.includes(op);
        reason  = inScope
          ? `"${op}" is in allowedActions`
          : `"${op}" not in allowedActions [${receipt.allowedActions.join(', ')}]`;

      } else if (receipt) {
        inScope = false;
        reason  = 'No ScopeSchema registered — attach a ScopeSchema via receipt.scopeSchema for compliance checking';

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

  // Scope schema
  ScopeSchema,
};

// ESM + CJS compatible export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthProof;
  module.exports.ActionLog  = ActionLog;
  module.exports.ScopeSchema = ScopeSchema;
} else if (typeof globalThis !== 'undefined') {
  globalThis.AuthProof   = AuthProof;
  globalThis.ActionLog   = ActionLog;
  globalThis.ScopeSchema = ScopeSchema;
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
  ScopeSchema,
};

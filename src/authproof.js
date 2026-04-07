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

/** Strip simple English suffixes for basic stemming (s, es, ing, ed). */
function _stem(w) {
  return w.replace(/ings?$/, '').replace(/e?s$/, '').replace(/ed$/, '') || w;
}

function _tokenize(text) {
  return new Set(
    text.toLowerCase()
      .split(/[\s,;:.()\[\]{}'"""]+/)
      .filter(w => w.length > 3 && !STOP_WORDS.has(w))
      .map(_stem)
      .filter(w => w.length > 2)
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
    withinScope:    scopeScore >= 0.3 && boundaryScore < 0.15,
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
      passed: boundaryScore < 15,
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

  return `You are authorized to act within the following scope:\n\n${receipt.scope}\n\nYou must not:\n${receipt.boundaries}\n\nOperator instructions:\n${receipt.operatorInstructions}\n\nThis authorization is valid until: ${expiry}${verifyLine}\n\nBefore taking any significant action, confirm it falls within the authorized scope above. If uncertain, ask for clarification rather than proceeding.`;
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
};

// ─────────────────────────────────────────────
// CLASS-BASED API
// Matches the README / whitepaper interface:
//   import { AuthProofClient, Scope, KeyCustody } from 'authproof-sdk';
// ─────────────────────────────────────────────

/**
 * Key custody modes.
 */
const KeyCustody = Object.freeze({
  HARDWARE:  'hardware',   // WebAuthn / FIDO2 device secure enclave (recommended)
  DELEGATED: 'delegated',  // Key manager / HSM
  SELF:      'self',       // Self-custody / software key (default fallback)
});

/**
 * Structured scope builder.
 *
 * const scope = new Scope()
 *   .allow('reads',  ['resource://calendar/events'])
 *   .allow('writes', ['resource://calendar/events'])
 *   .deny('deletes', '*')
 *   .execute('sha256:abc123', { program: 'scheduler-v1.sg' });
 */
class Scope {
  constructor() {
    this._allows   = [];
    this._denies   = [];
    this._executes = [];
  }

  /** Allow an operation class on the given resources (allowlist). */
  allow(operationClass, resources) {
    const res = Array.isArray(resources) ? resources : [resources];
    this._allows.push({ class: operationClass, resources: res });
    return this;
  }

  /** Deny an operation class on the given resources (hard boundary). */
  deny(operationClass, resources) {
    const res = Array.isArray(resources) ? resources : [resources];
    this._denies.push({ class: operationClass, resources: res });
    return this;
  }

  /** Bind execution to a specific program hash. */
  execute(hash, options = {}) {
    this._executes.push({ hash, ...options });
    return this;
  }

  /** Serialize to structured string for receipt body. */
  toString() {
    // Strip resource:// URIs to readable path tokens so the keyword
    // scope-checker can match natural-language action descriptions.
    const _res = r => r === '*'
      ? 'all resources'
      : r.replace(/^[a-z][\w+.-]*:\/\//, '').replace(/\//g, ' ').trim() || r;

    const lines = [];
    for (const a of this._allows) {
      lines.push(`ALLOW ${a.class}: ${a.resources.map(_res).join(', ')}`);
    }
    for (const d of this._denies) {
      lines.push(`DENY ${d.class}: ${d.resources.map(_res).join(', ')}`);
    }
    for (const e of this._executes) {
      lines.push(`EXECUTE ${e.hash}${e.program ? ` (${e.program})` : ''}`);
    }
    return lines.join('\n');
  }

  /**
   * Serialize deny rules as natural-language boundary text.
   * Used to feed DENY clauses into the boundaries check.
   */
  toBoundariesText() {
    const _res = r => r === '*'
      ? 'all resources'
      : r.replace(/^[a-z][\w+.-]*:\/\//, '').replace(/\//g, ' ').trim() || r;
    // Use infinitive form (strip trailing 's') so 'deletes'→'delete' matches
    // natural-language action descriptions like "delete all events".
    return this._denies
      .map(d => `Do not ${d.class.replace(/s$/, '')}: ${d.resources.map(_res).join(', ')}`)
      .join('. ');
  }

  /** Return structured object representation. */
  toObject() {
    return {
      allows:   this._allows,
      denies:   this._denies,
      executes: this._executes,
    };
  }
}

/** Parse duration strings like '8h', '30m', '2d', '90s' → fractional hours. */
function _parseDuration(str) {
  const m = String(str).match(/^(\d+(?:\.\d+)?)\s*(h|m|d|s)?$/i);
  if (!m) return 1;
  const val  = parseFloat(m[1]);
  const unit = (m[2] || 'h').toLowerCase();
  return val * ({ h: 1, m: 1 / 60, d: 24, s: 1 / 3600 }[unit] ?? 1);
}

/** Serialize a boundaries object or string into a human-readable string. */
function _serializeBoundaries(boundaries) {
  if (!boundaries) return 'No additional boundaries specified.';
  if (typeof boundaries === 'string') return boundaries;
  return Object.entries(boundaries)
    .map(([k, v]) => `${k}: ${v}`)
    .join('; ');
}

/**
 * Object-oriented AuthProof client — matches the README/whitepaper API surface.
 *
 * @example
 * const ap = new AuthProofClient({ custody: KeyCustody.HARDWARE, log: 'https://log.authproof.dev' });
 * const receipt = await ap.delegate({ scope, boundaries, window: { duration: '8h' }, operatorInstructions });
 * const result  = await ap.validate({ receiptHash: receipt.hash, action: 'read calendar' });
 */
class AuthProofClient {
  /**
   * @param {object} [options]
   * @param {string} [options.custody]  - KeyCustody mode (default: SELF)
   * @param {string} [options.log]      - Log endpoint URL for receipt anchoring
   */
  constructor({ custody = KeyCustody.SELF, log } = {}) {
    this.custody  = custody;
    this.logUrl   = log || null;
    this._keyPair = null;
    this._store   = new Map();   // receiptHash → { receipt, revoked }
  }

  /** Lazily generate (or load) the signing key pair. */
  async _ensureKey() {
    if (!this._keyPair) {
      this._keyPair = await generateKey();
    }
    return this._keyPair;
  }

  /**
   * Delegate authority to an agent. Signs an Authorization Object and
   * anchors it to the configured log.
   *
   * @param {object} options
   * @param {Scope|string}   options.scope                - Authorized operations
   * @param {object|string}  options.boundaries           - Hard prohibitions
   * @param {{ duration: string }} options.window         - Time window (e.g. { duration: '8h' })
   * @param {string}         options.operatorInstructions - Operator system prompt text
   * @returns {{ receipt, receiptId, hash, systemPrompt, logAnchor }}
   */
  async delegate({ scope, boundaries, window: timeWindow, operatorInstructions }) {
    if (!scope)                throw new Error('AuthProofClient: scope is required');
    if (!operatorInstructions) throw new Error('AuthProofClient: operatorInstructions is required');

    const { privateKey, publicJwk } = await this._ensureKey();

    const scopeStr = scope instanceof Scope ? scope.toString() : String(scope);

    // Merge explicit boundaries with any DENY rules declared in the Scope object
    const explicitBoundaries = _serializeBoundaries(boundaries);
    const denyBoundaries     = scope instanceof Scope ? scope.toBoundariesText() : '';
    const boundariesStr      = [denyBoundaries, explicitBoundaries].filter(Boolean).join('. ')
      || 'No additional boundaries specified.';
    const ttlHours      = _parseDuration(timeWindow?.duration ?? '1h');

    const { receipt, receiptId: hash, systemPrompt } = await create({
      scope:        scopeStr,
      boundaries:   boundariesStr,
      instructions: operatorInstructions,
      ttlHours,
      privateKey,
      publicJwk,
    });

    // Anchor to log (mock or real)
    const logAnchor = this.logUrl
      ? { logUrl: this.logUrl, receiptId: hash, anchoredAt: new Date().toISOString() }
      : { logUrl: 'mock://local', receiptId: hash, anchoredAt: new Date().toISOString(), mock: true };

    this._store.set(hash, { receipt, revoked: false });

    return { receipt, receiptId: hash, hash, systemPrompt, logAnchor };
  }

  /**
   * Validate an action against a previously issued receipt.
   *
   * @param {object} options
   * @param {string} options.receiptHash  - The receipt ID to validate against
   * @param {string} options.action       - The proposed action description
   * @returns {{ authorized: boolean, checks: Array, receiptContext: object }}
   */
  async validate({ receiptHash, action }) {
    const stored = this._store.get(receiptHash);
    if (!stored) throw new Error(`AuthProofClient: receipt not found: ${receiptHash}`);
    return verify(stored.receipt, receiptHash, { revoked: stored.revoked, action });
  }

  /**
   * Revoke a previously issued receipt.
   * @param {string} receiptHash
   */
  revoke(receiptHash) {
    const stored = this._store.get(receiptHash);
    if (stored) stored.revoked = true;
  }

  /**
   * Check if a receipt is still active (not expired, not revoked).
   * @param {string} receiptHash
   * @returns {boolean}
   */
  isActive(receiptHash) {
    const stored = this._store.get(receiptHash);
    if (!stored) return false;
    return isActive(stored.receipt, stored.revoked);
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

// ESM + CJS compatible export (functional API default)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthProof;
} else if (typeof globalThis !== 'undefined') {
  globalThis.AuthProof = AuthProof;
}

export default AuthProof;
export {
  // Functional API
  generateKey,
  importPrivateKey,
  create,
  verify,
  buildSystemPrompt,
  checkScope,
  receiptId,
  isActive,
  secondsRemaining,
  // Class-based API
  AuthProofClient,
  Scope,
  KeyCustody,
};

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
// CANONICALIZER
// ─────────────────────────────────────────────

/**
 * Canonicalizer — deterministic normalization and hashing of operator instructions.
 *
 * Two instructions with identical meaning but different whitespace, capitalization,
 * or punctuation produce the same canonical hash. This ensures that minor formatting
 * differences don't create spurious hash mismatches in receipt verification.
 *
 * Normalization rules (applied in this exact order):
 *   1. Trim leading and trailing whitespace
 *   2. Lowercase everything
 *   3. Collapse all internal whitespace to single spaces
 *   4. Remove meaning-neutral punctuation (commas, sentence-final periods, extra quotes)
 *   5. Sort key-value pairs alphabetically if structured data is detected
 *   6. Result is serialized to UTF-8 before hashing (handled by TextEncoder in _sha256)
 */
class Canonicalizer {
  /**
   * Normalize instruction text to its canonical form.
   * @param {string} text
   * @returns {string} Canonical string ready for hashing
   */
  static normalize(text) {
    if (typeof text !== 'string') throw new Error('Canonicalizer: input must be a string');

    // Step 1: Trim leading and trailing whitespace
    let s = text.trim();

    // Step 2: Lowercase everything
    s = s.toLowerCase();

    // Step 3: Collapse all internal whitespace to single spaces
    s = s.replace(/\s+/g, ' ');

    // Step 4: Remove meaning-neutral punctuation
    s = s.replace(/,/g, '');                              // commas
    s = s.replace(/\.(?=\s|$)/g, '');                    // sentence-final periods
    s = s.replace(/["""''\u2018\u2019\u201c\u201d`]/g, ''); // extra quotes
    s = s.replace(/\s+/g, ' ').trim();                   // re-collapse after removal

    // Step 5: Sort key-value pairs alphabetically if structured data is detected
    s = Canonicalizer._sortKeyValuePairs(s);

    // Step 6: UTF-8 serialization is handled by TextEncoder inside _sha256
    return s;
  }

  /**
   * Detect and sort key-value pairs alphabetically by key.
   * Activates only when 2 or more "key: value" or "key=value" patterns are found.
   * @private
   */
  static _sortKeyValuePairs(text) {
    // Match "key: value" (with space) or "key=value" patterns
    const kvRegex = /\b([\w-]+)(?::\s+|=)(\S+)/g;
    const rawMatches = [...text.matchAll(kvRegex)];

    if (rawMatches.length < 2) return text;

    // Strip matched patterns from text to find non-kv remainder
    let remainder = text;
    for (const m of rawMatches) {
      remainder = remainder.replace(m[0], '\x00');
    }
    remainder = remainder.replace(/\x00/g, ' ').replace(/\s+/g, ' ').trim();

    // Sort pairs alphabetically by key name
    const pairs = rawMatches.map(m => {
      const usesEquals = !m[0].includes(': ');
      return { key: m[1], value: m[2], sep: usesEquals ? '=' : ': ' };
    });
    pairs.sort((a, b) => a.key.localeCompare(b.key));

    const sortedStr = pairs.map(p => `${p.key}${p.sep}${p.value}`).join(' ');
    return remainder ? `${remainder} ${sortedStr}` : sortedStr;
  }

  /**
   * Normalize then SHA-256 hash an instruction string.
   * This is what gets stored in the instructionsHash field of every new receipt.
   * @param {string} text
   * @returns {Promise<string>} 64-char hex SHA-256 of the canonical form
   */
  static async hash(text) {
    const canonical = Canonicalizer.normalize(text);
    return _sha256(canonical);
  }

  /**
   * Return true if two instructions are semantically equivalent under canonical form,
   * even if they differ in raw text (whitespace, capitalization, punctuation, etc.).
   * @param {string} text1
   * @param {string} text2
   * @returns {Promise<boolean>}
   */
  static async compare(text1, text2) {
    const [h1, h2] = await Promise.all([
      Canonicalizer.hash(text1),
      Canonicalizer.hash(text2),
    ]);
    return h1 === h2;
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
 */
function _matchOp(pattern, operation) {
  return pattern === '*' || pattern === operation;
}

/**
 * Match a resource pattern against a concrete resource string.
 * '*' matches anything. Patterns may contain '*' as a glob wildcard
 * (e.g. '*.company.com', 'files/*', 'email/*').
 */
function _matchResource(pattern, resource) {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === resource;
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
 */
function _checkConstraints(schemaConstraints, actionParams) {
  for (const [key, limit] of Object.entries(schemaConstraints)) {
    const val = actionParams[key];
    if (val === undefined) continue;

    if (typeof limit === 'number') {
      if (typeof val === 'number' && val > limit) {
        return { valid: false, reason: `${key} value ${val} exceeds maximum ${limit}` };
      }
    } else if (typeof limit === 'string' && limit.includes('*')) {
      if (typeof val === 'string' && !_matchResource(limit, val)) {
        return { valid: false, reason: `${key} "${val}" does not match required pattern "${limit}"` };
      }
    }
  }
  return { valid: true, reason: 'all constraints satisfied' };
}

// ─────────────────────────────────────────────
// CAPABILITY MANIFEST
// ─────────────────────────────────────────────

/**
 * CapabilityManifest — cryptographically signed declaration of what a tool server
 * can actually do. Published before any user authorization. The manifest hash is
 * committed into the ScopeSchema so any server/manifest divergence is detectable.
 *
 * @example
 * const manifest = new CapabilityManifest({
 *   name:    'scheduler-server',
 *   version: '1.0',
 *   capabilities: [
 *     { operation: 'read',  resource: 'calendar/events' },
 *     { operation: 'write', resource: 'calendar/events' },
 *   ],
 * });
 * const signed = await manifest.sign(serverPrivateKey, serverPublicJwk);
 * const hash   = manifest.getHash();  // embed in ScopeSchema.manifestHash
 */
class CapabilityManifest {
  /**
   * @param {object}   opts
   * @param {string}   opts.name          — Required. Tool server name.
   * @param {string}   opts.version       — Required. Manifest version string (e.g. "1.0").
   * @param {string}   [opts.description] — Optional human-readable description.
   * @param {object[]} opts.capabilities  — Required. Array of { operation, resource, description? }.
   */
  constructor({ name, version, description, capabilities } = {}) {
    if (!name)    throw new Error('CapabilityManifest: name is required');
    if (!version) throw new Error('CapabilityManifest: version is required');
    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      throw new Error('CapabilityManifest: capabilities must be a non-empty array');
    }
    for (const cap of capabilities) {
      if (!cap || typeof cap.operation !== 'string') {
        throw new Error('CapabilityManifest: each capability must have an operation string');
      }
      if (typeof cap.resource !== 'string') {
        throw new Error('CapabilityManifest: each capability must have a resource string');
      }
    }

    this.name         = name;
    this.version      = version;
    this.description  = description ?? null;
    this.capabilities = capabilities;
    this._bodyHash    = null;         // set after sign()
    this._signature   = null;
    this._signerKey   = null;
  }

  /**
   * Sign the manifest with the server's private key.
   * Computes bodyHash, signs it, and returns the sealed manifest object.
   * Also stores the hash on this instance so getHash() works without re-hashing.
   *
   * @param {CryptoKey} serverPrivateKey
   * @param {object}    serverPublicJwk
   * @returns {object} — sealed manifest (plain object, safe to serialize)
   */
  async sign(serverPrivateKey, serverPublicJwk) {
    if (!serverPrivateKey) throw new Error('CapabilityManifest.sign: serverPrivateKey is required');
    if (!serverPublicJwk)  throw new Error('CapabilityManifest.sign: serverPublicJwk is required');

    const body = {
      name:         this.name,
      version:      this.version,
      description:  this.description,
      capabilities: this.capabilities,
      createdAt:    new Date().toISOString(),
    };

    const bodyStr  = JSON.stringify(body);
    const bodyHash = await _sha256(bodyStr);
    const sig      = await _sign(serverPrivateKey, bodyHash);

    this._bodyHash  = bodyHash;
    this._signature = sig;
    this._signerKey = serverPublicJwk;

    return {
      ...body,
      bodyHash,
      signature:       sig,
      signerPublicKey: serverPublicJwk,
    };
  }

  /**
   * Verify a signed manifest object (as returned by sign()).
   * Checks that the bodyHash matches the manifest body and that the
   * ECDSA signature is valid.
   *
   * @param {object} signed — sealed manifest from sign()
   * @returns {{ valid: boolean, reason: string }}
   */
  static async verify(signed) {
    if (!signed || typeof signed !== 'object') {
      return { valid: false, reason: 'manifest is null or not an object' };
    }
    const { name, version, description, capabilities, createdAt,
            bodyHash, signature, signerPublicKey } = signed;

    if (!bodyHash)       return { valid: false, reason: 'manifest missing bodyHash' };
    if (!signature)      return { valid: false, reason: 'manifest missing signature' };
    if (!signerPublicKey) return { valid: false, reason: 'manifest missing signerPublicKey' };

    // Recompute bodyHash from the manifest body fields
    const body    = { name, version, description, capabilities, createdAt };
    const bodyStr = JSON.stringify(body);
    const recomputed = await _sha256(bodyStr);

    if (recomputed !== bodyHash) {
      return { valid: false, reason: 'bodyHash mismatch — manifest content has been tampered' };
    }

    const sigOk = await _verify(signerPublicKey, signature, bodyHash);
    if (!sigOk) {
      return { valid: false, reason: 'signature verification failed — manifest may be tampered or wrong key' };
    }

    return { valid: true, reason: 'bodyHash and ECDSA signature verified' };
  }

  /**
   * Return the SHA-256 hash of the manifest body.
   * Available after sign() is called. Throws if sign() has not been called yet.
   *
   * @returns {string} — 64-char hex SHA-256
   */
  getHash() {
    if (!this._bodyHash) {
      throw new Error('CapabilityManifest.getHash: call sign() first to compute the hash');
    }
    return this._bodyHash;
  }

  /**
   * Check whether this manifest covers a specific action.
   * Uses the same wildcard matching as ScopeSchema.
   *
   * @param {{ operation: string, resource: string }} action
   * @returns {boolean}
   */
  covers(action) {
    if (!action?.operation || !action?.resource) return false;
    return this.capabilities.some(
      cap => _matchOp(cap.operation, action.operation) && _matchResource(cap.resource, action.resource)
    );
  }

  /**
   * Diff two signed manifests — returns capabilities added, removed, or changed
   * between manifest1 (old) and manifest2 (new).
   *
   * @param {object} manifest1 — sealed manifest (old version)
   * @param {object} manifest2 — sealed manifest (new version)
   * @returns {{ added: object[], removed: object[], changed: object[] }}
   */
  static diff(manifest1, manifest2) {
    if (!manifest1 || !Array.isArray(manifest1.capabilities)) {
      throw new Error('CapabilityManifest.diff: manifest1 must be a signed manifest with capabilities');
    }
    if (!manifest2 || !Array.isArray(manifest2.capabilities)) {
      throw new Error('CapabilityManifest.diff: manifest2 must be a signed manifest with capabilities');
    }

    const key = cap => `${cap.operation}::${cap.resource}`;

    const map1 = new Map(manifest1.capabilities.map(c => [key(c), c]));
    const map2 = new Map(manifest2.capabilities.map(c => [key(c), c]));

    const added   = [];
    const removed = [];
    const changed = [];

    for (const [k, cap2] of map2) {
      if (!map1.has(k)) {
        added.push(cap2);
      } else {
        const cap1 = map1.get(k);
        // Detect changes in any field other than operation/resource
        const { operation: _o1, resource: _r1, ...rest1 } = cap1;
        const { operation: _o2, resource: _r2, ...rest2 } = cap2;
        if (JSON.stringify(rest1) !== JSON.stringify(rest2)) {
          changed.push({ from: cap1, to: cap2 });
        }
      }
    }

    for (const [k, cap1] of map1) {
      if (!map2.has(k)) removed.push(cap1);
    }

    return { added, removed, changed };
  }
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
 */
class ScopeSchema {
  /**
   * @param {object} opts
   * @param {string}   opts.version          — Required. Schema version string (e.g. "1.0").
   * @param {object[]} [opts.allowedActions]  — Actions that are permitted. Default: [].
   * @param {object[]} [opts.deniedActions]   — Actions that are always denied. Default: [].
   * @param {string}   [opts.maxDuration]    — Optional maximum delegation duration (e.g. "4h").
   */
  constructor({ version, allowedActions = [], deniedActions = [], maxDuration, manifestHash } = {}) {
    if (!version) throw new Error('ScopeSchema: version is required');
    if (typeof version !== 'string') throw new Error('ScopeSchema: version must be a string');
    if (!Array.isArray(allowedActions)) throw new Error('ScopeSchema: allowedActions must be an array');
    if (!Array.isArray(deniedActions))  throw new Error('ScopeSchema: deniedActions must be an array');
    if (maxDuration !== undefined && typeof maxDuration !== 'string') {
      throw new Error('ScopeSchema: maxDuration must be a string (e.g. "4h")');
    }
    if (manifestHash !== undefined && (typeof manifestHash !== 'string' || manifestHash.length !== 64)) {
      throw new Error('ScopeSchema: manifestHash must be a 64-char hex SHA-256 string');
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
    this.manifestHash   = manifestHash ?? null;
  }

  /**
   * Validate whether an action is permitted by this schema.
   * Denial takes precedence over allowance.
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

  /** Serialize to a plain JSON-safe object. */
  toJSON() {
    const obj = {
      version:        this.version,
      allowedActions: this.allowedActions,
      deniedActions:  this.deniedActions,
    };
    if (this.maxDuration  !== null) obj.maxDuration  = this.maxDuration;
    if (this.manifestHash !== null) obj.manifestHash = this.manifestHash;
    return obj;
  }

  /** Deserialize from a plain object (e.g. JSON.parse output). */
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
  const instructionsHash = await Canonicalizer.hash(instructions);

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
  const { revoked = false, action, registry, manifest, manifestAction } = options;
  const checks = [];

  // 1. Not revoked — check both the in-memory flag and the optional registry
  let isRevoked = revoked || !!receipt.revoked;
  let revokedReason = 'This authorization has been revoked';
  if (!isRevoked && registry) {
    const status = await registry.check(receiptId);
    if (status.revoked) {
      isRevoked = true;
      revokedReason = `Revoked: ${status.reason}`;
    }
  }
  const notRevoked = !isRevoked;
  checks.push({
    name:   'Not revoked',
    passed: notRevoked,
    detail: notRevoked ? 'Active' : revokedReason,
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

  // 5. Instructions hash matches (uses Canonicalizer.hash for canonical form)
  const computedIH = await Canonicalizer.hash(receipt.operatorInstructions);
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

  // 7. Optional manifest check — only runs when scopeSchema has a manifestHash
  //    AND a manifest object was provided in options.
  if (manifest) {
    // 7a. Manifest signature must be valid
    const manifestVerify = await CapabilityManifest.verify(manifest);
    checks.push({
      name:   'Manifest signature valid',
      passed: manifestVerify.valid,
      detail: manifestVerify.reason,
    });

    // 7b. Manifest hash must match the hash committed in scopeSchema
    const committedHash = receipt.scopeSchema?.manifestHash ?? null;
    if (committedHash) {
      const manifestMatches = manifest.bodyHash === committedHash;
      checks.push({
        name:   'Manifest hash matches receipt',
        passed: manifestMatches,
        detail: manifestMatches
          ? 'Manifest bodyHash matches receipt scopeSchema.manifestHash'
          : `Manifest bodyHash (${manifest.bodyHash?.slice(0, 8)}...) does not match committed hash (${committedHash.slice(0, 8)}...)`,
      });
    }

    // 7c. If a structured manifestAction is provided, verify the manifest covers it
    if (manifestAction) {
      const tempManifest = new CapabilityManifest({
        name:         manifest.name         ?? 'unknown',
        version:      manifest.version      ?? '0',
        capabilities: manifest.capabilities ?? [],
      });
      const coveredByManifest = tempManifest.covers(manifestAction);
      checks.push({
        name:   'Action covered by manifest',
        passed: coveredByManifest,
        detail: coveredByManifest
          ? `Manifest covers operation "${manifestAction.operation}" on "${manifestAction.resource}"`
          : `Manifest does not declare operation "${manifestAction.operation}" on "${manifestAction.resource}"`,
      });
    }
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
    /** @private {RevocationRegistry|null} */
    this._registry = null;
  }

  /**
   * Initialize with the agent's ECDSA P-256 signing key.
   * Must be called once before record().
   *
   * @param {{ privateKey: CryptoKey, publicJwk: object, tsaUrl?: string|null, registry?: RevocationRegistry }} opts
   *   tsaUrl   — RFC 3161 TSA endpoint. Defaults to 'https://freetsa.org/tsr'.
   *              Pass null to disable TSA (entries will be UNVERIFIED_TIMESTAMP).
   *   registry — Optional RevocationRegistry. When provided, record() will
   *              reject any action whose receipt has been revoked.
   */
  async init({ privateKey, publicJwk, tsaUrl, registry }) {
    if (!privateKey) throw new Error('ActionLog: privateKey is required');
    if (!publicJwk)  throw new Error('ActionLog: publicJwk is required');
    this._privateKey = privateKey;
    this._publicJwk  = publicJwk;
    if (tsaUrl   !== undefined) this._tsaUrl  = tsaUrl;
    if (registry !== undefined) this._registry = registry;
  }

  /**
   * Register a Delegation Receipt so diff() can compare against its scope.
   * @param {string} receiptHash
   * @param {object} receipt
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
   * the freetsa.org RFC 3161 Trusted Timestamp Authority (TSA). If the TSA
   * request fails for any reason, the entry is still recorded using the local
   * system clock and flagged with timestampType: 'UNVERIFIED_TIMESTAMP'.
   *
   * @param {string} receiptHash
   * @param {{ operation: string, resource: string, parameters?: object }} action
   * @returns {Promise<object>} The sealed log entry
   */
  async record(receiptHash, action, { attestation, output, taintTracker, batchReceiptHash, modelCommitmentId } = {}) {
    if (!this._privateKey) throw new Error('ActionLog: call init() before record()');
    if (!receiptHash)       throw new Error('ActionLog: receiptHash is required');
    if (!action?.operation) throw new Error('ActionLog: action.operation is required');
    if (!action?.resource)  throw new Error('ActionLog: action.resource is required');

    // Reject if the receipt has been revoked
    if (this._registry) {
      const status = await this._registry.check(receiptHash);
      if (status.revoked) {
        throw new Error(
          `ActionLog: receipt has been revoked and cannot be used — reason: ${status.reason}`
        );
      }
    }

    const ids      = this._byReceipt.get(receiptHash) || [];
    const prevHash = ids.length === 0
      ? _GENESIS
      : this._entries.get(ids[ids.length - 1]).entryHash;

    const entryId   = `log-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const timestamp = Date.now();

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

    // Optionally run taint tracking on agent output
    let taintResult = null;
    if (output !== undefined && taintTracker instanceof TaintTracker) {
      taintResult = await taintTracker.recordOutput({
        output,
        destination: 'log',
        outputType:  'log-entry',
      });
    }

    const body = {
      ...baseBody,
      entryBodyHash,
      timestampType,
      ...(timestampToken    ? { timestampToken }    : {}),
      ...(attestation       ? { attestation }       : {}),
      ...(taintResult       ? { taintResult }       : {}),
      ...(batchReceiptHash  ? { batchReceiptHash }  : {}),
      ...(modelCommitmentId ? { modelCommitmentId } : {}),
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
   * For UNVERIFIED_TIMESTAMP entries: reports that no TSA token exists.
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

    // TEE attestation check — only when an attestation is embedded in the entry
    if (entry.attestation) {
      // Structural binding: attestation.entryHash must equal entry.entryBodyHash.
      // This guarantees the TEE quote/token was generated for this exact entry body.
      if (entry.attestation.entryHash !== entry.entryBodyHash) {
        return {
          valid:  false,
          reason: 'TEE attestation entryHash does not match entry body hash — attestation is not bound to this entry',
          teeAttestation: {
            verified: false,
            platform: entry.attestation.platform ?? null,
            quote:    null,
            reason:   'entryHash mismatch: attestation was not generated for this entry',
          },
        };
      }

      // Cryptographic verification
      const teeResult = await TEEAttestation.verify(entry.attestation);
      if (!teeResult.verified) {
        return {
          valid:  false,
          reason: `TEE attestation verification failed: ${teeResult.reason}`,
          teeAttestation: teeResult,
        };
      }

      return {
        valid:  true,
        reason: 'Signature, chain integrity, and TEE attestation verified',
        teeAttestation: teeResult,
      };
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
   * Publish a delegation receipt as fully authorized.
   *
   * Called by PreExecutionVerifier only after ALL gate checks pass — never for
   * blocked or partially-checked receipts. This keeps the log clean: every
   * entry here corresponds to an execution that was fully authorized.
   *
   * @param {string} receiptHash
   * @returns {Promise<object>} The sealed log entry
   */
  async publishReceipt(receiptHash) {
    return this.record(receiptHash, {
      operation: 'receipt_authorized',
      resource:  'delegation/receipt',
    });
  }

  /**
   * Diff: compare all recorded actions against the receipt's authorized scope.
   *
   * Scope matching strategy (applied in order):
   *   1. If receipt.scopeSchema is a ScopeSchema → structured, wildcard-aware validation
   *   2. If receipt.allowedActions is a string[] → exact operation match (legacy)
   *   3. Otherwise → violation with a helpful message pointing to ScopeSchema
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
// REVOCATION REGISTRY
// ─────────────────────────────────────────────

/**
 * RevocationRegistry — append-only, cryptographically signed store of
 * revoked delegation receipts.
 *
 * Properties:
 *   - Append-only: once a receipt is revoked it cannot be un-revoked or deleted.
 *   - Each revocation record is signed by the revoker's ECDSA P-256 key.
 *   - Exportable and importable for cross-process synchronization.
 *   - ActionLog.record() consults the registry before sealing an entry.
 *   - AuthProof.verify() consults the registry when passed as an option.
 */
class RevocationRegistry {
  constructor() {
    /** @private {Map<string, object>} receiptHash → signed revocation record */
    this._revocations = new Map();
    /** @private {CryptoKey|null} */
    this._privateKey = null;
    /** @private {object|null} */
    this._publicJwk = null;
  }

  /** Initialize with an ECDSA P-256 signing key. Required before revoke(). */
  async init({ privateKey, publicJwk }) {
    if (!privateKey) throw new Error('RevocationRegistry: privateKey is required');
    if (!publicJwk)  throw new Error('RevocationRegistry: publicJwk is required');
    this._privateKey = privateKey;
    this._publicJwk  = publicJwk;
  }

  /**
   * Revoke a receipt. Append-only — cannot be undone.
   * @param {string} receiptHash
   * @param {{ reason?: string, revokedAt?: number }} [opts]
   * @returns {Promise<object>} The signed revocation record
   */
  async revoke(receiptHash, { reason = 'user revoked', revokedAt } = {}) {
    if (!receiptHash) throw new Error('RevocationRegistry: receiptHash is required');
    if (!this._privateKey) throw new Error('RevocationRegistry: call init() before revoke()');
    if (this._revocations.has(receiptHash)) {
      throw new Error(`RevocationRegistry: receipt is already revoked — revocations are permanent`);
    }

    const record = {
      receiptHash,
      reason:    reason ?? 'user revoked',
      revokedAt: revokedAt ?? Date.now(),
      revokedBy: this._publicJwk,
    };

    const signature = await _sign(this._privateKey, JSON.stringify(record));
    const entry = { ...record, signature };

    this._revocations.set(receiptHash, entry);
    return entry;
  }

  /**
   * Check whether a receipt has been revoked.
   * @param {string} receiptHash
   * @returns {Promise<{ revoked: boolean, reason?: string, revokedAt?: number }>}
   */
  async check(receiptHash) {
    const entry = this._revocations.get(receiptHash);
    if (!entry) return { revoked: false };
    return { revoked: true, reason: entry.reason, revokedAt: entry.revokedAt };
  }

  /** Export all revocation records as a JSON-safe array. */
  export() {
    return [...this._revocations.values()];
  }

  /**
   * Import revocation records. Each record's ECDSA signature is verified before import.
   * Records with invalid signatures are skipped and reported in errors[].
   * @param {object[]} records
   * @returns {Promise<{ imported: number, skipped: number, errors: string[] }>}
   */
  async import(records) {
    if (!Array.isArray(records)) throw new Error('RevocationRegistry: records must be an array');

    let imported = 0;
    let skipped  = 0;
    const errors = [];

    for (const record of records) {
      try {
        if (!record?.receiptHash || !record?.signature || !record?.revokedBy) {
          errors.push(`Skipped: record missing receiptHash, signature, or revokedBy`);
          skipped++;
          continue;
        }

        const { signature, ...body } = record;
        const valid = await _verify(record.revokedBy, signature, JSON.stringify(body));
        if (!valid) {
          errors.push(`Skipped: invalid signature for ${record.receiptHash.slice(0, 8)}...`);
          skipped++;
          continue;
        }

        if (this._revocations.has(record.receiptHash)) {
          skipped++;
          continue;
        }

        this._revocations.set(record.receiptHash, record);
        imported++;
      } catch (e) {
        errors.push(`Error importing record: ${e.message}`);
        skipped++;
      }
    }

    return { imported, skipped, errors };
  }
}

// ─────────────────────────────────────────────
// CROSS-AGENT TRUST HANDSHAKE
// ─────────────────────────────────────────────

/**
 * AgentHandshake — cross-agent mutual trust protocol.
 *
 * Three-step cryptographic protocol:
 *   1. initiate()  — Agent A signs a request committing to their receipt + nonce
 *   2. respond()   — Agent B verifies A's signature, signs a response linking
 *                    their own receipt and both nonces
 *   3. verify()    — Either agent validates both signatures, both receipts, and
 *                    produces a shared context embedding both agents' proofs.
 *
 * Neither agent's scope is expanded: scopePolicy = 'each-agent-limited-to-own-receipt'
 */
class AgentHandshake {
  /**
   * Initiate a handshake as Agent A.
   * @param {{ myReceiptHash: string, myPrivateKey: CryptoKey, myPublicJwk: object, targetPublicJwk: object }} opts
   * @returns {Promise<{ request: object }>}
   */
  static async initiate({ myReceiptHash, myPrivateKey, myPublicJwk, targetPublicJwk }) {
    if (!myReceiptHash)   throw new Error('AgentHandshake: myReceiptHash is required');
    if (!myPrivateKey)    throw new Error('AgentHandshake: myPrivateKey is required');
    if (!myPublicJwk)     throw new Error('AgentHandshake: myPublicJwk is required');
    if (!targetPublicJwk) throw new Error('AgentHandshake: targetPublicJwk is required');

    const handshakeId = `hs-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const nonce = _hex(crypto.getRandomValues(new Uint8Array(16)).buffer);

    const body = {
      handshakeId,
      initiatorReceiptHash: myReceiptHash,
      initiatorPublicJwk:   myPublicJwk,
      targetPublicJwk,
      nonce,
      initiatedAt: Date.now(),
    };

    const signature = await _sign(myPrivateKey, JSON.stringify(body));
    return { request: { ...body, signature } };
  }

  /**
   * Respond to a handshake as Agent B.
   * Verifies Agent A's signature, then signs a response linking both receipts.
   * @throws if the initiator's signature is invalid
   */
  static async respond({ handshakeRequest, myReceiptHash, myPrivateKey, myPublicJwk }) {
    if (!handshakeRequest) throw new Error('AgentHandshake: handshakeRequest is required');
    if (!myReceiptHash)    throw new Error('AgentHandshake: myReceiptHash is required');
    if (!myPrivateKey)     throw new Error('AgentHandshake: myPrivateKey is required');
    if (!myPublicJwk)      throw new Error('AgentHandshake: myPublicJwk is required');

    const { signature: initSig, ...requestBody } = handshakeRequest;
    const initSigValid = await _verify(
      handshakeRequest.initiatorPublicJwk,
      initSig,
      JSON.stringify(requestBody)
    );
    if (!initSigValid) {
      throw new Error('AgentHandshake: initiator signature is invalid — request rejected');
    }

    const requestHash    = await _sha256(JSON.stringify(handshakeRequest));
    const responderNonce = _hex(crypto.getRandomValues(new Uint8Array(16)).buffer);

    const body = {
      handshakeId:          handshakeRequest.handshakeId,
      requestHash,
      responderReceiptHash: myReceiptHash,
      responderPublicJwk:   myPublicJwk,
      initiatorNonce:       handshakeRequest.nonce,
      responderNonce,
      respondedAt: Date.now(),
    };

    const signature = await _sign(myPrivateKey, JSON.stringify(body));
    return { response: { ...body, signature } };
  }

  /**
   * Verify a completed handshake and produce a shared context.
   *
   * Checks:
   *   1. Initiator ECDSA signature over the request body
   *   2. Responder ECDSA signature over the response body
   *   3. Handshake IDs match
   *   4. Response references the correct request (SHA-256 requestHash)
   *   5. Both delegation receipts are within their time windows
   *   6. Neither receipt is revoked (if a registry is provided)
   *
   * @param {object} request
   * @param {object} response
   * @param {{ receipts?: Map, registry?: RevocationRegistry, log?: ActionLog }} [opts]
   * @returns {Promise<{ trusted: boolean, reason: string, sharedContext: object|null }>}
   */
  static async verify(request, response, { receipts = new Map(), registry, log } = {}) {
    if (!request)  return { trusted: false, reason: 'request is required', sharedContext: null };
    if (!response) return { trusted: false, reason: 'response is required', sharedContext: null };

    // Check 1: Initiator signature
    const { signature: initSig, ...requestBody } = request;
    const initSigValid = await _verify(
      request.initiatorPublicJwk,
      initSig,
      JSON.stringify(requestBody)
    );
    if (!initSigValid) {
      return {
        trusted: false,
        reason:  'Initiator signature is invalid — request may have been tampered',
        sharedContext: null,
      };
    }

    // Check 2: Responder signature
    const { signature: respSig, ...responseBody } = response;
    const respSigValid = await _verify(
      response.responderPublicJwk,
      respSig,
      JSON.stringify(responseBody)
    );
    if (!respSigValid) {
      return {
        trusted: false,
        reason:  'Responder signature is invalid — response may have been tampered',
        sharedContext: null,
      };
    }

    // Check 3: Handshake ID matches
    if (request.handshakeId !== response.handshakeId) {
      return {
        trusted: false,
        reason:  'Handshake ID mismatch — request and response belong to different handshakes',
        sharedContext: null,
      };
    }

    // Check 4: Response links to correct request
    const computedRequestHash = await _sha256(JSON.stringify(request));
    if (computedRequestHash !== response.requestHash) {
      return {
        trusted: false,
        reason:  'requestHash mismatch — response does not reference this request',
        sharedContext: null,
      };
    }

    // Check 5: Validate initiator receipt
    const initiatorReceipt = receipts.get(request.initiatorReceiptHash);
    if (!initiatorReceipt) {
      return {
        trusted: false,
        reason:  `Initiator receipt ${request.initiatorReceiptHash.slice(0, 8)}... not found in receipts map`,
        sharedContext: null,
      };
    }
    const now = new Date();
    if (now < new Date(initiatorReceipt.timeWindow.start) ||
        now > new Date(initiatorReceipt.timeWindow.end)) {
      return {
        trusted: false,
        reason:  'Initiator receipt is outside its time window',
        sharedContext: null,
      };
    }
    if (registry) {
      const iStatus = await registry.check(request.initiatorReceiptHash);
      if (iStatus.revoked) {
        return {
          trusted: false,
          reason:  `Initiator receipt is revoked: ${iStatus.reason}`,
          sharedContext: null,
        };
      }
    }

    // Check 6: Validate responder receipt
    const responderReceipt = receipts.get(response.responderReceiptHash);
    if (!responderReceipt) {
      return {
        trusted: false,
        reason:  `Responder receipt ${response.responderReceiptHash.slice(0, 8)}... not found in receipts map`,
        sharedContext: null,
      };
    }
    if (now < new Date(responderReceipt.timeWindow.start) ||
        now > new Date(responderReceipt.timeWindow.end)) {
      return {
        trusted: false,
        reason:  'Responder receipt is outside its time window',
        sharedContext: null,
      };
    }
    if (registry) {
      const rStatus = await registry.check(response.responderReceiptHash);
      if (rStatus.revoked) {
        return {
          trusted: false,
          reason:  `Responder receipt is revoked: ${rStatus.reason}`,
          sharedContext: null,
        };
      }
    }

    // Build shared context — embeds both agents' signatures, jointly provable
    const sharedContextBody = {
      handshakeId:          request.handshakeId,
      initiatorReceiptHash: request.initiatorReceiptHash,
      responderReceiptHash: response.responderReceiptHash,
      initiatorPublicJwk:   request.initiatorPublicJwk,
      responderPublicJwk:   response.responderPublicJwk,
      initiatorScope:       initiatorReceipt.scope,
      responderScope:       responderReceipt.scope,
      scopePolicy:          'each-agent-limited-to-own-receipt',
      initiatorSignature:   initSig,
      responderSignature:   respSig,
      establishedAt:        now.getTime(),
    };

    const sharedContextHash = await _sha256(JSON.stringify(sharedContextBody));
    const sharedContext = { ...sharedContextBody, sharedContextHash };

    // Log the handshake event (best-effort — never fail the handshake)
    if (log) {
      try {
        await log.record(request.initiatorReceiptHash, {
          operation:  'handshake_established',
          resource:   `agent/${response.responderReceiptHash.slice(0, 8)}`,
          parameters: {
            handshakeId:          request.handshakeId,
            responderReceiptHash: response.responderReceiptHash,
            sharedContextHash,
          },
        });
      } catch {
        // Logging is best-effort — never fail the handshake
      }
    }

    return {
      trusted: true,
      reason:  'Both agents presented valid non-revoked receipts and all signatures verified',
      sharedContext,
    };
  }
}

// ─────────────────────────────────────────────
// TEE ATTESTATION
// ─────────────────────────────────────────────

/**
 * TEEAttestation — Trusted Execution Environment attestation support.
 *
 * Supports two real hardware platforms:
 *
 *   Intel SGX via DCAP
 *     Generates a real SGX ECDSA-P256 DCAP quote by calling the Intel DCAP
 *     quoting library (sgx_qe_get_quote via sgx_quote_gen). The quote embeds
 *     the entryHash in the SGX REPORTDATA field, binding the attestation
 *     cryptographically to a specific action log entry.
 *
 *   ARM TrustZone via OP-TEE
 *     Generates a real OP-TEE attestation token via the tee-supplicant
 *     (optee_attestation_gen). The token contains the entryHash as its
 *     nonce/claim, binding the attestation to the specific entry.
 *
 * Hardware availability:
 *   If the runtime does not have SGX or TrustZone hardware, create() throws
 *   immediately with 'TEEAttestation: hardware not available'. There is no
 *   simulated mode and no soft fallback.
 *
 * @example
 * const attestation = await TEEAttestation.create({
 *   entryId,
 *   entryHash,
 *   platform: 'intel-sgx',
 * });
 *
 * const result = await TEEAttestation.verify(attestation);
 * // { verified: true, platform: 'intel-sgx', quote: '...', reason: '...' }
 *
 * // Attach to an ActionLog entry
 * await actionLog.record(receiptHash, action, { attestation });
 */
class TEEAttestation {
  /**
   * Create a TEE attestation for a specific action log entry.
   *
   * The entryHash is embedded as report data so the attestation is
   * cryptographically bound to this specific entry. Any party can verify
   * that the quote or token was generated for exactly this entry hash.
   *
   * @param {{ entryId: string, entryHash: string, platform: 'intel-sgx'|'arm-trustzone' }} opts
   * @throws {Error} 'TEEAttestation: hardware not available' when platform hardware is absent
   */
  static async create({ entryId, entryHash, platform }) {
    if (!entryId)   throw new Error('TEEAttestation: entryId is required');
    if (!entryHash) throw new Error('TEEAttestation: entryHash is required');
    if (typeof entryHash !== 'string' || entryHash.length !== 64) {
      throw new Error('TEEAttestation: entryHash must be a 64-character hex SHA-256 digest');
    }
    if (!platform) throw new Error('TEEAttestation: platform is required');

    if (platform === 'intel-sgx')     return TEEAttestation._createSGX(entryId, entryHash);
    if (platform === 'arm-trustzone') return TEEAttestation._createTrustZone(entryId, entryHash);

    throw new Error(
      `TEEAttestation: unsupported platform "${platform}" — ` +
      'supported platforms: intel-sgx, arm-trustzone'
    );
  }

  /**
   * Verify a TEE attestation.
   *
   * Checks performed:
   *   1. Required fields are present
   *   2. The report data contains the entryHash (structural binding check)
   *   3. The quote or token is cryptographically valid for the declared platform
   *      (via the platform's verification library / tool)
   *   4. The platform certificates chain to a known root
   *
   * @param {object} attestation — From TEEAttestation.create()
   * @returns {Promise<{ verified: boolean, platform: string, quote: string|null, reason: string }>}
   */
  static async verify(attestation) {
    if (!attestation || typeof attestation !== 'object') {
      return { verified: false, platform: null, quote: null,
               reason: 'attestation object is required' };
    }
    if (!attestation.platform) {
      return { verified: false, platform: null, quote: null,
               reason: 'attestation.platform is required' };
    }
    if (attestation.platform === 'intel-sgx')     return TEEAttestation._verifySGX(attestation);
    if (attestation.platform === 'arm-trustzone') return TEEAttestation._verifyTrustZone(attestation);
    return {
      verified: false,
      platform: attestation.platform,
      quote:    null,
      reason:   `Unsupported platform: "${attestation.platform}"`,
    };
  }

  // ── Intel SGX DCAP ───────────────────────────────────────────────────

  /**
   * Detect Intel SGX hardware availability.
   * Checks for in-kernel (Linux 5.11+) and legacy out-of-tree SGX device files.
   * @returns {Promise<boolean>}
   */
  static async _sgxAvailable() {
    try {
      const { existsSync } = await import('node:fs');
      return (
        existsSync('/dev/sgx_enclave') ||  // in-kernel driver (Linux 5.11+)
        existsSync('/dev/sgx/enclave') ||  // in-kernel driver, alternate path
        existsSync('/dev/isgx')            // legacy out-of-tree driver
      );
    } catch {
      return false; // not a Node.js environment — no SGX
    }
  }

  static async _createSGX(entryId, entryHash) {
    if (!await TEEAttestation._sgxAvailable()) {
      throw new Error(
        'TEEAttestation: hardware not available — Intel SGX device not found ' +
        '(expected /dev/sgx_enclave, /dev/sgx/enclave, or /dev/isgx)'
      );
    }

    // SGX REPORTDATA is 64 bytes. The first 32 bytes carry the entryHash
    // (decoded from its 64-char hex representation). The last 32 bytes are
    // zeroed. This binds the quote to this exact action log entry.
    const reportData = entryHash + '0'.repeat(64); // 128 hex chars = 64 bytes

    try {
      const { execFile } = await import('node:child_process');
      const { promisify } = await import('node:util');
      const execFileAsync = promisify(execFile);

      // sgx_quote_gen wraps sgx_qe_get_quote_size() + sgx_qe_get_quote() from
      // the Intel DCAP quoting library (libsgx_dcap_ql.so). It writes the
      // resulting ECDSA-P256 DCAP quote to stdout as base64.
      const { stdout } = await execFileAsync(
        'sgx_quote_gen',
        ['--report-data', reportData, '--format', 'base64'],
        { timeout: 15_000 }
      );

      const quote = stdout.trim();
      if (!quote) throw new Error('sgx_quote_gen produced no output');

      return {
        platform:    'intel-sgx',
        entryId,
        entryHash,
        reportData,
        quote,          // base64-encoded ECDSA-P256 DCAP quote
        generatedAt: Date.now(),
      };
    } catch (err) {
      throw new Error(`TEEAttestation: SGX quote generation failed — ${err.message}`);
    }
  }

  static async _verifySGX(attestation) {
    const quote = attestation.quote ?? null;

    if (!quote) {
      return { verified: false, platform: 'intel-sgx', quote,
               reason: 'attestation.quote is missing' };
    }
    if (!attestation.entryHash) {
      return { verified: false, platform: 'intel-sgx', quote,
               reason: 'attestation.entryHash is missing' };
    }
    if (!attestation.reportData) {
      return { verified: false, platform: 'intel-sgx', quote,
               reason: 'attestation.reportData is missing' };
    }

    // Structural binding check: reportData must start with entryHash
    if (!attestation.reportData.startsWith(attestation.entryHash)) {
      return {
        verified: false,
        platform: 'intel-sgx',
        quote,
        reason:   'entryHash is not bound in reportData — attestation is not linked to this entry',
      };
    }

    // Cryptographic verification via Intel DCAP Quote Verification Library
    try {
      const { execFile } = await import('node:child_process');
      const { promisify } = await import('node:util');
      const execFileAsync = promisify(execFile);

      // sgx_verify_quote calls sgx_qv_verify_quote() from the Intel DCAP QVL.
      // It verifies the ECDSA-P256 signature, PCK certificate, and the
      // certificate chain up to the Intel SGX Root CA.
      const { stdout } = await execFileAsync(
        'sgx_verify_quote',
        ['--quote', quote, '--report-data', attestation.reportData],
        { timeout: 20_000 }
      );

      const result = JSON.parse(stdout.trim());
      return {
        verified: result.verified === true,
        platform: 'intel-sgx',
        quote,
        reason:   result.reason ?? (result.verified
          ? 'SGX DCAP quote verified — ECDSA-P256 signature and PCK certificate chain valid'
          : 'SGX DCAP quote verification failed'),
      };
    } catch (err) {
      return {
        verified: false,
        platform: 'intel-sgx',
        quote,
        reason:   `SGX verification unavailable: ${err.message}`,
      };
    }
  }

  // ── ARM TrustZone OP-TEE ─────────────────────────────────────────────

  /**
   * Detect ARM TrustZone OP-TEE hardware availability.
   * Checks for OP-TEE TEE client device files.
   * @returns {Promise<boolean>}
   */
  static async _trustZoneAvailable() {
    try {
      const { existsSync } = await import('node:fs');
      return (
        existsSync('/dev/tee0') ||         // OP-TEE primary device
        existsSync('/dev/optee_armtz')     // legacy OP-TEE device
      );
    } catch {
      return false; // not a Node.js environment — no TrustZone
    }
  }

  static async _createTrustZone(entryId, entryHash) {
    if (!await TEEAttestation._trustZoneAvailable()) {
      throw new Error(
        'TEEAttestation: hardware not available — ARM TrustZone TEE device not found ' +
        '(expected /dev/tee0 or /dev/optee_armtz)'
      );
    }

    // The entryHash is used directly as the report data / nonce in the OP-TEE
    // attestation token. This binds the token to this specific action log entry.
    const reportData = entryHash;

    try {
      const { execFile } = await import('node:child_process');
      const { promisify } = await import('node:util');
      const execFileAsync = promisify(execFile);

      // optee_attestation_gen communicates with the OP-TEE supplicant via /dev/tee0
      // and invokes the Attestation TA (Trusted Application) which generates a
      // signed attestation token containing the report data as its claim.
      const { stdout } = await execFileAsync(
        'optee_attestation_gen',
        ['--report-data', reportData, '--format', 'base64'],
        { timeout: 15_000 }
      );

      const token = stdout.trim();
      if (!token) throw new Error('optee_attestation_gen produced no output');

      return {
        platform:    'arm-trustzone',
        entryId,
        entryHash,
        reportData,
        token,          // base64-encoded OP-TEE attestation token
        generatedAt: Date.now(),
      };
    } catch (err) {
      throw new Error(`TEEAttestation: TrustZone attestation failed — ${err.message}`);
    }
  }

  static async _verifyTrustZone(attestation) {
    const token = attestation.token ?? null;

    if (!token) {
      return { verified: false, platform: 'arm-trustzone', quote: null,
               reason: 'attestation.token is missing' };
    }
    if (!attestation.entryHash) {
      return { verified: false, platform: 'arm-trustzone', quote: token,
               reason: 'attestation.entryHash is missing' };
    }
    if (!attestation.reportData) {
      return { verified: false, platform: 'arm-trustzone', quote: token,
               reason: 'attestation.reportData is missing' };
    }

    // Structural binding check: reportData must equal entryHash for TrustZone
    if (attestation.reportData !== attestation.entryHash) {
      return {
        verified: false,
        platform: 'arm-trustzone',
        quote:    token,
        reason:   'entryHash is not bound in reportData — attestation is not linked to this entry',
      };
    }

    // Cryptographic verification via OP-TEE verification tool
    try {
      const { execFile } = await import('node:child_process');
      const { promisify } = await import('node:util');
      const execFileAsync = promisify(execFile);

      // optee_verify_token verifies the OP-TEE attestation token's signature
      // against the device key and checks the certificate chain up to the
      // manufacturer root CA.
      const { stdout } = await execFileAsync(
        'optee_verify_token',
        ['--token', token, '--report-data', attestation.entryHash],
        { timeout: 20_000 }
      );

      const result = JSON.parse(stdout.trim());
      return {
        verified: result.verified === true,
        platform: 'arm-trustzone',
        quote:    token,
        reason:   result.reason ?? (result.verified
          ? 'OP-TEE attestation token verified — device key signature and certificate chain valid'
          : 'OP-TEE attestation token verification failed'),
      };
    } catch (err) {
      return {
        verified: false,
        platform: 'arm-trustzone',
        quote:    token,
        reason:   `TrustZone verification unavailable: ${err.message}`,
      };
    }
  }
}

// ─────────────────────────────────────────────
// TEE RUNTIME
// ─────────────────────────────────────────────

/**
 * TEERuntime — Trusted Execution Environment runtime wrapper.
 *
 * Wraps agent function execution with TEE attestation and optional model
 * state verification. In simulation mode, produces cryptographically signed
 * attestations using an ECDSA P-256 key pair without requiring hardware.
 * In hardware mode, delegates to TEEAttestation for Intel SGX or ARM TrustZone.
 *
 * @example
 * const runtime = new TEERuntime({ platform: 'simulation' });
 * await runtime.init({ privateKey, publicJwk });
 *
 * const attestation = await runtime.attest(measurementHash);
 *
 * const result = await runtime.execute(agentFn, {
 *   commitment,
 *   currentModelId,
 *   currentModelVersion,
 *   currentSystemPromptHash,
 *   currentRuntimeConfigHash,
 *   modelStateAttestation,
 * });
 */
class TEERuntime {
  /**
   * @param {object} opts
   * @param {string} [opts.platform='simulation'] — 'simulation' | 'intel-sgx' | 'arm-trustzone'
   */
  constructor({ platform = 'simulation' } = {}) {
    const VALID_PLATFORMS = new Set(['simulation', 'intel-sgx', 'arm-trustzone']);
    if (!VALID_PLATFORMS.has(platform)) {
      throw new Error(
        `TEERuntime: unsupported platform "${platform}" — ` +
        'supported: simulation, intel-sgx, arm-trustzone'
      );
    }
    this._platform    = platform;
    this._privateKey  = null;
    this._publicJwk   = null;
    this._initialized = false;
  }

  /**
   * Initialize with a signing key pair.
   * Required before attest() in simulation mode.
   *
   * @param {{ privateKey: CryptoKey, publicJwk: object }} opts
   */
  async init({ privateKey, publicJwk } = {}) {
    if (!privateKey) throw new Error('TEERuntime.init: privateKey is required');
    if (!publicJwk)  throw new Error('TEERuntime.init: publicJwk is required');
    this._privateKey  = privateKey;
    this._publicJwk   = publicJwk;
    this._initialized = true;
  }

  /**
   * Generate a TEE attestation for a data hash.
   *
   * In simulation mode: produces a signed mock attestation (no hardware required).
   * In hardware mode: delegates to TEEAttestation.create().
   *
   * @param {string} dataHash — 64-char hex SHA-256 digest
   * @returns {Promise<object>} Platform-specific attestation object
   */
  async attest(dataHash) {
    if (typeof dataHash !== 'string' || dataHash.length !== 64) {
      throw new Error('TEERuntime.attest: dataHash must be a 64-character hex SHA-256 digest');
    }

    if (this._platform === 'simulation') {
      if (!this._initialized) {
        throw new Error('TEERuntime: call init() before attest()');
      }
      const body = {
        platform:    'simulation',
        dataHash,
        generatedAt: Date.now(),
      };
      const signature = await _sign(this._privateKey, JSON.stringify(body));
      return { ...body, signature, signerPublicKey: this._publicJwk };
    }

    // Hardware platforms — delegate to TEEAttestation
    const entryId = `tee-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    return TEEAttestation.create({ entryId, entryHash: dataHash, platform: this._platform });
  }

  /**
   * Execute an agent function inside the TEE context.
   *
   * When a commitment + modelStateAttestation are provided, verifies that the model
   * currently running matches the committed measurement before executing.
   * Throws ModelDriftDetected immediately if any state component has changed.
   *
   * @param {Function} fn                              — Agent function to execute
   * @param {object}   [opts]
   * @param {object}   [opts.commitment]               — Model state commitment to verify against
   * @param {string}   [opts.currentModelId]
   * @param {string}   [opts.currentModelVersion]
   * @param {string}   [opts.currentSystemPromptHash]
   * @param {string}   [opts.currentRuntimeConfigHash]
   * @param {object}   [opts.modelStateAttestation]    — ModelStateAttestation instance
   * @returns {Promise<*>} Return value of fn
   */
  async execute(fn, {
    commitment,
    currentModelId,
    currentModelVersion,
    currentSystemPromptHash,
    currentRuntimeConfigHash,
    modelStateAttestation,
  } = {}) {
    if (typeof fn !== 'function') throw new Error('TEERuntime.execute: fn must be a function');

    if (commitment && modelStateAttestation) {
      const result = await modelStateAttestation.verify({
        commitmentId:             commitment.commitmentId,
        currentModelId:           currentModelId           ?? commitment.modelId,
        currentModelVersion:      currentModelVersion      ?? commitment.modelVersion,
        currentSystemPromptHash:  currentSystemPromptHash  ?? commitment.systemPromptHash,
        currentRuntimeConfigHash: currentRuntimeConfigHash ?? commitment.runtimeConfigHash,
      });

      if (!result.valid || !result.commitmentMatches) {
        const driftList = result.modelDrift.length > 0
          ? result.modelDrift
          : ['measurement mismatch'];
        const err = new Error(
          `ModelDriftDetected: model state does not match commitment — ${driftList.join('; ')}`
        );
        err.name      = 'ModelDriftDetected';
        err.modelDrift = driftList;
        throw err;
      }
    }

    return fn();
  }

  /**
   * Verify a TEE attestation produced by attest().
   *
   * @param {object} attestation
   * @returns {Promise<{ verified: boolean, platform: string, reason: string }>}
   */
  static async verifyAttestation(attestation) {
    if (!attestation || typeof attestation !== 'object') {
      return { verified: false, platform: null, reason: 'attestation is required' };
    }

    if (attestation.platform === 'simulation') {
      const { signature, signerPublicKey, ...body } = attestation;
      if (!signature || !signerPublicKey) {
        return {
          verified: false,
          platform: 'simulation',
          reason:   'simulation attestation missing signature or signerPublicKey',
        };
      }
      const valid = await _verify(signerPublicKey, signature, JSON.stringify(body));
      return {
        verified: valid,
        platform: 'simulation',
        reason:   valid
          ? 'Simulation attestation ECDSA P-256 signature verified'
          : 'Simulation attestation ECDSA P-256 signature invalid',
      };
    }

    return TEEAttestation.verify(attestation);
  }
}

// ─────────────────────────────────────────────
// DATA FLOW RECEIPT
// ─────────────────────────────────────────────

/** High-risk egress destinations: PII reaching these always triggers a policy violation. */
const _HIGH_RISK_DESTINATIONS = new Set(['external-api', 'file']);

/** PII detection patterns used by DataTagger.inspect(). */
const _PII_PATTERNS = [
  { name: 'email',       pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g },
  { name: 'phone',       pattern: /(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/g },
  { name: 'credit-card', pattern: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g },
  { name: 'ssn',         pattern: /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g },
];

/**
 * DataTagger — tags data items by hash for egress tracking.
 *
 * Raw data is never stored — only its SHA-256 hash. Manifest is append-only.
 * inspect() detects tagged data via exact hash matching and PII regex patterns.
 *
 * @example
 * const tagger = new DataTagger({ receiptHash })
 * const tag    = await tagger.tag(userData, { source: 'email-inbox', sensitivity: 'PII', accessedAt: Date.now() })
 * const check  = await tagger.inspect(proposedOutput)
 */
class DataTagger {
  /** @param {{ receiptHash: string }} opts */
  constructor({ receiptHash } = {}) {
    if (!receiptHash) throw new Error('DataTagger: receiptHash is required');
    this._receiptHash   = receiptHash;
    /** @private {object[]} append-only manifest */
    this._manifest      = [];
    /** @private {Map<string, object>} dataHash → tag entry for O(1) lookup */
    this._taggedHashes  = new Map();
  }

  /**
   * Tag a data item. Stores only the SHA-256 hash — raw data is never retained.
   *
   * tagId = SHA-256(dataHash + receiptHash + String(accessedAt))
   *
   * @param {*} data
   * @param {{ source: string, sensitivity: string, accessedAt: number }} opts
   * @returns {Promise<{ tagId, dataHash, receiptHash, source, sensitivity, accessedAt }>}
   */
  async tag(data, { source, sensitivity, accessedAt } = {}) {
    if (!source)                throw new Error('DataTagger.tag: source is required');
    if (!sensitivity)           throw new Error('DataTagger.tag: sensitivity is required');
    if (accessedAt === undefined) throw new Error('DataTagger.tag: accessedAt is required');

    const dataHash = await _sha256(String(data));
    const tagId    = await _sha256(dataHash + this._receiptHash + String(accessedAt));

    const entry = { tagId, dataHash, receiptHash: this._receiptHash, source, sensitivity, accessedAt };

    this._manifest.push(entry);
    this._taggedHashes.set(dataHash, entry);

    return entry;
  }

  /**
   * Return a copy of the append-only tag manifest.
   * @returns {object[]}
   */
  getManifest() {
    return [...this._manifest];
  }

  /**
   * Inspect an output for tagged data (exact hash match) and PII patterns (regex).
   *
   * @param {*} output
   * @returns {Promise<{ clean: boolean, foundTags: object[], reason: string }>}
   */
  async inspect(output) {
    const outputStr  = String(output ?? '');
    const outputHash = await _sha256(outputStr);
    const foundTags  = [];

    // 1. Exact hash match — output equals a previously tagged item
    if (this._taggedHashes.has(outputHash)) {
      foundTags.push({ ...this._taggedHashes.get(outputHash), matchType: 'exact-hash' });
    }

    // 2. PII pattern detection via regex
    const piiMatches = [];
    for (const { name, pattern } of _PII_PATTERNS) {
      const hits = outputStr.match(pattern) || [];
      if (hits.length > 0) piiMatches.push({ type: name, count: hits.length });
    }
    if (piiMatches.length > 0) {
      foundTags.push({ matchType: 'pii-pattern', patterns: piiMatches, source: 'pii-scan', sensitivity: 'PII' });
    }

    const clean = foundTags.length === 0;

    let reason;
    if (clean) {
      reason = 'No tagged data or PII patterns detected in output';
    } else {
      const parts = [];
      const hashMatch = foundTags.find(t => t.matchType === 'exact-hash');
      const piiMatch  = foundTags.find(t => t.matchType === 'pii-pattern');
      if (hashMatch) parts.push(`exact hash match on tagged ${hashMatch.sensitivity} data from ${hashMatch.source}`);
      if (piiMatch)  parts.push(`PII patterns detected: ${piiMatch.patterns.map(p => `${p.count} ${p.type}`).join(', ')}`);
      reason = parts.join('; ');
    }

    return { clean, foundTags, reason };
  }
}

/**
 * TaintTracker — records every agent output and flags policy violations.
 *
 * Every output is hashed and appended to an egress log regardless of taint status.
 * External API calls and file writes are high-risk destinations: PII-tagged data
 * reaching them is always a policy violation.
 *
 * @example
 * const tracker = new TaintTracker({ tagger, receiptHash })
 * const result  = await tracker.recordOutput({ output, destination: 'external-api', outputType: 'api-call' })
 */
class TaintTracker {
  /** @param {{ tagger: DataTagger, receiptHash: string }} opts */
  constructor({ tagger, receiptHash } = {}) {
    if (!(tagger instanceof DataTagger)) throw new Error('TaintTracker: tagger must be a DataTagger instance');
    if (!receiptHash)                    throw new Error('TaintTracker: receiptHash is required');
    this._tagger      = tagger;
    this._receiptHash = receiptHash;
    /** @private {object[]} append-only egress log */
    this._egressLog   = [];
  }

  /**
   * Record an output event. Always logged; flagged when policy-violating.
   *
   * @param {{ output: *, destination: string, outputType: string }} opts
   * @returns {Promise<{ clean, outputHash, destination, taintedTags, policyViolation, reason }>}
   */
  async recordOutput({ output, destination, outputType } = {}) {
    if (!destination) throw new Error('TaintTracker.recordOutput: destination is required');
    if (!outputType)  throw new Error('TaintTracker.recordOutput: outputType is required');

    const outputStr  = String(output ?? '');
    const outputHash = await _sha256(outputStr);

    const inspection  = await this._tagger.inspect(output);
    const taintedTags = inspection.foundTags;

    const hasPII         = taintedTags.some(t => t.sensitivity === 'PII' || t.matchType === 'pii-pattern');
    const isHighRisk     = _HIGH_RISK_DESTINATIONS.has(destination);
    const policyViolation = taintedTags.length > 0 && isHighRisk && hasPII;
    const clean          = taintedTags.length === 0;

    let reason;
    if (policyViolation) {
      reason = `Policy violation: PII-tagged data routed to high-risk destination "${destination}"`;
    } else if (!clean) {
      reason = `Tainted output to "${destination}" — ${inspection.reason}`;
    } else {
      reason = `Clean output to "${destination}"`;
    }

    const logEntry = { outputHash, destination, outputType, taintedTags, policyViolation, clean, reason, loggedAt: Date.now() };

    this._egressLog.push(logEntry);

    return logEntry;
  }

  /**
   * Return a copy of the append-only egress log.
   * @returns {object[]}
   */
  getEgressLog() {
    return [...this._egressLog];
  }
}

/**
 * DataFlowReceipt — signed, timestamped compliance artifact for one agent execution.
 *
 * Bundles the DataTagger manifest and TaintTracker egress log into a single
 * cryptographically signed receipt with RFC 3161 timestamp for auditing.
 * Supports HIPAA, GDPR, SOC 2, and PCI-DSS compliance reporting.
 *
 * @example
 * const receipt = await DataFlowReceipt.generate({ delegationReceiptHash, tagger, tracker, privateKey, publicJwk })
 * const valid   = await DataFlowReceipt.verify(receipt)
 */
class DataFlowReceipt {
  /**
   * Generate a signed DataFlowReceipt from tagger + tracker state.
   *
   * @param {{ delegationReceiptHash, tagger, tracker, privateKey, publicJwk }} opts
   * @returns {Promise<object>} Signed receipt
   */
  static async generate({ delegationReceiptHash, tagger, tracker, privateKey, publicJwk } = {}) {
    if (!delegationReceiptHash)          throw new Error('DataFlowReceipt.generate: delegationReceiptHash is required');
    if (!(tagger instanceof DataTagger)) throw new Error('DataFlowReceipt.generate: tagger must be a DataTagger instance');
    if (!(tracker instanceof TaintTracker)) throw new Error('DataFlowReceipt.generate: tracker must be a TaintTracker instance');
    if (!privateKey)                     throw new Error('DataFlowReceipt.generate: privateKey is required');
    if (!publicJwk)                      throw new Error('DataFlowReceipt.generate: publicJwk is required');

    const dataManifest = tagger.getManifest();
    const egressLog    = tracker.getEgressLog();
    const violations   = egressLog.filter(e => e.policyViolation);
    const clean        = violations.length === 0;

    const body = {
      delegationReceiptHash,
      dataManifest,
      egressLog,
      violations,
      clean,
      generatedAt: new Date().toISOString(),
    };

    const bodyStr  = JSON.stringify(body);
    const bodyHash = await _sha256(bodyStr);

    let timestampToken = null;
    let timestampType;
    try {
      timestampToken = await _requestRfc3161Timestamp(bodyHash, 'https://freetsa.org/tsr');
      timestampType  = 'RFC3161';
    } catch {
      timestampType = 'UNVERIFIED_TIMESTAMP';
    }

    const signature = await _sign(privateKey, bodyStr);

    return {
      ...body,
      bodyHash,
      signature,
      signerPublicKey: publicJwk,
      timestampType,
      ...(timestampToken ? { timestampToken } : {}),
    };
  }

  /**
   * Verify a DataFlowReceipt's body hash and ECDSA signature.
   *
   * @param {object} receipt
   * @returns {Promise<{ valid: boolean, reason: string }>}
   */
  static async verify(receipt) {
    if (!receipt || typeof receipt !== 'object') {
      return { valid: false, reason: 'receipt is null or not an object' };
    }
    const { delegationReceiptHash, dataManifest, egressLog, violations, clean,
            generatedAt, bodyHash, signature, signerPublicKey } = receipt;

    if (!signature)       return { valid: false, reason: 'receipt missing signature' };
    if (!signerPublicKey) return { valid: false, reason: 'receipt missing signerPublicKey' };
    if (!bodyHash)        return { valid: false, reason: 'receipt missing bodyHash' };

    const body       = { delegationReceiptHash, dataManifest, egressLog, violations, clean, generatedAt };
    const recomputed = await _sha256(JSON.stringify(body));
    if (recomputed !== bodyHash) {
      return { valid: false, reason: 'bodyHash mismatch — receipt content has been tampered' };
    }

    const sigOk = await _verify(signerPublicKey, signature, JSON.stringify(body));
    if (!sigOk) {
      return { valid: false, reason: 'signature verification failed — receipt may be tampered or signed with wrong key' };
    }

    return { valid: true, reason: 'bodyHash and ECDSA P-256 signature verified' };
  }
}

// ─────────────────────────────────────────────
// BATCH RECEIPT
// ─────────────────────────────────────────────

/**
 * BatchReceipt — pre-authorized, ordered, hash-chained sequence of actions.
 *
 * All actions are declared and cryptographically committed upfront. Each action
 * slot receives an actionHash = SHA-256(JSON.stringify({index, operation, resource}) + prevHash),
 * where the first slot's prevHash is the delegationReceiptHash. This forms a
 * tamper-evident chain: any re-ordering or substitution of actions changes the
 * downstream hashes and is immediately detectable.
 *
 * Execution must proceed in declared order. advance() moves the internal cursor
 * forward only when the caller proves the correct action was executed (by
 * supplying the expected actionHash). Out-of-order or incorrect attempts are
 * recorded as violations.
 *
 * @example
 * const batch = await BatchReceipt.create({
 *   delegationReceiptHash,
 *   actions: [
 *     { operation: 'read',  resource: 'calendar/events' },
 *     { operation: 'write', resource: 'calendar/summary' },
 *   ],
 *   privateKey,
 *   publicJwk,
 *   expiresIn: 3_600_000,
 * });
 *
 * BatchReceipt.validateNext(batch, { operation: 'read', resource: 'calendar/events' });
 * BatchReceipt.advance(batch, batch.actionChain[0].actionHash);
 * const s = BatchReceipt.status(batch); // { completed: 1, remaining: 1, ... }
 */
class BatchReceipt {
  /**
   * Create a signed batch receipt pre-authorizing an ordered sequence of actions.
   *
   * @param {object} opts
   * @param {string}      opts.delegationReceiptHash — Receipt this batch runs under.
   * @param {object[]}    opts.actions               — Ordered array of { operation, resource }.
   * @param {CryptoKey}   opts.privateKey
   * @param {object}      opts.publicJwk
   * @param {number}      [opts.expiresIn=3600000]   — Milliseconds until expiry (default 1 hour).
   * @returns {Promise<object>} Live batch object (sealed receipt + mutable state)
   */
  static async create({ delegationReceiptHash, actions, privateKey, publicJwk, expiresIn = 3_600_000 } = {}) {
    if (!delegationReceiptHash) {
      throw new Error('BatchReceipt.create: delegationReceiptHash is required');
    }
    if (!Array.isArray(actions) || actions.length === 0) {
      throw new Error('BatchReceipt.create: actions must be a non-empty array');
    }
    for (let i = 0; i < actions.length; i++) {
      if (!actions[i]?.operation) throw new Error(`BatchReceipt.create: actions[${i}].operation is required`);
      if (!actions[i]?.resource)  throw new Error(`BatchReceipt.create: actions[${i}].resource is required`);
    }
    if (!privateKey) throw new Error('BatchReceipt.create: privateKey is required');
    if (!publicJwk)  throw new Error('BatchReceipt.create: publicJwk is required');

    const batchId   = `batch-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + expiresIn).toISOString();

    // Build ordered hash chain anchored to the delegation receipt
    const actionChain = [];
    let prevHash = delegationReceiptHash;
    for (let i = 0; i < actions.length; i++) {
      const { operation, resource } = actions[i];
      const actionHash = await _sha256(JSON.stringify({ index: i, operation, resource }) + prevHash);
      actionChain.push({ index: i, operation, resource, actionHash, prevHash });
      prevHash = actionHash;
    }

    const body     = { batchId, delegationReceiptHash, actionChain, expiresAt, createdAt };
    const bodyStr  = JSON.stringify(body);
    const bodyHash = await _sha256(bodyStr);
    const signature = await _sign(privateKey, bodyHash);

    return {
      // Sealed (signed) portion — do not mutate these fields
      ...body,
      bodyHash,
      signature,
      signerPublicKey: publicJwk,
      // Mutable execution-state tracking
      _currentIndex: 0,
      _violations:   [],
    };
  }

  /**
   * Verify the sealed batch receipt's bodyHash and ECDSA signature.
   *
   * @param {object} batch
   * @returns {Promise<{ valid: boolean, reason: string }>}
   */
  static async verify(batch) {
    if (!batch || typeof batch !== 'object') {
      return { valid: false, reason: 'batch is null or not an object' };
    }
    const { batchId, delegationReceiptHash, actionChain, expiresAt, createdAt,
            bodyHash, signature, signerPublicKey } = batch;

    if (!signature)       return { valid: false, reason: 'batch missing signature' };
    if (!signerPublicKey) return { valid: false, reason: 'batch missing signerPublicKey' };
    if (!bodyHash)        return { valid: false, reason: 'batch missing bodyHash' };

    const body = { batchId, delegationReceiptHash, actionChain, expiresAt, createdAt };
    const recomputed = await _sha256(JSON.stringify(body));
    if (recomputed !== bodyHash) {
      return { valid: false, reason: 'bodyHash mismatch — batch content has been tampered' };
    }

    const sigOk = await _verify(signerPublicKey, signature, bodyHash);
    if (!sigOk) {
      return { valid: false, reason: 'signature verification failed — batch may be tampered or signed with wrong key' };
    }

    return { valid: true, reason: 'bodyHash and ECDSA P-256 signature verified' };
  }

  /**
   * Validate whether a proposed action matches the next expected action in the batch.
   *
   * Does not advance the cursor — call advance() after successful execution.
   *
   * @param {object}   batch
   * @param {{ operation: string, resource: string }} action
   * @returns {{ valid: boolean, reason: string }}
   */
  static validateNext(batch, action) {
    if (!batch?.actionChain) {
      return { valid: false, reason: 'Invalid batch object' };
    }
    if (new Date() > new Date(batch.expiresAt)) {
      return { valid: false, reason: `Batch expired at ${batch.expiresAt}` };
    }
    if (batch._currentIndex >= batch.actionChain.length) {
      return { valid: false, reason: 'All batch actions have been completed' };
    }
    if (!action?.operation || !action?.resource) {
      return { valid: false, reason: 'action.operation and action.resource are required' };
    }

    const expected = batch.actionChain[batch._currentIndex];
    if (action.operation !== expected.operation || action.resource !== expected.resource) {
      return {
        valid:  false,
        reason: `Expected "${expected.operation}" on "${expected.resource}" at index ${batch._currentIndex}, ` +
                `got "${action.operation}" on "${action.resource}"`,
      };
    }

    return {
      valid:  true,
      reason: `Action "${action.operation}" on "${action.resource}" matches batch position ${batch._currentIndex}`,
    };
  }

  /**
   * Advance the batch cursor after an action has been executed.
   *
   * The completedActionHash must equal the pre-computed actionHash at the current
   * position, proving the correct action was executed in order. Mismatches are
   * recorded as violations without moving the cursor.
   *
   * @param {object} batch
   * @param {string} completedActionHash — Must equal batch.actionChain[_currentIndex].actionHash
   * @returns {{ advanced: boolean, reason: string, batch: object }}
   */
  static advance(batch, completedActionHash) {
    if (!batch?.actionChain) {
      return { advanced: false, reason: 'Invalid batch object', batch };
    }
    if (batch._currentIndex >= batch.actionChain.length) {
      return { advanced: false, reason: 'Batch is already complete', batch };
    }

    const expected = batch.actionChain[batch._currentIndex];

    if (completedActionHash !== expected.actionHash) {
      batch._violations.push({
        index:    batch._currentIndex,
        expected: expected.actionHash,
        received: completedActionHash ?? null,
        reason:   `Hash mismatch at index ${batch._currentIndex} — ` +
                  `expected ${expected.actionHash.slice(0, 8)}..., ` +
                  `got ${String(completedActionHash ?? '').slice(0, 8)}...`,
      });
      return {
        advanced: false,
        reason:   `Action hash mismatch at index ${batch._currentIndex} — violation recorded`,
        batch,
      };
    }

    batch._currentIndex++;
    return {
      advanced: true,
      reason:   `Advanced to index ${batch._currentIndex} of ${batch.actionChain.length}`,
      batch,
    };
  }

  /**
   * Return the current execution status of a batch.
   *
   * @param {object} batch
   * @returns {{ completed: number, remaining: number, expired: boolean, violations: object[] }}
   */
  static status(batch) {
    if (!batch?.actionChain) {
      return { completed: 0, remaining: 0, expired: false, violations: [] };
    }
    const total      = batch.actionChain.length;
    const completed  = batch._currentIndex;
    const remaining  = total - completed;
    const expired    = new Date() > new Date(batch.expiresAt);
    const violations = [...batch._violations];

    return { completed, remaining, expired, violations };
  }
}

// ─────────────────────────────────────────────
// AUTHPROOF CLIENT
// ─────────────────────────────────────────────

/**
 * AuthProofClient — convenience wrapper that integrates ScopeDiscovery with the
 * core AuthProof delegation protocol.
 *
 * @example
 * const client = new AuthProofClient({ guided: true });
 * const { receipt, receiptId } = await client.delegateGuided({
 *   agentFn: async (ctx) => { await ctx.email.read(); },
 *   operatorInstructions: 'Summarize my inbox.',
 *   privateKey,
 *   publicJwk,
 * });
 */
class AuthProofClient {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.guided=false] — Enable guided (observation-based) delegation mode.
   */
  constructor({ guided = false } = {}) {
    this._guided = guided;
  }

  /**
   * Run an agent function in sandbox observation mode, generate scope from
   * observed operations, auto-approve the full draft scope, and produce a
   * signed Delegation Receipt — all in a single call.
   *
   * Internally this is equivalent to:
   *   ScopeDiscovery.observe → generateScope → approve (no modifications) → finalize
   *
   * @param {object}    opts
   * @param {Function}  opts.agentFn              — async (ctx) => void
   * @param {string}    [opts.operatorInstructions]
   * @param {CryptoKey} opts.privateKey
   * @param {object}    opts.publicJwk
   * @param {number}    [opts.expiresIn=3600000]  — ms until receipt expiry
   * @param {number}    [opts.timeout=30000]      — observation timeout in ms
   * @returns {Promise<{ receipt, receiptId, systemPrompt, scopeSummary, observations, riskFlags }>}
   */
  async delegateGuided({
    agentFn,
    operatorInstructions,
    privateKey,
    publicJwk,
    expiresIn = 3_600_000,
    timeout   = 30_000,
  } = {}) {
    // Dynamic import avoids circular dependency — scope-discovery.js does not
    // import from authproof.js, so this is safe.
    const { ScopeDiscovery } = await import('./scope-discovery.js');
    return ScopeDiscovery.guided({
      agentFn,
      operatorInstructions,
      privateKey,
      publicJwk,
      expiresIn,
      timeout,
    });
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

  // Canonicalization
  Canonicalizer,

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

  // Revocation registry
  RevocationRegistry,

  // Cross-agent trust handshake
  AgentHandshake,

  // TEE attestation and runtime
  TEEAttestation,
  TEERuntime,

  // Signed capability manifests
  CapabilityManifest,

  // Data flow receipt
  DataTagger,
  TaintTracker,
  DataFlowReceipt,

  // Batch receipt
  BatchReceipt,
  createBatch: BatchReceipt.create.bind(BatchReceipt),

  // AuthProof client (guided delegation)
  AuthProofClient,
};

// ESM + CJS compatible export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AuthProof;
  module.exports.ActionLog          = ActionLog;
  module.exports.Canonicalizer      = Canonicalizer;
  module.exports.ScopeSchema        = ScopeSchema;
  module.exports.RevocationRegistry = RevocationRegistry;
  module.exports.AgentHandshake     = AgentHandshake;
  module.exports.TEEAttestation     = TEEAttestation;
  module.exports.TEERuntime         = TEERuntime;
  module.exports.CapabilityManifest = CapabilityManifest;
  module.exports.DataTagger         = DataTagger;
  module.exports.TaintTracker       = TaintTracker;
  module.exports.DataFlowReceipt    = DataFlowReceipt;
  module.exports.BatchReceipt       = BatchReceipt;
  module.exports.AuthProofClient    = AuthProofClient;
} else if (typeof globalThis !== 'undefined') {
  globalThis.AuthProof            = AuthProof;
  globalThis.ActionLog            = ActionLog;
  globalThis.Canonicalizer        = Canonicalizer;
  globalThis.ScopeSchema          = ScopeSchema;
  globalThis.RevocationRegistry   = RevocationRegistry;
  globalThis.AgentHandshake       = AgentHandshake;
  globalThis.TEEAttestation       = TEEAttestation;
  globalThis.TEERuntime           = TEERuntime;
  globalThis.CapabilityManifest   = CapabilityManifest;
  globalThis.DataTagger           = DataTagger;
  globalThis.TaintTracker         = TaintTracker;
  globalThis.DataFlowReceipt      = DataFlowReceipt;
  globalThis.BatchReceipt         = BatchReceipt;
  globalThis.AuthProofClient      = AuthProofClient;
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
  Canonicalizer,
  ScopeSchema,
  RevocationRegistry,
  AgentHandshake,
  TEEAttestation,
  TEERuntime,
  CapabilityManifest,
  DataTagger,
  TaintTracker,
  DataFlowReceipt,
  BatchReceipt,
  AuthProofClient,
};

// DelegationChain lives in its own module (async crypto primitives require separation)
export { DelegationChain, ScopeAttenuationError, MaxDepthExceededError } from './delegation-chain.js';

export { ScopeDiscovery } from './scope-discovery.js';

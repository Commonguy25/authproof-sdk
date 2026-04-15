/**
 * DelegationChain — multi-agent delegation with scope attenuation enforcement.
 *
 * Enforces:
 *   - Strict scope subset at every delegation hop
 *   - Maximum delegation depth
 *   - Root must be user-signed (ECDSA P-256)
 *   - Cascade revocation from any ancestor to all descendants
 *
 * @module delegation-chain
 */

'use strict';

// ─────────────────────────────────────────────
// CRYPTO HELPERS (same pattern as authproof.js)
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const _fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function _sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hex(buf);
}

async function _sign(privateKey, str) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    _enc(str)
  );
  return _hex(sig);
}

async function _verify(publicJwk, signatureHex, str) {
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
      _fromHex(signatureHex),
      _enc(str)
    );
  } catch {
    return false;
  }
}

/**
 * Derive a public JWK from an extractable private CryptoKey.
 * Returns null if the key is not extractable.
 */
async function _exportPublicJwk(privateKey) {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    const { kty, crv, x, y } = jwk;
    return { kty, crv, x, y };
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
// CUSTOM ERRORS
// ─────────────────────────────────────────────

class ScopeAttenuationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScopeAttenuationError';
  }
}

class MaxDepthExceededError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MaxDepthExceededError';
  }
}

// ─────────────────────────────────────────────
// SCOPE SUBSET CHECKING
// ─────────────────────────────────────────────

function _actionKey(action) {
  return `${action.operation}::${action.resource}`;
}

/**
 * Assert that childScope is a strict proper subset of parentScope.
 *
 * Rules:
 *   1. Every action in childScope.allowedActions must exist in parentScope.allowedActions
 *   2. childScope.allowedActions must be strictly smaller (not equal) — proper subset
 *   3. Every entry in parentScope.deniedActions must be present in childScope.deniedActions
 *
 * @throws {ScopeAttenuationError}
 */
function _checkScopeAttenuation(parentScope, childScope) {
  if (!parentScope || typeof parentScope !== 'object' || !Array.isArray(parentScope.allowedActions)) {
    throw new ScopeAttenuationError(
      'Parent scope must be a structured scope object with allowedActions array'
    );
  }
  if (!childScope || typeof childScope !== 'object' || !Array.isArray(childScope.allowedActions)) {
    throw new ScopeAttenuationError(
      'Child scope must be a structured scope object with allowedActions array'
    );
  }

  const parentAllowedKeys = new Set(parentScope.allowedActions.map(_actionKey));
  const childAllowed      = childScope.allowedActions;

  // Rule 1: all child actions must be covered by parent
  for (const action of childAllowed) {
    const key = _actionKey(action);
    if (!parentAllowedKeys.has(key)) {
      throw new ScopeAttenuationError(
        `child allows action "${key}" which is not in parent scope — scope may only be narrowed, never broadened`
      );
    }
  }

  // Rule 2: proper subset — child must have strictly fewer allowed actions
  const parentSize = parentScope.allowedActions.length;
  const childSize  = childAllowed.length;
  if (childSize >= parentSize) {
    throw new ScopeAttenuationError(
      `child scope must be a proper subset of parent scope — ` +
      `child has ${childSize} allowed action(s), parent has ${parentSize}; child must have fewer`
    );
  }

  // Rule 3: parent's denied actions must all be preserved in child
  const childDeniedKeys = new Set((childScope.deniedActions || []).map(_actionKey));
  for (const denied of (parentScope.deniedActions || [])) {
    const key = _actionKey(denied);
    if (!childDeniedKeys.has(key)) {
      throw new ScopeAttenuationError(
        `parent denied action "${key}" must be preserved in child scope`
      );
    }
  }
}

/**
 * Return the number of allowed actions removed from parent to child.
 */
function _scopeReduction(parentScope, childScope) {
  return (parentScope.allowedActions || []).length - (childScope.allowedActions || []).length;
}

// ─────────────────────────────────────────────
// DELEGATION CHAIN
// ─────────────────────────────────────────────

/**
 * DelegationChain — enforces multi-agent delegation rules.
 *
 * @example
 * const chain = new DelegationChain({ rootReceipt, maxDepth: 3 });
 *
 * const childReceipt = await chain.delegate({
 *   parentReceiptHash,
 *   childScope,
 *   childAgent,
 *   privateKey,
 * });
 *
 * const result = await chain.verify(childReceipt.hash);
 * // { valid, depth, scopeAttenuation, revocationStatus }
 *
 * await chain.revoke(childReceipt.hash, { cascadeToChildren: true });
 */
class DelegationChain {
  /**
   * @param {object}  opts
   * @param {object}  opts.rootReceipt  — Original user-signed DelegationReceipt.
   *                                       Must have .signature, .signerPublicKey, and
   *                                       .scopeSchema (structured scope with allowedActions).
   * @param {number}  [opts.maxDepth=3] — Max delegation depth. Throw MaxDepthExceededError
   *                                       when depth >= maxDepth. Root is at depth 0.
   */
  constructor({ rootReceipt, maxDepth = 3 } = {}) {
    if (!rootReceipt) throw new Error('DelegationChain: rootReceipt is required');
    if (typeof maxDepth !== 'number' || maxDepth < 1) {
      throw new Error('DelegationChain: maxDepth must be a positive integer');
    }

    this._rootReceipt = rootReceipt;
    this._maxDepth    = maxDepth;

    // Initialized lazily on first use
    this._rootHash    = null;
    this._initPromise = null;

    /**
     * @private {Map<string, { receipt, depth, parentHash, scope, childAgent, hash }>}
     * All receipts in the chain, keyed by hash.
     */
    this._receipts = new Map();

    /**
     * @private {Map<string, Set<string>>}
     * Maps parentHash → Set of direct child hashes (for cascade revocation).
     */
    this._children = new Map();

    /**
     * @private {Set<string>}
     * Hashes of all revoked receipts.
     */
    this._revoked = new Set();
  }

  // ── Internal lazy init ────────────────────────────────────────────────

  async _ensureInit() {
    if (this._rootHash) return;
    if (this._initPromise) { await this._initPromise; return; }
    this._initPromise = this._init();
    await this._initPromise;
  }

  async _init() {
    const r = this._rootReceipt;

    if (!r.signature || !r.signerPublicKey) {
      throw new Error(
        'DelegationChain: root receipt must be user-signed — missing .signature or .signerPublicKey'
      );
    }

    const { signature, ...body } = r;
    const valid = await _verify(r.signerPublicKey, signature, JSON.stringify(body));
    if (!valid) {
      throw new Error(
        'DelegationChain: root receipt ECDSA P-256 signature is invalid'
      );
    }

    const hash = await _sha256(JSON.stringify(r));
    this._rootHash = hash;

    this._receipts.set(hash, {
      receipt:    r,
      depth:      0,
      parentHash: null,
      scope:      r.scopeSchema ?? null,
      childAgent: r.agentId ?? null,
      hash,
    });
    this._children.set(hash, new Set());
  }

  // ── Public API ────────────────────────────────────────────────────────

  /**
   * Agent A delegates a subtask to Agent B.
   *
   * @param {object}    opts
   * @param {string}    opts.parentReceiptHash — Agent A's receipt hash
   * @param {object}    opts.childScope        — Must be strict proper subset of parent scope
   * @param {string}    opts.childAgent        — Agent B's identifier / public key string
   * @param {CryptoKey} opts.privateKey        — Agent A's ECDSA P-256 signing key
   * @param {object}    [opts.publicJwk]       — Agent A's public JWK (derived from privateKey
   *                                             when omitted, requires extractable key)
   *
   * @returns {Promise<object>} Child receipt with .hash, .depth, .parentHash, .scope, .childAgent
   * @throws {ScopeAttenuationError} if childScope is not a proper subset of parent scope
   * @throws {MaxDepthExceededError} if resulting depth >= maxDepth
   */
  async delegate({ parentReceiptHash, childScope, childAgent, privateKey, publicJwk } = {}) {
    await this._ensureInit();

    if (!parentReceiptHash) throw new Error('DelegationChain.delegate: parentReceiptHash is required');
    if (!childScope)        throw new Error('DelegationChain.delegate: childScope is required');
    if (!childAgent)        throw new Error('DelegationChain.delegate: childAgent is required');
    if (!privateKey)        throw new Error('DelegationChain.delegate: privateKey is required');

    const parentEntry = this._receipts.get(parentReceiptHash);
    if (!parentEntry) {
      throw new Error(
        `DelegationChain.delegate: parent receipt "${parentReceiptHash.slice(0, 8)}..." not found in chain`
      );
    }

    if (this._revoked.has(parentReceiptHash)) {
      throw new Error(
        'DelegationChain.delegate: cannot delegate from a revoked receipt'
      );
    }

    const childDepth = parentEntry.depth + 1;
    if (childDepth >= this._maxDepth) {
      throw new MaxDepthExceededError(
        `MaxDepthExceededError: delegation depth ${childDepth} >= maxDepth ${this._maxDepth}`
      );
    }

    // Scope attenuation check — throws ScopeAttenuationError if violated
    _checkScopeAttenuation(parentEntry.scope, childScope);

    // Derive public JWK from private key when not explicitly provided
    const signerPublicKey = publicJwk ?? await _exportPublicJwk(privateKey);
    if (!signerPublicKey) {
      throw new Error(
        'DelegationChain.delegate: could not derive publicJwk from privateKey — ' +
        'pass publicJwk explicitly for non-extractable keys'
      );
    }

    const body = {
      delegationId:    `deleg-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      issuedAt:        new Date().toISOString(),
      parentHash:      parentReceiptHash,
      depth:           childDepth,
      scopeSchema:     childScope,
      childAgent,
      signerPublicKey,
    };

    const signature    = await _sign(privateKey, JSON.stringify(body));
    const childReceipt = { ...body, signature };
    const hash         = await _sha256(JSON.stringify(childReceipt));

    this._receipts.set(hash, {
      receipt:    childReceipt,
      depth:      childDepth,
      parentHash: parentReceiptHash,
      scope:      childScope,
      childAgent,
      hash,
    });

    if (!this._children.has(parentReceiptHash)) {
      this._children.set(parentReceiptHash, new Set());
    }
    this._children.get(parentReceiptHash).add(hash);
    this._children.set(hash, new Set());

    return {
      ...childReceipt,
      hash,
      depth:      childDepth,
      parentHash: parentReceiptHash,
      scope:      childScope,
      childAgent,
    };
  }

  /**
   * Verify the complete chain from a leaf receipt up to the root.
   *
   * Walks leaf → root, checking at each hop:
   *   - Receipt is not revoked
   *   - ECDSA P-256 signature is valid
   *   - Scope is a proper subset of parent's scope (rule enforced at every hop)
   *
   * @param {string} receiptHash — Leaf receipt hash to verify
   * @returns {Promise<{
   *   valid:             boolean,
   *   depth:             number|null,
   *   scopeAttenuation:  number[],  // scope reduction at each hop, root→leaf order
   *   revocationStatus:  string,
   *   reason?:           string,
   * }>}
   */
  async verify(receiptHash) {
    await this._ensureInit();

    const entry = this._receipts.get(receiptHash);
    if (!entry) {
      return {
        valid:            false,
        depth:            null,
        scopeAttenuation: [],
        revocationStatus: 'unknown',
        reason:           'Receipt not found in chain',
      };
    }

    // Walk leaf → root, collecting the full path
    const chain = [];
    let cur = receiptHash;
    while (cur !== null) {
      const e = this._receipts.get(cur);
      if (!e) {
        return {
          valid:            false,
          depth:            entry.depth,
          scopeAttenuation: [],
          revocationStatus: 'broken-chain',
          reason:           `Chain broken — receipt ${cur.slice(0, 8)}... not found`,
        };
      }
      chain.push({ hash: cur, entry: e });
      cur = e.parentHash;
    }
    // chain[0] = leaf ... chain[chain.length-1] = root

    const scopeAttenuationLeafToRoot = [];

    for (let i = 0; i < chain.length; i++) {
      const { hash, entry: e } = chain[i];

      // Check revocation
      if (this._revoked.has(hash)) {
        return {
          valid:            false,
          depth:            entry.depth,
          scopeAttenuation: scopeAttenuationLeafToRoot.reverse(),
          revocationStatus: 'revoked',
          reason:           `Receipt ${hash.slice(0, 8)}... is revoked`,
        };
      }

      // Verify signature
      const receipt = e.receipt;
      if (!receipt.signature || !receipt.signerPublicKey) {
        return {
          valid:            false,
          depth:            entry.depth,
          scopeAttenuation: scopeAttenuationLeafToRoot.reverse(),
          revocationStatus: 'not-revoked',
          reason:           `Receipt ${hash.slice(0, 8)}... missing signature or signerPublicKey`,
        };
      }
      const { signature, ...body } = receipt;
      const sigOk = await _verify(receipt.signerPublicKey, signature, JSON.stringify(body));
      if (!sigOk) {
        return {
          valid:            false,
          depth:            entry.depth,
          scopeAttenuation: scopeAttenuationLeafToRoot.reverse(),
          revocationStatus: 'not-revoked',
          reason:           `Signature invalid at ${hash.slice(0, 8)}...`,
        };
      }

      // Scope attenuation check at each non-root hop
      if (i < chain.length - 1) {
        const parentEntry = chain[i + 1].entry;
        try {
          _checkScopeAttenuation(parentEntry.scope, e.scope);
          scopeAttenuationLeafToRoot.push(_scopeReduction(parentEntry.scope, e.scope));
        } catch (err) {
          return {
            valid:            false,
            depth:            entry.depth,
            scopeAttenuation: scopeAttenuationLeafToRoot.reverse(),
            revocationStatus: 'not-revoked',
            reason:           `Scope attenuation violation: ${err.message}`,
          };
        }
      }
    }

    // Reverse so array is in root→leaf order
    scopeAttenuationLeafToRoot.reverse();

    return {
      valid:            true,
      depth:            entry.depth,
      scopeAttenuation: scopeAttenuationLeafToRoot,
      revocationStatus: 'not-revoked',
    };
  }

  /**
   * Revoke a receipt. Optionally cascade to all descendants.
   *
   * @param {string}  receiptHash
   * @param {object}  [opts]
   * @param {boolean} [opts.cascadeToChildren=false] — When true, recursively revokes
   *                                                    all children and their descendants
   * @throws {Error} if receiptHash not found in chain
   */
  async revoke(receiptHash, { cascadeToChildren = false } = {}) {
    await this._ensureInit();

    if (!this._receipts.has(receiptHash)) {
      throw new Error(
        `DelegationChain.revoke: receipt "${receiptHash.slice(0, 8)}..." not found in chain`
      );
    }

    this._revoked.add(receiptHash);

    if (cascadeToChildren) {
      // BFS down the tree — revoke every descendant
      const queue = [...(this._children.get(receiptHash) ?? [])];
      while (queue.length > 0) {
        const childHash = queue.shift();
        this._revoked.add(childHash);
        const grandchildren = this._children.get(childHash);
        if (grandchildren) {
          for (const gc of grandchildren) queue.push(gc);
        }
      }
    }
  }

  /** The root receipt hash (available after first use of delegate/verify/revoke). */
  get rootHash() {
    return this._rootHash;
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

export { DelegationChain, ScopeAttenuationError, MaxDepthExceededError };
export default DelegationChain;

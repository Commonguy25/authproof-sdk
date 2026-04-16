/**
 * TokenPreparer — userspace capability token preparation for TEE enforcement.
 *
 * Produces a signed capability token that a TEE runtime can inject into a
 * process context. The token is then validated by an eBPF LSM hook on every
 * relevant syscall, enforcing the delegation receipt's scope at the kernel level.
 *
 * // eBPF kernel module required for hardware enforcement
 * // Token is prepared but kernel-level injection requires
 * // the eBPF LSM module — see GitHub issue #[ebpf-help-wanted]
 * // Contact: github.com/Commonguy25/authproof-sdk/issues
 * //
 * // DO NOT add kernel-level eBPF code here. This file handles
 * // the userspace side only. The kernel module is a separate
 * // open-source contribution opportunity.
 */

'use strict';

// ─────────────────────────────────────────────
// CRYPTO PRIMITIVES
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

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

// ─────────────────────────────────────────────
// TOKEN PREPARER
// ─────────────────────────────────────────────

/**
 * TokenPreparer — prepares signed capability tokens for TEE process injection.
 *
 * The token lifecycle:
 *   1. TEE runtime computes mrenclave (SHA-256 of platform+verifierHash+modelHash)
 *   2. TokenPreparer.prepare() builds and signs a capability token binding the
 *      receipt, scope, and TEE quote into a single verifiable object
 *   3. Token is injected into the agent process context (via prctl in production)
 *   4. eBPF LSM validates the token on every relevant syscall
 *      — this step requires the kernel module (see issue #[ebpf-help-wanted])
 *
 * The returned ebpfMapEntry is the data structure that would be written into
 * the eBPF map when the kernel module is available.
 *
 * @example
 * const token = await TokenPreparer.prepare({
 *   receiptHash, scopeHash, teeQuoteHash, expiresAt, privateKey
 * })
 * // { token, tokenHash, ebpfMapEntry, status: 'PENDING_KERNEL_MODULE' }
 */
class TokenPreparer {
  /**
   * Prepare a signed capability token for TEE process injection.
   *
   * @param {object}    opts
   * @param {string}    opts.receiptHash  — SHA-256 of the delegation receipt
   * @param {string}    opts.scopeHash    — SHA-256 of the authorized scope
   * @param {string}    opts.teeQuoteHash — SHA-256 of the TEE attestation quote
   * @param {number}    opts.expiresAt    — Unix timestamp (ms) when the token expires
   * @param {CryptoKey} opts.privateKey   — ECDSA P-256 private key for token signing
   *
   * @returns {Promise<{
   *   token:        object,  // signed token body
   *   tokenHash:    string,  // SHA-256 of the full token (64-char hex)
   *   ebpfMapEntry: object,  // ready-to-write eBPF map entry (kernel module required)
   *   status:       string,  // 'PENDING_KERNEL_MODULE'
   * }>}
   */
  static async prepare({ receiptHash, scopeHash, teeQuoteHash, expiresAt, privateKey } = {}) {
    if (!receiptHash)  throw new Error('TokenPreparer.prepare: receiptHash is required');
    if (!scopeHash)    throw new Error('TokenPreparer.prepare: scopeHash is required');
    if (!teeQuoteHash) throw new Error('TokenPreparer.prepare: teeQuoteHash is required');
    if (!expiresAt)    throw new Error('TokenPreparer.prepare: expiresAt is required');
    if (!privateKey)   throw new Error('TokenPreparer.prepare: privateKey is required');

    const expiresAtMs = typeof expiresAt === 'number'
      ? expiresAt
      : new Date(expiresAt).getTime();

    // Build the token body — all binding fields are included before signing
    const body = {
      receiptHash,
      scopeHash,
      teeQuoteHash,
      expiresAt:  expiresAtMs,
      preparedAt: Date.now(),
      status:     'PENDING_KERNEL_MODULE',
    };

    // Sign the token body with the TEE's key material
    const bodyStr   = JSON.stringify(body);
    const signature = await _sign(privateKey, bodyStr);

    // Sealed token — body + ECDSA signature
    const token     = { ...body, signature };

    // tokenHash is the SHA-256 of the complete sealed token
    const tokenHash = await _sha256(JSON.stringify(token));

    // eBPF map entry — written by the kernel module into the BPF map on injection
    // This structure is what the eBPF LSM reads on every relevant syscall.
    // The kernel module is an open-source contribution opportunity:
    //   github.com/Commonguy25/authproof-sdk/issues
    const ebpfMapEntry = {
      receiptHash,
      scopeHash,
      tokenHash,
      expiresAt:  expiresAtMs,
      status:     'PENDING_KERNEL_MODULE',
    };

    return {
      token,
      tokenHash,
      ebpfMapEntry,
      status: 'PENDING_KERNEL_MODULE',
    };
  }
}

export { TokenPreparer };
export default TokenPreparer;

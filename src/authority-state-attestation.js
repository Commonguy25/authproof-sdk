'use strict';

// Private crypto helpers (same pattern as model-state-attestation.js — no import from
// authproof.js here because authproof.js imports this module, and a mutual import
// would create a circular ESM dependency).

const _enc = s => new TextEncoder().encode(s);
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

async function _sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hex(buf);
}

// Recursive key-sorted JSON stringify so { b:1, a:2 } and { a:2, b:1 } produce the same string.
function _stableStringify(val) {
  if (val === null || val === undefined) return JSON.stringify(val);
  if (Array.isArray(val))               return `[${val.map(_stableStringify).join(',')}]`;
  if (typeof val !== 'object')          return JSON.stringify(val);
  const keys  = Object.keys(val).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${_stableStringify(val[k])}`);
  return `{${pairs.join(',')}}`;
}

// ─────────────────────────────────────────────
// AUTHORITY STATE ATTESTATION
// ─────────────────────────────────────────────

/**
 * AuthorityStateAttestation -- cryptographic commitment to the authority state
 * of the principal at delegation time.
 *
 * Closes the authority-drift gap: a Delegation Receipt proves a human authorized
 * an agent, but does not prove the principal's roles, groups, or entitlements
 * have not changed since the receipt was signed. Committing a hash of the authority
 * state at issuance time lets PreExecutionVerifier detect any drift at execution time.
 *
 * Recommended authorityState shape (all fields optional, any free-form object accepted):
 * @typedef {object} AuthorityState
 * @property {string[]} [roles]         - Role identifiers (e.g. ['admin', 'editor'])
 * @property {string[]} [groups]        - Group memberships (e.g. ['engineering', 'oncall'])
 * @property {string[]} [entitlements]  - Entitlement strings (e.g. ['pii:read', 'billing:write'])
 * @property {object}   [attributes]   - Arbitrary key-value attributes
 */
class AuthorityStateAttestation {
  /**
   * Produce a deterministic SHA-256 commitment to an authority state object.
   * Key order does not affect the output -- { b:1, a:2 } and { a:2, b:1 }
   * produce the same commitment.
   *
   * @param {AuthorityState} authorityState - Free-form object to commit to.
   * @returns {Promise<string>} 64-char hex SHA-256 digest
   */
  static async commit(authorityState) {
    const canonical = _stableStringify(authorityState ?? {});
    return _sha256(canonical);
  }

  /**
   * Verify that a current authority state matches a prior commitment.
   *
   * @param {string}          authorityStateCommitment - 64-char hex SHA-256 from a prior commit()
   * @param {AuthorityState}  currentAuthorityState    - Current state to verify against
   * @returns {Promise<boolean>} true if the states match, false on drift
   */
  static async verify(authorityStateCommitment, currentAuthorityState) {
    const current = await AuthorityStateAttestation.commit(currentAuthorityState);
    return current === authorityStateCommitment;
  }
}

export { AuthorityStateAttestation };
export default AuthorityStateAttestation;

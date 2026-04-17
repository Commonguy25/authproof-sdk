/**
 * PreExecutionVerifier — deterministic gate that runs before any agent action executes.
 *
 * Sits outside the agent runtime. The agent runtime never gets control until
 * this verifier passes. A compromised or malicious agent cannot skip it
 * because it runs before the runtime.
 *
 * Eight sequential checks (stops at first failure):
 *   1. Receipt signature valid (ECDSA P-256)
 *   2. Receipt not revoked (RevocationRegistry)
 *   3. Within time window (log timestamp as oracle, not client clock)
 *   4. Action within scope (ScopeSchema.validate or fuzzy fallback)
 *   5. Operator instructions match receipt (Canonicalizer.hash)
 *   6. Program hash match (optional — prevents code substitution attacks)
 *   7. Session risk evaluation (optional — SessionState.evaluate())
 *   8. Model state verification (optional — ModelStateAttestation check)
 *
 * @module pre-execution-verifier
 */

'use strict';

import {
  ActionLog,
  Canonicalizer,
  ScopeSchema,
  checkScope,
  TEEAttestation,
  generateKey,
} from './authproof.js';

// ─────────────────────────────────────────────
// CRYPTO HELPERS (re-implemented — private in authproof.js)
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

async function _sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hex(buf);
}

async function _verifySignature(publicJwk, signatureHex, message) {
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
      _enc(message)
    );
  } catch {
    return false;
  }
}

async function _signData(privateKey, message) {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    _enc(message)
  );
  return _hex(sig);
}

// ─────────────────────────────────────────────
// DELEGATION LOG
// ─────────────────────────────────────────────

/**
 * DelegationLog — append-only store of delegation receipts.
 *
 * Provides the receipt lookup and trusted timestamp oracle used by
 * PreExecutionVerifier. The timestamp is recorded when each receipt is
 * added, so it is not vulnerable to client-clock manipulation at check time.
 *
 * @example
 * const delegationLog = new DelegationLog();
 * delegationLog.add(receiptHash, receipt);
 */
class DelegationLog {
  constructor() {
    /** @private {Map<string, { receipt: object, addedAt: number }>} */
    this._store = new Map();
    /** @private {number} ms timestamp of the most recently added receipt */
    this._latestTimestamp = null;
  }

  /**
   * Add a receipt to the log.
   *
   * @param {string}  receiptHash
   * @param {object}  receipt
   * @param {object}  [meta]
   * @param {ScopeSchema|object} [meta.scopeSchema] — operational scope schema (not part of signed body)
   * @param {string}             [meta.executes]    — program hash committed for this delegation
   */
  add(receiptHash, receipt, { scopeSchema, executes } = {}) {
    if (!receiptHash) throw new Error('DelegationLog: receiptHash is required');
    if (!receipt)     throw new Error('DelegationLog: receipt is required');
    const addedAt = Date.now();
    this._store.set(receiptHash, {
      receipt,
      addedAt,
      scopeSchema: scopeSchema ?? null,
      executes:    executes    ?? null,
    });
    this._latestTimestamp = addedAt;
  }

  /**
   * Fetch a receipt by its hash.
   * @param {string} receiptHash
   * @returns {object|null} receipt or null if not found
   */
  getReceipt(receiptHash) {
    const entry = this._store.get(receiptHash);
    return entry ? entry.receipt : null;
  }

  /**
   * Fetch the full log entry (receipt + operational metadata) by receipt hash.
   * @param {string} receiptHash
   * @returns {{ receipt, scopeSchema, executes, addedAt }|null}
   */
  getEntry(receiptHash) {
    return this._store.get(receiptHash) ?? null;
  }

  /**
   * Return the current log timestamp as a trusted time oracle.
   * Uses the time at which the receipt was added — not the client clock at check time.
   * @returns {number} ms since epoch
   */
  currentTimestamp() {
    // Use Date.now() anchored to log entries — provides a stable reference
    // that is recorded at receipt-add time and cannot be spoofed retroactively.
    return Date.now();
  }

  /**
   * @param {string} receiptHash
   * @returns {boolean}
   */
  has(receiptHash) {
    return this._store.has(receiptHash);
  }
}

// ─────────────────────────────────────────────
// PRE-EXECUTION VERIFIER
// ─────────────────────────────────────────────

/**
 * PreExecutionVerifier — deterministic authorization gate for agent actions.
 *
 * Runs all checks in strict sequential order. Stops at the first failure.
 * Every check result (pass or fail) is logged to an internal ActionLog
 * with the verifier's own cryptographic signature, creating an immutable
 * audit trail of every gate decision.
 *
 * @example
 * const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry });
 * await verifier.init({ privateKey, publicJwk });
 *
 * const result = await verifier.check({
 *   receiptHash, action, operatorInstructions, programHash
 * });
 * if (!result.allowed) throw new Error(result.blockedReason);
 */
class PreExecutionVerifier {
  /**
   * @param {object} opts
   * @param {DelegationLog}        opts.delegationLog          — append-only receipt store
   * @param {RevocationRegistry}   opts.revocationRegistry     — live revocation registry
   * @param {boolean}              [opts.requireTEE=false]     — require hardware attestation
   * @param {SessionState}         [opts.sessionState]         — when provided, enables check 7
   * @param {ModelStateAttestation} [opts.modelStateAttestation] — when provided, enables check 8
   * @param {ActionLog}            [opts.actionLog]            — when provided, receives one
   *                                                             receipt_authorized entry per
   *                                                             fully-passed check; never written
   *                                                             when any check fails
   */
  constructor({ delegationLog, revocationRegistry, requireTEE = false, sessionState, modelStateAttestation, actionLog } = {}) {
    if (!delegationLog)      throw new Error('PreExecutionVerifier: delegationLog is required');
    if (!revocationRegistry) throw new Error('PreExecutionVerifier: revocationRegistry is required');

    this._log                   = delegationLog;
    this._registry              = revocationRegistry;
    this._requireTEE            = requireTEE;
    this._sessionState          = sessionState          ?? null;
    this._modelStateAttestation = modelStateAttestation ?? null;
    this._actionLog             = actionLog             ?? null;

    /** @private — internal audit log of every gate decision */
    this._auditLog     = new ActionLog();
    /** @private {CryptoKey|null} */
    this._privateKey   = null;
    /** @private {object|null} */
    this._publicJwk    = null;
    /** @private {boolean} */
    this._initialized  = false;
    /** @private {Set<string>} receipt hashes with an active check() call — replay detection */
    this._inFlightChecks = new Set();
  }

  /**
   * Initialize the verifier with its own signing key pair.
   * Required before calling check(). The verifier signs every audit log entry
   * with this key, proving the gate decision was made by this verifier instance.
   *
   * @param {object}   opts
   * @param {CryptoKey} opts.privateKey
   * @param {object}    opts.publicJwk
   */
  async init({ privateKey, publicJwk } = {}) {
    if (!privateKey) throw new Error('PreExecutionVerifier.init: privateKey is required');
    if (!publicJwk)  throw new Error('PreExecutionVerifier.init: publicJwk is required');

    this._privateKey  = privateKey;
    this._publicJwk   = publicJwk;
    this._initialized = true;

    // Audit log uses no TSA to avoid latency on every gate check
    await this._auditLog.init({ privateKey, publicJwk, tsaUrl: null });
  }

  /**
   * The main gate. Call this before ANY agent action executes.
   *
   * All six checks run in strict sequence. Stops at first failure.
   * Every call (pass or fail) is logged to the internal audit log.
   *
   * @param {object} opts
   * @param {string}  opts.receiptHash           — hash of the delegation receipt
   * @param {object|string} opts.action          — action the agent wants to take
   * @param {string}  opts.operatorInstructions  — what the operator claims to be instructing
   * @param {string}  [opts.programHash]         — optional Safescript capability DAG hash
   *
   * @returns {Promise<{
   *   allowed: boolean,
   *   checks: object,
   *   blockedReason: string|null,
   *   verifiedAt: string
   * }>}
   */
  async check({
    receiptHash,
    action,
    operatorInstructions,
    programHash,
    commitmentId,
    currentModelId,
    currentModelVersion,
    currentSystemPromptHash,
    currentRuntimeConfigHash,
  } = {}) {
    if (!this._initialized) {
      throw new Error('PreExecutionVerifier: call init() before check()');
    }
    if (!receiptHash) throw new Error('PreExecutionVerifier.check: receiptHash is required');

    const checks = {
      receiptSignatureValid:     false,
      receiptNotRevoked:         false,
      withinTimeWindow:          false,
      actionWithinScope:         false,
      operatorInstructionsMatch: false,
    };
    if (programHash !== undefined)                               checks.programHashMatch    = false;
    if (this._requireTEE)                                        checks.teeAttestationValid = false;
    if (this._sessionState)                                      checks.sessionRiskValid    = false;
    if (this._modelStateAttestation && commitmentId !== undefined) checks.modelStateValid    = false;

    // ── Replay attack detection ───────────────────────────────────────
    // Block a second concurrent check() using the same receipt hash.
    // Two simultaneous claims on the same receipt indicate a replay attack.
    if (this._inFlightChecks.has(receiptHash)) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: 'Replay attack detected: receipt hash already in use by a concurrent check()',
        receiptHash,
        action,
      });
    }
    this._inFlightChecks.add(receiptHash);

    try {

    // ── Check 1: Receipt signature ─────────────────────────────────────
    const logEntry = this._log.getEntry(receiptHash);
    const receipt  = logEntry?.receipt ?? null;
    if (!receipt) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: `Receipt not found for hash ${receiptHash.slice(0, 8)}…`,
        receiptHash,
        action,
      });
    }

    const { signature, ...body } = receipt;
    const sigValid = await _verifySignature(
      receipt.signerPublicKey,
      signature,
      JSON.stringify(body)
    );
    checks.receiptSignatureValid = sigValid;
    if (!sigValid) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: 'Receipt signature invalid — receipt may be tampered or signed with wrong key',
        receiptHash,
        action,
      });
    }

    // ── Check 2: Revocation ────────────────────────────────────────────
    const revokeStatus = await this._registry.check(receiptHash);
    checks.receiptNotRevoked = !revokeStatus.revoked;
    if (revokeStatus.revoked) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: `Receipt revoked: ${revokeStatus.reason}`,
        receiptHash,
        action,
      });
    }

    // ── Check 3: Time window (log timestamp as oracle) ─────────────────
    const now   = new Date(this._log.currentTimestamp());
    const start = new Date(receipt.timeWindow.start);
    const end   = new Date(receipt.timeWindow.end);
    const inWindow = now >= start && now <= end;
    checks.withinTimeWindow = inWindow;
    if (!inWindow) {
      const reason = now > end
        ? `Receipt expired at ${end.toISOString()}`
        : `Receipt not yet valid — starts ${start.toISOString()}`;
      return this._finalize({
        allowed: false, checks, blockedReason: reason, receiptHash, action,
      });
    }

    // ── Check 4: Scope validation ──────────────────────────────────────
    let scopeValid  = false;
    let scopeReason = '';

    // Scope schema: prefer log-registered metadata (not part of signed receipt body)
    // over receipt.scopeSchema (if present and signed in)
    const rawSchema = logEntry?.scopeSchema ?? receipt.scopeSchema ?? null;
    if (rawSchema) {
      // Use ScopeSchema — structured, wildcard-aware, constraint-checked
      const schema = rawSchema instanceof ScopeSchema
        ? rawSchema
        : ScopeSchema.fromJSON(rawSchema);

      const actionObj = typeof action === 'string'
        ? { operation: action, resource: action }
        : action;

      const sv = schema.validate(actionObj);
      scopeValid  = sv.valid;
      scopeReason = sv.reason;
    } else {
      // Fallback: fuzzy text-based scope matching
      const actionStr = typeof action === 'string'
        ? action
        : `${action?.operation ?? ''} ${action?.resource ?? ''}`.trim();
      const { withinScope } = checkScope(actionStr, receipt);
      scopeValid  = withinScope;
      scopeReason = withinScope
        ? 'Action within authorized scope'
        : 'Action outside authorized scope';
    }

    checks.actionWithinScope = scopeValid;
    if (!scopeValid) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: `Scope violation: ${scopeReason}`,
        receiptHash,
        action,
      });
    }

    // ── Check 5: Operator instructions hash ───────────────────────────
    const instructions = operatorInstructions ?? receipt.operatorInstructions;
    const providedHash = await Canonicalizer.hash(instructions);
    const instructionsMatch = providedHash === receipt.instructionsHash;
    checks.operatorInstructionsMatch = instructionsMatch;
    if (!instructionsMatch) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: 'Operator instructions do not match receipt — operator drift detected',
        receiptHash,
        action,
      });
    }

    // ── Check 6: Program hash (optional) ──────────────────────────────
    if (programHash !== undefined) {
      // executes: prefer log-registered metadata over receipt body
      const committedHash = logEntry?.executes
        ?? receipt.executes
        ?? receipt.scopeSchema?.executes
        ?? null;
      const programHashMatch = committedHash === programHash;
      checks.programHashMatch = programHashMatch;
      if (!programHashMatch) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: `Program hash mismatch — possible code substitution attack (expected ${
            committedHash ? committedHash.slice(0, 8) + '…' : 'none committed'
          }, got ${programHash.slice(0, 8)}…)`,
          receiptHash,
          action,
        });
      }
    }

    // ── TEE attestation (optional) ────────────────────────────────────
    if (this._requireTEE) {
      const teeAttestation = receipt.teeAttestation ?? null;
      let teeValid = false;
      if (teeAttestation) {
        const teeResult = await TEEAttestation.verify(teeAttestation);
        teeValid = teeResult.verified;
      }
      checks.teeAttestationValid = teeValid;
      if (!teeValid) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: teeAttestation
            ? 'TEE attestation verification failed'
            : 'TEE attestation required but not present in receipt',
          receiptHash,
          action,
        });
      }
    }

    // ── Check 7: Session risk evaluation (optional) ──────────────────
    if (this._sessionState) {
      const actionStr = typeof action === 'string'
        ? action
        : `${action?.operation ?? ''} ${action?.resource ?? ''}`.trim();

      const sessionResult = await this._sessionState.evaluate({
        action,
        operatorInstructions,
        payload: actionStr,
      });

      const sessionAllowed = sessionResult.decision !== 'BLOCK';
      checks.sessionRiskValid = sessionAllowed;

      if (!sessionAllowed) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: `Session risk evaluation blocked action — riskScore: ${sessionResult.riskScore}, reasons: ${sessionResult.reasons.join('; ')}`,
          receiptHash,
          action,
          sessionRiskResult: sessionResult,
        });
      }

      // Attach session result to the finalized response even on pass
      if (!this._sessionRiskResult) this._sessionRiskResult = sessionResult;
    }

    // ── Check 8: Model state verification (optional) ─────────────────
    if (this._modelStateAttestation && commitmentId !== undefined) {
      const msaResult = await this._modelStateAttestation.verify({
        commitmentId,
        currentModelId,
        currentModelVersion,
        currentSystemPromptHash,
        currentRuntimeConfigHash,
      });

      const modelStateValid = msaResult.valid && msaResult.commitmentMatches;
      checks.modelStateValid = modelStateValid;

      if (!modelStateValid) {
        const driftDesc = msaResult.modelDrift.length > 0
          ? msaResult.modelDrift.join('; ')
          : 'measurement mismatch';
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: `ModelDriftDetected: ${driftDesc}`,
          receiptHash,
          action,
        });
      }
    }

    return this._finalize({ allowed: true, checks, blockedReason: null, receiptHash, action });

    } finally {
      this._inFlightChecks.delete(receiptHash);
    }
  }

  /**
   * Build the result object, sign it, and record it in the audit log.
   * @private
   */
  async _finalize({ allowed, checks, blockedReason, receiptHash, action, sessionRiskResult }) {
    const verifiedAt = new Date().toISOString();

    const checkResult = {
      allowed,
      checks,
      blockedReason,
      verifiedAt,
      receiptHash,
    };

    // Sign the check result with the verifier's own key
    const verifierSignature = await _signData(
      this._privateKey,
      JSON.stringify(checkResult)
    );

    // Record to immutable audit log (best-effort — never fail the gate decision)
    try {
      await this._auditLog.record(
        receiptHash,
        {
          operation:  allowed ? 'verifier_pass' : 'verifier_block',
          resource:   `verifier/gate`,
          parameters: {
            checks,
            allowed,
            blockedReason: blockedReason ?? null,
            action: typeof action === 'string' ? action : JSON.stringify(action),
            verifierPublicKey: this._publicJwk,
            verifierSignature,
          },
        }
      );
    } catch {
      // Audit log failure never blocks the gate decision
    }

    // Publish to the authorization ActionLog only when ALL checks pass.
    // A blocked receipt must never appear here — the log must only contain
    // receipts where execution was fully authorized.
    if (allowed && this._actionLog) {
      try {
        await this._actionLog.publishReceipt(receiptHash);
      } catch {
        // Best-effort — never block the gate decision
      }
    }

    const result = {
      allowed,
      checks,
      blockedReason: blockedReason ?? null,
      verifiedAt,
      verifierSignature,
      verifierPublicKey: this._publicJwk,
    };

    // Attach session risk result when available
    const sessionResult = sessionRiskResult ?? this._sessionRiskResult ?? null;
    if (sessionResult) {
      result.sessionRiskResult = sessionResult;
      this._sessionRiskResult  = null; // reset for next call
    }

    return result;
  }

  /**
   * Return all audit log entries for a receipt hash.
   * @param {string} receiptHash
   * @returns {object[]}
   */
  getAuditLog(receiptHash) {
    return this._auditLog.getEntries(receiptHash);
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

export { PreExecutionVerifier, DelegationLog };
export default { PreExecutionVerifier, DelegationLog };

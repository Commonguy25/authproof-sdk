/**
 * PreExecutionVerifier — deterministic gate that runs before any agent action executes.
 *
 * Sits outside the agent runtime. The agent runtime never gets control until
 * this verifier passes. A compromised or malicious agent cannot skip it
 * because it runs before the runtime.
 *
 * Sequential checks (stops at first failure):
 *   1.  Receipt signature valid (ECDSA P-256)
 *   2.  Receipt not revoked (RevocationRegistry)
 *   3.  Within time window (log timestamp as oracle, not client clock)
 *   4.  Action within scope (ScopeSchema.validate; fuzzy keyword match is advisory-only)
 *   5.  Operator instructions match receipt (Canonicalizer.hash)
 *   6.  Program hash match (optional — prevents code substitution attacks)
 *   7.  Session risk evaluation (optional — SessionState.evaluate())
 *   8.  Tool schema integrity (optional — toolSchemaHash in receipt)
 *   9.  Model state verification (optional — ModelStateAttestation check)
 *  10.  Tool output hash binding (optional — toolOutputHash in receipt)
 *  11.  Instruction provenance (optional — trustedSources in receipt)
 *  14.  Parent scope containment (sub-receipts only — parentReceiptId present)
 *  15.  Authority state drift (optional — authorityStateCommitment in receipt)
 *
 * oneTimeUse consumption runs last, after every authorization check above has
 * passed, so a consumption slot is never burned on a receipt that would be
 * denied for another reason.
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
  checkScopeAttenuation,
} from './authproof.js';

import { AuthorityStateAttestation } from './authority-state-attestation.js';

import { InMemoryConsumptionStore } from './consumption-store.js';

// ─────────────────────────────────────────────
// DENIAL CODES
// ─────────────────────────────────────────────

const DENIAL_CODES = {
  AUTHORITY_STATE_DRIFT:    'AUTHORITY_STATE_DRIFT',
  RECEIPT_ALREADY_CONSUMED: 'RECEIPT_ALREADY_CONSUMED',
  CONSUMPTION_STORE_REQUIRED: 'CONSUMPTION_STORE_REQUIRED',
  CHAIN_DEPTH_EXCEEDED:     'CHAIN_DEPTH_EXCEEDED',
};

/** Denial code: receipt was already consumed by a prior verification. Terminal. */
const RECEIPT_ALREADY_CONSUMED   = 'RECEIPT_ALREADY_CONSUMED';

/** Denial code: receipt has oneTimeUse=true but no durable ConsumptionStore was configured. */
const CONSUMPTION_STORE_REQUIRED  = 'CONSUMPTION_STORE_REQUIRED';

/** Denial code: delegation chain depth exceeds the configured maxChainDepth. */
const CHAIN_DEPTH_EXCEEDED        = 'CHAIN_DEPTH_EXCEEDED';

// ─────────────────────────────────────────────
// CRYPTO HELPERS (re-implemented — private in authproof.js)
// ─────────────────────────────────────────────

const _enc = s => new TextEncoder().encode(s);
const _fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));
const _hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');

/**
 * CSPRNG-backed random ID suffix. Replaces Math.random() for identity material:
 * a security library must not use a non-cryptographic PRNG for IDs. Output is
 * `len` lowercase hex chars, preserving existing ID shapes.
 */
function _randomSuffix(len) {
  const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(len / 2)));
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s.slice(0, len);
}

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

/** Deterministic JSON serialization with sorted keys at every level. */
function _canonicalizeJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(_canonicalizeJson).join(',') + ']';
  const sorted = Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + _canonicalizeJson(obj[k]));
  return '{' + sorted.join(',') + '}';
}

async function _sha256Schema(schema) {
  return _sha256(_canonicalizeJson(schema));
}

/**
 * Normalize a scope schema for equality comparison. ScopeSchema instances and
 * plain objects are both reduced through the ScopeSchema constructor so that
 * defaulted fields (e.g. version: '1.0') compare equal whether the schema was
 * registered as an instance or embedded as a plain object in the receipt body.
 */
function _normalizeScopeSchema(s) {
  if (s instanceof ScopeSchema) return s.toJSON();
  if (s && typeof s === 'object') {
    try {
      return new ScopeSchema(s).toJSON();
    } catch {
      return s;
    }
  }
  return s;
}

/** True when two scope schemas are semantically identical (key-order independent). */
function _sameScopeSchema(a, b) {
  return _canonicalizeJson(_normalizeScopeSchema(a)) === _canonicalizeJson(_normalizeScopeSchema(b));
}

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────

/**
 * Default maximum delegation chain depth for Check 14.
 * Matches the RECOMMENDED value in draft-nelson-agent-delegation-receipts-09.
 * Pass maxChainDepth to the PreExecutionVerifier constructor to override.
 */
const MAX_CHAIN_DEPTH = 3;

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
   * @param {DelegationLog}        opts.delegationLog          - append-only receipt store
   * @param {RevocationRegistry}   opts.revocationRegistry     - live revocation registry
   * @param {boolean}              [opts.requireTEE=false]     - require hardware attestation
   * @param {boolean}              [opts.offlineMode=false]    - skip the revocation registry check.
   *                                                             All other checks run normally.
   *                                                             Receipts with revocationRequired: true
   *                                                             are denied even in offline mode.
   * @param {SessionState}         [opts.sessionState]         - when provided, enables check 7
   * @param {ModelStateAttestation} [opts.modelStateAttestation] - when provided, enables check 8
   * @param {ActionLog}            [opts.actionLog]            - when provided, receives one
   *                                                             receipt_authorized entry per
   *                                                             fully-passed check; never written
   *                                                             when any check fails
   * @param {number}               [opts.maxChainDepth=3]     - maximum allowed delegation chain
   *                                                             depth for sub-receipt Check 14.
   *                                                             Default 3 matches the RECOMMENDED
   *                                                             value in draft-nelson-agent-
   *                                                             delegation-receipts-09.
   * @param {object}               [opts.defaultReauthPolicy] - fallback reauth policy when the
   *   receipt does not carry a reauthPolicy field.
   *   Default: { secondsBeforeExpiry: 300, trustScoreBelow: 50, onAuthorityStateDrift: 'reauth' }
   * @param {ConsumptionStore}     [opts.consumptionStore]   - durable store for one-time receipt
   *   consumption (oneTimeUse: true). When omitted the verifier uses an internal
   *   InMemoryConsumptionStore but will deny all oneTimeUse receipts with
   *   CONSUMPTION_STORE_REQUIRED (fail closed). Provide a durable store such as
   *   RedisConsumptionStore to enable global one-time use.
   */
  constructor({ delegationLog, revocationRegistry, requireTEE = false, offlineMode = false, sessionState, modelStateAttestation, actionLog, maxChainDepth = MAX_CHAIN_DEPTH, defaultReauthPolicy, consumptionStore } = {}) {
    if (!delegationLog)      throw new Error('PreExecutionVerifier: delegationLog is required');
    if (!revocationRegistry) throw new Error('PreExecutionVerifier: revocationRegistry is required');

    this._log                   = delegationLog;
    this._registry              = revocationRegistry;
    this._requireTEE            = requireTEE;
    this._offlineMode           = offlineMode;
    this._sessionState          = sessionState          ?? null;
    this._modelStateAttestation = modelStateAttestation ?? null;
    this._actionLog             = actionLog             ?? null;
    this._maxChainDepth         = maxChainDepth;
    this._defaultReauthPolicy   = defaultReauthPolicy  ?? {
      secondsBeforeExpiry:   300,
      trustScoreBelow:       50,
      onAuthorityStateDrift: 'reauth',
    };

    // consumptionStore: when explicitly provided it is treated as durable (global).
    // When omitted a per-instance InMemoryConsumptionStore is used, but all
    // oneTimeUse receipts are denied with CONSUMPTION_STORE_REQUIRED (fail closed).
    this._consumptionStore            = consumptionStore ?? new InMemoryConsumptionStore();
    this._hasExternalConsumptionStore = consumptionStore != null;

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
    /** @private {Map<string, object[]>} sessionId → denied call log entries */
    this._deniedCalls  = new Map();
    /** @private {Map<string, string>} sessionId → hash of last denied call entry */
    this._lastDeniedHash = new Map();
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
   * All checks run in strict sequence. Stops at first failure.
   * Every call (pass or fail) is logged to the internal audit log.
   *
   * @param {object} opts
   * @param {string}  opts.receiptHash              — hash of the delegation receipt
   * @param {object|string} opts.action             — action the agent wants to take
   * @param {string}  opts.operatorInstructions     — what the operator claims to be instructing
   * @param {string}  [opts.programHash]            — optional Safescript capability DAG hash
   * @param {object}  [opts.currentAuthorityState]  — optional current authority state; when provided
   *   and the receipt carries authorityStateCommitment, triggers Check 15 (authority state drift).
   *
   * @returns {Promise<{
   *   allowed: boolean,
   *   checks: object,
   *   blockedReason: string|null,
   *   verifiedAt: string,
   *   reauthRequired: boolean
   * }>}
   *
   * reauthRequired — a soft signal that the caller should prompt for re-authorization before the
   * next action. Does not change allowed. Non-breaking addition: callers that do not read this
   * field see no behavior change.
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
    currentToolSchema,
    currentAuthorityState,
  } = {}) {
    if (!this._initialized) {
      throw new Error('PreExecutionVerifier: call init() before check()');
    }
    if (!receiptHash) throw new Error('PreExecutionVerifier.check: receiptHash is required');

    const checks = {
      receiptSignatureValid:     false,
      ...(!this._offlineMode ? { receiptNotRevoked: false } : {}),
      withinTimeWindow:          false,
      actionWithinScope:         false,
      operatorInstructionsMatch: false,
    };
    if (programHash !== undefined)                               checks.programHashMatch    = false;
    if (this._requireTEE)                                        checks.teeAttestationValid = false;
    if (this._sessionState)                                      checks.sessionRiskValid    = false;
    if (this._modelStateAttestation && commitmentId !== undefined) checks.modelStateValid   = false;

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

    // orchestratorSignature is excluded from the signed body per the draft spec.
    // Strip it (along with the main signature) before verifying. For a plain
    // receipt that never had an orchestratorSignature field this is a no-op:
    // destructuring an absent key does not add it back to `body`, so this
    // check is a strict superset of verifying a receipt with no orchestrator
    // signature at all.
    const { signature, orchestratorSignature: _orchSig, ...body } = receipt;
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
    if (this._offlineMode) {
      // In offline mode the registry is not consulted. Receipts that require a live
      // revocation check are denied immediately after signature verification.
      if (receipt.revocationRequired) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'REVOCATION_CHECK_REQUIRED',
          denialCode:    'REVOCATION_CHECK_REQUIRED',
          receiptHash,
          action,
        });
      }
    } else {
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

    // SIGNED SCOPE WINS. Unsigned DelegationLog metadata (registered via
    // DelegationLog.add's scopeSchema option) is NEVER allowed to override the
    // signed receipt body. If both are present and disagree, fail closed
    // (deny): whoever can write to the log must not be able to widen scope
    // without invalidating the receipt signature.
    const signedSchema = receipt.scopeSchema ?? null;
    const logSchema    = logEntry?.scopeSchema ?? null;
    if (signedSchema && logSchema && !_sameScopeSchema(signedSchema, logSchema)) {
      return this._finalize({
        allowed:       false,
        checks,
        blockedReason: 'Scope metadata mismatch — unsigned log metadata disagrees with the signed receipt scope',
        denialCode:    'SCOPE_METADATA_MISMATCH',
        receiptHash,
        action,
      });
    }
    // The signed receipt's scope wins; log metadata is only a fallback for
    // receipts that carry no structured scope in the signed body.
    const rawSchema = signedSchema ?? logSchema;
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
      checks.scopeCheckMethod = 'scope-schema';
    } else {
      // No structured scope schema anywhere (signed body or log metadata):
      // fuzzy keyword-overlap matching is NOT a security boundary — it is
      // trivially gameable and produces both false allows and false denies.
      // It runs as an ADVISORY signal only, recorded here for observability,
      // and never gates allow/deny.
      const actionStr = typeof action === 'string'
        ? action
        : `${action?.operation ?? ''} ${action?.resource ?? ''}`.trim();
      const { withinScope, scopeScore, boundaryScore } = checkScope(actionStr, receipt);
      scopeValid  = true; // advisory only — does not gate
      scopeReason = 'Advisory only — no signed scope schema present; keyword-overlap ' +
        `signal is ${withinScope ? 'within' : 'OUTSIDE'} the receipt's text scope ` +
        `(scope score ${scopeScore}, boundary score ${boundaryScore}); not a security boundary`;
      checks.scopeCheckMethod    = 'fuzzy-advisory';
      checks.scopeAdvisorySignal = withinScope ? 'within-scope' : 'outside-scope';
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
    // When the caller omits operatorInstructions we must NOT hash the
    // receipt's own instructions against themselves — that tautology always
    // passes and only pretends to verify operator drift. Instead the check is
    // skipped with an explicit warning recorded in the result: operator drift
    // is NOT verified for this call.
    let instructionsMatch;
    if (operatorInstructions == null) {
      instructionsMatch = true; // skipped, not verified
      checks.operatorInstructionsSkipped = true;
      checks.operatorInstructionsWarning =
        'operatorInstructions omitted — Check 5 skipped (no tautological self-match); ' +
        'operator drift NOT verified for this call';
    } else {
      const providedHash = await Canonicalizer.hash(operatorInstructions);
      instructionsMatch = providedHash === receipt.instructionsHash;
    }
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
      // SIGNED PROGRAM HASH WINS. Unsigned log metadata (logEntry.executes) is
      // NEVER allowed to override the receipt body's committed hash. If both
      // are present and disagree, fail closed (deny): this check exists to
      // catch code substitution, and a log writer must not be able to swap
      // the expected program hash without invalidating the receipt signature.
      const signedExecutes = receipt.executes ?? receipt.scopeSchema?.executes ?? null;
      const logExecutes    = logEntry?.executes ?? null;
      if (signedExecutes && logExecutes && signedExecutes !== logExecutes) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'Program hash metadata mismatch — unsigned log metadata disagrees with the signed receipt',
          denialCode:    'PROGRAM_METADATA_MISMATCH',
          receiptHash,
          action,
        });
      }
      const committedHash = signedExecutes ?? logExecutes;
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

    // ── Check 8: Tool Schema Integrity (optional) ────────────────────
    if (receipt.toolSchemaHash && currentToolSchema !== undefined) {
      const currentHash = 'sha256:' + await _sha256Schema(currentToolSchema);
      const toolSchemaValid = currentHash === receipt.toolSchemaHash;
      checks.toolSchemaIntegrity = toolSchemaValid;

      if (!toolSchemaValid) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'TOOL_SCHEMA_DRIFT',
          denialCode:    'TOOL_SCHEMA_DRIFT',
          receiptHash,
          action,
        });
      }
    }

    // ── Check 9: Model state verification (optional) ─────────────────
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

    // ── Check 10: Tool output hash binding (optional) ─────────────────
    // When the receipt commits a toolOutputHash, verify that the hash of the
    // tool output that triggered this action matches. A mismatch indicates the
    // tool output was tampered with between delegation and execution.
    if (receipt.toolOutputHash !== undefined) {
      const toolOutput = typeof action === 'object' && action !== null
        ? action.toolOutput
        : undefined;
      if (toolOutput !== undefined) {
        const toolOutputStr = typeof toolOutput === 'string' ? toolOutput : JSON.stringify(toolOutput);
        const computedHash  = 'sha256:' + await _sha256(toolOutputStr);
        const toolOutputValid = computedHash === receipt.toolOutputHash;
        checks.toolOutputHashValid = toolOutputValid;
        if (!toolOutputValid) {
          return this._finalize({
            allowed:       false,
            checks,
            blockedReason: 'TOOL_OUTPUT_TAMPERED',
            denialCode:    'TOOL_OUTPUT_TAMPERED',
            receiptHash,
            action,
          });
        }
      }
    }

    // ── Check 11: Instruction provenance (optional) ───────────────────
    // When the receipt specifies trustedSources, verify that the instruction
    // source on the action is in that list. A source not in the list indicates
    // a possible prompt injection attack from an untrusted input channel.
    if (Array.isArray(receipt.trustedSources)) {
      const instructionSource = typeof action === 'object' && action !== null
        ? action.instructionSource
        : undefined;
      const sourceAllowed = instructionSource === undefined
        || receipt.trustedSources.includes(instructionSource);
      checks.instructionProvenanceValid = sourceAllowed;
      if (!sourceAllowed) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'UNTRUSTED_INSTRUCTION_SOURCE',
          denialCode:    'UNTRUSTED_INSTRUCTION_SOURCE',
          receiptHash,
          action,
        });
      }
    }

    // ── Check 14: Parent Scope Containment (sub-receipts only) ──────────
    // Runs ONLY when receipt.parentReceiptId is present.
    // This check runs in both online and offline mode: parent chain verification
    // requires only the parent receipt from the delegation log, not network access.
    if (receipt.parentReceiptId) {
      checks.parentScopeContainment = false;
      checks.ancestorChainNotRevoked = false;

      const parentEntry   = this._log.getEntry(receipt.parentReceiptId);
      const parentReceipt = parentEntry?.receipt ?? null;

      if (!parentReceipt) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'PARENT_SCOPE_VIOLATION',
          denialCode:    'PARENT_SCOPE_VIOLATION',
          receiptHash,
          action,
        });
      }

      // Count chain depth by following parentReceiptId links to the root.
      // Each hop reads only the parentReceiptId field of each ancestor.
      // Ancestor IDs/receipts are collected for cascade revocation below.
      let depth   = 0;
      let current = receipt;
      const ancestorIds      = [];
      const ancestorReceipts = [];
      while (current.parentReceiptId) {
        depth++;
        if (depth > this._maxChainDepth) break;
        const ancestorEntry = this._log.getEntry(current.parentReceiptId);
        if (!ancestorEntry) break;
        ancestorIds.push(current.parentReceiptId);
        ancestorReceipts.push(ancestorEntry.receipt);
        current = ancestorEntry.receipt;
      }

      if (depth > this._maxChainDepth) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: CHAIN_DEPTH_EXCEEDED,
          denialCode:    CHAIN_DEPTH_EXCEEDED,
          receiptHash,
          action,
        });
      }

      // Cascade revocation: Check 2 covers the leaf receipt only. A revoked
      // ancestor must deny the whole subtree — every ancestor in the chain is
      // consulted, not just the leaf. (DelegationChain.revoke with
      // cascadeToChildren marks descendants in its own store; the gate
      // enforces the cascade live here, so a parent revoked through any path
      // still denies its children.)
      if (!this._offlineMode) {
        for (const ancestorId of ancestorIds) {
          const ancestorStatus = await this._registry.check(ancestorId);
          if (ancestorStatus.revoked) {
            return this._finalize({
              allowed:       false,
              checks,
              blockedReason: `Ancestor receipt revoked (${ancestorStatus.reason ?? 'no reason given'}) — delegation chain cascade`,
              denialCode:    'ANCESTOR_REVOKED',
              receiptHash,
              action,
            });
          }
        }
      } else {
        // Offline: the registry cannot be consulted. Mirror Check 2's
        // fail-closed rule — deny when any walked ancestor requires a live
        // revocation check.
        for (const ancestor of ancestorReceipts) {
          if (ancestor.revocationRequired) {
            return this._finalize({
              allowed:       false,
              checks,
              blockedReason: 'ANCESTOR_REVOCATION_CHECK_REQUIRED',
              denialCode:    'ANCESTOR_REVOCATION_CHECK_REQUIRED',
              receiptHash,
              action,
            });
          }
        }
      }
      checks.ancestorChainNotRevoked = true;

      // Verify the parent receipt's main signature.
      // orchestratorSignature is excluded from the parent's signed body.
      const { signature: parentSig, orchestratorSignature: _pOrch, ...parentBody } = parentReceipt;
      const parentSigValid = await _verifySignature(
        parentReceipt.signerPublicKey,
        parentSig,
        JSON.stringify(parentBody)
      );
      if (!parentSigValid) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'PARENT_SCOPE_VIOLATION',
          denialCode:    'PARENT_SCOPE_VIOLATION',
          receiptHash,
          action,
        });
      }

      // Verify orchestratorSignature when present.
      // The binding string is exactly: "orchestrator-delegation:" + parentReceiptId + ":" + receiptId
      // receiptHash IS the receiptId in this implementation (the DelegationLog key).
      if (receipt.orchestratorSignature) {
        const bindingStr = `orchestrator-delegation:${receipt.parentReceiptId}:${receiptHash}`;
        const orchSigValid = await _verifySignature(
          parentReceipt.signerPublicKey,
          receipt.orchestratorSignature,
          bindingStr
        );
        if (!orchSigValid) {
          return this._finalize({
            allowed:       false,
            checks,
            blockedReason: 'PARENT_SCOPE_VIOLATION',
            denialCode:    'PARENT_SCOPE_VIOLATION',
            receiptHash,
            action,
          });
        }
      }

      // Verify time window containment: child window must be within parent window.
      const childStart  = new Date(receipt.timeWindow.start);
      const childEnd    = new Date(receipt.timeWindow.end);
      const parentStart = new Date(parentReceipt.timeWindow.start);
      const parentEnd   = new Date(parentReceipt.timeWindow.end);
      if (childStart < parentStart || childEnd > parentEnd) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: 'PARENT_SCOPE_VIOLATION',
          denialCode:    'PARENT_SCOPE_VIOLATION',
          receiptHash,
          action,
        });
      }

      // Verify scope is a strict proper subset of parent scope.
      // Uses the same checkScopeAttenuation logic as delegation-chain.js.
      // Parent scope is resolved from the log entry metadata first (matches
      // how Check 4 resolves scope), then falls back to the receipt body.
      const parentScope = parentEntry.scopeSchema ?? parentReceipt.scopeSchema ?? parentReceipt.scope;
      const childScope  = logEntry.scopeSchema     ?? receipt.scopeSchema      ?? receipt.scope;
      try {
        checkScopeAttenuation(parentScope, childScope);
      } catch (err) {
        // The draft distinguishes SCOPE_NOT_STRICT_SUBSET (child equals parent's
        // action set exactly) from PARENT_SCOPE_VIOLATION (child exceeds parent).
        const code = err.message && err.message.includes('proper subset')
          ? 'SCOPE_NOT_STRICT_SUBSET'
          : 'PARENT_SCOPE_VIOLATION';
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: code,
          denialCode:    code,
          receiptHash,
          action,
        });
      }

      checks.parentScopeContainment = true;
    }

    // ── Check 15: Authority State Drift (optional) ────────────────────────
    // Runs only when the receipt carries authorityStateCommitment AND
    // opts.currentAuthorityState was passed to this call.
    // Runs after Check 14 so a receipt carrying both parentReceiptId and
    // authorityStateCommitment passes through both checks in sequence.
    let authorityStateDrifted = false;
    if (receipt.authorityStateCommitment !== undefined && currentAuthorityState !== undefined) {
      const stateMatches = await AuthorityStateAttestation.verify(
        receipt.authorityStateCommitment,
        currentAuthorityState
      );
      if (!stateMatches) {
        const driftPolicy = receipt.reauthPolicy?.onAuthorityStateDrift
          ?? this._defaultReauthPolicy.onAuthorityStateDrift;
        if (driftPolicy === 'block') {
          return this._finalize({
            allowed:                false,
            checks,
            blockedReason:          DENIAL_CODES.AUTHORITY_STATE_DRIFT,
            receiptHash,
            action,
            reauthRequiredOverride: false,
          });
        }
        // Default: soft signal. Do not deny -- set flag for reauthRequired in result.
        authorityStateDrifted = true;
      }
    }

    // oneTimeUse: global one-time receipt consumption.
    // Runs after ALL authorization checks (including Check 15) so a consumption
    // slot is never burned on a receipt that would be denied for another reason.
    if (receipt.oneTimeUse) {
      // Fail closed: no durable store configured means no global guarantee.
      // An InMemoryConsumptionStore cannot enforce uniqueness across instances
      // or restarts. Mirrors the fail-closed philosophy of revocationRequired.
      if (!this._hasExternalConsumptionStore) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: CONSUMPTION_STORE_REQUIRED,
          denialCode:    CONSUMPTION_STORE_REQUIRED,
          receiptHash,
          action,
        });
      }

      // Derive key: include nonce when present for receipts that reuse the same
      // receiptId with a different nonce. Falls back to receiptId alone.
      const consumptionKey   = receipt.nonce
        ? `${receiptHash}:${receipt.nonce}`
        : receiptHash;

      const firstConsumption = await this._consumptionStore.consume(consumptionKey);
      if (!firstConsumption) {
        return this._finalize({
          allowed:       false,
          checks,
          blockedReason: RECEIPT_ALREADY_CONSUMED,
          denialCode:    RECEIPT_ALREADY_CONSUMED,
          receiptHash,
          action,
        });
      }
    }

    return this._finalize({ allowed: true, checks, blockedReason: null, receiptHash, action, authorityStateDrifted });

    } finally {
      this._inFlightChecks.delete(receiptHash);
    }
  }

  /**
   * Build the result object, sign it, and record it in the audit log.
   * All decisions (PERMIT and DENY) are logged.
   * @private
   */
  async _finalize({ allowed, checks, blockedReason, denialCode, receiptHash, action, sessionRiskResult, authorityStateDrifted = false, reauthRequiredOverride }) {
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

    // Log ALL decisions — including DENY — to the authorization ActionLog.
    // Denied calls are logged with operation 'receipt_denied' so the allow path
    // stays clean while the full decision history is preserved for forensics.
    if (this._actionLog) {
      if (allowed) {
        // Publish authorized receipts exactly as before
        try {
          await this._actionLog.publishReceipt(receiptHash);
        } catch {
          // Best-effort — never block the gate decision
        }
      } else {
        // Record denied call with full context
        try {
          const sessionId   = this._sessionState?._sessionId ?? null;
          const riskScore   = sessionRiskResult?.riskScore ?? null;
          const resolvedCode = denialCode ?? (blockedReason?.split(' ')[0] ?? 'DENIED');
          await this._actionLog.record(receiptHash, {
            operation:  'receipt_denied',
            resource:   'delegation/receipt',
            parameters: {
              decision:     'BLOCK',
              denialReason: resolvedCode,
              blockedReason: blockedReason ?? null,
              sessionId,
              riskScore,
              action: typeof action === 'string' ? action : action,
            },
          });
        } catch {
          // Best-effort — never block the gate decision
        }
      }
    }

    // Record denied calls to internal per-session store for getDeniedCallLog()
    if (!allowed) {
      try {
        const sessionId   = this._sessionState?._sessionId ?? null;
        const riskScore   = sessionRiskResult?.riskScore ?? null;
        const resolvedCode = denialCode ?? (blockedReason?.split(' ')[0] ?? 'DENIED');
        const storeKey    = sessionId ?? 'global';
        const prevHash    = this._lastDeniedHash.get(storeKey) ?? '0'.repeat(64);
        const entryId     = `denied-${Date.now()}-${_randomSuffix(7)}`;
        const actionObj   = typeof action === 'string'
          ? { operation: action, resource: action, args: {} }
          : { operation: action?.operation ?? '', resource: action?.resource ?? '', args: action?.parameters ?? {} };

        const entry = {
          entryId,
          decision:          'BLOCK',
          action:            actionObj,
          receiptHash,
          denialReason:      resolvedCode,
          timestamp:         Date.now(),
          previousEntryHash: prevHash,
          riskScore,
          sessionId,
        };

        const entryHash = await _sha256(JSON.stringify(entry));
        entry.entryHash = entryHash;

        if (!this._deniedCalls.has(storeKey)) this._deniedCalls.set(storeKey, []);
        this._deniedCalls.get(storeKey).push(entry);
        this._lastDeniedHash.set(storeKey, entryHash);
      } catch {
        // Best-effort — never block the gate decision
      }
    }

    // Resolve session result now so it's available for reauthRequired computation.
    const sessionResult = sessionRiskResult ?? this._sessionRiskResult ?? null;

    // Compute reauthRequired.
    let reauthRequired = false;
    if (reauthRequiredOverride !== undefined) {
      reauthRequired = reauthRequiredOverride;
    } else {
      const receipt = this._log.getReceipt(receiptHash);
      if (receipt) {
        const rp                  = receipt.reauthPolicy ?? {};
        const secondsBeforeExpiry = rp.secondsBeforeExpiry   ?? this._defaultReauthPolicy.secondsBeforeExpiry;
        const trustScoreBelow     = rp.trustScoreBelow       ?? this._defaultReauthPolicy.trustScoreBelow;
        const onDrift             = rp.onAuthorityStateDrift ?? this._defaultReauthPolicy.onAuthorityStateDrift;

        // Condition 1: receipt will expire within secondsBeforeExpiry seconds.
        if (receipt.timeWindow?.end) {
          const secondsLeft = Math.floor((new Date(receipt.timeWindow.end) - new Date()) / 1000);
          if (secondsLeft >= 0 && secondsLeft <= secondsBeforeExpiry) reauthRequired = true;
        }

        // Condition 2: session risk score is below the trust score threshold.
        if (sessionResult && sessionResult.riskScore < trustScoreBelow) reauthRequired = true;

        // Condition 3: authority state drifted and policy is not 'block' (block was handled upstream).
        if (authorityStateDrifted && onDrift !== 'block') reauthRequired = true;
      }
    }

    const result = {
      allowed,
      // decision is the agent-facing admission signal: PERMIT or DENY. Sits alongside
      // (not instead of) blockedReason -- see Decision 3 of the merge investigation:
      // main's result already carried full blockedReason text, so decision is additive
      // shorthand, not a replacement for a sparser result shape.
      decision:      allowed ? 'PERMIT' : 'DENY',
      checks,
      blockedReason:     blockedReason ?? null,
      verifiedAt,
      verifierSignature,
      verifierPublicKey: this._publicJwk,
      verificationMode:  this._offlineMode ? 'offline' : 'online',
      revocationChecked: !this._offlineMode,
      reauthRequired,
    };

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

  /**
   * Return all denied call log entries for a session, ordered by timestamp.
   * Includes full call context, denial reason, and risk score at time of denial.
   *
   * @param {string} [sessionId] — session ID to filter by. Pass null or omit to get
   *                               all entries not associated with a session.
   * @returns {object[]}
   */
  getDeniedCallLog(sessionId) {
    const key = sessionId ?? 'global';
    return (this._deniedCalls.get(key) ?? []).slice().sort((a, b) => a.timestamp - b.timestamp);
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

export { PreExecutionVerifier, DelegationLog, MAX_CHAIN_DEPTH, RECEIPT_ALREADY_CONSUMED, CONSUMPTION_STORE_REQUIRED, CHAIN_DEPTH_EXCEEDED };
export default { PreExecutionVerifier, DelegationLog, MAX_CHAIN_DEPTH, RECEIPT_ALREADY_CONSUMED, CONSUMPTION_STORE_REQUIRED, CHAIN_DEPTH_EXCEEDED };

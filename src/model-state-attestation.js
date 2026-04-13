/**
 * ModelStateAttestation — cryptographic binding between a delegation receipt
 * and the exact model state that was authorized to act on it.
 *
 * Closes the model-substitution gap in the delegation chain: a Delegation Receipt
 * proves a human authorized an agent to act, but does not prove the model executing
 * the receipt is the same model the user authorized. An operator could swap a
 * fine-tuned or modified model after receipt signing and the receipt would remain
 * valid. ModelStateAttestation binds the delegation to a cryptographic measurement
 * of the model state at both issuance time and execution time. If anything changes,
 * the attestation fails and execution is blocked.
 *
 * Model measurement (SHA-256 of five canonical components in order):
 *   1. Canonicalizer.normalize(modelId)
 *   2. Canonicalizer.normalize(modelVersion)
 *   3. systemPromptHash
 *   4. runtimeConfigHash
 *   5. receiptHash  ← binds measurement to the specific delegation
 *
 * @module model-state-attestation
 */

'use strict';

import { Canonicalizer } from './authproof.js';

// ─────────────────────────────────────────────
// PRIVATE CRYPTO HELPERS
// ─────────────────────────────────────────────

const _enc     = s => new TextEncoder().encode(s);
const _hex     = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
const _fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));

async function _sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', _enc(str));
  return _hex(buf);
}

async function _sign(privateKey, str) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, _enc(str));
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

// ─────────────────────────────────────────────
// MODEL STATE ATTESTATION
// ─────────────────────────────────────────────

/**
 * ModelStateAttestation — commit to a model state at delegation time, verify
 * it matches at execution time.
 *
 * @example
 * const attestation = new ModelStateAttestation({ teeRuntime, actionLog });
 *
 * // At delegation time
 * const commitment = await attestation.commit({
 *   receiptHash, modelId, modelVersion,
 *   systemPromptHash, runtimeConfigHash,
 *   privateKey, publicJwk,
 * });
 *
 * // At execution time
 * const result = await attestation.verify({
 *   commitmentId: commitment.commitmentId,
 *   currentModelId, currentModelVersion,
 *   currentSystemPromptHash, currentRuntimeConfigHash,
 * });
 * if (!result.valid) throw new Error('ModelDriftDetected');
 *
 * // Full audit chain
 * const chainProof = await attestation.generateChainProof({
 *   receiptHash, commitmentId, actionLogEntryId,
 * });
 */
class ModelStateAttestation {
  /**
   * @param {object} opts
   * @param {object} opts.teeRuntime — TEERuntime instance (provides attest())
   * @param {object} opts.actionLog  — ActionLog instance (for audit trail)
   */
  constructor({ teeRuntime, actionLog } = {}) {
    if (!teeRuntime) throw new Error('ModelStateAttestation: teeRuntime is required');
    if (!actionLog)  throw new Error('ModelStateAttestation: actionLog is required');

    this._teeRuntime   = teeRuntime;
    this._actionLog    = actionLog;
    /** @private {Map<string, object>} commitmentId → sealed commitment */
    this._commitments  = new Map();
  }

  // ─────────────────────────────────────────────
  // MEASUREMENT
  // ─────────────────────────────────────────────

  /**
   * Compute the model measurement: SHA-256 of five canonical components concatenated.
   *
   * Components (in this exact order):
   *   1. Canonicalizer.normalize(modelId)
   *   2. Canonicalizer.normalize(modelVersion)
   *   3. systemPromptHash
   *   4. runtimeConfigHash
   *   5. receiptHash
   *
   * The same model with a different system prompt produces a different measurement.
   * The same model on a different receipt produces a different measurement.
   * Every combination is unique and verifiable.
   *
   * @param {{ modelId, modelVersion, systemPromptHash, runtimeConfigHash, receiptHash }} components
   * @returns {Promise<string>} 64-char hex SHA-256 measurement
   */
  static async computeMeasurement({ modelId, modelVersion, systemPromptHash, runtimeConfigHash, receiptHash }) {
    const canonical = [
      Canonicalizer.normalize(modelId),
      Canonicalizer.normalize(modelVersion),
      systemPromptHash,
      runtimeConfigHash,
      receiptHash,
    ].join('');
    return _sha256(canonical);
  }

  // ─────────────────────────────────────────────
  // COMMIT
  // ─────────────────────────────────────────────

  /**
   * Capture and commit model state at delegation time.
   *
   * Computes the model measurement, signs the commitment with the operator's
   * private key, and obtains a TEE attestation of the measurement. The resulting
   * commitment is stored internally and returned.
   *
   * @param {object}    opts
   * @param {string}    opts.receiptHash        — Delegation receipt this commitment is bound to
   * @param {string}    opts.modelId            — Model identifier (e.g. 'claude-sonnet-4-5')
   * @param {string}    opts.modelVersion       — Version string
   * @param {string}    opts.systemPromptHash   — SHA-256 of the system prompt
   * @param {string}    opts.runtimeConfigHash  — SHA-256 of runtime configuration
   * @param {CryptoKey} opts.privateKey         — Operator signing key
   * @param {object}    opts.publicJwk          — Operator public key
   *
   * @returns {Promise<{
   *   commitmentId,
   *   receiptHash,
   *   modelMeasurement,
   *   modelId,
   *   modelVersion,
   *   systemPromptHash,
   *   runtimeConfigHash,
   *   committedAt,
   *   signature,
   *   signerPublicKey,
   *   teeAttestation
   * }>}
   */
  async commit({
    receiptHash,
    modelId,
    modelVersion,
    systemPromptHash,
    runtimeConfigHash,
    privateKey,
    publicJwk,
  } = {}) {
    if (!receiptHash)       throw new Error('ModelStateAttestation.commit: receiptHash is required');
    if (!modelId)           throw new Error('ModelStateAttestation.commit: modelId is required');
    if (!modelVersion)      throw new Error('ModelStateAttestation.commit: modelVersion is required');
    if (!systemPromptHash)  throw new Error('ModelStateAttestation.commit: systemPromptHash is required');
    if (!runtimeConfigHash) throw new Error('ModelStateAttestation.commit: runtimeConfigHash is required');
    if (!privateKey)        throw new Error('ModelStateAttestation.commit: privateKey is required');
    if (!publicJwk)         throw new Error('ModelStateAttestation.commit: publicJwk is required');

    const commitmentId = `msc-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    // Compute the model measurement
    const modelMeasurement = await ModelStateAttestation.computeMeasurement({
      modelId, modelVersion, systemPromptHash, runtimeConfigHash, receiptHash,
    });

    const committedAt = new Date().toISOString();

    // Build and sign the commitment body
    const body = {
      commitmentId,
      receiptHash,
      modelMeasurement,
      modelId,
      modelVersion,
      systemPromptHash,
      runtimeConfigHash,
      committedAt,
    };

    const signature = await _sign(privateKey, JSON.stringify(body));

    // Obtain TEE attestation of the model measurement
    const teeAttestation = await this._teeRuntime.attest(modelMeasurement);

    const commitment = {
      ...body,
      signature,
      signerPublicKey: publicJwk,
      teeAttestation,
    };

    this._commitments.set(commitmentId, commitment);
    return commitment;
  }

  // ─────────────────────────────────────────────
  // VERIFY
  // ─────────────────────────────────────────────

  /**
   * Verify that the model currently running matches the committed model state.
   *
   * Computes the measurement of the current state and compares it component-by-component
   * against the committed values. Any difference is reported in modelDrift[].
   * Obtains a TEE attestation of the verification result.
   *
   * @param {object} opts
   * @param {string} opts.commitmentId              — ID of the commitment to verify against
   * @param {string} opts.currentModelId
   * @param {string} opts.currentModelVersion
   * @param {string} opts.currentSystemPromptHash
   * @param {string} opts.currentRuntimeConfigHash
   *
   * @returns {Promise<{
   *   valid: boolean,
   *   commitmentMatches: boolean,
   *   modelDrift: string[],
   *   verifiedAt: string,
   *   teeAttestation: object
   * }>}
   */
  async verify({
    commitmentId,
    currentModelId,
    currentModelVersion,
    currentSystemPromptHash,
    currentRuntimeConfigHash,
  } = {}) {
    if (!commitmentId) throw new Error('ModelStateAttestation.verify: commitmentId is required');

    const commitment = this._commitments.get(commitmentId);
    if (!commitment) {
      return {
        valid:             false,
        commitmentMatches: false,
        modelDrift:        [`commitment not found: ${commitmentId}`],
        verifiedAt:        new Date().toISOString(),
        teeAttestation:    null,
      };
    }

    // Detect per-component drift
    const modelDrift = [];

    if (Canonicalizer.normalize(currentModelId) !== Canonicalizer.normalize(commitment.modelId)) {
      modelDrift.push(
        `modelId changed: ${commitment.modelId} → ${currentModelId}`
      );
    }
    if (Canonicalizer.normalize(currentModelVersion) !== Canonicalizer.normalize(commitment.modelVersion)) {
      modelDrift.push(
        `modelVersion changed: ${commitment.modelVersion} → ${currentModelVersion}`
      );
    }
    if (currentSystemPromptHash !== commitment.systemPromptHash) {
      modelDrift.push(
        `systemPromptHash changed: ${commitment.systemPromptHash.slice(0, 8)}... → ${currentSystemPromptHash.slice(0, 8)}...`
      );
    }
    if (currentRuntimeConfigHash !== commitment.runtimeConfigHash) {
      modelDrift.push(
        `runtimeConfigHash changed: ${commitment.runtimeConfigHash.slice(0, 8)}... → ${currentRuntimeConfigHash.slice(0, 8)}...`
      );
    }

    // Recompute measurement of current state
    const currentMeasurement = await ModelStateAttestation.computeMeasurement({
      modelId:           currentModelId,
      modelVersion:      currentModelVersion,
      systemPromptHash:  currentSystemPromptHash,
      runtimeConfigHash: currentRuntimeConfigHash,
      receiptHash:       commitment.receiptHash,
    });

    const commitmentMatches = currentMeasurement === commitment.modelMeasurement;
    const valid = commitmentMatches && modelDrift.length === 0;
    const verifiedAt = new Date().toISOString();

    // Obtain TEE attestation of the verification result
    const verificationHash = await _sha256(JSON.stringify({
      commitmentId,
      currentMeasurement,
      commitmentMatches,
      verifiedAt,
    }));
    const teeAttestation = await this._teeRuntime.attest(verificationHash);

    return {
      valid,
      commitmentMatches,
      modelDrift,
      verifiedAt,
      teeAttestation,
    };
  }

  // ─────────────────────────────────────────────
  // CHAIN PROOF
  // ─────────────────────────────────────────────

  /**
   * Generate a complete verifiable chain proof linking all four layers:
   *
   *   Delegation Receipt
   *     └─► Model State Commitment
   *           └─► Execution Attestation
   *                 └─► Action Log Entry
   *
   * @param {object} opts
   * @param {string} opts.receiptHash       — Delegation receipt hash
   * @param {string} opts.commitmentId      — Model state commitment ID
   * @param {string} opts.actionLogEntryId  — Action log entry ID
   *
   * @returns {Promise<{
   *   chainProofId,
   *   chain: {
   *     delegationReceipt:    { receiptHash, boundAt },
   *     modelStateCommitment: { commitmentId, modelMeasurement, modelId, modelVersion, committedAt, signature, teeAttestation },
   *     executionAttestation: { teeAttestation },
   *     actionLogEntry:       { actionLogEntryId, receiptHash }
   *   },
   *   chainHash,
   *   generatedAt
   * }>}
   */
  async generateChainProof({ receiptHash, commitmentId, actionLogEntryId } = {}) {
    if (!receiptHash)      throw new Error('ModelStateAttestation.generateChainProof: receiptHash is required');
    if (!commitmentId)     throw new Error('ModelStateAttestation.generateChainProof: commitmentId is required');
    if (!actionLogEntryId) throw new Error('ModelStateAttestation.generateChainProof: actionLogEntryId is required');

    const commitment = this._commitments.get(commitmentId);
    if (!commitment) {
      throw new Error(
        `ModelStateAttestation.generateChainProof: commitment not found: ${commitmentId}`
      );
    }

    const chainProofId = `cp-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const generatedAt  = new Date().toISOString();

    // Compute a binding hash that anchors all four layers
    const chainHash = await _sha256(JSON.stringify({
      receiptHash,
      commitmentId,
      modelMeasurement: commitment.modelMeasurement,
      actionLogEntryId,
    }));

    return {
      chainProofId,
      chain: {
        delegationReceipt: {
          receiptHash,
          boundAt: commitment.committedAt,
        },
        modelStateCommitment: {
          commitmentId,
          modelMeasurement: commitment.modelMeasurement,
          modelId:          commitment.modelId,
          modelVersion:     commitment.modelVersion,
          committedAt:      commitment.committedAt,
          signature:        commitment.signature,
          teeAttestation:   commitment.teeAttestation,
        },
        executionAttestation: {
          // The TEE attestation produced at commitment time proves the measurement
          // was captured inside a trusted execution environment.
          teeAttestation: commitment.teeAttestation,
        },
        actionLogEntry: {
          actionLogEntryId,
          receiptHash,
        },
      },
      chainHash,
      generatedAt,
    };
  }

  // ─────────────────────────────────────────────
  // ACCESSORS
  // ─────────────────────────────────────────────

  /**
   * Retrieve a stored commitment by ID.
   * @param {string} commitmentId
   * @returns {object|null}
   */
  getCommitment(commitmentId) {
    return this._commitments.get(commitmentId) ?? null;
  }

  /**
   * Verify the cryptographic integrity of a commitment object.
   * Checks that the signature over the body fields is valid.
   *
   * @param {object} commitment — From commit() or external source
   * @returns {Promise<{ valid: boolean, reason: string }>}
   */
  static async verifyCommitmentIntegrity(commitment) {
    if (!commitment || typeof commitment !== 'object') {
      return { valid: false, reason: 'commitment is null or not an object' };
    }
    const {
      commitmentId, receiptHash, modelMeasurement, modelId, modelVersion,
      systemPromptHash, runtimeConfigHash, committedAt,
      signature, signerPublicKey,
    } = commitment;

    if (!signature)       return { valid: false, reason: 'commitment missing signature' };
    if (!signerPublicKey) return { valid: false, reason: 'commitment missing signerPublicKey' };

    const body = {
      commitmentId, receiptHash, modelMeasurement, modelId, modelVersion,
      systemPromptHash, runtimeConfigHash, committedAt,
    };

    const sigOk = await _verify(signerPublicKey, signature, JSON.stringify(body));
    return sigOk
      ? { valid: true,  reason: 'Commitment ECDSA P-256 signature verified' }
      : { valid: false, reason: 'Commitment signature verification failed — commitment may be tampered' };
  }
}

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

export { ModelStateAttestation };
export default ModelStateAttestation;

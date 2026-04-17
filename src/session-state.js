/**
 * SessionState — adaptive trust and risk scoring for long-running agent sessions.
 *
 * Answers "Is this safe right now?" — a question that static delegation receipts
 * cannot answer. Tracks trust decay, anomaly history, and per-session risk patterns
 * to produce ALLOW / REQUIRE_APPROVAL / BLOCK decisions with full audit trail.
 *
 * The mental model: Stripe Radar for AI agent actions. Each action is scored
 * against five deterministic checks. The session accumulates trust (or loses it)
 * as actions succeed or trigger anomalies. Suspended sessions block everything.
 *
 * @example
 * const session = new SessionState({ receiptHash, policy: { blockThreshold: 85 } });
 * const decision = await session.evaluate({ action, payload });
 * await session.record(action, decision);
 * const state = session.getState();
 */

'use strict';

import { RiskScorer }             from './risk-scorer.js';
import { SensitivityClassifier }  from './sensitivity-classifier.js';

// ─── Anomaly severity levels ──────────────────────────────────────────────────

const ANOMALY_SEVERITY = {
  'prompt-injection':        5,
  'sensitive-data-external': 4,
  'frequency-spike':         3,
  'scope-edge':              2,
  'first-time-action':       1,
};

// ─── Default policy ───────────────────────────────────────────────────────────

const DEFAULT_POLICY = {
  allowThreshold:           30,
  requireApprovalThreshold: 70,
  blockThreshold:           85,
  trustDecayRate:           0.05,
  trustRecoveryRate:        0.01,
};

// ─────────────────────────────────────────────────────────────────────────────

class SessionState {
  /**
   * @param {object} opts
   * @param {string}  opts.receiptHash          — hash of the delegation receipt backing this session
   * @param {object}  [opts.actionLog]          — optional ActionLog instance for audit recording
   * @param {object}  [opts.revocationRegistry] — optional RevocationRegistry
   * @param {object}  [opts.policy]             — threshold and decay policy overrides
   * @param {number}  [opts.policy.allowThreshold=30]
   * @param {number}  [opts.policy.requireApprovalThreshold=70]
   * @param {number}  [opts.policy.blockThreshold=85]
   * @param {number}  [opts.policy.trustDecayRate=0.05]
   * @param {number}  [opts.policy.trustRecoveryRate=0.01]
   */
  constructor({
    receiptHash,
    actionLog,
    revocationRegistry,
    policy = {},
  } = {}) {
    if (!receiptHash) throw new Error('SessionState: receiptHash is required');

    this._receiptHash        = receiptHash;
    this._actionLog          = actionLog          ?? null;
    this._revocationRegistry = revocationRegistry ?? null;

    this._policy = { ...DEFAULT_POLICY, ...policy };

    // Session identity
    this._sessionId    = `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    this._startedAt    = new Date().toISOString();
    this._lastActionAt = null;

    // Trust state — starts at 100, bounded [0, 100]
    this.trustScore    = 100;
    this._riskScore    = 0;

    // Activity counters
    this._actionCount   = 0;
    this._anomalyCount  = 0;
    this._anomalies     = [];

    // Sensitivity level of the most recent payload
    this._sensitivityLevel = 'PUBLIC';

    // Internal state consumed by RiskScorer (accessed directly via sessionState ref)
    this._actionHistory   = [];  // [{ actionType: string, timestamp: number }]
    this._usedPermissions = new Set();
    this._seenDomains     = new Set();

    this._scorer     = new RiskScorer();
    this._classifier = new SensitivityClassifier();
  }

  // ─── Status ────────────────────────────────────────────────────────────────

  /**
   * Compute the session status from the current trust score.
   * @returns {'ACTIVE'|'DEGRADED'|'SUSPENDED'}
   */
  get _status() {
    if (this.trustScore < 10) return 'SUSPENDED';
    if (this.trustScore < 30) return 'DEGRADED';
    return 'ACTIVE';
  }

  // ─── Core API ──────────────────────────────────────────────────────────────

  /**
   * Evaluate whether an action should be allowed.
   *
   * @param {object} opts
   * @param {string|object} opts.action                — action the agent wants to take
   * @param {string}        [opts.operatorInstructions] — current operator instructions
   * @param {*}             [opts.payload]             — payload to scan for sensitive data
   *
   * @returns {Promise<{
   *   decision:    'ALLOW'|'REQUIRE_APPROVAL'|'BLOCK',
   *   trustScore:  number,
   *   riskScore:   number,
   *   reasons:     string[],
   *   sessionId:   string,
   *   actionCount: number,
   *   anomalies:   object[],
   * }>}
   */
  async evaluate({ action, operatorInstructions, payload } = {}) {
    // SUSPENDED — block all actions immediately
    if (this._status === 'SUSPENDED') {
      return {
        decision:    'BLOCK',
        trustScore:  this.trustScore,
        riskScore:   100,
        reasons:     ['Session is SUSPENDED — trust score below 10, all actions blocked'],
        sessionId:   this._sessionId,
        actionCount: this._actionCount,
        anomalies:   [...this._anomalies],
      };
    }

    // Classify payload sensitivity
    const sensitivityLevel = await this._classifier.classify(payload ?? '');
    this._sensitivityLevel = sensitivityLevel;

    // Compute effective thresholds (adjusted by sensitivity level)
    const thresholds = this._effectiveThresholds(sensitivityLevel);

    // Run the five risk checks
    const result = await this._scorer.score({
      action,
      payload,
      sessionState: this,
      receiptScope: null,
    });

    const riskScore = result.score;
    this._riskScore = riskScore;

    // Collect human-readable reasons from check findings
    const reasons = [];
    for (const check of result.checks) {
      if (check.findings?.length > 0) {
        reasons.push(...check.findings.map(f => `[check-${check.check}] ${f}`));
      }
    }

    // Detect anomaly types from findings
    const anomalies = this._extractAnomalies(result.checks);

    // Decision engine
    let decision;
    if (riskScore >= thresholds.blockThreshold) {
      decision = 'BLOCK';
    } else if (riskScore >= thresholds.requireApprovalThreshold) {
      decision = 'REQUIRE_APPROVAL';
    } else {
      decision = 'ALLOW';
    }

    return {
      decision,
      trustScore:  this.trustScore,
      riskScore:   Math.round(riskScore),
      reasons,
      sessionId:   this._sessionId,
      actionCount: this._actionCount,
      anomalies,
    };
  }

  /**
   * Record an action and its result, updating trust score and session history.
   *
   * @param {string|object} action   — action that was executed
   * @param {object}        [result] — result from evaluate() (used to extract anomalies)
   */
  async record(action, result) {
    const actionType = typeof action === 'string'
      ? action
      : `${action?.operation ?? ''}:${action?.resource ?? ''}`;

    const now = Date.now();

    // Append to history for frequency analysis
    this._actionHistory.push({ actionType, timestamp: now });

    // Mark permission as used
    this._usedPermissions.add(actionType);

    // Track any external domains mentioned in the result
    if (result) {
      const resultText = typeof result === 'string' ? result : JSON.stringify(result);
      const domainMatches = resultText.match(/https?:\/\/(?!localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)[\w.-]+\.[a-z]{2,}/gi) ?? [];
      for (const url of domainMatches) {
        this._seenDomains.add(url);
      }
    }

    this._actionCount++;
    this._lastActionAt = new Date(now).toISOString();

    // Extract anomalies from the evaluation result
    const anomalies = Array.isArray(result?.anomalies) ? result.anomalies : [];

    if (anomalies.length > 0) {
      for (const anomaly of anomalies) {
        this._anomalyCount++;
        this._anomalies.push({ ...anomaly, recordedAt: new Date(now).toISOString() });
        // Trust decay: each anomaly erodes trust by severity × decayRate
        const decay = anomaly.severity * this._policy.trustDecayRate;
        this.trustScore = Math.max(0, this.trustScore - decay);
      }
    } else {
      // Clean action — slowly recover trust
      this.trustScore = Math.min(100, this.trustScore + this._policy.trustRecoveryRate);
    }
  }

  /**
   * Return a snapshot of the current session state.
   *
   * @returns {{
   *   sessionId:        string,
   *   receiptHash:      string,
   *   trustScore:       number,
   *   riskScore:        number,
   *   actionCount:      number,
   *   anomalyCount:     number,
   *   sensitivityLevel: string,
   *   startedAt:        string,
   *   lastActionAt:     string|null,
   *   status:           'ACTIVE'|'DEGRADED'|'SUSPENDED',
   * }}
   */
  getState() {
    return {
      sessionId:        this._sessionId,
      receiptHash:      this._receiptHash,
      trustScore:       this.trustScore,
      riskScore:        this._riskScore,
      actionCount:      this._actionCount,
      anomalyCount:     this._anomalyCount,
      sensitivityLevel: this._sensitivityLevel,
      startedAt:        this._startedAt,
      lastActionAt:     this._lastActionAt,
      status:           this._status,
    };
  }

  /**
   * Reauthorize the session after a REQUIRE_APPROVAL decision.
   * Resets trust score and clears accumulated anomalies.
   *
   * @param {{ userApproval: boolean, receiptHash?: string }} opts
   *   userApproval — must be true; the caller is confirming the user explicitly approved
   *   receiptHash  — optional new receipt hash to switch to
   */
  async reauthorize({ userApproval = false, receiptHash } = {}) {
    if (!userApproval) {
      throw new Error('SessionState.reauthorize: userApproval must be true');
    }

    if (receiptHash) {
      this._receiptHash = receiptHash;
    }

    // Full trust reset on explicit reauthorization
    this.trustScore    = 100;
    this._anomalies    = [];
    this._anomalyCount = 0;
  }

  // ─── Private helpers ───────────────────────────────────────────────────────

  /**
   * Extract structured anomaly objects from scoring check findings.
   * @private
   */
  _extractAnomalies(checks) {
    const anomalies = [];

    for (const check of checks) {
      if (!Array.isArray(check.findings)) continue;
      for (const finding of check.findings) {
        const f = String(finding).toLowerCase();
        if (f.includes('prompt-injection')) {
          anomalies.push({ type: 'prompt-injection', severity: ANOMALY_SEVERITY['prompt-injection'] });
        } else if (f.includes('external-domain-with-sensitive-data')) {
          anomalies.push({ type: 'sensitive-data-external', severity: ANOMALY_SEVERITY['sensitive-data-external'] });
        } else if (f.startsWith('frequency-spike')) {
          anomalies.push({ type: 'frequency-spike', severity: ANOMALY_SEVERITY['frequency-spike'] });
        } else if (f === 'scope-boundary' || f === 'new-permission') {
          anomalies.push({ type: 'scope-edge', severity: ANOMALY_SEVERITY['scope-edge'] });
        } else if (f === 'first-time-external-domain') {
          anomalies.push({ type: 'first-time-action', severity: ANOMALY_SEVERITY['first-time-action'] });
        }
      }
    }

    return anomalies;
  }

  /**
   * Compute effective thresholds adjusted for the payload sensitivity level.
   * @private
   */
  _effectiveThresholds(sensitivityLevel) {
    let { allowThreshold, requireApprovalThreshold, blockThreshold } = this._policy;

    switch (sensitivityLevel) {
      case 'RESTRICTED':
        // Very sensitive data — block threshold drops to at most 60
        blockThreshold = Math.min(blockThreshold, 60);
        break;
      case 'CONFIDENTIAL':
        // Sensitive data — approval threshold drops to at most 40
        requireApprovalThreshold = Math.min(requireApprovalThreshold, 40);
        break;
      case 'INTERNAL':
        // No change
        break;
      case 'PUBLIC':
        // Relaxed thresholds for public data
        allowThreshold           += 10;
        requireApprovalThreshold += 10;
        blockThreshold           += 10;
        break;
    }

    return { allowThreshold, requireApprovalThreshold, blockThreshold };
  }
}

export { SessionState };

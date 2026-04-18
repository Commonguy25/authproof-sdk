'use strict';

/**
 * ApprovalOutcomeLogger — records human approval outcomes and computes
 * noise-vs-signal metrics per rule, enabling data-driven threshold recalibration.
 *
 * Entirely in-memory — no SQLite or network dependencies.
 *
 * Key metrics:
 *   noiseScore  = (approvalRate * 0.6) + (lowTimeToDecision * 0.4)
 *                 where lowTimeToDecision = % of decisions made in under 3 seconds
 *   signalScore = (denialRate * 0.5) + (subsequentAnomalyRate * 0.5)
 *
 * Recommendation priority: CRITICAL > LIKELY_NOISE > WORKING > NEEDS_DATA
 *
 * Fatigue formula:
 *   fatigueScore = (approvalsInWindow / 20 * 40) + (speedScore * 60)
 *   where speedScore = fraction of decisions under 2 seconds in the window
 */
class ApprovalOutcomeLogger {
  /**
   * @param {object} opts
   * @param {object} [opts.actionLog]    — ActionLog instance (optional, for future integration)
   * @param {object} [opts.sessionState] — SessionState instance (optional)
   * @param {object} [opts.storage]      — In-memory backing store (optional, no SQLite)
   */
  constructor({ actionLog, sessionState, storage = null } = {}) {
    this._actionLog   = actionLog    ?? null;
    this._sessionState = sessionState ?? null;
    this._events      = [];

    // Attach to storage object if provided so callers can inspect raw events
    if (storage && typeof storage === 'object') {
      storage.events = this._events;
    }
  }

  /**
   * Record a single approval decision outcome.
   *
   * @param {object} opts
   * @param {string}  opts.eventId
   * @param {string}  opts.sessionId
   * @param {string}  opts.receiptHash
   * @param {string}  opts.ruleTriggered
   * @param {number}  opts.riskScore
   * @param {string}  opts.decision           — 'REQUIRE_APPROVAL'
   * @param {string}  opts.outcome            — 'APPROVED'|'DENIED'|'TIMEOUT'
   * @param {number}  opts.timeToDecisionMs
   * @param {string}  opts.operatorId
   * @param {boolean} [opts.subsequentAnomaly=false]
   * @returns {Promise<object>} The stored record
   */
  async recordOutcome({
    eventId,
    sessionId,
    receiptHash,
    ruleTriggered,
    riskScore,
    decision,
    outcome,
    timeToDecisionMs,
    operatorId,
    subsequentAnomaly = false,
  }) {
    const record = {
      eventId,
      sessionId,
      receiptHash,
      ruleTriggered,
      riskScore,
      decision,
      outcome,
      timeToDecisionMs,
      operatorId,
      subsequentAnomaly,
      recordedAt: Date.now(),
    };
    this._events.push(record);
    return record;
  }

  /**
   * Compute per-rule noise/signal metrics and recommendation.
   *
   * @param {string} ruleName
   * @returns {Promise<object>}
   */
  async getRuleReport(ruleName) {
    const ruleEvents = this._events.filter(e => e.ruleTriggered === ruleName);
    const totalFired = ruleEvents.length;

    if (totalFired === 0) {
      return {
        ruleName,
        totalFired: 0,
        approvalRate: 0,
        denialRate: 0,
        timeoutRate: 0,
        avgTimeToDecision: 0,
        subsequentAnomalyRate: 0,
        noiseScore: 0,
        signalScore: 0,
        recommendation: 'NEEDS_DATA',
      };
    }

    const approvals = ruleEvents.filter(e => e.outcome === 'APPROVED').length;
    const denials   = ruleEvents.filter(e => e.outcome === 'DENIED').length;
    const timeouts  = ruleEvents.filter(e => e.outcome === 'TIMEOUT').length;

    const approvalRate = (approvals / totalFired) * 100;
    const denialRate   = (denials   / totalFired) * 100;
    const timeoutRate  = (timeouts  / totalFired) * 100;

    const totalMs = ruleEvents.reduce((s, e) => s + (e.timeToDecisionMs ?? 0), 0);
    const avgTimeToDecision = totalMs / totalFired;

    // lowTimeToDecision: % of decisions made in under 3 seconds
    const fastCount = ruleEvents.filter(e => (e.timeToDecisionMs ?? 0) < 3000).length;
    const lowTimeToDecision = (fastCount / totalFired) * 100;

    const anomalyCount = ruleEvents.filter(e => e.subsequentAnomaly).length;
    const subsequentAnomalyRate = (anomalyCount / totalFired) * 100;

    const noiseScore  = (approvalRate * 0.6) + (lowTimeToDecision * 0.4);
    const signalScore = (denialRate   * 0.5) + (subsequentAnomalyRate * 0.5);

    // Priority: CRITICAL > LIKELY_NOISE > WORKING > NEEDS_DATA
    let recommendation;
    if (subsequentAnomalyRate > 20) {
      recommendation = 'CRITICAL';
    } else if (noiseScore > 70 && totalFired > 10) {
      recommendation = 'LIKELY_NOISE';
    } else if (signalScore > 40) {
      recommendation = 'WORKING';
    } else {
      recommendation = 'NEEDS_DATA';
    }

    return {
      ruleName,
      totalFired,
      approvalRate,
      denialRate,
      timeoutRate,
      avgTimeToDecision,
      subsequentAnomalyRate,
      noiseScore,
      signalScore,
      recommendation,
    };
  }

  /**
   * Compute approval fatigue for a specific operator within a rolling time window.
   *
   * fatigueScore = (approvalsInWindow / 20 * 40) + (speedScore * 60)
   * speedScore   = fraction of all decisions in window made in under 2 seconds
   *
   * @param {object} opts
   * @param {string} opts.operatorId
   * @param {number} [opts.windowMinutes=60]
   * @returns {Promise<object>}
   */
  async getApprovalFatigue({ operatorId, windowMinutes = 60 } = {}) {
    const now      = Date.now();
    const windowMs = windowMinutes * 60 * 1000;

    const windowEvents = this._events.filter(e =>
      e.operatorId === operatorId && (now - e.recordedAt) <= windowMs
    );

    const approvalsInWindow = windowEvents.filter(e => e.outcome === 'APPROVED').length;

    const fastCount  = windowEvents.filter(e => (e.timeToDecisionMs ?? 0) < 2000).length;
    const speedScore = windowEvents.length > 0 ? fastCount / windowEvents.length : 0;

    const maxApprovalsPerHour = 20;
    const fatigueScore = (approvalsInWindow / maxApprovalsPerHour * 40) + (speedScore * 60);

    const totalMs = windowEvents.reduce((s, e) => s + (e.timeToDecisionMs ?? 0), 0);
    const avgTimeToDecisionMs = windowEvents.length > 0 ? totalMs / windowEvents.length : 0;

    let recommendation;
    if (fatigueScore > 70) {
      recommendation = 'HIGH_FATIGUE';
    } else if (fatigueScore > 40) {
      recommendation = 'ELEVATED';
    } else {
      recommendation = 'NORMAL';
    }

    return {
      operatorId,
      approvalsInWindow,
      avgTimeToDecisionMs,
      fatigueScore,
      recommendation,
    };
  }

  /**
   * Full calibration report across all rules.
   *
   * @returns {Promise<object>}
   */
  async getCalibrationReport() {
    const ruleNames = [...new Set(this._events.map(e => e.ruleTriggered).filter(Boolean))];
    const rules     = await Promise.all(ruleNames.map(r => this.getRuleReport(r)));

    const operators = [...new Set(this._events.map(e => e.operatorId).filter(Boolean))];
    let totalFatigueScore = 0;
    for (const op of operators) {
      const f = await this.getApprovalFatigue({ operatorId: op, windowMinutes: 60 });
      totalFatigueScore += f.fatigueScore;
    }
    const approvalFatigueScore = operators.length > 0 ? totalFatigueScore / operators.length : 0;

    const recommendations = [];
    for (const rule of rules) {
      if (rule.recommendation === 'CRITICAL') {
        recommendations.push(
          `URGENT: ${rule.ruleName} has critical anomaly rate — immediate review required`
        );
      } else if (rule.recommendation === 'LIKELY_NOISE') {
        recommendations.push(
          `NOISE: ${rule.ruleName} appears to be generating noise — consider raising threshold`
        );
      }
    }

    return {
      generatedAt:    new Date().toISOString(),
      totalEvents:    this._events.length,
      rulesAnalyzed:  ruleNames.length,
      rules,
      approvalFatigueScore,
      recommendations,
    };
  }

  /**
   * Dashboard data snapshot: summary stats, per-rule reports, recent events, advisor summary.
   *
   * recentEvents is capped at the last 50 events to prevent unbounded payload growth.
   *
   * @returns {Promise<object>}
   */
  async getDashboardData() {
    const totalApprovals = this._events.filter(e => e.outcome === 'APPROVED').length;
    const totalDenials   = this._events.filter(e => e.outcome === 'DENIED').length;
    const totalTimeouts  = this._events.filter(e => e.outcome === 'TIMEOUT').length;

    const ruleNames = [...new Set(this._events.map(e => e.ruleTriggered).filter(Boolean))];
    const rules     = await Promise.all(ruleNames.map(r => this.getRuleReport(r)));

    const rulesNeedingAttention = rules
      .filter(r => r.recommendation === 'CRITICAL' || r.recommendation === 'LIKELY_NOISE')
      .map(r => r.ruleName);

    const operators = [...new Set(this._events.map(e => e.operatorId).filter(Boolean))];
    let totalFatigueScore = 0;
    for (const op of operators) {
      const f = await this.getApprovalFatigue({ operatorId: op, windowMinutes: 60 });
      totalFatigueScore += f.fatigueScore;
    }
    const overallApprovalFatigueScore =
      operators.length > 0 ? totalFatigueScore / operators.length : 0;

    const recentEvents = this._events.slice(-50);

    const advisorSuggestions = rules
      .filter(r => r.recommendation === 'LIKELY_NOISE' || r.recommendation === 'CRITICAL')
      .map(r => ({
        rule: r.ruleName,
        reasoning: r.recommendation === 'CRITICAL'
          ? `Anomaly rate ${r.subsequentAnomalyRate.toFixed(1)}% exceeds critical threshold`
          : `High noise score (${r.noiseScore.toFixed(1)}) — operators may be approving without review`,
        confidence: r.totalFired >= 100 ? 'HIGH' : r.totalFired >= 50 ? 'MEDIUM' : 'LOW',
        dataPoints: r.totalFired,
      }));

    return {
      summary: {
        totalApprovals,
        totalDenials,
        totalTimeouts,
        overallApprovalFatigueScore,
        rulesNeedingAttention,
      },
      rules,
      recentEvents,
      advisor: {
        disclaimer:    'These are data-driven suggestions. Human review required before applying any changes.',
        neverAutoApply: true,
        suggestions:   advisorSuggestions,
      },
    };
  }
}

export { ApprovalOutcomeLogger };
export default ApprovalOutcomeLogger;

'use strict';

/**
 * ThresholdAdvisor — READ-ONLY data-driven suggestions for rule threshold adjustments.
 *
 * STRUCTURAL GUARANTEE: This class has no applyChange method and no mechanism to
 * modify any rule threshold. Suggestions are advisory only. A human operator must
 * review and apply changes via PolicyManager. This is enforced by the class structure,
 * not by convention.
 *
 * Confidence levels:
 *   HIGH   — 100+ events, clear pattern
 *   MEDIUM — 50–99 events, moderate pattern
 *   LOW    — < 50 events — warning added automatically
 */

const _DISCLAIMER =
  'These are data-driven suggestions. Human review required before applying any changes.';

class ThresholdAdvisor {
  /**
   * @param {object} opts
   * @param {object} opts.outcomeLogger — ApprovalOutcomeLogger instance
   */
  constructor({ outcomeLogger } = {}) {
    if (!outcomeLogger) throw new Error('ThresholdAdvisor: outcomeLogger is required');
    this._outcomeLogger = outcomeLogger;
    // NOTE: applyChange is intentionally absent — see class docblock.
  }

  /**
   * Generate threshold adjustment suggestions based on outcome data.
   *
   * The returned object always contains:
   *   - disclaimer   (string)  — human review reminder
   *   - neverAutoApply (true)  — structural marker, always present
   *   - suggestions  (array)   — per-rule suggestions
   *   - generatedAt  (string)  — ISO timestamp
   *
   * @returns {Promise<object>}
   */
  async getAdvice() {
    const calibration = await this._outcomeLogger.getCalibrationReport();
    const suggestions = [];

    for (const rule of calibration.rules) {
      const dataPoints = rule.totalFired;

      let confidence;
      let warning;

      if (dataPoints >= 100) {
        confidence = 'HIGH';
      } else if (dataPoints >= 50) {
        confidence = 'MEDIUM';
      } else {
        confidence = 'LOW';
        warning = 'Insufficient data for high confidence. Minimum 50 events recommended.';
      }

      let suggestedThreshold;
      let reasoning;

      if (rule.recommendation === 'CRITICAL') {
        suggestedThreshold = 'review';
        reasoning =
          `Rule "${rule.ruleName}" has a critical subsequent anomaly rate ` +
          `(${rule.subsequentAnomalyRate.toFixed(1)}%). Actions approved under this rule ` +
          `are later flagged as anomalous. Immediate human review required before any ` +
          `threshold change.`;
      } else if (rule.recommendation === 'LIKELY_NOISE') {
        suggestedThreshold = 'raise';
        reasoning =
          `Rule "${rule.ruleName}" shows a high noise score (${rule.noiseScore.toFixed(1)}). ` +
          `${rule.approvalRate.toFixed(1)}% of decisions were approved and ` +
          `${(rule.noiseScore - rule.approvalRate * 0.6).toFixed(1)} points come from fast approvals. ` +
          `Operators may be approving reflexively rather than thoughtfully. ` +
          `Consider raising the risk threshold to reduce false-positive interruptions.`;
      } else if (rule.recommendation === 'WORKING') {
        suggestedThreshold = 'maintain';
        reasoning =
          `Rule "${rule.ruleName}" is showing clear signal (score: ${rule.signalScore.toFixed(1)}). ` +
          `${rule.denialRate.toFixed(1)}% denial rate suggests operators are making meaningful ` +
          `decisions. Current threshold appears calibrated correctly.`;
      } else {
        suggestedThreshold = 'collect-data';
        reasoning =
          `Rule "${rule.ruleName}" has insufficient data (${dataPoints} events fired). ` +
          `Minimum 10 events required for meaningful analysis. Continue monitoring before ` +
          `adjusting thresholds.`;
      }

      const suggestion = {
        rule: rule.ruleName,
        currentThreshold:   null,
        suggestedThreshold,
        reasoning,
        confidence,
        dataPoints,
      };

      if (warning !== undefined) suggestion.warning = warning;

      suggestions.push(suggestion);
    }

    return {
      generatedAt:    new Date().toISOString(),
      disclaimer:     _DISCLAIMER,
      suggestions,
      neverAutoApply: true,
    };
  }
}

export { ThresholdAdvisor };
export default ThresholdAdvisor;

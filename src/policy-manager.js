'use strict';

/**
 * PolicyManager — human-applied threshold and policy changes with full audit trail.
 *
 * Every change is logged with: who made it, when, why, what changed, and (optionally)
 * which ThresholdAdvisor suggestion it implements. Changes can be reverted; reverts are
 * also fully logged. The history is append-only from the caller's perspective.
 *
 * PolicyManager never consults ThresholdAdvisor directly — that is a deliberate
 * separation of concerns. Callers read ThresholdAdvisor advice and then call
 * PolicyManager.applyChange() when they decide to act on a suggestion.
 */
class PolicyManager {
  /**
   * @param {object} opts
   * @param {object} [opts.sessionState]   — SessionState instance
   * @param {object} [opts.outcomeLogger]  — ApprovalOutcomeLogger instance
   * @param {object} [opts.auditLog]       — ActionLog instance for external audit trail
   */
  constructor({ sessionState, outcomeLogger, auditLog } = {}) {
    this._sessionState  = sessionState  ?? null;
    this._outcomeLogger = outcomeLogger ?? null;
    this._auditLog      = auditLog      ?? null;
    /** @private {object[]} ordered list of all changes */
    this._changes = [];
    /** @private {number} monotonic counter for unique changeIds */
    this._counter = 0;
  }

  /**
   * Record a human-applied policy change.
   *
   * Every field is stored verbatim. No validation of newValue against any schema —
   * that is intentional; PolicyManager is a recorder, not an enforcer.
   *
   * @param {object} opts
   * @param {string}  opts.rule
   * @param {string}  opts.field
   * @param {*}       opts.oldValue
   * @param {*}       opts.newValue
   * @param {string}  opts.appliedBy
   * @param {string}  opts.reason
   * @param {string}  [opts.advisorSuggestionId]
   * @returns {Promise<object>} The stored change record
   */
  async applyChange({ rule, field, oldValue, newValue, appliedBy, reason, advisorSuggestionId } = {}) {
    if (!rule)      throw new Error('PolicyManager.applyChange: rule is required');
    if (!field)     throw new Error('PolicyManager.applyChange: field is required');
    if (!appliedBy) throw new Error('PolicyManager.applyChange: appliedBy is required');
    if (!reason)    throw new Error('PolicyManager.applyChange: reason is required');

    this._counter++;
    const changeId = `policy-${Date.now()}-${this._counter}`;

    const record = {
      changeId,
      rule,
      field,
      oldValue,
      newValue,
      appliedBy,
      reason,
      appliedAt:           new Date().toISOString(),
      advisorSuggestionId: advisorSuggestionId ?? null,
      status:              'ACTIVE',
      revertedAt:          null,
      revertedBy:          null,
    };

    this._changes.push(record);
    return record;
  }

  /**
   * Revert a previously applied change.
   *
   * Sets status to 'REVERTED' and records revertedAt + revertedBy in-place.
   * Throws if the changeId is not found or if the change is already reverted.
   *
   * @param {string} changeId
   * @param {object} [opts]
   * @param {string} [opts.revertedBy='system']
   * @returns {Promise<object>} The updated change record
   */
  async revertChange(changeId, { revertedBy = 'system' } = {}) {
    const change = this._changes.find(c => c.changeId === changeId);
    if (!change) {
      throw new Error(`PolicyManager.revertChange: change "${changeId}" not found`);
    }
    if (change.status === 'REVERTED') {
      throw new Error(`PolicyManager.revertChange: change "${changeId}" is already reverted`);
    }

    change.status     = 'REVERTED';
    change.revertedAt = new Date().toISOString();
    change.revertedBy = revertedBy;

    return change;
  }

  /**
   * Return the full ordered history of all changes (ACTIVE and REVERTED).
   *
   * Returns a shallow copy so callers cannot mutate internal state.
   *
   * @returns {Promise<object[]>}
   */
  async getHistory() {
    return [...this._changes];
  }
}

export { PolicyManager };
export default PolicyManager;

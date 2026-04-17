/**
 * SensitivityClassifier — classify data payloads by sensitivity level.
 *
 * Levels (highest → lowest):
 *   RESTRICTED   — SSN, credit card, medical record IDs, API keys
 *   CONFIDENTIAL — internal emails, system prompts, config files, DB schemas
 *   INTERNAL     — company domain refs, internal project names, user IDs
 *   PUBLIC       — everything else
 */

'use strict';

// RESTRICTED patterns — highest sensitivity
const _RESTRICTED_PATTERNS = [
  /\b\d{3}[-]?\d{2}[-]?\d{4}\b/,                                                          // SSN
  /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/,           // credit card
  /\b(?:MRN|medical[_-]?record|patient[_-]?id|date[_-]?of[_-]?birth|diagnosis[_-]?code)\b/i, // medical record identifiers
  /(?:sk-|pk-|api-)[a-zA-Z0-9]{8,}/,                                                       // API keys
];

// CONFIDENTIAL patterns
const _CONFIDENTIAL_PATTERNS = [
  /[a-zA-Z0-9._%+\-]+@(?:internal|corp|company|enterprise)\.[a-zA-Z]{2,}/i, // internal email addresses
  /\bsystem[_\s]?prompt\b/i,                                                 // system prompts
  /\b\w+\.(?:env|config|yaml|yml|toml|ini)\b/i,                             // config files
  /(?:CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|database\s+schema|schema\.sql)/i, // database schemas
];

// INTERNAL patterns
const _INTERNAL_PATTERNS = [
  /\b(?:internal|corp|company|enterprise)\.[a-zA-Z]{2,}/i, // company domain references
  /\b(?:project|repo|repository|sprint|jira|linear)\s*[:#\-]\s*\w+/i, // internal project names
  /\buser[_-]?id\s*[:=]\s*\S+|\buid\s*[:=]\s*\S+/i, // user IDs with values
];

class SensitivityClassifier {
  /**
   * Classify a payload by sensitivity level.
   * @param {*} payload — string, object, or any serializable value
   * @returns {Promise<'RESTRICTED'|'CONFIDENTIAL'|'INTERNAL'|'PUBLIC'>}
   */
  async classify(payload) {
    const text = typeof payload === 'object' && payload !== null
      ? JSON.stringify(payload)
      : String(payload ?? '');

    for (const pattern of _RESTRICTED_PATTERNS) {
      if (pattern.test(text)) return 'RESTRICTED';
    }

    for (const pattern of _CONFIDENTIAL_PATTERNS) {
      if (pattern.test(text)) return 'CONFIDENTIAL';
    }

    for (const pattern of _INTERNAL_PATTERNS) {
      if (pattern.test(text)) return 'INTERNAL';
    }

    return 'PUBLIC';
  }
}

export { SensitivityClassifier };

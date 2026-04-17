/**
 * RiskScorer — deterministic five-check risk scoring for session evaluation.
 *
 * Five checks applied in order:
 *   1. Sensitive data detection (scan payload)
 *   2. External exfiltration risk
 *   3. Action frequency anomaly
 *   4. Scope edge usage
 *   5. Session trust factor (multiplier)
 */

'use strict';

import { SensitivityClassifier } from './sensitivity-classifier.js';

// ─── Sensitive data detection patterns ────────────────────────────────────────

const _SSN_PATTERN       = /\b\d{3}[-]?\d{2}[-]?\d{4}\b/;
const _CC_PATTERN        = /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/;
const _API_KEY_PATTERN   = /(?:sk-|pk-|api-)[a-zA-Z0-9]{4,}/;
const _INJECT_PATTERN    = /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|you\s+are\s+now\s+|act\s+as\s+(?:a\s+)?(?:different|unrestricted|evil)|pretend\s+(?:you\s+are|to\s+be)|forget\s+(?:all\s+)?(?:previous|your)\s+instructions?|jailbreak|dan\s+mode)/i;
const _PASSWORD_PATTERN  = /\b(?:password|passwd|secret|credential)\s*[:=]\s*\S+/i;

/** External domain — not localhost/RFC1918 */
const _EXTERNAL_DOMAIN   = /https?:\/\/(?!localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)([\w.-]+\.[a-z]{2,})/i;

// ─── Shannon entropy ──────────────────────────────────────────────────────────

function _entropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  let e = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    e -= p * Math.log2(p);
  }
  return e;
}

function _hasHighEntropyString(text) {
  // Tokens longer than 20 chars with Shannon entropy > 4 bits/char are suspicious
  const tokens = text.split(/[\s,;:!?'"()\[\]{}\n\t]+/);
  return tokens.some(tok => tok.length > 20 && _entropy(tok) > 4);
}

// ─────────────────────────────────────────────────────────────────────────────

class RiskScorer {
  constructor() {
    this._classifier = new SensitivityClassifier();
  }

  /**
   * Score an action for risk. Returns a raw score (0–∞ before trust multiplier).
   *
   * @param {object} opts
   * @param {string|object} opts.action        — action being evaluated
   * @param {*}             opts.payload       — payload to scan
   * @param {object}        [opts.sessionState] — live SessionState instance (for history)
   * @param {string}        [opts.receiptScope] — receipt scope text for boundary detection
   *
   * @returns {Promise<{
   *   score: number,
   *   checks: object[],
   *   sensitiveDataDetected: boolean,
   *   externalDomain: string|null,
   * }>}
   */
  async score({ action, payload, sessionState, receiptScope } = {}) {
    const text = (typeof payload === 'object' && payload !== null)
      ? JSON.stringify(payload)
      : String(payload ?? '');

    const actionType = typeof action === 'string'
      ? action
      : `${action?.operation ?? ''}:${action?.resource ?? ''}`;

    let rawScore            = 0;
    let sensitiveDataDetected = false;
    const checks            = [];

    // ── Check 1: Sensitive data detection ─────────────────────────────────────
    let c1 = 0;
    const c1Findings = [];

    if (_SSN_PATTERN.test(text)) {
      c1 += 35;
      c1Findings.push('ssn');
      sensitiveDataDetected = true;
    }
    if (_CC_PATTERN.test(text)) {
      c1 += 35;
      c1Findings.push('credit-card');
      sensitiveDataDetected = true;
    }
    if (_API_KEY_PATTERN.test(text)) {
      c1 += 30;
      c1Findings.push('api-key');
      sensitiveDataDetected = true;
    }
    if (_hasHighEntropyString(text)) {
      c1 += 20;
      c1Findings.push('high-entropy');
    }
    if (_INJECT_PATTERN.test(text)) {
      c1 += 40;
      c1Findings.push('prompt-injection');
      sensitiveDataDetected = true;
    }
    if (_PASSWORD_PATTERN.test(text)) {
      c1 += 25;
      c1Findings.push('password-keyword');
      sensitiveDataDetected = true;
    }

    rawScore += c1;
    checks.push({ check: 1, name: 'Sensitive data detection', score: c1, findings: c1Findings });

    // ── Check 2: External exfiltration risk ───────────────────────────────────
    let c2 = 0;
    const c2Findings = [];
    const extMatch    = text.match(_EXTERNAL_DOMAIN);
    const externalDomain = extMatch ? extMatch[0] : null;

    if (externalDomain) {
      if (sensitiveDataDetected) {
        c2 += 30;
        c2Findings.push('external-domain-with-sensitive-data');
      }
      const seenDomains = sessionState?._seenDomains ?? new Set();
      if (!seenDomains.has(externalDomain)) {
        c2 += 15;
        c2Findings.push('first-time-external-domain');
      }
    }

    rawScore += c2;
    checks.push({ check: 2, name: 'External exfiltration risk', score: c2, findings: c2Findings });

    // ── Check 3: Action frequency anomaly ─────────────────────────────────────
    let c3 = 0;
    const c3Findings = [];

    if (sessionState) {
      const history = sessionState._actionHistory ?? [];
      const now = Date.now();
      const window60s = now - 60_000;

      const recentSame = history.filter(
        h => h.actionType === actionType && h.timestamp >= window60s
      ).length;

      if (recentSame > 10) {
        c3 += 25;
        c3Findings.push(`frequency-spike:${recentSame}`);
      }

      if (history.length > 50) {
        c3 += 15;
        c3Findings.push(`high-action-count:${history.length}`);
      }
    }

    rawScore += c3;
    checks.push({ check: 3, name: 'Action frequency anomaly', score: c3, findings: c3Findings });

    // ── Check 4: Scope edge usage ─────────────────────────────────────────────
    let c4 = 0;
    const c4Findings = [];

    if (sessionState) {
      const usedPermissions = sessionState._usedPermissions ?? new Set();
      if (!usedPermissions.has(actionType)) {
        c4 += 10;
        c4Findings.push('new-permission');
      }

      if (receiptScope) {
        const scopeStr  = typeof receiptScope === 'string' ? receiptScope : JSON.stringify(receiptScope);
        const actionStr = typeof action === 'string' ? action : JSON.stringify(action);
        const scopeWords  = new Set(scopeStr.toLowerCase().split(/\W+/).filter(w => w.length > 3));
        const actionWords = actionStr.toLowerCase().split(/\W+/).filter(w => w.length > 3);
        const hits  = actionWords.filter(w => scopeWords.has(w)).length;
        const ratio = actionWords.length > 0 ? hits / actionWords.length : 0;
        if (ratio > 0.1 && ratio < 0.5) {
          c4 += 10;
          c4Findings.push('scope-boundary');
        }
      }
    }

    rawScore += c4;
    checks.push({ check: 4, name: 'Scope edge usage', score: c4, findings: c4Findings });

    // ── Check 5: Session trust factor ─────────────────────────────────────────
    const trustScore     = sessionState?.trustScore ?? 100;
    const trustMult      = 1 + (100 - trustScore) / 100;
    const finalScore     = rawScore * trustMult;

    checks.push({
      check: 5,
      name: 'Session trust factor',
      trustScore,
      multiplier: trustMult,
      finalScore,
    });

    return {
      score: Math.round(finalScore),
      checks,
      sensitiveDataDetected,
      externalDomain,
    };
  }
}

export { RiskScorer };

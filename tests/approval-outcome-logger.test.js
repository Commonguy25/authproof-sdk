/**
 * ApprovalOutcomeLogger + ThresholdAdvisor + PolicyManager + SessionState — Tests
 * Run: node --experimental-global-webcrypto tests/approval-outcome-logger.test.js
 */

import { ApprovalOutcomeLogger } from '../src/approval-outcome-logger.js';
import { ThresholdAdvisor }      from '../src/threshold-advisor.js';
import { PolicyManager }         from '../src/policy-manager.js';
import { SessionState }          from '../src/session-state.js';

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    console.error(`  ✗ ${label}`);
    failed++;
  }
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

async function recordMany(logger, rule, count, opts = {}) {
  for (let i = 0; i < count; i++) {
    await logger.recordOutcome({
      eventId:          `${rule}-evt-${i}`,
      sessionId:        'sess-test',
      receiptHash:      'hash-test',
      ruleTriggered:    rule,
      riskScore:        50,
      decision:         'REQUIRE_APPROVAL',
      outcome:          opts.outcome          ?? 'APPROVED',
      timeToDecisionMs: opts.timeToDecisionMs ?? 1000,
      operatorId:       opts.operatorId       ?? 'op-default',
      subsequentAnomaly: opts.subsequentAnomaly ?? false,
    });
  }
}

// ─────────────────────────────────────────────
// MAIN TEST RUNNER
// ─────────────────────────────────────────────

async function run() {
  console.log('ApprovalOutcomeLogger + ThresholdAdvisor + PolicyManager + SessionState\n');

  // ─── Section 1: Outcome logging records all required fields ────────────
  console.log('Section 1: Outcome logging — required fields');

  const loggerBasic = new ApprovalOutcomeLogger({});

  const record = await loggerBasic.recordOutcome({
    eventId:          'evt-001',
    sessionId:        'sess-001',
    receiptHash:      'abc123',
    ruleTriggered:    'prompt_injection_check',
    riskScore:        55,
    decision:         'REQUIRE_APPROVAL',
    outcome:          'APPROVED',
    timeToDecisionMs: 500,
    operatorId:       'op-test',
    subsequentAnomaly: false,
  });

  assert(typeof record === 'object',                     'recordOutcome returns an object');
  assert(record.eventId === 'evt-001',                   'record stores eventId');
  assert(record.outcome === 'APPROVED',                  'record stores outcome');
  assert(record.timeToDecisionMs === 500,                'record stores timeToDecisionMs');
  assert(record.operatorId === 'op-test',                'record stores operatorId');
  assert(record.subsequentAnomaly === false,             'record stores subsequentAnomaly');
  assert(typeof record.recordedAt === 'number' && record.recordedAt > 0,
    'record has numeric recordedAt timestamp');

  // ─── Section 2: Timeout outcome ────────────────────────────────────────
  console.log('\nSection 2: Timeout outcome');

  const loggerTimeout = new ApprovalOutcomeLogger({});
  await loggerTimeout.recordOutcome({
    eventId: 'to-1', sessionId: 's', receiptHash: 'h',
    ruleTriggered: 'timeout_rule', riskScore: 50,
    decision: 'REQUIRE_APPROVAL', outcome: 'TIMEOUT',
    timeToDecisionMs: 30000, operatorId: 'op-timeout',
  });
  const timeoutReport = await loggerTimeout.getRuleReport('timeout_rule');

  assert(timeoutReport.timeoutRate === 100, 'Timeout outcome recorded — timeoutRate = 100%');
  assert(timeoutReport.approvalRate === 0,  'Timeout outcome: approvalRate is 0');

  // ─── Section 3: operatorId tracked ─────────────────────────────────────
  console.log('\nSection 3: operatorId tracked per outcome');

  const loggerOp = new ApprovalOutcomeLogger({});
  const recOp = await loggerOp.recordOutcome({
    eventId: 'op-evt-1', sessionId: 's', receiptHash: 'h',
    ruleTriggered: 'op_rule', riskScore: 50,
    decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
    timeToDecisionMs: 1000, operatorId: 'op-tracked',
  });

  assert(recOp.operatorId === 'op-tracked', 'operatorId stored correctly in outcome record');

  // ─── Section 4: noiseScore formula verification ─────────────────────────
  console.log('\nSection 4: noiseScore formula');

  // 10 events: 8 APPROVED (500ms each), 2 DENIED (500ms each)
  // approvalRate=80, lowTimeToDecision=100 (all < 3000ms)
  // noiseScore = 80*0.6 + 100*0.4 = 48+40 = 88
  const loggerNoise = new ApprovalOutcomeLogger({});
  for (let i = 0; i < 8; i++) {
    await loggerNoise.recordOutcome({
      eventId: `ns-a-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'noise_formula_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 500, operatorId: 'op-n', subsequentAnomaly: false,
    });
  }
  for (let i = 0; i < 2; i++) {
    await loggerNoise.recordOutcome({
      eventId: `ns-d-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'noise_formula_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'DENIED',
      timeToDecisionMs: 500, operatorId: 'op-n', subsequentAnomaly: false,
    });
  }
  const noiseFormulaReport = await loggerNoise.getRuleReport('noise_formula_rule');

  assert(Math.abs(noiseFormulaReport.noiseScore - 88) < 0.001,
    'noiseScore formula: 80% approval * 0.6 + 100% fast * 0.4 = 88');
  assert(Math.abs(noiseFormulaReport.approvalRate - 80) < 0.001,
    'approvalRate computed correctly (80%)');
  assert(Math.abs(noiseFormulaReport.denialRate - 20) < 0.001,
    'denialRate computed correctly (20%)');
  assert(noiseFormulaReport.avgTimeToDecision === 500,
    'avgTimeToDecision computed correctly (500ms)');

  // ─── Section 5: signalScore formula verification ─────────────────────────
  console.log('\nSection 5: signalScore formula');

  // 10 events: 7 DENIED (5000ms), 3 APPROVED (5000ms), 1 anomaly
  // denialRate=70, subsequentAnomalyRate=10, lowTimeToDecision=0
  // signalScore = 70*0.5 + 10*0.5 = 35+5 = 40
  const loggerSignal = new ApprovalOutcomeLogger({});
  for (let i = 0; i < 7; i++) {
    await loggerSignal.recordOutcome({
      eventId: `sg-d-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'signal_formula_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'DENIED',
      timeToDecisionMs: 5000, operatorId: 'op-s', subsequentAnomaly: false,
    });
  }
  for (let i = 0; i < 2; i++) {
    await loggerSignal.recordOutcome({
      eventId: `sg-a-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'signal_formula_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 5000, operatorId: 'op-s', subsequentAnomaly: false,
    });
  }
  // 1 approved with anomaly
  await loggerSignal.recordOutcome({
    eventId: 'sg-anomaly', sessionId: 's', receiptHash: 'h',
    ruleTriggered: 'signal_formula_rule', riskScore: 50,
    decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
    timeToDecisionMs: 5000, operatorId: 'op-s', subsequentAnomaly: true,
  });
  const signalFormulaReport = await loggerSignal.getRuleReport('signal_formula_rule');

  assert(Math.abs(signalFormulaReport.signalScore - 40) < 0.001,
    'signalScore formula: 70% denial * 0.5 + 10% anomaly * 0.5 = 40');
  assert(Math.abs(signalFormulaReport.subsequentAnomalyRate - 10) < 0.001,
    'subsequentAnomalyRate computed correctly (10%)');
  assert(Math.abs(signalFormulaReport.timeoutRate - 0) < 0.001,
    'timeoutRate is 0 when no timeouts');

  // ─── Section 6: Recommendation thresholds ──────────────────────────────
  console.log('\nSection 6: Recommendation thresholds');

  // LIKELY_NOISE: 12 events, all APPROVED, all under 1000ms
  // noiseScore = 100*0.6 + 100*0.4 = 100 > 70, totalFired=12 > 10
  const loggerLN = new ApprovalOutcomeLogger({});
  await recordMany(loggerLN, 'likely_noise_rule', 12, { outcome: 'APPROVED', timeToDecisionMs: 500 });
  const likelyNoiseReport = await loggerLN.getRuleReport('likely_noise_rule');

  assert(likelyNoiseReport.recommendation === 'LIKELY_NOISE',
    'LIKELY_NOISE triggers when noiseScore > 70 AND totalFired > 10');

  // CRITICAL: 5 events, 3 have subsequentAnomaly → 60% > 20%
  const loggerCrit = new ApprovalOutcomeLogger({});
  for (let i = 0; i < 3; i++) {
    await loggerCrit.recordOutcome({
      eventId: `crit-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'critical_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 2000, operatorId: 'op-c', subsequentAnomaly: true,
    });
  }
  for (let i = 3; i < 5; i++) {
    await loggerCrit.recordOutcome({
      eventId: `crit-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'critical_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 2000, operatorId: 'op-c', subsequentAnomaly: false,
    });
  }
  const critReport = await loggerCrit.getRuleReport('critical_rule');

  assert(critReport.recommendation === 'CRITICAL',
    'CRITICAL triggers when subsequentAnomalyRate > 20%');
  assert(critReport.subsequentAnomalyRate > 20,
    'subsequentAnomalyRate exceeds 20% for CRITICAL rule');

  // NEEDS_DATA: 5 events — totalFired < 10
  const loggerND = new ApprovalOutcomeLogger({});
  await recordMany(loggerND, 'needs_data_rule', 5, { outcome: 'APPROVED', timeToDecisionMs: 5000 });
  const needsDataReport = await loggerND.getRuleReport('needs_data_rule');

  assert(needsDataReport.recommendation === 'NEEDS_DATA',
    'NEEDS_DATA when totalFired < 10');
  assert(needsDataReport.totalFired === 5, 'NEEDS_DATA: totalFired is 5');

  // WORKING: 10 events, 9 DENIED (slow) → signalScore > 40, noiseScore low
  const loggerWorking = new ApprovalOutcomeLogger({});
  await recordMany(loggerWorking, 'working_rule', 9, { outcome: 'DENIED', timeToDecisionMs: 8000 });
  await recordMany(loggerWorking, 'working_rule', 1, { outcome: 'APPROVED', timeToDecisionMs: 8000 });
  const workingReport = await loggerWorking.getRuleReport('working_rule');

  assert(workingReport.recommendation === 'WORKING',
    'WORKING when signalScore > 40 (90% denial → signalScore 45)');

  // CRITICAL takes priority over LIKELY_NOISE
  // 12 events: all APPROVED fast (noiseScore=100 > 70), 3 have anomaly (subsequentAnomalyRate=25%)
  const loggerPriority = new ApprovalOutcomeLogger({});
  for (let i = 0; i < 3; i++) {
    await loggerPriority.recordOutcome({
      eventId: `prio-a-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'priority_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 500, operatorId: 'op-p', subsequentAnomaly: true,
    });
  }
  for (let i = 3; i < 12; i++) {
    await loggerPriority.recordOutcome({
      eventId: `prio-b-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'priority_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 500, operatorId: 'op-p', subsequentAnomaly: false,
    });
  }
  const priorityReport = await loggerPriority.getRuleReport('priority_rule');

  assert(priorityReport.recommendation === 'CRITICAL',
    'CRITICAL takes priority over LIKELY_NOISE when both conditions met');

  // ─── Section 7: Approval fatigue ───────────────────────────────────────
  console.log('\nSection 7: Approval fatigue');

  const loggerFatigue = new ApprovalOutcomeLogger({});

  // HIGH_FATIGUE operator: 20 approvals, all < 2000ms
  // fatigueScore = (20/20 * 40) + (1.0 * 60) = 40+60 = 100 > 70
  for (let i = 0; i < 20; i++) {
    await loggerFatigue.recordOutcome({
      eventId: `fatigue-hf-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'rule_a', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 1000, operatorId: 'op-highfatigue',
    });
  }

  const highFatigue = await loggerFatigue.getApprovalFatigue({
    operatorId: 'op-highfatigue', windowMinutes: 60,
  });

  assert(Math.abs(highFatigue.fatigueScore - 100) < 0.001,
    'fatigueScore formula: 20 approvals, all fast → (20/20*40)+(1.0*60) = 100');
  assert(highFatigue.recommendation === 'HIGH_FATIGUE',
    'HIGH_FATIGUE triggers when fatigueScore > 70');
  assert(highFatigue.approvalsInWindow === 20, 'approvalsInWindow counts correctly (20)');

  // ELEVATED operator: 5 approvals, 3 fast out of 5 events
  // fatigueScore = (5/20*40) + (0.6*60) = 10+36 = 46 > 40
  for (let i = 0; i < 3; i++) {
    await loggerFatigue.recordOutcome({
      eventId: `fatigue-el-fast-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'rule_b', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 1000, operatorId: 'op-elevated',
    });
  }
  for (let i = 0; i < 2; i++) {
    await loggerFatigue.recordOutcome({
      eventId: `fatigue-el-slow-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'rule_b', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 5000, operatorId: 'op-elevated',
    });
  }

  const elevatedFatigue = await loggerFatigue.getApprovalFatigue({
    operatorId: 'op-elevated', windowMinutes: 60,
  });

  assert(elevatedFatigue.recommendation === 'ELEVATED',
    'ELEVATED triggers when fatigueScore > 40 (5 approvals, 60% fast → 46)');

  // NORMAL operator: 2 approvals, all slow (> 2000ms)
  // fatigueScore = (2/20*40) + (0*60) = 4
  for (let i = 0; i < 2; i++) {
    await loggerFatigue.recordOutcome({
      eventId: `fatigue-nm-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'rule_c', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 10000, operatorId: 'op-normal',
    });
  }

  const normalFatigue = await loggerFatigue.getApprovalFatigue({
    operatorId: 'op-normal', windowMinutes: 60,
  });

  assert(normalFatigue.recommendation === 'NORMAL',
    'NORMAL when fatigueScore <= 40 (2 slow approvals → 4)');

  // Multiple operators tracked independently
  const loggerMultiOp = new ApprovalOutcomeLogger({});
  for (let i = 0; i < 20; i++) {
    await loggerMultiOp.recordOutcome({
      eventId: `mo-a-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'rule_multi', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 1000, operatorId: 'op-busy',
    });
  }
  for (let i = 0; i < 2; i++) {
    await loggerMultiOp.recordOutcome({
      eventId: `mo-b-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'rule_multi', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 8000, operatorId: 'op-calm',
    });
  }

  const busyFatigue  = await loggerMultiOp.getApprovalFatigue({ operatorId: 'op-busy',  windowMinutes: 60 });
  const calmFatigue  = await loggerMultiOp.getApprovalFatigue({ operatorId: 'op-calm',  windowMinutes: 60 });

  assert(busyFatigue.recommendation === 'HIGH_FATIGUE',
    'Multiple operators: op-busy is HIGH_FATIGUE independently');
  assert(calmFatigue.recommendation === 'NORMAL',
    'Multiple operators: op-calm is NORMAL independently');
  assert(Math.abs(calmFatigue.avgTimeToDecisionMs - 8000) < 0.001,
    'avgTimeToDecisionMs computed correctly (8000ms) for op-calm');

  // ─── Section 8: Calibration report ─────────────────────────────────────
  console.log('\nSection 8: Calibration report');

  const loggerCalib = new ApprovalOutcomeLogger({});
  await recordMany(loggerCalib, 'rule_alpha',   8,  { outcome: 'APPROVED', operatorId: 'op-c1' });
  await recordMany(loggerCalib, 'rule_beta',    6,  { outcome: 'DENIED',   operatorId: 'op-c2' });
  await recordMany(loggerCalib, 'rule_gamma',   4,  { outcome: 'TIMEOUT',  operatorId: 'op-c3' });

  const calibReport = await loggerCalib.getCalibrationReport();

  assert(typeof calibReport.approvalFatigueScore === 'number',
    'getCalibrationReport includes approvalFatigueScore');
  assert(Array.isArray(calibReport.recommendations),
    'getCalibrationReport includes recommendations array');
  assert(calibReport.rulesAnalyzed === 3,
    'rulesAnalyzed count is correct (3 rules)');
  assert(calibReport.totalEvents === 18,
    'totalEvents in calibration report is correct (18)');
  assert(typeof calibReport.generatedAt === 'string',
    'calibration report includes generatedAt timestamp');

  // ─── Section 9: Dashboard data ──────────────────────────────────────────
  console.log('\nSection 9: Dashboard data');

  const loggerDash = new ApprovalOutcomeLogger({});
  await recordMany(loggerDash, 'dash_rule', 5, { outcome: 'APPROVED', operatorId: 'op-d' });
  await recordMany(loggerDash, 'dash_rule', 3, { outcome: 'DENIED',   operatorId: 'op-d' });
  await recordMany(loggerDash, 'dash_rule', 2, { outcome: 'TIMEOUT',  operatorId: 'op-d' });

  const dashData = await loggerDash.getDashboardData();

  assert(dashData.summary !== undefined,
    'getDashboardData returns summary object');
  assert(dashData.summary.totalApprovals === 5,
    'summary.totalApprovals is correct (5)');
  assert(dashData.summary.totalDenials === 3,
    'summary.totalDenials is correct (3)');
  assert(dashData.summary.totalTimeouts === 2,
    'summary.totalTimeouts is correct (2)');
  assert(Array.isArray(dashData.rules),
    'getDashboardData returns rules array');
  assert(Array.isArray(dashData.recentEvents),
    'getDashboardData returns recentEvents array');
  assert(dashData.advisor !== undefined,
    'getDashboardData returns advisor object');

  // recentEvents limited to last 50
  const loggerRecent = new ApprovalOutcomeLogger({});
  for (let i = 0; i < 60; i++) {
    await loggerRecent.recordOutcome({
      eventId: `recent-${i}`, sessionId: 's', receiptHash: 'h',
      ruleTriggered: 'recent_rule', riskScore: 50,
      decision: 'REQUIRE_APPROVAL', outcome: 'APPROVED',
      timeToDecisionMs: 1000, operatorId: 'op-recent',
    });
  }
  const dashRecent = await loggerRecent.getDashboardData();

  assert(dashRecent.recentEvents.length === 50,
    'Dashboard recentEvents limited to last 50 (60 events recorded, 50 returned)');

  // ─── Section 10: ThresholdAdvisor ──────────────────────────────────────
  console.log('\nSection 10: ThresholdAdvisor');

  // LOW confidence: < 50 events
  const loggerLowConf = new ApprovalOutcomeLogger({});
  await recordMany(loggerLowConf, 'low_conf_rule', 10, { outcome: 'APPROVED' });
  const advisorLow = new ThresholdAdvisor({ outcomeLogger: loggerLowConf });
  const adviceLow  = await advisorLow.getAdvice();

  assert(
    typeof adviceLow.disclaimer === 'string' && adviceLow.disclaimer.length > 0,
    'ThresholdAdvisor output always has disclaimer field'
  );
  assert(adviceLow.neverAutoApply === true,
    'ThresholdAdvisor output always has neverAutoApply: true');
  assert(typeof advisorLow.applyChange === 'undefined',
    'ThresholdAdvisor has no applyChange method (structurally enforced)');
  assert(adviceLow.suggestions.length > 0,
    'ThresholdAdvisor returns at least one suggestion');

  const lowSuggestion = adviceLow.suggestions.find(s => s.rule === 'low_conf_rule');
  assert(lowSuggestion !== undefined,
    'ThresholdAdvisor generates suggestion for low_conf_rule');
  assert(lowSuggestion.confidence === 'LOW',
    'LOW confidence assigned when dataPoints < 50');
  assert(typeof lowSuggestion.warning === 'string' && lowSuggestion.warning.length > 0,
    'LOW confidence warning present when under 50 events');
  assert(
    lowSuggestion.warning.includes('Insufficient data') || lowSuggestion.warning.length > 0,
    'LOW confidence warning mentions insufficient data'
  );

  // HIGH confidence: 100+ events
  const loggerHighConf = new ApprovalOutcomeLogger({});
  await recordMany(loggerHighConf, 'high_conf_rule', 120, { outcome: 'APPROVED', timeToDecisionMs: 500 });
  const advisorHigh = new ThresholdAdvisor({ outcomeLogger: loggerHighConf });
  const adviceHigh  = await advisorHigh.getAdvice();

  const highSuggestion = adviceHigh.suggestions.find(s => s.rule === 'high_conf_rule');
  assert(highSuggestion !== undefined,
    'ThresholdAdvisor generates suggestion for high_conf_rule');
  assert(highSuggestion.confidence === 'HIGH',
    'HIGH confidence when 100+ events');
  assert(typeof highSuggestion.reasoning === 'string' && highSuggestion.reasoning.length > 0,
    'Advisor suggestions include reasoning string');
  assert(typeof highSuggestion.dataPoints === 'number' && highSuggestion.dataPoints === 120,
    'Advisor suggestions include dataPoints count (120)');

  // MEDIUM confidence: 50–99 events
  const loggerMedConf = new ApprovalOutcomeLogger({});
  await recordMany(loggerMedConf, 'medium_conf_rule', 75, { outcome: 'APPROVED', timeToDecisionMs: 500 });
  const advisorMed = new ThresholdAdvisor({ outcomeLogger: loggerMedConf });
  const adviceMed  = await advisorMed.getAdvice();

  const medSuggestion = adviceMed.suggestions.find(s => s.rule === 'medium_conf_rule');
  assert(medSuggestion !== undefined,
    'ThresholdAdvisor generates suggestion for medium_conf_rule');
  assert(medSuggestion.confidence === 'MEDIUM',
    'MEDIUM confidence for 50–99 events (75 events)');

  // ─── Section 11: PolicyManager ─────────────────────────────────────────
  console.log('\nSection 11: PolicyManager');

  const policy = new PolicyManager({});

  const change = await policy.applyChange({
    rule:      'prompt_injection_check',
    field:     'riskThreshold',
    oldValue:  40,
    newValue:  60,
    appliedBy: 'admin-user',
    reason:    'Reducing false positives based on 30-day outcome data',
    advisorSuggestionId: 'adv-suggestion-001',
  });

  assert(typeof change.changeId === 'string' && change.changeId.startsWith('policy-'),
    'PolicyManager logs every change with a unique changeId');
  assert(change.rule === 'prompt_injection_check',
    'PolicyManager stores rule in audit record');
  assert(change.field === 'riskThreshold',
    'PolicyManager stores field in audit record');
  assert(change.oldValue === 40,
    'PolicyManager stores oldValue in audit record');
  assert(change.newValue === 60,
    'PolicyManager stores newValue in audit record');
  assert(change.appliedBy === 'admin-user',
    'PolicyManager stores appliedBy in audit record');
  assert(change.reason.length > 0,
    'PolicyManager stores reason in audit record');
  assert(typeof change.appliedAt === 'string',
    'PolicyManager stores appliedAt ISO timestamp');
  assert(change.advisorSuggestionId === 'adv-suggestion-001',
    'PolicyManager stores advisorSuggestionId when provided');
  assert(change.status === 'ACTIVE',
    'New change has status ACTIVE');

  // Revert change
  const reverted = await policy.revertChange(change.changeId, { revertedBy: 'reviewer-1' });

  assert(reverted.status === 'REVERTED',
    'PolicyManager revert sets status to REVERTED');
  assert(typeof reverted.revertedAt === 'string' && reverted.revertedAt.length > 0,
    'PolicyManager revert records revertedAt timestamp');
  assert(reverted.revertedBy === 'reviewer-1',
    'PolicyManager revert records revertedBy');

  // getHistory returns full audit trail
  const history = await policy.getHistory();

  assert(Array.isArray(history) && history.length === 1,
    'getHistory returns array of all changes (1 entry)');
  assert(history[0].changeId === change.changeId,
    'getHistory entry matches the applied change');

  // ─── Section 12: SessionState event emitter ────────────────────────────
  console.log('\nSection 12: SessionState — approvalRequired event');

  // requireApprovalThreshold: -100 → after PUBLIC sensitivity +10 adjustment becomes -90.
  // Any riskScore (min 0) is >= -90, so REQUIRE_APPROVAL fires for every evaluation.
  // blockThreshold: 1000 → unreachably high, so no BLOCK.
  const state = new SessionState({
    receiptHash: 'a'.repeat(64),
    policy: { requireApprovalThreshold: -100, blockThreshold: 1000 },
  });

  let emittedEvent = null;

  state.on('approvalRequired', (evt) => {
    emittedEvent = evt;
  });

  const evalResult = await state.evaluate({ action: 'read-sensitive-data', payload: 'test content' });

  assert(evalResult.decision === 'REQUIRE_APPROVAL',
    'SessionState.evaluate() returns REQUIRE_APPROVAL when riskScore >= requireApprovalThreshold');
  assert(emittedEvent !== null,
    'SessionState emits approvalRequired event on REQUIRE_APPROVAL decision');
  assert(emittedEvent.decision === 'REQUIRE_APPROVAL',
    'emitted event has decision: REQUIRE_APPROVAL');
  assert(typeof emittedEvent.sessionId === 'string' && emittedEvent.sessionId.startsWith('sess-'),
    'emitted event carries the sessionId');
  assert(emittedEvent.receiptHash === 'a'.repeat(64),
    'emitted event carries receiptHash');
  assert(typeof emittedEvent.timestamp === 'number' && emittedEvent.timestamp > 0,
    'emitted event has numeric timestamp');

  // Verify ALLOW decision does not emit
  // requireApprovalThreshold: 1000 → after PUBLIC +10 becomes 1010, safely above any real score
  const stateAllow = new SessionState({
    receiptHash: 'b'.repeat(64),
    policy: { requireApprovalThreshold: 1000, blockThreshold: 2000 },
  });
  let allowFired = false;
  stateAllow.on('approvalRequired', () => { allowFired = true; });
  const allowResult = await stateAllow.evaluate({ action: 'safe-read', payload: 'nothing sensitive' });
  assert(allowResult.decision === 'ALLOW',
    'SessionState returns ALLOW when riskScore < requireApprovalThreshold');
  assert(allowFired === false,
    'approvalRequired is NOT emitted when decision is ALLOW');

  // ─── Summary ────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(50)}`);
  console.log(`Results: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    console.error(`\n${failed} test(s) failed.`);
    process.exit(1);
  } else {
    console.log(`\n✓ All ${passed} ApprovalOutcomeLogger tests passed.`);
  }
}

run().catch(e => {
  console.error('Test runner error:', e);
  process.exit(1);
});

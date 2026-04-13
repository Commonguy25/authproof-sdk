/**
 * AuthProof generic function wrapper.
 *
 * Wraps any async function so it is automatically gated by PreExecutionVerifier.
 * The wrapped function never executes unless all six checks pass.
 *
 * @example
 * import { guardFunction } from 'authproof-sdk/middleware/generic'
 * const guardedExecute = guardFunction(executeAction, {
 *   receiptHash,
 *   verifier,
 *   action:               { operation: 'execute', resource: 'pipeline/run' },
 *   operatorInstructions: 'Run the analysis pipeline',
 * })
 * await guardedExecute(payload)
 */

'use strict';

/**
 * Wrap any function so every call is gated by PreExecutionVerifier.
 *
 * @param {function} fn              — the function to guard
 * @param {object}   opts
 * @param {string}               opts.receiptHash           — delegation receipt hash
 * @param {PreExecutionVerifier} opts.verifier              — initialized verifier instance
 * @param {object|string|function} [opts.action]            — action descriptor, or function(args)→action
 * @param {string|function}      [opts.operatorInstructions] — instructions, or function(args)→string
 * @param {string}               [opts.programHash]         — optional capability DAG hash
 * @returns {function} guarded async function
 */
export function guardFunction(fn, {
  receiptHash,
  verifier,
  action,
  operatorInstructions,
  programHash,
} = {}) {
  if (typeof fn !== 'function') throw new Error('guardFunction: fn must be a function');
  if (!receiptHash) throw new Error('guardFunction: receiptHash is required');
  if (!verifier)    throw new Error('guardFunction: verifier is required');

  return async function guardedFunction(...args) {
    // action and operatorInstructions can be static values or functions over the call args
    const resolvedAction = typeof action === 'function'
      ? action(...args)
      : (action ?? { operation: fn.name || 'execute', resource: 'function/call' });

    const resolvedInstructions = typeof operatorInstructions === 'function'
      ? operatorInstructions(...args)
      : operatorInstructions;

    const checkOpts = {
      receiptHash,
      action:               resolvedAction,
      operatorInstructions: resolvedInstructions,
    };
    if (programHash !== undefined) checkOpts.programHash = programHash;

    const result = await verifier.check(checkOpts);

    if (!result.allowed) {
      const err = new Error(`[AuthProof] Action blocked: ${result.blockedReason}`);
      err.authproofResult = result;
      throw err;
    }

    return fn(...args);
  };
}

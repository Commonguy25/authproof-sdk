/**
 * AuthProof Express/HTTP middleware.
 *
 * Drop-in Express middleware that gates every request through PreExecutionVerifier.
 * The request handler never executes unless all six checks pass.
 *
 * @example
 * import { authproofMiddleware } from 'authproof-sdk/middleware/express'
 * app.use(authproofMiddleware({
 *   verifier,
 *   getReceiptHash:          (req) => req.headers['x-receipt-hash'],
 *   getAction:               (req) => ({ operation: req.method.toLowerCase(), resource: req.path }),
 *   getOperatorInstructions: (req) => req.headers['x-operator-instructions'],
 * }))
 */

'use strict';

/**
 * Create an Express middleware that gates every request through PreExecutionVerifier.
 *
 * @param {object} opts
 * @param {PreExecutionVerifier} opts.verifier                        — initialized verifier instance
 * @param {function}             opts.getReceiptHash                  — extract receiptHash from req; returns string or null
 * @param {function}             [opts.getAction]                     — extract action from req; defaults to { operation: method, resource: path }
 * @param {function}             [opts.getOperatorInstructions]       — extract operatorInstructions from req; defaults to x-operator-instructions header
 * @param {function}             [opts.getProgramHash]                — extract programHash from req (optional)
 * @param {function}             [opts.onBlocked]                     — custom handler for blocked requests; defaults to 403 JSON
 * @returns {function} Express middleware (req, res, next)
 */
export function authproofMiddleware({
  verifier,
  getReceiptHash,
  getAction,
  getOperatorInstructions,
  getProgramHash,
  onBlocked,
} = {}) {
  if (!verifier)       throw new Error('authproofMiddleware (express): verifier is required');
  if (!getReceiptHash) throw new Error('authproofMiddleware (express): getReceiptHash is required');

  const _getAction = typeof getAction === 'function'
    ? getAction
    : (req) => ({ operation: req.method.toLowerCase(), resource: req.path });

  const _getOperatorInstructions = typeof getOperatorInstructions === 'function'
    ? getOperatorInstructions
    : (req) => req.headers?.['x-operator-instructions'] ?? null;

  const _getProgramHash = typeof getProgramHash === 'function'
    ? getProgramHash
    : (req) => req.headers?.['x-program-hash'] ?? undefined;

  const _onBlocked = typeof onBlocked === 'function'
    ? onBlocked
    : (req, res, result) => {
        res.status(403).json({
          error:         'AuthProof: action blocked',
          blockedReason: result.blockedReason,
          verifiedAt:    result.verifiedAt,
        });
      };

  return async function authproofGate(req, res, next) {
    try {
      const receiptHash = getReceiptHash(req);

      if (!receiptHash) {
        res.status(401).json({ error: 'AuthProof: x-receipt-hash header required' });
        return;
      }

      const action               = _getAction(req);
      const operatorInstructions = _getOperatorInstructions(req);
      const programHash          = _getProgramHash(req);

      const result = await verifier.check({
        receiptHash,
        action,
        operatorInstructions,
        ...(programHash !== undefined ? { programHash } : {}),
      });

      if (!result.allowed) {
        _onBlocked(req, res, result);
        return;
      }

      // Attach result to request for downstream handlers
      req.authproofResult = result;
      next();
    } catch (err) {
      res.status(500).json({ error: `AuthProof internal error: ${err.message}` });
    }
  };
}

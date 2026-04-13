/**
 * AuthProof LangChain middleware.
 *
 * Wraps a LangChain agent so every tool call goes through PreExecutionVerifier
 * before reaching the agent runtime. The agent never gets control unless all
 * six checks pass.
 *
 * @example
 * import { authproofMiddleware } from 'authproof-sdk/middleware/langchain'
 * const guardedAgent = authproofMiddleware(agent, {
 *   receiptHash,
 *   verifier,
 *   operatorInstructions,   // optional — defaults to receipt's stored instructions
 * })
 * // Every agent.invoke() and tool call goes through PreExecutionVerifier
 */

'use strict';

/**
 * Wrap a LangChain agent (or any object with an invoke() method) so that every
 * invocation is gated by PreExecutionVerifier.
 *
 * @param {object} agent                   — LangChain agent with invoke() method
 * @param {object} opts
 * @param {string}              opts.receiptHash          — delegation receipt hash
 * @param {PreExecutionVerifier} opts.verifier            — initialized verifier instance
 * @param {string}              [opts.operatorInstructions] — current operator instructions
 * @param {function}            [opts.getAction]          — extract action from invoke args; defaults to HTTP-style operation
 * @returns {object} guarded agent proxy
 */
export function authproofMiddleware(agent, {
  receiptHash,
  verifier,
  operatorInstructions,
  getAction,
} = {}) {
  if (!agent)       throw new Error('authproofMiddleware (langchain): agent is required');
  if (!receiptHash) throw new Error('authproofMiddleware (langchain): receiptHash is required');
  if (!verifier)    throw new Error('authproofMiddleware (langchain): verifier is required');

  const _defaultGetAction = (input) => ({
    operation: 'invoke',
    resource:  typeof input === 'string' ? input.slice(0, 64) : 'agent/invoke',
  });

  const _getAction = typeof getAction === 'function' ? getAction : _defaultGetAction;

  // Return a proxy that intercepts invoke() and any tool call() methods
  const handler = {
    get(target, prop) {
      const orig = target[prop];

      if (prop === 'invoke' || prop === 'call' || prop === 'run') {
        return async function guardedInvoke(...args) {
          const action = _getAction(args[0]);

          const result = await verifier.check({
            receiptHash,
            action,
            operatorInstructions,
          });

          if (!result.allowed) {
            const err = new Error(`[AuthProof] Action blocked: ${result.blockedReason}`);
            err.authproofResult = result;
            throw err;
          }

          return typeof orig === 'function'
            ? orig.apply(target, args)
            : orig;
        };
      }

      // For tool arrays — wrap each tool's call/invoke method
      if (prop === 'tools' && Array.isArray(orig)) {
        return orig.map(tool => authproofMiddleware(tool, {
          receiptHash,
          verifier,
          operatorInstructions,
          getAction: (input) => ({
            operation: 'tool_call',
            resource:  tool.name ?? 'unknown_tool',
          }),
        }));
      }

      return typeof orig === 'function' ? orig.bind(target) : orig;
    },
  };

  return new Proxy(agent, handler);
}

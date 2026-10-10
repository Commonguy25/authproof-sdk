/**
 * authproof — CommonJS entry point.
 *
 * The package is authored as native ESM (`src/authproof.js`, `"type": "module"`).
 * This thin shim re-exports the ESM entry for `require()` consumers via
 * `createRequire`, so both of these work:
 *
 *   const AuthProof = require('authproof');            // default export
 *   const { ActionLog, ScopeSchema } = require('authproof'); // named exports
 *
 * NOTE: synchronously requiring an ESM module requires Node.js >= 20.19.0 or
 * >= 22.12.0. On older Node versions `require('authproof')` throws
 * ERR_REQUIRE_ESM — use `import` instead. (`package.json` declares
 * `engines: node >= 18`, so ESM `import` remains the portable path there.)
 */

'use strict';

const { createRequire } = require('node:module');
const esmRequire = createRequire(__filename);

// `require(esm)` returns the module namespace object. Expose the default
// export as the module itself (mirroring the package's historical CJS shape)
// and copy the named exports onto it.
const ns = esmRequire('./authproof.js');
module.exports = ns && ns.default ? ns.default : ns;
if (ns && typeof ns === 'object') {
  for (const key of Object.keys(ns)) {
    if (key === 'default') continue;
    module.exports[key] = ns[key];
  }
}

// issue-receipt.mjs — generates a signed delegation receipt for testing
// Run: node issue-receipt.mjs
// Output: session-receipt.json in the current directory

import { writeFileSync } from 'fs';
import AuthProof from './node_modules/authproof/src/authproof.js';

const { privateKey, publicJwk } = await AuthProof.generateKey();

const { receipt, receiptId } = await AuthProof.create({
  scope:        'Read calendar events. Search the web for information.',
  boundaries:   'Do not send emails. Do not delete files. Do not access payment methods.',
  instructions: 'Summarize clearly. Cite sources. Stay within the authorized scope.',
  ttlHours:     4,
  privateKey,
  publicJwk,
});

const output = { receiptId, receipt, publicJwk };

writeFileSync('session-receipt.json', JSON.stringify(output, null, 2));
console.log('Receipt issued:', receiptId);
console.log('Written to: session-receipt.json');

// server.js — DRP sidecar for LangGraph Python integration
// Requires: authproof@latest, express  (authproof 2.1.1 confirmed working)
// Start: node server.js

import express from 'express';

// Direct file paths bypass the package exports map restriction.
// Both files ship inside the authproof package under src/.
import AuthProof, { RevocationRegistry } from './node_modules/authproof/src/authproof.js';
import { PreExecutionVerifier, DelegationLog } from './node_modules/authproof/src/pre-execution-verifier.js';

const app = express();
app.use(express.json());

// Generate a verifier key pair at startup.
// In production, load from a secrets manager and persist across restarts.
const { privateKey, publicJwk } = await AuthProof.generateKey();

const delegationLog      = new DelegationLog();
const revocationRegistry = new RevocationRegistry();
await revocationRegistry.init({ privateKey, publicJwk });

const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry });
await verifier.init({ privateKey, publicJwk });

// POST /register
// Call once at the start of each agent session.
// Registers a user-signed receipt so the verifier can look it up on /check calls.
// Body: { receiptId: string, receipt: object }
app.post('/register', (req, res) => {
  const { receiptId, receipt } = req.body;
  if (!receiptId || typeof receiptId !== 'string') {
    return res.status(400).json({ error: 'receiptId is required and must be a string' });
  }
  if (!receipt || typeof receipt !== 'object') {
    return res.status(400).json({ error: 'receipt is required and must be an object' });
  }
  delegationLog.add(receiptId, receipt);
  console.log(`[register] receipt registered: ${receiptId.slice(0, 30)}...`);
  res.json({ ok: true, receiptId });
});

// POST /check
// Call before every agent tool node.
// Returns { allowed, checks, blockedReason, verifiedAt, verifierSignature }.
// allowed is true (PERMIT) or false (DENY). blockedReason is null on PERMIT.
// Body: { receiptHash: string, action: string|object, operatorInstructions: string }
app.post('/check', async (req, res) => {
  const { receiptHash, action, operatorInstructions } = req.body;
  if (!receiptHash || typeof receiptHash !== 'string') {
    return res.status(400).json({ error: 'receiptHash is required and must be a string' });
  }
  if (!action) {
    return res.status(400).json({ error: 'action is required' });
  }
  try {
    const result = await verifier.check({ receiptHash, action, operatorInstructions });
    const label = result.allowed ? 'PERMIT' : `DENY (${result.blockedReason})`;
    console.log(`[check] ${label} — action: ${JSON.stringify(action).slice(0, 60)}`);
    res.json(result);
  } catch (err) {
    console.error('[check] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.DRP_PORT || 3000;
app.listen(PORT, () => {
  console.log(`DRP sidecar listening on port ${PORT}`);
  console.log(`  POST /register  — register a receipt before the session starts`);
  console.log(`  POST /check     — gate an action before the tool node executes`);
});

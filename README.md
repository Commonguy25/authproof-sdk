# AuthProof

**Cryptographically signed delegation receipts for AI agents.**

Define exactly what an AI agent can and can't do. Sign it. Share it. Verify it anywhere.

```js
import AuthProof from 'authproof';

const { privateKey, publicJwk } = await AuthProof.generateKey();

const { receiptId, systemPrompt } = await AuthProof.create({
  scope:        'Search the web for competitor pricing and summarize findings.',
  boundaries:   'Do not send emails. Do not make purchases.',
  instructions: 'Cite every source. Keep the report under 500 words.',
  ttlHours:     4,
  privateKey,
  publicJwk,
});

// Paste systemPrompt into any AI chat or agent system prompt
```

---

## The Problem

AI agents are taking real actions — browsing the web, scheduling meetings, sending emails, making purchases. But there's no standard way to define what an agent is authorized to do, or prove it after the fact.

AuthProof fixes that with a simple, tamper-proof delegation receipt:

- **Cryptographically signed** — ECDSA P-256 via the native Web Crypto API
- **Content-addressed** — SHA-256 proof ID that changes if anything is modified
- **Time-windowed** — auto-expires, no open-ended permissions
- **Instantly revocable** — one call to invalidate
- **Zero dependencies** — works in Node.js, browsers, Deno, Bun, Cloudflare Workers

---

## Install

```bash
npm install authproof
```

Or load directly in a browser / Deno:

```js
import AuthProof from 'https://esm.sh/authproof@1';
```

---

## Quick Start

### 1. Generate a key pair

```js
import AuthProof from 'authproof';

const { privateKey, publicJwk, privateJwk } = await AuthProof.generateKey();

// Store privateJwk securely (env var, secrets manager, etc.)
// publicJwk is safe to store anywhere
```

### 2. Create a receipt

```js
const { receipt, receiptId, systemPrompt } = await AuthProof.create({
  scope:        'Read the user\'s calendar for the next 7 days and identify conflicts.',
  boundaries:   'Do not create, edit, or delete calendar events. Do not read emails.',
  instructions: 'Present the 3 best available slots with a brief reason for each.',
  ttlHours:     1,           // Expires in 1 hour
  privateKey,
  publicJwk,
  agentId:      'calendar-agent-v1',   // optional
  metadata:     { requestedBy: 'user@example.com' },  // optional
});

console.log(receiptId);    // 64-char SHA-256 proof ID
console.log(systemPrompt); // ready-to-paste AI system prompt
```

### 3. Use the system prompt

Paste `systemPrompt` into any AI:

```
You are authorized to act within the following scope:

Read the user's calendar for the next 7 days and identify conflicts.

You must not:
Do not create, edit, or delete calendar events. Do not read emails.

Operator instructions:
Present the 3 best available slots with a brief reason for each.

This authorization is valid until: Apr 5, 2026, 3:00 PM
Authorization ID: a3f9c2...
```

### 4. Verify a receipt

```js
const result = await AuthProof.verify(receipt, receiptId, {
  action: 'Check calendar for next Tuesday and find a free hour',
});

if (result.authorized) {
  console.log('✓ Action authorized');
} else {
  console.log('✗ Denied:', result.checks.filter(c => !c.passed));
}
```

---

## API Reference

### `AuthProof.generateKey()`

Generate a new ECDSA P-256 signing key pair.

```js
const { privateKey, publicJwk, privateJwk } = await AuthProof.generateKey();
```

Returns:
- `privateKey` — `CryptoKey` for signing
- `publicJwk` — plain object, safe to store publicly
- `privateJwk` — plain object, **store securely**

---

### `AuthProof.importPrivateKey(privateJwk)`

Load a signing key from a stored JWK (e.g., from an env var).

```js
const privateJwk = JSON.parse(process.env.AUTHPROOF_PRIVATE_JWK);
const privateKey = await AuthProof.importPrivateKey(privateJwk);
```

---

### `AuthProof.create(options)`

Create a signed delegation receipt.

| Option | Type | Required | Description |
|---|---|---|---|
| `scope` | string | ✓ | What the AI is authorized to do |
| `boundaries` | string | ✓ | What the AI must never do |
| `instructions` | string | ✓ | How the AI should approach the task |
| `ttlHours` | number | — | Validity window in hours (default: `1`) |
| `privateKey` | CryptoKey | ✓ | ECDSA P-256 signing key |
| `publicJwk` | object | ✓ | Corresponding public key JWK |
| `agentId` | string | — | Optional agent identifier |
| `metadata` | object | — | Optional arbitrary metadata |

Returns `{ receipt, receiptId, systemPrompt }`.

---

### `AuthProof.verify(receipt, receiptId, options?)`

Verify a receipt locally — no network required.

```js
const result = await AuthProof.verify(receipt, receiptId, {
  revoked: false,   // pass true if you've marked it revoked in your store
  action:  'Proposed action text to scope-check',
});
```

Returns:
```js
{
  authorized: true | false,
  result: 'Human-readable verdict',
  checks: [
    { name: 'Not revoked',       passed: true,  detail: 'Active' },
    { name: 'Within time window',passed: true,  detail: 'Expires Apr 5, 2026' },
    { name: 'Signature valid',   passed: true,  detail: 'ECDSA P-256 verified' },
    { name: 'Receipt ID matches',passed: true,  detail: 'SHA-256 hash verified' },
    { name: 'Instructions intact',passed: true, detail: 'Instructions hash verified' },
    // if action provided:
    { name: 'Action within scope', passed: true, detail: '72% keyword match' },
    { name: 'Action not blocked',  passed: true, detail: '8% overlap with boundaries' },
  ],
  receiptContext: { scope, boundaries, operatorInstructions, timeWindow, ... }
}
```

---

### `AuthProof.buildSystemPrompt(receipt, receiptId, verifyUrl?)`

Build a ready-to-use system prompt from a receipt.

```js
const prompt = AuthProof.buildSystemPrompt(receipt, receiptId, 'https://authproof.dev');
```

---

### `AuthProof.checkScope(action, receipt)`

Quick keyword-overlap scope check without full verification.

```js
const { withinScope, scopeScore, boundaryScore } = AuthProof.checkScope(
  'Search Google for competitor pricing',
  receipt
);
// { withinScope: true, scopeScore: 72, boundaryScore: 5 }
```

---

### `AuthProof.isActive(receipt, revoked?)`

Returns `true` if the receipt is currently within its time window and not revoked.

```js
AuthProof.isActive(receipt);           // true
AuthProof.isActive(receipt, true);     // false (revoked)
```

---

### `AuthProof.secondsRemaining(receipt)`

Seconds until the receipt expires. Returns `0` if already expired.

```js
const secs = AuthProof.secondsRemaining(receipt);
console.log(`Expires in ${Math.floor(secs / 60)} minutes`);
```

---

### `AuthProof.receiptId(receipt)`

Compute the SHA-256 receipt ID from a receipt object.

```js
const id = await AuthProof.receiptId(receipt);
```

---

## Integrations

### LangChain / LangGraph

```js
const { systemPrompt, receiptId } = await AuthProof.create({ ... });

const messages = [
  { role: 'system', content: systemPrompt },
  { role: 'user',   content: userMessage },
];

// Pass to your LangChain chain or LangGraph node
```

### n8n

In a **Code node** before your AI node:

```js
const AuthProof = require('authproof');
const privateKey = await AuthProof.importPrivateKey(JSON.parse($env.AUTHPROOF_PRIVATE_JWK));
const publicJwk  = JSON.parse($env.AUTHPROOF_PUBLIC_JWK);

const { systemPrompt, receiptId } = await AuthProof.create({
  scope:        $input.item.json.scope,
  boundaries:   $input.item.json.boundaries,
  instructions: $input.item.json.instructions,
  ttlHours:     1,
  privateKey,
  publicJwk,
});

return [{ json: { ...$input.item.json, systemPrompt, receiptId } }];
```

### Express.js Middleware

```js
import { authproofMiddleware } from 'authproof/examples/integrations.js';

app.use('/api/agent', authproofMiddleware(receiptStore));
// Agent must send: X-AuthProof-Receipt-Id header
```

### Cloudflare Workers / Deno

```js
import AuthProof from 'https://esm.sh/authproof@1';
// All APIs work identically — uses native Web Crypto
```

---

## Receipt Schema

```json
{
  "delegationId":         "auth-1712345678901-a3f9c",
  "issuedAt":             "2026-04-05T14:00:00.000Z",
  "scope":                "Search the web for competitor pricing...",
  "boundaries":           "Do not send emails. Do not make purchases.",
  "timeWindow": {
    "start":              "2026-04-05T14:00:00.000Z",
    "end":                "2026-04-05T18:00:00.000Z"
  },
  "operatorInstructions": "Cite every source. Keep under 500 words.",
  "instructionsHash":     "a3f9c2d1...",
  "signerPublicKey": {
    "kty": "EC", "crv": "P-256", "x": "...", "y": "..."
  },
  "agentId":              "my-agent-v1",
  "metadata":             {},
  "signature":            "3045022100..."
}
```

The **receipt ID** is `SHA-256(JSON.stringify(receipt))` — if any field changes, the ID changes.

---

## Supabase Backend (optional)

For persistent receipts with remote verify/revoke, deploy the included Edge Functions.
See the SQL schema and function code in [`examples/integrations.js`](examples/integrations.js).

```sql
create table receipts (
  hash                 text primary key,
  delegation_id        text not null,
  scope                text not null,
  boundaries           text not null,
  time_window_start    timestamptz not null,
  time_window_end      timestamptz not null,
  operator_instructions text not null,
  instructions_hash    text not null,
  signer_public_key    jsonb not null,
  signature            text not null,
  issued_at            timestamptz not null,
  revoked              boolean default false,
  revoked_at           timestamptz
);
```

---

## Interactive Tool

Not a developer? Use the **[AuthProof web app](https://authproof.dev)** — no code required.  
Create, verify, and manage receipts visually in your browser.

---

## License

MIT — free for personal and commercial use.

---

## Contributing

PRs welcome. Run tests with:

```bash
node tests/authproof.test.js
```

40 tests, zero dependencies, zero build step required.

# AuthProof SDK

**A cryptographic delegation protocol for agentic AI — closes the user-to-operator trust gap that IETF frameworks leave open.**

---

## The Problem

Every existing IETF framework for agent identity — [AIP](https://identity.foundation/agent-identity-protocol/), [draft-klrc-aiagent-auth](https://datatracker.ietf.org/), [WIMSE](https://datatracker.ietf.org/wg/wimse/about/) — addresses service-to-agent trust: how a downstream service verifies that an agent is authorized to call it. None of them address **user-to-operator trust**.

The delegation chain in current agentic systems is:

```
User → Operator → Agent → Services
```

The user instructs the operator. The operator instructs the agent. But no cryptographic record of the user's original intent exists at the moment of delegation. The operator becomes a trusted third party with unchecked authority to expand, distort, or omit the user's instructions before they reach the agent.

The consequences:

- Users cannot prove what they authorized.
- Regulators have no audit trail.
- Courts have no evidence chain.
- Agents cannot distinguish legitimate operator instructions from compromised or rogue ones.

AuthProof fills this gap.

---

## The Core Primitive: Delegation Receipt

A **Delegation Receipt** is a signed Authorization Object anchored to a decentralized append-only log before any agent action begins. It contains four required fields:

### Scope

An explicit allowlist of permitted operations. Everything not listed is denied by default. Expressed in structured format — not natural language. Operation classes:

| Class | Description |
|---|---|
| `reads` | Read access to specified resources |
| `writes` | Write access to specified resources |
| `deletes` | Deletion of specified resources |
| `executes` | Execution of a specific program, referenced by its **static capability signature hash** |

`executes` is the most dangerous class. It must reference the cryptographic hash of a Safescript program's static capability DAG — not a name, URI, or description. No hash match means no execution.

### Boundaries

Explicit prohibitions that cannot be overridden by operator instructions under any circumstances. User-defined hard limits that survive any subsequent operator instruction.

### Time Window

Validity period of the authorization. The **log timestamp** is the time oracle — not the client clock. Client clocks are explicitly excluded from time validation.

### Operator Instruction Hash

A cryptographic hash of the operator's stated instructions at delegation time. If the operator subsequently instructs the agent differently, the discrepancy is detectable from the log without any additional trust assumptions.

The user signs this object with their private key via **WebAuthn/FIDO2 using the device secure enclave**. The signature is published to the log before any agent action. Every subsequent agent action references the receipt hash. Actions outside scope are cryptographically invalid.

---

## Trust Stack Architecture

Three protocol layers eliminate three trusted third parties:

### Layer 1 — Signed Capability Manifest *(removes trust in the registry)*

In the current MCP ecosystem, there is no cryptographic attestation that a tool server's descriptions match what it actually does. An operator can present an arbitrary schema.

The fix: tool servers publish a **cryptographically signed capability manifest** before any user authorization occurs. The `scope` field of the Delegation Receipt references the **hash of this manifest** — not the operator's self-reported schema. Divergence between server behavior and manifest is detectable at the log layer.

### Layer 2 — Delegation Receipt *(removes trust in the operator)*

The user's original intent is immutably recorded before operator instructions reach the agent. Operator deviation is provable.

### Layer 3 — Safescript Execution *(removes trust in the code)*

[Safescript](https://github.com/safescript) is an open-source sandboxed language for AI agent execution. Its static DAG structure means every program's full capability signature is computable before it runs — no dynamic dispatch, no runtime capability expansion.

The `executes` scope class references a specific Safescript capability signature hash. If the operator-supplied program does not match the committed hash, execution is blocked. The agent cannot be substituted with a different program after delegation.

---

## Quick Start

```js
import { AuthProof, Scope, KeyCustody } from 'authproof-sdk';

// Initialize with hardware-backed key custody (recommended)
const authproof = new AuthProof({
  custody: KeyCustody.HARDWARE, // WebAuthn/FIDO2 via device secure enclave
  log: 'https://log.authproof.dev',
});

// Define permitted operations — explicit allowlist, deny-by-default
const scope = new Scope()
  .allow('reads',  ['resource://calendar/events', 'resource://email/inbox'])
  .allow('writes', ['resource://calendar/events'])
  .deny('deletes', '*')
  .execute('sha256:a3f1c9d8...', { program: 'scheduler-v1.sg' }); // Safescript hash

// Hard limits that survive any operator instruction
const boundaries = {
  never: ['external-network', 'credential-store', 'payment-methods'],
};

// Issue the Delegation Receipt — anchored to log before any agent action
const receipt = await authproof.delegate({
  scope,
  boundaries,
  window: { duration: '8h' },           // validated against log timestamp
  operatorInstructions: instructionText, // hashed and committed
});

// receipt.id    — unique receipt identifier
// receipt.hash  — reference in every agent action
// receipt.log   — append-only log anchor

// Agent-side: validate an action against the receipt
const check = await authproof.validate({
  receiptHash: receipt.hash,
  action: { class: 'writes', resource: 'resource://calendar/events' },
});

if (!check.authorized) {
  // Out-of-scope action: surface a micro-receipt request to the user
  const microReceipt = await authproof.requestMicroReceipt({
    action: check.requestedAction,
    parent: receipt.hash,
  });
}
```

---

## Dynamic Authorization: Micro-Receipts

For tool calls not covered by the original Delegation Receipt, the agent cannot proceed silently. The protocol mandates:

1. Agent identifies an out-of-scope capability requirement.
2. Agent surfaces a **capability request** to the user describing the specific action.
3. User signs a **micro-receipt** covering only that action.
4. Agent proceeds, referencing the micro-receipt hash.

Unknown actions require explicit new user authorization. Dependency resolution follows the same rule — dependencies are checked against the hash of the dependency manifest committed at delegation time. Unexpected dependencies are a scope violation.

---

## Concurrent Agents

Each delegation event carries a unique receipt ID. Concurrent agents each reference their own receipt hash. They are distinguishable by receipt, not by agent identity.

---

## Key Management

| Model | Description | Recommended |
|---|---|---|
| **Hardware** | WebAuthn/FIDO2 via device secure enclave. Private key never leaves hardware. | **Yes — default** |
| **Delegated** | Trusted key manager holds the key on the user's behalf. | Environments without FIDO2 support |
| **Self-custody** | User holds and manages their own private key. | Advanced users, air-gapped workflows |

Hardware custody is the recommended default. The private key never leaves the secure enclave; signing is protected by device biometrics or PIN.

---

## Action Log

A Delegation Receipt defines what an AI agent is authorized to do. The **Action Log** records what it actually did — and makes any deviation instantly verifiable.

Every action an agent takes produces a signed, timestamped entry linked to the active receipt. Entries form a tamper-evident chain: each entry embeds the SHA-256 hash of the previous one, so any retroactive modification is detectable without a trusted third party. The `diff()` method is the audit primitive — it lines up the receipt's authorized scope against every recorded action and returns any deviations.

```js
import AuthProof, { ActionLog } from 'authproof-sdk';

// 1. Issue a delegation receipt as normal
const { privateKey, publicJwk } = await AuthProof.generateKey();

const { receipt, receiptId } = await AuthProof.create({
  scope:        'Search the web for competitor pricing. Read calendar events.',
  boundaries:   'Do not send emails. Do not make purchases.',
  instructions: 'Cite sources. Keep under 500 words.',
  ttlHours:     4,
  privateKey,
  publicJwk,
});

// 2. Initialize the action log with the agent's signing key
const log = new ActionLog();
await log.init({ privateKey, publicJwk });

// Register the receipt so diff() knows what was authorized
log.registerReceipt(receiptId, receipt);

// 3. Record each action the agent takes
const e1 = await log.record(receiptId, {
  operation:  'Search competitor pricing',
  resource:   'web/search',
  parameters: { query: 'rival.com pricing 2024' },
});

const e2 = await log.record(receiptId, {
  operation:  'Read calendar events',
  resource:   'calendar/events',
  parameters: { range: 'this_week' },
});

// 4. Verify an individual entry (signature + chain integrity)
const check = await log.verify(e1.entryId);
// { valid: true, reason: 'Signature and chain integrity verified' }

// 5. Diff: authorized scope vs. everything that was done
const report = log.diff(receiptId);
// {
//   clean:        true,
//   totalEntries: 2,
//   compliant:    [{ entry: {...}, reason: '"Search competitor pricing" matches authorized scope' }, ...],
//   violations:   [],
// }

// A scope violation surfaces immediately
await log.record(receiptId, { operation: 'Send email', resource: 'email/outbox' });
const auditReport = log.diff(receiptId);
// auditReport.violations[0].reason →
//   '"Send email" outside authorized scope (0% scope match, 92% boundary overlap)'
```

### Action Log API

| Method | Description |
|---|---|
| `new ActionLog()` | Create a new log instance. State is in-memory. |
| `log.init({ privateKey, publicJwk })` | Initialize with the agent's ECDSA P-256 key. Required before `record()`. |
| `log.registerReceipt(receiptHash, receipt)` | Register a receipt for scope comparison. Required before `diff()`. |
| `log.record(receiptHash, action)` | Append a signed, chain-linked entry. Returns the sealed entry. |
| `log.verify(entryId)` | Verify one entry's signature and chain position. Returns `{ valid, reason }`. |
| `log.getEntries(receiptHash)` | All entries for a receipt in chronological order. |
| `log.diff(receiptHash)` | Compare all entries against the receipt's scope. Returns `{ compliant, violations, clean }`. |
| `log.verifyTimestamp(entryId)` | Verify the RFC 3161 token on an entry. Returns `{ verified, type, reason, timestamp }`. |

### Timestamps

By default, `record()` obtains a cryptographically signed timestamp from the [freetsa.org](https://freetsa.org) RFC 3161 Trusted Timestamp Authority (TSA) and embeds the token in every log entry. RFC 3161 tokens are issued by a third-party TSA, signed with the TSA's private key, and independently verifiable — they cannot be forged or backdated by the recording party.

If the TSA request fails (network unavailable, timeout), the entry is still recorded and flagged with `timestampType: 'UNVERIFIED_TIMESTAMP'`. Callers can distinguish the two cases and act accordingly. Use `log.verifyTimestamp(entryId)` to independently verify a token after the fact.

For environments where outbound network access is restricted, pass `tsaUrl: null` to `log.init()` to disable TSA requests; all entries will be `UNVERIFIED_TIMESTAMP`.

### Important

Always define scope using explicit `allowedActions` arrays. Text-based scope matching is available for development only and is not suitable for production or compliance contexts.

---

## Installation

```bash
npm install authproof-sdk
```

- npm: https://www.npmjs.com/package/authproof-sdk
- GitHub: https://github.com/Commonguy25/authproof-sdk
- Protocol specification: [`WHITEPAPER.md`](WHITEPAPER.md)

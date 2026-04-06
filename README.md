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

## Installation

```bash
npm install authproof-sdk
```

- npm: https://www.npmjs.com/package/authproof-sdk
- GitHub: https://github.com/Commonguy25/authproof-sdk
- Protocol specification: [`WHITEPAPER.md`](WHITEPAPER.md)

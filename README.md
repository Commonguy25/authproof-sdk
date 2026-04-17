# AuthProof SDK

**A cryptographic delegation protocol for agentic AI — closes the user-to-operator trust gap that IETF frameworks leave open.**

---

## Pre-Execution Verifier

**The deterministic gate that runs before any agent action executes.**

The `PreExecutionVerifier` sits outside the agent runtime. The runtime never gets control until the verifier passes. A compromised or malicious agent cannot skip it — it runs before the runtime starts.

### Why it matters

Traditional authorization checks happen inside the agent runtime. If the runtime is compromised, those checks can be skipped, reordered, or bypassed. `PreExecutionVerifier` eliminates this attack surface by moving authorization outside the runtime entirely. The agent only executes if — and only if — all six sequential checks pass first.

### Quickstart

```js
import { PreExecutionVerifier, DelegationLog } from 'authproof-sdk/pre-execution-verifier'
import { RevocationRegistry } from 'authproof-sdk'

// 1. Set up the gate
const delegationLog      = new DelegationLog()
const revocationRegistry = new RevocationRegistry()
await revocationRegistry.init({ privateKey, publicJwk })

const verifier = new PreExecutionVerifier({ delegationLog, revocationRegistry })
await verifier.init({ privateKey: verifierKey, publicJwk: verifierPub })

// 2. Register your delegation receipt
delegationLog.add(receiptHash, receipt)

// 3. Gate every action — before the agent runs
const result = await verifier.check({
  receiptHash,
  action:               { operation: 'read', resource: 'calendar' },
  operatorInstructions: 'Summarize meetings. Stay within scope.',
  programHash,          // optional: prevents code substitution attacks
})

if (!result.allowed) {
  throw new Error(`Blocked: ${result.blockedReason}`)
}
// Agent runtime only reaches here after all six checks pass
```

### Six sequential checks (stops at first failure)

| # | Check | Blocks when |
|---|-------|-------------|
| 1 | Receipt signature | ECDSA P-256 signature invalid or receipt tampered |
| 2 | Revocation | Receipt has been revoked via `RevocationRegistry` |
| 3 | Time window | Receipt expired or not yet valid (log timestamp oracle, not client clock) |
| 4 | Scope | Action not in `ScopeSchema.allowedActions` or fails text-based scope matching |
| 5 | Operator instructions | Current instructions don't match the hash locked into the receipt at issuance |
| 6 | Program hash | Provided `programHash` doesn't match the committed `executes` hash (code substitution prevention) |

Every check result — pass or fail — is automatically logged to an immutable `ActionLog` signed with the verifier's own key.

### Middleware integrations

Drop-in wrappers for common frameworks. Each wrapper gates every call through `PreExecutionVerifier` before the wrapped code executes.

- **[LangChain](src/middleware/langchain.js)** — wraps any agent with an `invoke()` method
- **[Express/HTTP](src/middleware/express.js)** — request middleware for any Express-compatible framework
- **[Generic function wrapper](src/middleware/generic.js)** — wraps any async function

```js
// LangChain
import { authproofMiddleware } from 'authproof-sdk/middleware/langchain'
const guardedAgent = authproofMiddleware(agent, { receiptHash, verifier })

// Express
import { authproofMiddleware } from 'authproof-sdk/middleware/express'
app.use(authproofMiddleware({ verifier, getReceiptHash: (req) => req.headers['x-receipt-hash'] }))

// Any function
import { guardFunction } from 'authproof-sdk/middleware/generic'
const guardedExecute = guardFunction(executeAction, { receiptHash, verifier, action })
```

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

### Production Warning

Timestamps in v1 use the client clock. For compliance or legal contexts where timestamps must be independently verifiable, replace with an RFC 3161 trusted timestamp authority before deploying in production.

### Important

Always define scope using explicit `allowedActions` arrays. Text-based scope matching is available for development only and is not suitable for production or compliance contexts.

---

## Confidential Deployment

Run AuthProof agents inside hardware-attested Trusted Execution Environments (TEEs). The `ConfidentialRuntime` class binds delegation receipts to enclave measurements, so any substitution of model weights, verifier code, or platform is detectable before execution.

### Hardware requirements

- **Intel TDX** — Intel Ice Lake Xeon or newer (4th-gen Xeon Scalable). Azure DCdsv3-series, GCP C3 Confidential VMs.
- **AMD SEV-SNP** — AMD EPYC 3rd-gen (Milan) or newer. Azure DCasv5-series, AWS m6a with Nitro Enclaves.

### Create a receipt with TEE measurement binding

```javascript
import { AuthProofClient } from 'authproof-sdk';

const client = new AuthProofClient();
const { receipt } = await client.delegate({
  scope: 'Summarize calendar events',
  operatorInstructions: 'Stay within scope.',
  expiresIn: '2h',
  privateKey,
  publicJwk,
  teeConfig: {
    platform:     'intel-tdx',
    verifierHash: verifierCodeHash,   // SHA-256 of your verifier binary
    modelHash:    modelWeightsHash,   // SHA-256 of model weights
  },
});
// receipt.teeMeasurement.expectedMrenclave is now bound to the receipt
```

### Deploy on Azure Confidential Computing (Intel TDX)

```javascript
import { ConfidentialRuntime } from 'authproof-sdk';

// Generate deployment configuration
const config = ConfidentialRuntime.azureTDXConfig({
  receiptHash,
  verifierHash,
  modelHash,
  region: 'eastus',
});
// config.vmSize === 'Standard_DC4ds_v3'
// config.attestationEndpoint === 'https://sharedeus.eus.attest.azure.net'
// config.receiptBinding binds the receipt to the VM measurement

// At runtime inside the VM:
const runtime = new ConfidentialRuntime({
  platform:  'intel-tdx',
  verifier,
  actionLog,
});
const result = await runtime.launch({
  receiptHash, agentFn, operatorInstructions,
  verifierHash, modelHash,
  teeMeasurement: receipt.teeMeasurement,   // mismatch blocks execution
});
```

Azure SKU requirements: `Standard_DC4ds_v3` or larger from the DCdsv3-series. Enable Confidential OS disk encryption. Use Microsoft Azure Attestation (MAA) shared endpoint for quote verification.

### Deploy on AWS Nitro Enclaves

```javascript
const config = ConfidentialRuntime.awsNitroConfig({
  receiptHash,
  verifierHash,
  modelHash,
  region: 'us-east-1',
});
// config.instanceType === 'c6a.xlarge'
// config.enclaveOptions.enabled === true
// config.pcr0 is the combined receipt+verifier+model measurement
```

AWS requirements: `c6a.xlarge` or larger with `--enclave-options Enabled`. Use `nitro-cli` to build and run the enclave image. PCR0 in the attestation document must match `config.pcr0` for the receipt binding to be valid.

### Deploy on Kubernetes

```javascript
const manifest = ConfidentialRuntime.kubernetesConfig({
  receiptHash,
  platform:   'intel-tdx',
  namespace:  'production',
});
// manifest is a full K8s List containing:
//   - Pod with TDX node selector and attestation sidecar
//   - ServiceAccount with minimal RBAC
//   - ConfigMap with receipt binding
```

Apply with `kubectl apply -f` after serializing to YAML. The node selector `intel.feature.node.kubernetes.io/tdx: "true"` requires the Intel Device Plugin for Kubernetes.

### eBPF kernel module — help wanted

The TEE enforcement layer is complete through the userspace side (`ConfidentialRuntime`, `TokenPreparer`). The final enforcement step — validating the signed capability token on every syscall via an eBPF LSM hook — requires a kernel module that is open for contribution.

Engineers with eBPF LSM experience (Isovalent, Red Canary, or similar) are especially welcome. Open an issue or PR at https://github.com/Commonguy25/authproof-sdk/issues

---

## Installation

```bash
npm install authproof-sdk
```

- npm: https://www.npmjs.com/package/authproof-sdk
- GitHub: https://github.com/Commonguy25/authproof-sdk
- Protocol specification: [`WHITEPAPER.md`](WHITEPAPER.md)

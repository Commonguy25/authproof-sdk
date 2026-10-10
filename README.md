# AuthProof SDK

AuthProof is an audit and attribution layer for AI agents. It lets you prove what a user authorized before the agent acted, and it records what the agent actually did against that authorization.

The mechanism is simple. The user signs a delegation receipt with their own private key. The receipt carries scope, boundaries, operator instructions (hashed), and a time window. A pre-execution verifier checks each proposed action against the receipt, and an append-only action log records what ran. The result is evidence: what was authorized, diffed against what happened.

This is not a security control against a malicious operator. The verifier runs in the same process as the agent, and a dishonest operator can simply not call it. No cryptographic property can fix that from inside the same runtime. AuthProof proves authorization for deployments that run the gate, and it gives auditors, regulators, and users a record they can check after the fact.

**What makes it different:**

- **The user is the signing authority.** The authorization object is signed with the user's private key, not written into an operator-managed policy. The signed scope and program hash in the receipt always win over operator log metadata. If operator metadata conflicts with the signed receipt, the gate denies the action instead of following the metadata.

- **Two-phase model-state commitment.** The model is measured at authorization time and re-measured before execution. These measurements are software-computed and self-attested, not hardware-rooted. They are tamper-evidence for honest deployments, not proof against a hostile host.

- **Provider update versus malicious substitution, distinguished.** Model-state changes classify into legitimate provider updates (`PROVIDER_UPDATE_REQUIRES_REAUTH`) and unauthorized swaps (`MALICIOUS_MODEL_SUBSTITUTION`). Each produces a machine-readable denial reason code identifying which components changed.

## Pre-Execution Verifier

**The gate that runs before any agent action executes.**

`PreExecutionVerifier.check()` verifies each proposed action against the signed delegation receipt. Route every action through it in your agent's process, before the action runs. The verifier signs its own allow/deny decisions into an audit log, so every result is part of the record.

One hard truth to build around: the verifier is same-process. It verifies proof; it cannot stop an operator who refuses to call it. Use it where you want evidence, not where you need enforcement against the operator running the code.

### Why it matters

Most agent authorization today is the operator’s word: a policy the operator wrote, enforced by code the operator controls. When something goes wrong, there is no record of what the user actually authorized, only the operator’s reconstruction of it. AuthProof flips that. The user’s signed receipt predates execution, and the action log records what ran against it. The question “did the user authorize this?” becomes checkable instead of arguable.

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

// 3. Gate every action â before the agent runs
const result = await verifier.check({
  receiptHash,
  action:               { operation: 'read', resource: 'calendar' },
  operatorInstructions: 'Summarize meetings. Stay within scope.',
  programHash,          // optional: prevents code substitution attacks
})

if (!result.allowed) {
  throw new Error(`Blocked: ${result.blockedReason}`)
}
// Agent runtime only reaches here after all thirteen checks pass
```

### Thirteen sequential checks (stops at first failure)

| # | Check | Blocks when |
|---|-------|-------------|
| 1 | Receipt signature | ECDSA P-256 signature invalid or receipt tampered |
| 2 | Revocation | Receipt has been revoked via `RevocationRegistry` (cascade: a revoked ancestor denies its descendants) |
| 3 | Time window | Receipt expired or not yet valid (log timestamp oracle, not client clock) |
| 4 | Scope | Action not in `ScopeSchema.allowedActions`; without a structured schema, keyword matching is advisory-only and never gates |
| 5 | Operator instructions | Provided instructions don't match the hash locked into the receipt at issuance; skipped with a warning when the caller omits them |
| 6 | Program hash | Provided `programHash` doesn't match the committed `executes` hash (optional) |
| 7 | Session risk | Trust/risk thresholds exceeded (optional) |
| 8 | Tool schema integrity | `toolSchemaHash` doesn't match the receipt (optional) |
| 9 | Model state | Model drift detected (optional; software-computed, self-attested measurement) |
| 10 | Tool output hash binding | Output hash doesn't match the receipt (optional) |
| 11 | Instruction provenance | Instruction source not in the receipt's `trustedSources` (optional) |
| 14 | Parent scope containment | Sub-receipt exceeds the parent's scope (sub-receipts only); revoking any ancestor denies the child at check time |
| 15 | Authority state drift | `authorityStateCommitment` drifted since issuance (optional) |

Slots 12 and 13 were never implemented; the numbering gap is historical. The gate stops at the first failed check. One-time-use consumption runs last, after every check passes, so a consumption slot is never burned on a receipt that would be denied for another reason.

Every check result, pass or fail, is automatically logged to an immutable `ActionLog` signed with the verifier's own key.

**Signed data wins.** The signed receipt's scope and program hash always win over operator log metadata. If unsigned `DelegationLog` metadata disagrees with the signed receipt, the gate denies the action (`SCOPE_METADATA_MISMATCH` / `PROGRAM_METADATA_MISMATCH`). Log metadata is a fallback only when the receipt carries no structured scope or signed `executes` value.

**Guided delegation is guided by observation.** `ScopeDiscovery.guided()` and `AuthProofClient.delegateGuided()` run `observe → generateScope → approve → finalize` in one call, and the full observed draft scope is auto-approved with no human review. For a genuine human-authorization moment, pass the `reviewDraft` hook (approve, modify, or decline the draft before issuance) or run the steps separately with an explicit `approve()`.

### Middleware integrations

Drop-in wrappers for common frameworks. Each wrapper gates every call through `PreExecutionVerifier` before the wrapped code executes.

- **[LangChain](src/middleware/langchain.js)** â wraps any agent with an `invoke()` method
- **[Express/HTTP](src/middleware/express.js)** â request middleware for any Express-compatible framework
- **[Generic function wrapper](src/middleware/generic.js)** â wraps any async function

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

## What It Is Not

Read this before deciding what AuthProof proves for you.

- **Not a barrier to a malicious operator.** The verifier runs in the same process as the agent. Nothing in the SDK stops a dishonest operator from skipping the gate. AuthProof is proof for deployments that run the gate, not control for deployments that refuse to.
- **No hardware attestation.** TEE and model-state features are software-computed, self-attested measurements for audit and tamper-evidence in honest deployments. Hardware guarantees require real TEE hardware and are not provided by this SDK.
- **Signatures are not canonical.** The JS SDK signs insertion-order JSON. Cross-implementation verification breaks, and a JWS/COSE canonical profile is future work. The Python SDK is a partial port, not a mirror: it is wire-incompatible with the JavaScript SDK (different field names, signature encoding, and canonicalization), so the two cannot verify each other's receipts.
- **Timestamps are presence-checked.** The SDK confirms an RFC 3161 token's bytes contain the entry digest. It does not verify the TSA's cryptographic signature or certificate chain. Full RFC 3161 signature verification is out of scope.
- **Text-scope matching is advisory only.** Without a structured `ScopeSchema`, scope matching is a keyword-overlap signal recorded for observability. It never allows or denies. Real scope enforcement requires a `ScopeSchema`.
- **Check 5 can be skipped.** If the caller does not supply the operator's claimed instructions, check 5 is skipped with a warning. Operator drift is not verified for that call. Always pass `operatorInstructions` when drift detection matters.
- **No key management story.** Key rotation, KMS/HSM integration, and compromise procedures are not part of this SDK.
- **No receipt nonce.** Single-use semantics need a durable `ConsumptionStore` (a Redis adapter is included). Without one, replay detection across processes is not guaranteed.

## The Problem

Every existing IETF framework for agent identity â [AIP](https://identity.foundation/agent-identity-protocol/), [draft-klrc-aiagent-auth](https://datatracker.ietf.org/), [WIMSE](https://datatracker.ietf.org/wg/wimse/about/) â addresses service-to-agent trust: how a downstream service verifies that an agent is authorized to call it. None of them address **user-to-operator trust**.

The delegation chain in current agentic systems is:

```
User â Operator â Agent â Services
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

An explicit allowlist of permitted operations. Everything not listed is denied by default. Expressed in structured format â not natural language. Operation classes:

| Class | Description |
|---|---|
| `reads` | Read access to specified resources |
| `writes` | Write access to specified resources |
| `deletes` | Deletion of specified resources |
| `executes` | Execution of a specific program, referenced by its **static capability signature hash** |

`executes` is the most dangerous class. It must reference the cryptographic hash of a Safescript program's static capability DAG â not a name, URI, or description. No hash match means no execution.

### Boundaries

Explicit prohibitions that cannot be overridden by operator instructions under any circumstances. User-defined hard limits that survive any subsequent operator instruction.

### Time Window

Validity period of the authorization. The **log timestamp** is the time oracle â not the client clock. Client clocks are explicitly excluded from time validation.

### Operator Instruction Hash

A cryptographic hash of the operator's stated instructions at delegation time. If the operator subsequently instructs the agent differently, the discrepancy is detectable from the log without any additional trust assumptions.

The user signs this object with their private key. Hardware-backed signing via WebAuthn/FIDO2 and the device secure enclave is the recommended custody model; software key generation is also supported. The signature is published to the log before any agent action. Every subsequent agent action references the receipt hash. Actions routed through the gate that fall outside scope are denied.

---

## Trust Stack Architecture

Three protocol layers eliminate three trusted third parties:

### Layer 1 â Signed Capability Manifest *(removes trust in the registry)*

In the current MCP ecosystem, there is no cryptographic attestation that a tool server's descriptions match what it actually does. An operator can present an arbitrary schema.

The fix: tool servers publish a **cryptographically signed capability manifest** before any user authorization occurs. The `scope` field of the Delegation Receipt references the **hash of this manifest** â not the operator's self-reported schema. Divergence between server behavior and manifest is detectable at the log layer.

### Layer 2 â Delegation Receipt *(removes trust in the operator)*

The user's original intent is immutably recorded before operator instructions reach the agent. Operator deviation is provable.

### Layer 3 â Safescript Execution *(removes trust in the code)*

[Safescript](https://github.com/safescript) is an open-source sandboxed language for AI agent execution. Its static DAG structure means every program's full capability signature is computable before it runs â no dynamic dispatch, no runtime capability expansion.

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

// Define permitted operations â explicit allowlist, deny-by-default
const scope = new Scope()
  .allow('reads',  ['resource://calendar/events', 'resource://email/inbox'])
  .allow('writes', ['resource://calendar/events'])
  .deny('deletes', '*')
  .execute('sha256:a3f1c9d8...', { program: 'scheduler-v1.sg' }); // Safescript hash

// Hard limits that survive any operator instruction
const boundaries = {
  never: ['external-network', 'credential-store', 'payment-methods'],
};

// Issue the Delegation Receipt â anchored to log before any agent action
const receipt = await authproof.delegate({
  scope,
  boundaries,
  window: { duration: '8h' },           // validated against log timestamp
  operatorInstructions: instructionText, // hashed and committed
});

// receipt.id    â unique receipt identifier
// receipt.hash  â reference in every agent action
// receipt.log   â append-only log anchor

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

Unknown actions require explicit new user authorization. Dependency resolution follows the same rule â dependencies are checked against the hash of the dependency manifest committed at delegation time. Unexpected dependencies are a scope violation.

---

## Concurrent Agents

Each delegation event carries a unique receipt ID. Concurrent agents each reference their own receipt hash. They are distinguishable by receipt, not by agent identity.

---

## Key Management

| Model | Description | Recommended |
|---|---|---|
| **Hardware** | WebAuthn/FIDO2 via device secure enclave. Private key never leaves hardware. | **Yes â default** |
| **Delegated** | Trusted key manager holds the key on the user's behalf. | Environments without FIDO2 support |
| **Self-custody** | User holds and manages their own private key. | Advanced users, air-gapped workflows |

Hardware custody is the recommended default. The private key never leaves the secure enclave; signing is protected by device biometrics or PIN.

---

## Action Log

A Delegation Receipt defines what an AI agent is authorized to do. The **Action Log** records what it actually did â and makes any deviation instantly verifiable.

Every action an agent takes produces a signed, timestamped entry linked to the active receipt. Entries form a tamper-evident chain: each entry embeds the SHA-256 hash of the previous one, so any retroactive modification is detectable without a trusted third party. The `diff()` method is the audit primitive â it lines up the receipt's authorized scope against every recorded action and returns any deviations.

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
// auditReport.violations[0].reason â
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

Timestamps in v1 use the client clock. The SDK can request RFC 3161 trusted timestamps from a configured TSA, but timestamp verification is presence-only: the SDK confirms the token bytes contain the entry's digest. It does not validate the TSA's signature or certificate chain, so a forged token embedding the digest would pass. For compliance or legal contexts that require real trusted timestamps, pair the SDK with a TSA you trust and verify its tokens with an independent RFC 3161 implementation. Full TSA-signature verification is out of scope for this SDK.

### Important

Always define scope using explicit `allowedActions` arrays. Text-based scope matching is available for development only and is not suitable for production or compliance contexts.

---

## Confidential Deployment

Bind delegation receipts to enclave measurements. On real TDX or SEV-SNP hardware, those measurements come from the platform. Everywhere else, and in every default configuration, they are software-computed and self-attested.

Honesty note: `ConfidentialRuntime` computes `mrenclave` as SHA-256 over caller-supplied strings, and its "TDX quote" is a deterministic hash, not a hardware-signed attestation. `TEERuntime` defaults to `platform: 'simulation'` (signed mock attestation). `launch()` does not execute inside a hardware TEE. These features give you tamper-evidence for audit in honest deployments. They are not hardware-rooted attestation, and real hardware guarantees require real TEE hardware.

### Hardware requirements

- **Intel TDX** â Intel Ice Lake Xeon or newer (4th-gen Xeon Scalable). Azure DCdsv3-series, GCP C3 Confidential VMs.
- **AMD SEV-SNP** â AMD EPYC 3rd-gen (Milan) or newer. Azure DCasv5-series, AWS m6a with Nitro Enclaves.

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

### eBPF kernel module â help wanted

The TEE enforcement layer is complete through the userspace side (`ConfidentialRuntime`, `TokenPreparer`). The final enforcement step â validating the signed capability token on every syscall via an eBPF LSM hook â requires a kernel module that is open for contribution.

Engineers with eBPF LSM experience (Isovalent, Red Canary, or similar) are especially welcome. Open an issue or PR at https://github.com/Commonguy25/authproof-sdk/issues

---

## Examples

Two runnable examples live in the `examples/` directory.

**[`examples/langchain-example.js`](examples/langchain-example.js)** â Shows the full LangChain integration path: generate a key pair, issue a delegation receipt, initialize `PreExecutionVerifier`, and wrap any agent with `authproofMiddleware` so every `invoke()` call is gated before the agent runtime gets control. Includes a mock agent you can run immediately and the exact code pattern for a real `AgentExecutor`. Run with `npm run example:langchain`.

**[`examples/webauthn-example.html`](examples/webauthn-example.html)** â A self-contained three-card browser demo of the full delegation flow. Card 1 lets you define scope, boundaries, and operator instructions, then signs a receipt with a local key (swap in `navigator.credentials` for real WebAuthn). Card 2 displays the receipt ID, expiry, system prompt, and raw JSON. Card 3 lets you type any proposed action and verify it against the receipt in real time, showing each check result. Open directly in a browser â no build step required.

---

## Tests

- JavaScript: **1,392 tests across 23 suites, all passing** (`npm test`). Verified with a fresh run on this branch, October 9, 2026.
- Python (`sdk-python/`): **36 tests, all passing** (`pytest tests/` in a clean venv with `pytest-asyncio` installed). Verified with a fresh run on this branch, October 9, 2026.

Test counts drift when hard-coded, so treat these as a snapshot of this branch, not a promise. If a number above stops matching the suite, the suite is right.

## Install Notes

- `require('authproof')` needs Node >= 20.19 or >= 22.12 (synchronous `require(esm)`). On older Node, use `import`. The `engines` field still lists `>=18.0.0`.
- The Python SDK (`authproof-py`) is a partial port of the JS primitives for Python clients. It is wire-incompatible with the JavaScript SDK, so one cannot verify the other's receipts.

## Installation

```bash
npm install authproof-sdk
```

- npm: https://www.npmjs.com/package/authproof-sdk
- GitHub: https://github.com/Commonguy25/authproof-sdk
- Protocol specification: [`WHITEPAPER.md`](WHITEPAPER.md)

# AuthProof: A Cryptographic Delegation Protocol for Agentic AI Systems

**Version 0.1 — April 2026**

---

## Abstract

Agentic AI systems introduce a novel trust problem that existing identity and authorization frameworks do not address: the gap between a user's original authorization intent and the instructions an operator delivers to an agent on the user's behalf. This paper describes the AuthProof protocol, which uses cryptographic delegation receipts anchored to a decentralized append-only log to make user-to-operator trust verifiable and operator deviation from stated instructions provable. The protocol comprises three interlocking layers — a signed capability manifest at the discovery layer, a Delegation Receipt at the authorization layer, and Safescript-bound execution at the runtime layer — that together eliminate three categories of trusted third party from the agentic trust stack. We describe the full protocol design, analyze its security properties, and compare it to existing approaches including WIMSE, AIP, and OAuth 2.0 Token Exchange.

---

## 1. Problem Statement

### 1.1 The Agentic Delegation Chain

Agentic AI systems involve at minimum three principals:

- **User** — the human whose resources and authority are being delegated
- **Operator** — the developer or company who builds and deploys the agent
- **Agent** — the AI system taking actions on the user's behalf

The delegation chain is:

```
User → Operator → Agent → Services
```

The user grants authority to the operator. The operator translates that authority into instructions for the agent. The agent acts on downstream services. At each step, fidelity to the user's original intent depends entirely on the honesty and competence of the intermediate party.

### 1.2 The Missing Cryptographic Anchor

In current agentic deployments, the user's authorization is captured in natural language — a chat message, a consent checkbox, a terms-of-service agreement. None of these produce a cryptographically verifiable record of what the user actually authorized at the moment of delegation. There is no artifact that can be independently audited, presented in court, or verified by the agent itself.

This creates three compounding problems:

**The repudiation problem.** If an agent takes an action the user did not authorize, there is no cryptographic evidence of what the user did authorize. The operator's account of the authorization is the only record, and it is unverifiable.

**The drift problem.** Operators may update their system prompts, change agent behavior, or respond to external pressure (legal, commercial, regulatory) in ways that diverge from the user's original authorization. Nothing in the current architecture makes this divergence detectable.

**The audit problem.** Regulators auditing agentic behavior have no evidence chain connecting an agent's actions to a user's original consent. The operator's logs are the only source of truth, and those logs are controlled by the party whose conduct is under scrutiny.

### 1.3 IETF Framework Analysis

Several IETF working groups have produced or are producing specifications for agent identity and authorization. Each addresses a different trust boundary — none addresses user-to-operator trust.

**WIMSE (Workload Identity in Multi-System Environments)** addresses how workloads authenticate to each other in multi-cloud and multi-service environments. The trust problem it solves is service-to-service: can service B verify that the request it received came from a legitimate workload A? It does not address whether the workload was authorized by the user to make that request in the first place.

**AIP (Agent Identity Protocol)** addresses how agents establish and present identity to services they call. It defines credential structures for agent principals. Like WIMSE, its trust model is downstream of the operator — it assumes the operator has correctly represented the user's authorization and concerns itself with how that representation is communicated to services.

**draft-klrc-aiagent-auth** addresses OAuth-style authorization flows for AI agents, allowing agents to obtain access tokens for downstream APIs. It solves the service authorization problem — whether the agent can call an API — but not the delegation integrity problem — whether the operator's instructions to the agent faithfully represent the user's authorization.

**OAuth 2.0 Token Exchange (RFC 8693)** and **Rich Authorization Requests (RFC 9396)** provide mechanisms for scoped token issuance and delegation chains between services, but they operate at the service layer. The user's intent is represented by the OAuth grant, which is under operator control.

The gap is consistent: all existing frameworks take the operator's faithful representation of user intent as a precondition. AuthProof addresses that precondition directly.

---

## 2. Protocol Design

### 2.1 The Delegation Receipt

The central artifact of the AuthProof protocol is the **Delegation Receipt** — a signed Authorization Object containing four required fields.

**Scope.** An explicit allowlist of permitted operations expressed in structured format. Natural language is prohibited in the scope field because it is ambiguous, subject to interpretation, and cannot be used for deterministic validation. Operations are classified into four classes: `reads`, `writes`, `deletes`, and `executes`. An agent may only perform operations that appear in the scope. Everything else is denied by default.

The `executes` class is treated separately because it is the most dangerous. It must reference the cryptographic hash of a specific program's static capability signature rather than a program name or URI. The implications of this design are discussed in Section 3.3.

**Boundaries.** Explicit prohibitions that survive any subsequent operator instruction. Where scope defines what is permitted, boundaries define what is forbidden regardless of what the operator instructs. Boundaries cannot be waived or overridden by the operator.

**Time Window.** The validity period of the authorization. Critically, the time oracle for validation is the **log timestamp** — the timestamp assigned by the append-only log when the receipt is anchored — not the client clock. Client clocks are untrusted. An agent cannot extend or validate its own authorization by manipulating local time.

**Operator Instruction Hash.** A cryptographic hash (SHA-256) of the operator's stated instructions at delegation time. This field is what makes operator drift detectable. If the operator later issues different instructions to the agent, the agent can compare the hash of those instructions to the committed hash. A mismatch is provable from the log entry without any additional trust assumptions.

### 2.2 Receipt Issuance

Receipt issuance follows this sequence:

1. The operator presents their intended instructions to the user.
2. The user reviews the scope, boundaries, time window, and operator instructions.
3. The user signs the Authorization Object using their private key via WebAuthn/FIDO2.
4. The signed receipt is submitted to a decentralized append-only log.
5. The log assigns a timestamp and returns a log anchor (inclusion proof).
6. No agent action may begin until the log anchor is confirmed.

The log timestamp in step 5 establishes the authoritative issuance time. The log anchor provides a tamper-evident record that the receipt existed at that time with that content.

### 2.3 Receipt Validation

Before executing any action, the agent must:

1. Retrieve the receipt by its hash.
2. Verify the user's signature against the receipt content.
3. Confirm the receipt is within its time window per the log timestamp.
4. Confirm the action falls within the scope allowlist.
5. Confirm the action does not violate any boundary.
6. For `executes` actions: confirm the program's capability signature hash matches the hash in the scope field.

Any validation failure aborts the action. The agent does not proceed. There is no fallback to operator instruction.

### 2.4 Formal Verification Pseudocode

The complete validation procedure for a single agent action can be stated precisely as:

```
Verify(receipt, action):
  if not VerifySig(receipt.signature, receipt.content, userPubKey) → fail
  if not InTimeWindow(receipt.timeWindow, logTimestamp) → fail
  if not InScope(action, receipt.scope) → fail
  if ViolatesBoundary(action, receipt.boundaries) → fail
  if action.type == EXECUTE and Hash(SafescriptDAG(program)) != receipt.execHash → fail
  if Hash(currentOperatorInstructions) != receipt.instructionHash → fail
  return true
```

Each step eliminates a distinct attack surface. `VerifySig` confirms the receipt was signed by the user's private key and has not been altered since signing — any tampering with the receipt content invalidates the signature. `InTimeWindow` checks the action against the log-assigned timestamp, not the client clock, preventing time manipulation. `InScope` enforces the deny-by-default allowlist: if the action is not explicitly listed, it fails regardless of operator instruction. `ViolatesBoundary` enforces the user's hard limits, which survive any subsequent operator override. The `EXECUTE` hash check computes the static capability signature of the actual program the agent has been given and compares it to the hash committed at delegation — substituting a different program after signing is detectable without any runtime introspection. Finally, the instruction hash check compares the hash of the operator's current instructions against the hash committed at delegation time — if the operator has changed its instructions since the receipt was issued, the mismatch is immediately detectable from the log entry, with no reliance on the operator's own account.

---

## 3. Trust Stack Architecture

### 3.1 Layer 1: Signed Capability Manifest

The first trust gap in the agentic stack occurs at tool discovery. In the MCP ecosystem and similar tool-server architectures, an agent discovers available tools from a registry or manifest provided by the server. There is currently no cryptographic attestation that a server's self-reported tool descriptions match what the server actually does. An operator could publish a benign tool description to obtain user authorization, then deploy a server that executes different behavior.

The AuthProof fix is the **Signed Capability Manifest**. Before any user authorization occurs, the tool server publishes a manifest of its actual capabilities, signed with its own private key. The manifest hash is committed to the append-only log. The `scope` field of the Delegation Receipt references this manifest hash — not the operator's self-reported schema.

If the server's behavior diverges from the signed manifest, the divergence is detectable: an agent can compare its observed tool behavior against the manifest and flag violations. The user's authorization is anchored to a specific, signed description of what the tool can do — not to the operator's description of what they say it will do.

### 3.2 Layer 2: Delegation Receipt

As described in Section 2. The Delegation Receipt removes trust in the operator as a faithful intermediary. The user's intent is recorded before the operator's instructions reach the agent. The operator's instructions are hashed and committed. Any deviation is provable from the public log.

### 3.3 Layer 3: Safescript Execution

The third trust gap occurs at the code execution layer. Even with a signed manifest and a Delegation Receipt, an operator could supply a different program than the one the user authorized. A program identified by name or URI can be silently replaced.

AuthProof addresses this using [Safescript](https://github.com/safescript), an open-source sandboxed programming language designed for AI agent execution. Safescript's key property is that it compiles to a static directed acyclic graph (DAG): every program's full capability signature — what resources it reads, writes, and calls — is computable from the source before execution begins. There is no dynamic dispatch, no runtime module loading, no capability expansion.

The `executes` scope class requires the hash of a specific Safescript program's static capability DAG. The agent computes the capability signature of the program it has been given and compares it to the committed hash. If they do not match, execution is blocked. The operator cannot substitute a different program after delegation.

---

## 4. Dynamic Authorization

### 4.1 Micro-Receipts

Agentic tasks are frequently open-ended. Users cannot always anticipate every tool call an agent will need to make. The AuthProof protocol handles this through **micro-receipts**: minimal, scoped authorizations for specific actions not covered by the original Delegation Receipt.

When an agent encounters a tool call outside its current scope, it must not proceed silently. The protocol requires:

1. The agent pauses execution.
2. The agent surfaces a **capability request** to the user specifying the exact action required.
3. The user reviews and signs a micro-receipt covering only that action, with a reference to the parent Delegation Receipt.
4. The agent proceeds, referencing the micro-receipt hash.

The agent cannot autonomously expand its own capability envelope. Unknown actions require explicit new user authorization.

### 4.2 Dependency Integrity

Dependencies introduced at runtime are subject to the same rules as explicit tool calls. At delegation time, the hash of the dependency manifest is committed to the Delegation Receipt. If the agent encounters a dependency not present in the committed manifest, it is a scope violation and execution halts. The agent cannot silently acquire new capabilities through dependency chains.

---

## 5. Concurrent Agent Model

In multi-agent deployments, multiple agents may operate concurrently on behalf of the same user. The AuthProof model handles this by assigning a unique receipt ID to each delegation event. Concurrent agents each hold and reference their own receipt hash.

This design makes concurrent agents distinguishable by their authorization artifact rather than their identity. An audit of a multi-agent system can reconstruct exactly which authorization each agent was operating under at each point in time, independently of the agent's claimed identity. Receipt IDs are immutable log entries — they cannot be retroactively altered.

---

## 6. Key Management

AuthProof supports three key custody models:

**Hardware custody.** The user's private key is generated inside and never leaves the device secure enclave. Signing operations are performed by the enclave and exposed to the application only as completed signatures via the WebAuthn/FIDO2 API. This is the recommended model. The key cannot be extracted by malware, compromised operators, or supply chain attacks on the SDK.

**Delegated custody.** The user's private key is held by a trusted key management service. This model is appropriate for environments without FIDO2 hardware support (legacy enterprise systems, server-side agents) and for users who require key recovery. The trust assumption is the key manager; the key manager does not have the ability to issue receipts on the user's behalf without the user's explicit signing instruction.

**Self-custody.** The user holds and manages their own private key material. This model requires the user to implement their own secure key storage. It is appropriate for technically sophisticated users and air-gapped environments. Key loss is irrecoverable.

---

## 7. Security Analysis

### 7.1 Operator Compromise

If an operator's systems are compromised, the attacker gains control of the operator's instructions to the agent. Under current architectures, this is indistinguishable from legitimate operator behavior. Under AuthProof, any instruction diverging from the hash committed in the Delegation Receipt is detectable by the agent. The attacker cannot issue instructions that pass hash verification without access to the user's private key.

### 7.2 Operator Malfeasance

If an operator intentionally instructs the agent to exceed the user's authorization — whether under commercial pressure, legal compulsion, or bad faith — the deviation is provable from the append-only log. The operator cannot alter the log entry. The operator cannot alter the signed receipt. The discrepancy between committed instructions and actual instructions is an auditable fact.

### 7.3 Log Integrity

The security of the protocol depends on the tamper-evidence of the append-only log. A log that can be silently altered eliminates the audit trail. The protocol is designed for decentralized log implementations (transparency logs in the Certificate Transparency model) that do not depend on a single operator for integrity. Log fork detection follows established approaches from CT ecosystems.

### 7.4 Key Compromise

If the user's signing key is compromised, an attacker can issue Delegation Receipts in the user's name. Hardware custody significantly reduces this risk by making key extraction technically infeasible on modern devices with secure enclaves. Receipt revocation is supported: a revocation entry anchored to the log invalidates all receipts issued before the revocation timestamp.

### 7.5 Revocation Mechanism

Receipt revocation is a first-class protocol operation, not an out-of-band administrative action. When a user wishes to revoke a Delegation Receipt — due to key compromise, changed intent, or completed task — they issue a **Revocation Receipt** following this procedure:

1. The user constructs a revocation record containing: the SHA-256 hash of the original Delegation Receipt being revoked, the reason for revocation, and the revocation timestamp.
2. The user signs the revocation record with the same private key used to sign the original receipt.
3. The signed revocation record is published to the append-only log, producing an immutable log anchor.
4. The revocation registry — a queryable index of all published revocation records — is updated.

The log anchor establishes an authoritative revocation time. Actions taken before this timestamp under the original receipt remain valid. Actions attempted after this timestamp must fail validation.

**Verification must check revocation first.** The `Verify` procedure in Section 2.4 is extended with a pre-check: before evaluating signature, time window, scope, or boundaries, the verifier queries the revocation registry for the receipt hash. If a valid, signed revocation record exists, the check fails immediately and no further steps are evaluated. This ordering ensures revoked receipts cannot pass verification on any other grounds.

Because the revocation record is itself signed by the user and anchored to the log, it carries the same evidentiary weight as the original receipt. Revocation is auditable, tamper-evident, and does not depend on the operator to propagate or acknowledge it.

### 7.6 Scope Creep via Micro-Receipt Fatigue

A malicious operator could structure an agentic workflow to generate many micro-receipt requests in rapid succession, inducing the user to approve actions they do not meaningfully review. This is analogous to notification fatigue attacks against 2FA prompts. The protocol does not eliminate this risk, but it makes every micro-receipt a signed, auditable artifact — the user's approval is recorded. Rate-limiting and UI affordances are the primary mitigation.

### 7.7 Non-Repudiation and Soundness

Let `R` be a Delegation Receipt with content `C`, user signature `σ = Sign(sk_u, C)`, and log anchor `L`. Let `a` be an agent action. Define `Authorized(a, R)` to be true if and only if `Verify(R, a)` returns true per the procedure in Section 2.4.

**Non-repudiation.** If `Verify(R, a) = true`, then `VerifySig(σ, C, pk_u) = true`, which implies `σ` was produced by the holder of `sk_u`. Under the ECDSA P-256 unforgeability assumption (EUF-CMA), no party without `sk_u` can produce a valid `σ` for any `C`. Therefore, the existence of a valid receipt on the log is non-repudiable evidence that the holder of `sk_u` authorized the content of `C` at time `L`. The user cannot plausibly deny having issued the receipt.

**Soundness.** For any action `a` where `Verify(R, a) = true`: (i) `a` falls within the scope allowlist in `C` (by the `InScope` check); (ii) `a` does not violate any boundary in `C` (by the `ViolatesBoundary` check); (iii) if `a` is an execution action, the program's capability signature matches the hash committed in `C` (by the `EXECUTE` hash check); (iv) the operator's instructions at execution time hash to the value committed in `C` (by the instruction hash check). It follows that any deviation from (i)–(iv) causes `Verify` to return false, and therefore any detectable deviation is provable from `C` and `L` without additional trust assumptions. The operator cannot alter `C` without invalidating `σ`; the operator cannot alter `L` by the tamper-evidence property of the append-only log. **Corollary:** a valid receipt implies the action was explicitly authorized; any deviation from the authorized parameters is detectable from the public log.

### 7.8 Cryptographic Primitive Considerations

The AuthProof protocol uses SHA-256 throughout: for receipt ID computation, instruction hash commitment, manifest body hashing, action log entry chaining, and revocation record linking. SHA-256 provides 128 bits of collision resistance under current cryptanalysis and is suitable for all protocol roles as specified.

**Hash function upgrade path.** The receipt structure includes a version field. A future protocol version may migrate to SHA-3-256 (FIPS 202) or BLAKE3. Both are drop-in replacements for the SHA-256 role in this protocol — the structural commitment mechanism is hash-function-agnostic. Migration requires a versioned receipt format and a transition period during which verifiers accept both hash algorithms. No structural redesign is required.

**Quantum resistance.** ECDSA P-256 is vulnerable to Shor's algorithm on a sufficiently capable quantum computer. The signing layer of the protocol — receipt signing, action log entry signing, and revocation signing — is therefore not post-quantum secure under current implementations. The migration path is through the FIDO2/WebAuthn credential layer: FIDO2 authenticators are expected to support post-quantum signature schemes (CRYSTALS-Dilithium, FALCON) as NIST PQC standards are finalized and incorporated into platform authenticator firmware. Because all AuthProof signing is abstracted behind the WebAuthn API, a platform-level upgrade to post-quantum FIDO2 authenticators upgrades the protocol's quantum resistance without protocol-layer changes. The append-only log and hash commitment structures are unaffected — SHA-256 preimage resistance is not threatened by known quantum algorithms.

### 7.9 Complete Enforcement Architecture

**Three-layer enforcement model:**

- **Layer 1: Receipt** — Cryptographic proof of user authorization (what). The user signs a Delegation Receipt specifying scope, boundaries, and operator instructions. The signature is ECDSA P-256; the receipt ID is SHA-256 of the full receipt JSON. Any tampering is immediately detectable.
- **Layer 2: TEE** — Hardware-measured execution environment (where and how). The agent runs inside an attested enclave whose measurement is bound to the receipt via `teeMeasurement.expectedMrenclave`. Any substitution of model weights, verifier code, or platform produces a different `mrenclave` and is detectable before execution.
- **Layer 3: eBPF** — Kernel-level enforcement that cannot be bypassed (enforced). An eBPF LSM hook validates the signed capability token on every relevant syscall. Scope violations are denied at the kernel level before they reach userspace. This layer is open for contribution — see below.

**Intel TDX and AMD SEV-SNP** provide encrypted memory pages that are inaccessible to the host OS and hypervisor, hardware-rooted attestation quotes signed by the CPU vendor's key, and measured boot that hashes every component loaded into the enclave. AuthProof binds delegation receipts to enclave measurements via `ConfidentialRuntime`: `mrenclave = SHA-256(platform + verifierHash + modelHash)`. This value is committed into the receipt's `teeMeasurement.expectedMrenclave` field at delegation time. At execution time, `ConfidentialRuntime.launch()` recomputes `mrenclave` from its runtime parameters and rejects the execution if there is any mismatch.

**Token injection pattern:** The TEE enforcement layer follows this sequence:
1. `ConfidentialRuntime.launch()` computes `mrenclave` and verifies the receipt measurement
2. `PreExecutionVerifier.check()` gates execution — no valid receipt, no run
3. `TokenPreparer.prepare()` builds a signed capability token binding receipt hash, scope hash, and TEE quote hash
4. The token is injected into the agent process context via `prctl` (production)
5. The eBPF LSM validates the token on every `security_file_open`, `security_socket_connect`, and `security_task_execve` syscall
6. Any operation not covered by the token's scope is denied at the kernel level before it reaches userspace

**Why eBPF closes the final circularity:** Without kernel enforcement, a compromised agent runtime could call `verifier.check()` with a spoofed receipt, receive `allowed: true`, and then ignore the scope. The eBPF LSM runs in kernel space and cannot be disabled by userspace code — including a compromised agent runtime. The three-layer model is complete and non-bypassable only when all three layers are present.

**Current status:**
- Receipt layer: **complete** — `AuthProofClient.delegate()`, `AuthProof.create()`, `verify()`
- TEE attestation layer: **complete** — `TEEAttestation` class (Intel SGX, ARM TrustZone)
- TEE enforcement layer: **complete** — `ConfidentialRuntime`, `TokenPreparer`
- eBPF kernel module: **open for contribution** — see [GitHub issues](https://github.com/Commonguy25/authproof-sdk/issues)

**How to contribute the eBPF module:** Engineers with eBPF LSM experience (Isovalent, Red Canary, or similar) are especially welcome. Open an issue or PR at https://github.com/Commonguy25/authproof-sdk/issues — Technical requirements: CO-RE eBPF + BTF (no custom kernel modules), Kernel 5.8+ BPF LSM support, must pass the eBPF verifier cleanly, security review required before merge. Reference implementations: Tetragon (Cilium) for syscall-level enforcement, Falco + KubeArmor for eBPF security at scale, and the eBPF Foundation LSM samples.

---

## 8. Data Flow Receipt

### 8.1 Motivation

A Delegation Receipt establishes what an agent is authorized to do. But it does not capture what data the agent touched during execution — which inputs it accessed, what sensitive information it processed, and where that information subsequently flowed. This gap creates a compliance blind spot: a receipt may be valid and unrevoked, yet the agent may have propagated PII to an external system outside any user-visible boundary.

The Data Flow Receipt addresses this. It is a cryptographically signed compliance artifact that tracks, at a per-execution level, every piece of data the agent accessed, tags each piece with sensitivity metadata, and records every egress event against a policy that defines which destinations are acceptable for which sensitivity classes. The result is a signed, verifiable record that can be attached to a Delegation Receipt to prove data handling compliance.

### 8.2 Components

**DataTagger** is the data access ledger. When the agent accesses a piece of data — a user record, a database row, an API response — the operator calls `tagger.tag(data, { source, sensitivity, accessedAt })`. The tagger computes `SHA-256(data)` and derives a stable `tagId = SHA-256(dataHash + receiptHash + accessedAt)`. Raw data is never stored; only the hash is recorded. The tag is appended to an in-memory manifest alongside its source label and sensitivity classification (e.g., `"PII"`, `"confidential"`, `"public"`).

**TaintTracker** is the egress policy enforcer. Before the agent sends any output — to a log, an external API, a file, a downstream system — the operator calls `tracker.recordOutput({ output, destination, outputType })`. The tracker runs two checks: (1) exact-hash matching against the DataTagger manifest, detecting when a previously tagged value appears verbatim in the output; (2) PII regex scanning, detecting email addresses, US phone numbers, credit card numbers, and Social Security numbers that may not have been tagged at ingestion. If the output contains PII (either by tag or by pattern) and the destination is classified as high-risk (`external-api`, `file`), a policy violation is flagged. The egress event — clean or violating — is appended to an internal log.

**DataFlowReceipt** is the signed artifact. At the end of execution, `DataFlowReceipt.generate({ delegationReceiptHash, tagger, tracker, privateKey, publicJwk })` serializes the full data manifest and egress log, computes `bodyHash = SHA-256(JSON.stringify(body))`, signs the body with ECDSA P-256, and requests a RFC 3161 trusted timestamp from the configured TSA (falling back to a local-clock `UNVERIFIED_TIMESTAMP` if the TSA is unreachable). The result is a self-contained, verifiable record. `DataFlowReceipt.verify(receipt)` recomputes the body hash and verifies the ECDSA signature, returning `{ valid, reason }`.

### 8.3 Policy Model

The current egress policy is conservative by design:

- **High-risk destinations:** `external-api`, `file`. Any output to these destinations that contains PII (tagged or pattern-detected) constitutes a policy violation.
- **Non-high-risk destinations:** `user`, `log`, and any other destination string. PII in these destinations is flagged as tainted but does not constitute a policy violation.
- **Sensitivity escalation:** A tag with any sensitivity class is recorded in the egress log. Only tags with `sensitivity = "PII"` or outputs matching PII regex patterns trigger policy violations at high-risk destinations.

This model reflects the most common compliance requirement — preventing PII from leaving a controlled execution environment via an unapproved channel — while leaving non-PII data movement unrestricted.

### 8.4 ActionLog Integration

`ActionLog.record()` accepts an optional `taintTracker` argument. When provided, it calls `tracker.recordOutput({ output, destination: 'log', outputType: 'log-entry' })` automatically before constructing the log entry, embedding the taint result in the entry body. This means every logged action transparently records whether tainted data was present in the agent's output at that step, without requiring the operator to call the tracker separately.

### 8.5 Trust Properties

The Data Flow Receipt provides the following guarantees:

1. **Data access non-repudiation.** Every tagged input produces a `tagId` that is deterministically bound to the Delegation Receipt hash. An operator cannot retroactively claim a piece of data was not accessed — the tagId can only be produced from the combination of the data, the receipt, and the access timestamp.

2. **Egress integrity.** The egress log and data manifest are included verbatim in the signed body. A verifier who holds the signer's public key can confirm that the log has not been modified after generation.

3. **PII detection coverage.** The dual detection strategy — exact-hash matching plus regex scanning — provides defense in depth. Exact-hash matching catches structured data that was explicitly tagged; regex scanning catches PII that entered the agent's context through untagged channels (e.g., an LLM response that included a user's email address from its training context).

4. **Binding to Delegation Receipt.** The `delegationReceiptHash` field binds the Data Flow Receipt to the specific delegation under which execution occurred. A verifier can confirm that the data handling record corresponds to the authorization record for the same session.

---

## 9. Model State Attestation: Closing the Model Identity Gap

### 9.1 The Problem — Operator Model Substitution Attack

The Delegation Receipt described in Section 2 proves that a human authorized a specific agent to act within defined scope and boundaries. It does not prove that the model executing the receipt is the same model the user thought they were authorizing.

Consider the following attack scenario:

1. A user authorizes `claude-sonnet-4-5` to manage their calendar under a set of stated boundaries.
2. The operator signs a Delegation Receipt reflecting those boundaries.
3. Before execution, the operator silently substitutes a fine-tuned variant of the model — one that has been trained to be more aggressive, less bounded, or to prioritize operator interests over user interests.
4. The substituted model executes under the valid Delegation Receipt. All cryptographic checks pass because the receipt is genuine.

This is the **model substitution attack**: a valid receipt being executed by an unauthorized model. The receipt proves authorization; it does not prove identity of the executing model. The gap is structural and cannot be closed by receipt verification alone.

### 9.2 The Primitive — Model State Commitment and Execution Verification

The **Model State Attestation** closes this gap by introducing a two-phase cryptographic protocol that binds the delegation receipt to a measurement of the model state at both issuance time and execution time.

**Phase 1 — Commitment (at delegation time):**

Before execution begins, the operator commits to the exact model state that will execute. The commitment is a cryptographic measurement of five components concatenated in canonical order:

```
modelMeasurement = SHA-256(
  Canonicalizer.normalize(modelId)      ||
  Canonicalizer.normalize(modelVersion) ||
  systemPromptHash                      ||
  runtimeConfigHash                     ||
  receiptHash
)
```

The inclusion of `receiptHash` as the fifth component is critical: it binds the model measurement to the specific delegation under which execution will occur. The same model with the same system prompt but a different receipt produces a different measurement. A commitment cannot be reused across delegations.

The commitment is signed by the operator's ECDSA P-256 key and attested by the TEE runtime, producing a sealed artifact:

```
{
  commitmentId,
  receiptHash,          // bound delegation
  modelMeasurement,     // SHA-256 of all five components
  modelId,
  modelVersion,
  systemPromptHash,
  runtimeConfigHash,
  committedAt,          // ISO timestamp
  signature,            // operator ECDSA P-256 signature
  signerPublicKey,
  teeAttestation        // TEE hardware proof of commitment
}
```

**Phase 2 — Verification (at execution time):**

Immediately before the agent function executes, the current model state is measured using the same five-component computation. The resulting measurement is compared against the committed measurement. If the two measurements differ — for any reason — execution is blocked with a `ModelDriftDetected` error that identifies exactly which components changed.

### 9.3 The Five-Layer Chain

With Model State Attestation added, the complete verifiable chain of accountability becomes:

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Delegation Receipt                                    │
│  SHA-256 signed commitment: human authorized agent to act        │
│  Fields: scope, boundaries, instructions, timeWindow, signature  │
└────────────────────────────┬────────────────────────────────────┘
                             │ receiptHash bound into commitment
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2 — Model State Commitment                                │
│  Cryptographic measurement of the authorized model state         │
│  modelMeasurement = SHA-256(modelId || modelVersion ||           │
│                             systemPromptHash ||                  │
│                             runtimeConfigHash || receiptHash)    │
│  Signed by operator + TEE attested at delegation time            │
└────────────────────────────┬────────────────────────────────────┘
                             │ commitmentId referenced at execution
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3 — Execution Attestation                                 │
│  TEE verifies current model state matches commitment             │
│  If any component changed: ModelDriftDetected, block immediately │
│  TEE attestation proves verification occurred inside enclave     │
└────────────────────────────┬────────────────────────────────────┘
                             │ verificationTeeAttestation bound
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│  Layer 4 — Action Log Entry                                      │
│  Append-only, chain-linked, agent-signed record of execution     │
│  Includes modelCommitmentId, binding action to model state       │
└─────────────────────────────────────────────────────────────────┘
```

The `generateChainProof()` method produces a single serializable artifact that encodes this entire chain, enabling any external verifier to trace a specific action back through execution attestation, model commitment, and delegation receipt in a single pass.

### 9.4 Security Properties

**What Model State Attestation proves:**

1. **Model identity at commitment time.** The operator committed to a specific `(modelId, modelVersion, systemPromptHash, runtimeConfigHash)` tuple before execution began. The ECDSA signature and TEE attestation prove this commitment was made inside a trusted environment and has not been altered.

2. **Model state at execution time.** The TEE verification attestation proves that the model measurement was recomputed inside the enclave immediately before execution, and that the recomputed measurement matched the committed measurement.

3. **Delegation binding.** The `receiptHash` component in the measurement ensures the commitment is irrevocably bound to a specific delegation. A commitment made under receipt A cannot be presented as valid under receipt B.

4. **Drift detection.** The per-component comparison in `verify()` identifies exactly which aspects of the model state changed — model identity, version, system prompt, or runtime configuration — enabling forensic analysis of how an unauthorized execution occurred.

**What Model State Attestation does not prove:**

1. **Correctness of the committed model.** The attestation proves the executing model matches the committed model. It does not prove the committed model is safe, aligned, or has not been fine-tuned in ways the user did not anticipate. The user's trust in the operator's commitment is still required.

2. **That `systemPromptHash` reflects a safe system prompt.** The attestation proves the system prompt did not change between commitment and execution. It does not inspect the content of the system prompt.

3. **Hardware attestation without TEE hardware.** In simulation mode (the default for testing), attestations are signed with an ECDSA key pair rather than produced by real SGX or TrustZone hardware. Production deployments should use `platform: 'intel-sgx'` or `platform: 'arm-trustzone'`.

### 9.5 Formal Definition of Model Drift

**Model drift** is defined as any divergence between the model state at commitment time and the model state at execution time. Specifically, a `ModelDriftDetected` condition is raised when any of the following is true:

- `Canonicalizer.normalize(currentModelId) ≠ Canonicalizer.normalize(committedModelId)`
- `Canonicalizer.normalize(currentModelVersion) ≠ Canonicalizer.normalize(committedModelVersion)`
- `currentSystemPromptHash ≠ committedSystemPromptHash`
- `currentRuntimeConfigHash ≠ committedRuntimeConfigHash`
- `computeMeasurement(currentState) ≠ committedModelMeasurement`

The measurement check is redundant given the component checks but provides an additional cryptographic guarantee: even if the component comparison logic contains a bug, the SHA-256 measurement comparison will catch any state change.

### 9.6 Integration with the Delegation Receipt

The Model State Attestation integrates with the existing delegation primitives at three points:

**PreExecutionVerifier (check 7).** When a `ModelStateAttestation` instance is provided to the verifier constructor and a `commitmentId` is passed to `check()`, check 7 runs after all six existing checks. If model drift is detected, execution is blocked with `ModelDriftDetected` before the agent function ever receives control.

**TEERuntime.execute().** When an agent function is executed via `TEERuntime.execute()` with a `commitment` and `modelStateAttestation` instance, the runtime automatically verifies model state inside the enclave before invoking the function. This provides defense-in-depth: even if the PreExecutionVerifier is bypassed, the runtime enforces the commitment.

**ActionLog.record().** When `modelCommitmentId` is passed to `ActionLog.record()`, the commitment ID is embedded in the log entry, creating an auditable link between every recorded action and the model state commitment under which it was authorized.

### 9.7 The Combined Framework

Together, the Delegation Receipt and Model State Attestation form a complete framework for verifiable AI agent accountability:

| Layer | Primitive | What it proves |
|---|---|---|
| Authorization | Delegation Receipt | Human authorized agent with defined scope |
| Identity | Model State Commitment | Which model was authorized to execute |
| Execution | Execution Attestation | Authorized model actually ran (no substitution) |
| Audit | Action Log Entry | What the model actually did |

An auditor presented with a chain proof can verify each layer independently and confirm that the action recorded in the log was taken by the model the user authorized, acting within the scope the user defined, under conditions that have not been altered since authorization was granted.

### 9.8 Provider Updates vs. Malicious Substitution

#### The Problem with Uniform Blocking

Section 9.5 defines `ModelDriftDetected` as any divergence between committed and current model state. For self-hosted models, this uniform block is appropriate: any change to `modelId` or `modelVersion` not made by the operator is evidence of a substitution attack.

Hosted model providers (OpenAI, Anthropic, Google, etc.) present a different threat model. A provider may silently update the underlying model that a versioned alias resolves to — for example, `gpt-4` → `gpt-4-0613` → `gpt-4-0125` — without any operator action. The operator did not change their configuration; the provider changed the model behind a stable identifier. Treating this identically to a deliberate operator substitution is too blunt: it would block legitimate executions whenever a provider retires a model version, forcing operators to recommit on every provider maintenance cycle regardless of whether any security-relevant change occurred.

#### Two Distinct Mismatch Types

`ModelStateAttestation` distinguishes two categories of measurement mismatch:

**`MaliciousSubstitution`** — The operator explicitly changed the model identifier or version after the commitment was signed. This is always a hard block. Execution is immediately terminated with `ModelDriftDetected` regardless of any policy setting. Indicators:
- `currentModelId ≠ committedModelId` (the operator's explicitly configured base model changed), OR
- `currentSystemPromptHash ≠ committedSystemPromptHash` (system prompt was modified), OR
- `currentRuntimeConfigHash ≠ committedRuntimeConfigHash` (runtime configuration was modified).

**`ProviderUpdate`** — The model version changed, but the operator's configured `modelId` (the `operatorSetModelId` recorded at commit time) is unchanged. The provider silently updated the model behind a stable alias. Indicators:
- `currentModelId === committedModelId` (same base model the operator configured), AND
- `currentModelVersion ≠ committedModelVersion` (only the version changed).

#### The `providerUpdatePolicy` Field

Operators declare how provider updates should be handled at construction time:

```js
const attestation = new ModelStateAttestation({
  teeRuntime,
  actionLog,
  providerUpdatePolicy: 'reauthorize',  // default
  // or: 'block'
});
```

**`providerUpdatePolicy: 'block'`** — Treat provider updates identically to `MaliciousSubstitution`. Any version change blocks execution immediately. Use this when the deployment requires strict model pinning and any unannounced version change must halt operations.

**`providerUpdatePolicy: 'reauthorize'`** (default) — When a provider update is detected, do not block the current call outright. Instead:
1. Return `{ allowed: false, reason: 'PROVIDER_UPDATE_DETECTED', requiresReauthorization: true, previousVersion, currentVersion }` from `verify()`.
2. Set an internal `pendingReauthorization` flag on the attestation instance.
3. Log the discrepancy with `PROVIDER_UPDATE_DETECTED` status.
4. Block **all subsequent executions** under this attestation instance until `reauthorize()` is called.

This gives operators and users a recovery path. The provider update is flagged and the system halts, but the cause is clearly identified as a non-malicious provider action, allowing the user to explicitly acknowledge the change and re-authorize rather than treating it as a security incident.

#### The `reauthorize()` Flow

After a `PROVIDER_UPDATE_DETECTED` event, the user must explicitly acknowledge the version change:

```js
await attestation.reauthorize({ userApproval: true, newCommitmentId });
```

- `userApproval: true` is required; omitting it or passing `false` throws immediately.
- `newCommitmentId` is optional — pass the ID of a new commitment created for the updated model version if the operator has re-committed to the new provider version.
- On success, `pendingReauthorization` is cleared and subsequent `verify()` calls proceed normally.

The `reauthorize()` call is an explicit human-in-the-loop checkpoint: the system will not silently resume execution after a provider update. A human must acknowledge the change, review the new version, and explicitly approve continued operation.

#### Why This Matters for Hosted Model Providers

For deployments against hosted model APIs, the `MaliciousSubstitution` / `ProviderUpdate` distinction separates two meaningfully different security events:

| Event | Threat level | Appropriate response |
|---|---|---|
| Operator changes `modelId` to a different base model | High — potential substitution attack | Hard block, security incident |
| Operator changes system prompt after signing | High — instruction injection risk | Hard block, security incident |
| Provider retires a model version and updates the alias | Low-medium — capability drift | Flag, require user acknowledgment, allow recovery |

The distinction also preserves the audit trail. Both event types are recorded with their specific `mismatchType` (`MaliciousSubstitution` or `ProviderUpdate`), giving auditors the information needed to distinguish security incidents from routine provider maintenance in the chain proof.

---

## 10. Scope Discovery Protocol — Closing the Upstream Authorization Gap

### 10.1 The Design-Time Problem

The Delegation Receipt solves the *transmission* problem: once a user has defined what an agent may do, the receipt cryptographically binds and verifies that definition. But this solution assumes the user can correctly define scope upfront. In practice, they cannot.

A user deploying an AI agent for the first time does not know which API endpoints it will call, which database tables it will query, how many times it will poll a resource, or whether it will ever attempt a write operation. Asking users to define scope before they observe agent behavior produces one of two failure modes:

- **Over-authorization.** The user grants broad permissions ("access email") to avoid blocking the agent. The agent is now authorized to delete messages, send external communications, or enumerate the entire inbox — operations the user never intended to permit.
- **Under-authorization.** The user grants narrow permissions and the agent fails mid-task, requiring repeated round-trips to expand scope incrementally. Users respond by granting progressively wider permissions in frustration.

Neither outcome produces a receipt that reflects the user's actual intent. The scope field becomes a legal fiction rather than a genuine authorization boundary. This is the *upstream authorization gap* — the receipt is cryptographically sound but semantically wrong from the moment it is issued.

### 10.2 The Observation Mode Approach

ScopeDiscovery addresses the upstream gap by inverting the authorization sequence. Instead of asking users to define scope before running the agent, it runs the agent first — in a sandboxed simulation — and uses the observed behavior to generate the scope definition.

The protocol proceeds in four stages:

**Stage 1 — Sandboxed observation.** The operator provides the agent function. `ScopeDiscovery.observe()` wraps every supported resource type (email, calendar, payment, files, db, network) in a transparent proxy that intercepts all operation calls. The agent runs to completion inside this sandbox. Every call to `ctx.email.read()`, `ctx.payment.charge()`, `ctx.files.delete()`, or any other operation is intercepted, timestamped, and appended to an observation log. Mock data that matches the expected structure is returned so the agent proceeds normally without knowing it is not executing against real systems. No real I/O occurs. No side effects are produced.

**Stage 2 — Scope generation.** `generateScope()` analyzes the observation log and produces:
- A `draftScope` object with an `allowedActions` list (de-duplicated observed operations) and conservative `deniedActions` defaults (delete, execute, payment).
- A `plainSummary` — a human-readable description of what the agent did, written in non-technical language suitable for end-user review.
- `riskFlags` — a list of specific concerns: delete operations, execute operations, payment operations, external send/write operations, and any operation called more than 50 times (indicating potential unbounded looping behavior).
- `suggestedDenials` — a list of dangerous operations the agent did not use, with per-entry explanations. These are explicitly recommended for the denied list as a belt-and-suspenders defense.

**Stage 3 — Plain language review.** The operator or user reviews the plain summary, risk flags, and suggested denials before approving. `approve()` accepts `remove` and `add` arrays, allowing surgical modification of the draft scope: stripping operations the user did not intend to permit, or adding operations the sandboxed run did not cover but the operator knows the agent will need. This is the moment of genuine human authorization — grounded in observed behavior rather than speculation.

**Stage 4 — Cryptographic commitment.** `finalize()` embeds the approved scope into a Delegation Receipt using the same cryptographic structure as `AuthProof.create()`. The receipt includes a `scopeSchema` field with the structured allowed and denied action lists, and a `discoveryMetadata` field recording the observation count, any timeout abort, and the risk flags at generation time. The receipt is ECDSA P-256 signed and is immediately verifiable with `AuthProof.verify()`. The scope definition is no longer a user's guess — it is an observation-grounded, cryptographically committed authorization boundary.

### 10.3 Grounded Scope Through Sandboxed Simulation

The critical property of observation-based scope generation is *grounding*: every entry in the `allowedActions` list corresponds to an operation the agent actually performed during a representative run. This is not a user estimating what the agent might need — it is a structural record of what the agent did.

Grounding has three practical consequences:

**Precision.** The allowedActions list contains exactly the resource/operation pairs that appeared in the observation log. An agent that reads email but never writes it gets a receipt authorizing `read` on `email`, not `write`. The permission boundary is as narrow as the agent's actual behavior.

**Defensibility.** When a receipt is later audited, the `discoveryMetadata.observationCount` and `riskFlags` fields provide evidence that scope was derived from observation rather than assumption. The audit trail runs from observation to draft to approval to receipt.

**Ratcheting.** Each time the agent's behavior changes, a new observation session produces a new draft. If the agent begins calling `payment.charge` in a new version, that operation surfaces in the risk flags before any receipt is issued for the updated agent. Drift in agent behavior is detectable before it is authorized.

### 10.4 The Plain Language Review Step

Cryptographic scope schemas are precise but opaque to non-technical users. A user presented with `{ operation: "write", resource: "calendar" }` does not know whether this means "add one event" or "rewrite the entire calendar."

The `plainSummary` field addresses this by translating the observation log into prose. A typical summary reads:

> During the observation session, the agent performed the following operations:
>   • email: read, list
>   • calendar: write
>
> Frequently called operations: email:read (×12)
>
> Total operations observed: 14

Users reviewing this summary can identify immediately that the agent reads email heavily (12 calls), writes to the calendar, and never touches payment or file systems. They can then use `remove` and `add` in `approve()` to reflect their actual intent before the receipt is signed.

Risk flags present specific concerns in plain language: `"delete operation observed on resource db"`, `"high-frequency operation detected: email:read called 87 times (>50)"`. These are not stack traces — they are decision prompts for humans who may not read code.

### 10.5 Integration with the Delegation Receipt

The receipt produced by `finalize()` is structurally identical to one produced by `AuthProof.create()`. It carries all standard fields — `delegationId`, `scope`, `boundaries`, `timeWindow`, `operatorInstructions`, `instructionsHash`, `signerPublicKey`, `signature` — and is verifiable with `AuthProof.verify()` without any modification to the verification protocol.

Two additional fields bridge the discovery protocol to the receipt:

**`scopeSchema`** embeds the structured `allowedActions` and `deniedActions` lists approved by the human reviewer. Where `scope` is a human-readable text field used for semantic matching, `scopeSchema` provides machine-readable, programmatically enforceable action boundaries. PreExecutionVerifier can validate proposed actions against `scopeSchema` before execution begins.

**`discoveryMetadata`** records the observation context: how many operations were seen, whether the session was aborted by timeout, and what risk flags were present at generation time. This makes the authorization chain auditable end-to-end: an auditor can see not just what was authorized, but the process by which the authorization was derived.

### 10.6 Guided Delegation Mode

For operators who trust their agent's behavior in the observation session and do not need manual review, `ScopeDiscovery.guided()` provides a single-call end-to-end flow:

```js
const { receipt, receiptId, riskFlags, observations } = await ScopeDiscovery.guided({
  agentFn: async (ctx) => { /* agent implementation */ },
  operatorInstructions: 'Process the weekly report.',
  privateKey,
  publicJwk,
});
```

Guided mode runs `observe → generateScope → approve → finalize` automatically. The returned `riskFlags` allow operators to inspect what was flagged even when they choose not to gate on it. `AuthProofClient.delegateGuided()` provides the same capability through the client API.

### 10.7 Closing Both Gaps

The Delegation Receipt closes the *downstream authorization gap*: it proves what the user authorized and makes operator deviation from that authorization cryptographically detectable at runtime. The Scope Discovery Protocol closes the *upstream authorization gap*: it ensures that what the user authorized in the first place reflects the agent's actual behavior rather than an uninformed guess.

Together they form a complete authorization chain:

| Stage | Gap | Primitive | What it provides |
|---|---|---|---|
| Before authorization | Upstream | ScopeDiscovery.observe() | Grounded scope derived from actual agent behavior |
| At authorization | Upstream | ScopeDiscovery.finalize() | Cryptographic commitment to observation-derived scope |
| During execution | Downstream | AuthProof.verify() + ActionLog | Runtime enforcement and tamper-evident audit trail |
| After execution | Downstream | ScopeDiscovery.fromReceipt() | Drift detection — compare receipt to new observations |

Automated observation eliminates the guesswork that produces over-broad receipts. Cryptographic commitment to the observation-derived scope eliminates the trust-me assertion that makes receipts unfalsifiable. The result is an authorization system that is both usable — users review behavior they observed, not permissions they invented — and verifiable — every scope boundary is signed, tamper-evident, and auditable.

---

## 11. Comparison to Existing Approaches

| Property | OAuth 2.0 / RAR | WIMSE | AIP | AuthProof |
|---|---|---|---|---|
| Service-to-agent trust | ✓ | ✓ | ✓ | ✓ |
| User-to-operator trust | ✗ | ✗ | ✗ | ✓ |
| Operator deviation detectable | ✗ | ✗ | ✗ | ✓ |
| Append-only audit log | ✗ | ✗ | ✗ | ✓ |
| Deny-by-default scope | Partial | ✗ | ✗ | ✓ |
| Execution hash binding | ✗ | ✗ | ✗ | ✓ |
| Hardware key custody | ✗ | ✗ | ✗ | ✓ (default) |
| Dynamic micro-authorization | ✗ | ✗ | ✗ | ✓ |
| Concurrent agent isolation | Via token scope | Via workload ID | Via agent ID | Via receipt ID |

AuthProof is not a replacement for WIMSE, AIP, or OAuth 2.0. It operates at a different layer. In a complete agentic trust stack, AuthProof provides the user-to-operator layer; existing frameworks continue to provide the service-to-agent layer. They are complementary.

---

## 12. Multi-Agent Delegation Chains

When a delegated agent needs to hand off a subtask to another agent, the chain of authority must remain auditable and bounded. AuthProof's `DelegationChain` primitive enforces three invariants at every hop.

### Scope Attenuation Rules

Each delegation step must produce a **strict proper subset** of the parent's authorized actions. "Proper subset" means:

1. Every action the child is permitted must already appear in the parent's `allowedActions`.
2. The child must have strictly fewer permitted actions than the parent — equal scope is rejected.
3. Every action explicitly denied by the parent (`deniedActions`) must be carried forward into the child. A child may add new denied actions but may never drop a denial that the parent established.

These rules ensure that authority can only flow downward — no agent in a chain can grant permissions it was not itself given.

### Max Depth Enforcement

The chain tracks the depth of every receipt. The root receipt (signed directly by the user) is at depth 0. Each delegation increments the depth. When a delegation would produce a receipt at depth ≥ `maxDepth`, a `MaxDepthExceededError` is thrown before the receipt is created. The default `maxDepth` is 3, meaning a user can authorize at most three levels of agent-to-agent hand-off before the chain must be re-anchored at the user level.

### Cascade Revocation Semantics

`DelegationChain.revoke(hash, { cascadeToChildren: true })` performs a breadth-first walk of all descendants and marks each one revoked. The revocation is stored in an in-memory `Set`; it is not append-only at the chain level (the underlying `RevocationRegistry` provides append-only semantics when plugged in). A receipt revoked without `cascadeToChildren` invalidates only itself — its children remain valid until explicitly revoked. This allows operators to surgically cut one agent out of a chain without disrupting sibling branches.

### Why Root Must Always Be User-Signed

The root receipt is the only trust anchor in the delegation chain. If the root could be generated by an agent or operator without user involvement, the entire chain could be bootstrapped unilaterally — defeating the purpose of the protocol. By requiring the root to carry a valid ECDSA P-256 signature from the user's key, `DelegationChain.init()` cryptographically binds the chain to explicit user consent. Any downstream agent that wants to prove its authority can walk the chain to the root and demonstrate a continuous path of scope-narrowing receipts signed at each hop.

---


## 13. Conclusion

The agentic AI deployment model creates a trust problem that existing identity and authorization frameworks were not designed to address. The operator sits between the user and the agent with unchecked authority over what the agent is instructed to do. AuthProof makes that authority cryptographically bounded, the user's original intent immutably recorded, and operator deviation provable from a public log. The three-layer trust stack — signed capability manifest, Delegation Receipt, and Safescript execution binding — systematically eliminates trusted intermediaries from the agentic delegation chain.

The protocol is designed to be composable with, not competitive with, existing IETF work. A complete agentic trust stack requires both.

---

**Package:** `authproof-sdk`
**npm:** https://www.npmjs.com/package/authproof-sdk
**GitHub:** https://github.com/Commonguy25/authproof-sdk

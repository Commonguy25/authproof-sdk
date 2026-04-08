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

## 9. Comparison to Existing Approaches

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

## 10. Conclusion

The agentic AI deployment model creates a trust problem that existing identity and authorization frameworks were not designed to address. The operator sits between the user and the agent with unchecked authority over what the agent is instructed to do. AuthProof makes that authority cryptographically bounded, the user's original intent immutably recorded, and operator deviation provable from a public log. The three-layer trust stack — signed capability manifest, Delegation Receipt, and Safescript execution binding — systematically eliminates trusted intermediaries from the agentic delegation chain.

The protocol is designed to be composable with, not competitive with, existing IETF work. A complete agentic trust stack requires both.

---

**Package:** `authproof-sdk`
**npm:** https://www.npmjs.com/package/authproof-sdk
**GitHub:** https://github.com/Commonguy25/authproof-sdk

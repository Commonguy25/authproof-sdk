# AuthProof Community Posts

---

## Post 1 — Hacker News (Show HN)

**Title:** Show HN: AuthProof – cryptographic delegation receipts to close the user-to-operator AI agent trust gap

---

Show HN: AuthProof — https://github.com/Commonguy25/authproof-sdk

WIMSE, AIP, and draft-klrc-aiagent-auth all address service-to-agent trust: how a downstream API verifies that an agent is authorized to call it. None of them address user-to-operator trust: whether the operator's instructions to the agent actually reflect what the user authorized.

The trust gap is structural. The delegation chain is User → Operator → Agent → Services. The user tells the operator what they want. The operator writes a system prompt. But there is no cryptographic record of the user's original intent at the moment of delegation. The operator becomes an unchecked intermediary. If an operator is compromised, goes rogue, or is compelled by a court order, the agent cannot distinguish that from legitimate instruction. The user has no recourse. Auditors have no evidence chain.

AuthProof fills that gap with a **Delegation Receipt**: a signed Authorization Object anchored to a decentralized append-only log before any agent action begins. Four fields: a structured scope (explicit allowlist, deny by default), hard boundaries the operator cannot override, a time window anchored to the log timestamp not the client clock, and a hash of the operator's stated instructions at delegation time. If the operator later instructs the agent differently, the hash mismatch is provable from the log.

The trust stack has three layers:

1. **Signed capability manifest** — the scope field references the hash of a signed server manifest, not the operator's self-reported schema. Tool server behavior that diverges from the manifest is detectable.

2. **Delegation Receipt** — removes trust in the operator as a faithful intermediary.

3. **Safescript execution binding** — the `executes` scope class requires the hash of a specific Safescript program's static capability DAG. Safescript is statically analyzable before execution; there's no dynamic dispatch. If the operator supplies a different program than the one the user authorized, it doesn't run.

For out-of-scope tool calls, the agent pauses and requests a micro-receipt from the user for that specific action. No silent capability expansion.

Anticipating the obvious objections:

**"Why not just use OAuth scopes?"** OAuth scopes represent the operator's request for access, not the user's authorization of a specific agent behavior. The operator controls the token request. AuthProof commits the user's authorization before the operator's instructions reach the agent.

**"Why a custom log? Why not a blockchain?"** The protocol is log-agnostic. Any tamper-evident append-only log with fork detection works. Certificate Transparency-style logs are a natural fit. Blockchain is one option; it's not required.

**"What if the user doesn't understand the scope they're signing?"** The scope is structured, not natural language — that's a deliberate protocol constraint. UI is a separate problem. The protocol guarantees that what the user signs is what the agent is bound by; it doesn't guarantee the user will read it carefully, any more than a contract guarantees the signer read it.

**"Safescript is obscure."** It is. The `executes` layer is the most ambitious part of the protocol and the least mature. It's a design stake in the ground for what the correct solution looks like; the practical adoption path for execution binding may involve other static-analysis tools.

npm: `npm install authproof-sdk`
Whitepaper: WHITEPAPER.md in the repo

Interested in serious critique on the log design and the micro-receipt UX problem.

---

## Post 2 — r/netsec

**Title:** AuthProof: making operator malfeasance in AI agent systems cryptographically provable

---

Something that's been bugging me about the current AI agent security landscape: we've spent a lot of energy on service-to-agent authentication (can the API verify the agent is authorized?) and almost none on user-to-operator trust (can the user prove what they actually authorized?).

The threat model that nobody is talking about:

**Scenario 1: Operator compromise.** An attacker compromises an operator's systems and modifies the system prompt the agent receives. Under current architectures, the agent cannot distinguish this from a legitimate instruction change. There's no committed record of what the operator was supposed to say.

**Scenario 2: Operator malfeasance.** An operator, under commercial pressure or legal compulsion, instructs the agent to do something outside the user's original authorization. A law enforcement agency issues a subpoena requiring the operator to exfiltrate user data through the agent. The user has no cryptographic evidence of what they authorized. The operator's logs are the only record, controlled by the party whose conduct is in question.

**Scenario 3: Regulatory audit.** A regulator wants to audit whether an agentic system operated within the user's authorization. The only evidence available is operator-controlled logs. There's no independent anchor for what the user authorized.

I've been building AuthProof to address this directly. The core primitive is a **Delegation Receipt**: a signed Authorization Object that the user signs before any agent action begins, anchored to a tamper-evident append-only log. Four fields:

- **Scope** — explicit structured allowlist of permitted operations (reads, writes, deletes, executes). Deny by default. Not natural language.
- **Boundaries** — hard prohibitions that the operator cannot override.
- **Time window** — validated against the log timestamp, not the client clock.
- **Operator instruction hash** — SHA-256 of the operator's stated instructions at delegation time.

That last field is the key one for the threat model. If the operator later instructs the agent differently — whether because of compromise, malfeasance, or legal compulsion — the hash mismatch is detectable and provable from the public log. The operator cannot alter the log entry. The discrepancy between what the operator said they would do and what they actually instructed becomes an auditable fact.

This doesn't prevent operator malfeasance. It makes it provable. That's the design goal: shift the trust model from "trust the operator" to "the operator's deviation from stated instructions is a publicly verifiable fact."

The `executes` scope class adds another layer: it references the hash of a Safescript program's static capability signature, not the program name. The operator can't swap in a different program after delegation without the substitution being detectable.

For concurrent agents: each delegation event gets its own unique receipt. Concurrent agents are distinguishable by receipt ID, not by agent identity. An audit can reconstruct exactly which authorization each agent was operating under at each point in time.

Repo: https://github.com/Commonguy25/authproof-sdk

Curious what the netsec perspective is on the log design — specifically around fork detection and the trust assumptions in the log operator. The protocol is designed to work with CT-style logs; happy to discuss the threat model in more depth.

---

## Post 3 — r/LLMDevs

**Title:** AuthProof: how to add cryptographic authorization receipts to your agentic workflow (with micro-receipt flow explained)

---

If you're building agentic workflows, here's a problem you probably haven't solved yet: how do you prove, after the fact, that your agent only did what the user authorized? Not just "we have logs" — cryptographically provable, tamper-evident, auditable?

AuthProof is an npm package that adds a delegation receipt layer to any agentic workflow. Here's what it looks like in practice.

**The basic setup:**

```
npm install authproof-sdk
```

**The workflow:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    DELEGATION PHASE                             │
│  (happens before the agent does anything)                       │
│                                                                 │
│  1. Operator presents intended instructions to user             │
│  2. User defines scope (what agent CAN do — allowlist)          │
│  3. User defines boundaries (what agent CANNOT do — hard stops) │
│  4. User sets time window (e.g. "valid for 4 hours")            │
│  5. User signs the Authorization Object via WebAuthn/FIDO2      │
│  6. Signed receipt is anchored to append-only log               │
│  7. Log returns a timestamp anchor ← this is the time oracle    │
│                                                                 │
│  Result: receipt.hash (agent carries this into every action)    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AGENT EXECUTION PHASE                        │
│                                                                 │
│  For each action the agent wants to take:                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ authproof.validate({ receiptHash, action })              │   │
│  │                                                          │   │
│  │  Checks:                                                 │   │
│  │  ✓ Signature valid                                       │   │
│  │  ✓ Within time window (log timestamp, not client clock)  │   │
│  │  ✓ Action in scope allowlist                             │   │
│  │  ✓ Action not in boundaries (hard stops)                 │   │
│  │  ✓ Operator instructions hash unchanged                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│               │                        │                        │
│           AUTHORIZED               NOT AUTHORIZED               │
│               │                        │                        │
│               ▼                        ▼                        │
│         Proceed with          ┌─────────────────────┐          │
│           action              │  MICRO-RECEIPT FLOW  │          │
│                               │                     │          │
│                               │ 1. Agent PAUSES      │          │
│                               │ 2. Surfaces request  │          │
│                               │    to user:          │          │
│                               │    "I need to do X   │          │
│                               │    which isn't in    │          │
│                               │    your receipt.     │          │
│                               │    Authorize it?"    │          │
│                               │ 3. User signs a      │          │
│                               │    micro-receipt     │          │
│                               │    (just for X)      │          │
│                               │ 4. Agent proceeds    │          │
│                               │    with micro-       │          │
│                               │    receipt hash      │          │
│                               └─────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

**When does the agent actually pause for a micro-receipt?**

Any time it encounters a tool call not covered by the original scope. In practice this comes up in a few places:

- The user authorized `reads` on their calendar but the agent discovers it needs `reads` on a linked contacts list to resolve an attendee name.
- The user authorized a specific Safescript program to run, but a dependency that wasn't in the committed manifest is pulled in.
- The agent is asked to call a tool it discovered dynamically that wasn't in the signed capability manifest at delegation time.

The agent doesn't get to make a judgment call here. The protocol is: pause, surface, sign, proceed. No silent capability expansion.

**Scope structure:**

Scope is not natural language — it's a structured allowlist:

```js
const scope = new Scope()
  .allow('reads',  ['resource://calendar/events'])
  .allow('writes', ['resource://calendar/events'])
  .deny('deletes', '*')                               // hard boundary
  .execute('sha256:a3f1c9d8...', { program: 'scheduler-v1.sg' });
```

Operation classes are `reads`, `writes`, `deletes`, and `executes`. The `executes` class binds to a specific program hash — if you're not using Safescript yet, you can use this for any statically analyzable program; it's a protocol field, not an SDK requirement.

**Concurrent agents:**

Each delegation event gets a unique receipt ID. If you're running multiple agents concurrently, each one gets its own receipt. They're distinguishable by receipt hash in your logs — you can reconstruct exactly what each agent was authorized to do at each point in time, independently of agent identity.

**Key custody:**

Default is WebAuthn/FIDO2 via device secure enclave — the signing key never leaves hardware. You can also use delegated custody (key manager) or self-custody if your environment doesn't have FIDO2 support.

Repo + full docs: https://github.com/Commonguy25/authproof-sdk
Whitepaper with protocol spec: WHITEPAPER.md in the repo

Happy to answer questions about how to integrate this into LangGraph, n8n, or custom agent loops.

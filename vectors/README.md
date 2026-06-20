# DRP Conformance Test Vectors

Conformance test vectors for the **Delegation Receipt Protocol (DRP)**.
Each vector is a JSON file containing a pre-signed receipt (or receipt chain)
and the expected outcome when that receipt is presented to the reference verifier.

Vectors are generated from the reference SDK on branch `sdk-features`
(commits up to and including the one-time-consumption feature, latest hash `1f173d3`).

---

## Directory layout

```
vectors/
  canonicalization/   -- canonical encoding lock vectors (5 files)
  positive/           -- PERMIT vectors (5 files)
  negative/           -- DENY vectors (9 files)
  generate-vectors.js -- script that produces the JSON files (requires crypto)
  run-vectors.js      -- runner that verifies all vectors against the SDK
  README.md           -- this file
```

---

## How to run

```
node --experimental-global-webcrypto vectors/run-vectors.js
```

Exit code 0 means all vectors pass. Non-zero means at least one failure.

To regenerate vector files (produces new ECDSA key pairs and signatures):

```
node --experimental-global-webcrypto vectors/generate-vectors.js
```

---

## Vector format

### Canonicalization vectors (`canonicalization/*.json`)

```json
{
  "id": "canonical-01",
  "description": "...",
  "instructions": "<raw instruction text>",
  "normalizedForm": "<after Canonicalizer.normalize()>",
  "canonicalBytes": "<hex of UTF-8(normalizedForm)>",
  "sha256": "<SHA-256 of UTF-8(normalizedForm) as hex>",
  "receipt": {
    "instructionsHash": "<must equal sha256>",
    "signerPublicKey": { ... },
    "timeWindow": { "start": "...", "end": "..." },
    "issuedAt": "...",
    "delegationId": "..."
  }
}
```

These prove that an implementer's canonicalization of instruction text produces
byte-identical output to the reference SDK. The `sha256` field must equal
`receipt.instructionsHash` (the SDK stores `Canonicalizer.hash(instructions)`
in the receipt body at creation time).

**Canonical normalization steps (in order):**
1. Trim leading and trailing whitespace
2. Lowercase everything
3. Collapse all internal whitespace to single spaces
4. Remove meaning-neutral punctuation (commas, sentence-final periods, extra quotes)
5. Sort key-value pairs alphabetically if structured data is detected
6. Encode result as UTF-8 before hashing

### Positive vectors (`positive/*.json`)

```json
{
  "id": "...",
  "description": "...",
  "receipt": { ... },
  "receiptId": "<SHA-256 of JSON.stringify(receipt)>",
  "parentReceipt": { ... },          // optional, for delegation chains
  "parentReceiptId": "...",          // optional
  "parentScopeSchema": { ... },      // optional
  "chainReceipts": [ ... ],          // optional, for deep chains
  "action": "string or {operation,resource}",
  "operatorInstructions": "...",
  "currentAuthorityState": { ... },  // optional, for Check 15
  "verifierOptions": {
    "scopeSchema": { ... },          // registered in DelegationLog metadata
    "consumptionStore": "durable",   // "durable" or null
    "maxChainDepth": 3               // default 3
  },
  "expected": {
    "outcome": "PERMIT"
  }
}
```

### Negative vectors (`negative/*.json`)

Same format as positive, plus:

```json
{
  "testBehavior": "concurrent_replay | second_presentation",  // optional
  "expected": {
    "outcome": "DENY",
    "denialCode": "<substring that must appear in result.blockedReason>"
  }
}
```

The runner checks `result.blockedReason.includes(expected.denialCode)`.
For named SDK constants (`RECEIPT_ALREADY_CONSUMED`, `CONSUMPTION_STORE_REQUIRED`,
`PARENT_SCOPE_VIOLATION`) the `blockedReason` equals the constant exactly.

---

## Results table

| vector id                        | type     | expected outcome | expected denial code                           |
|----------------------------------|----------|------------------|------------------------------------------------|
| minimal-valid                    | positive | PERMIT           |                                                |
| delegation-chain                 | positive | PERMIT           |                                                |
| narrowed-sub-receipt             | positive | PERMIT           |                                                |
| authority-state-no-drift         | positive | PERMIT           |                                                |
| one-time-use-first-presentation  | positive | PERMIT           |                                                |
| invalid-signature                | negative | DENY             | Receipt signature invalid                      |
| expired                          | negative | DENY             | Receipt expired at                             |
| action-not-in-scope              | negative | DENY             | Scope violation                                |
| tampered-action-hash             | negative | DENY             | Operator instructions do not match receipt     |
| replay-same-session              | negative | DENY             | Replay attack detected                         |
| one-time-use-already-consumed    | negative | DENY             | RECEIPT_ALREADY_CONSUMED                       |
| one-time-use-no-store            | negative | DENY             | CONSUMPTION_STORE_REQUIRED                     |
| parent-scope-violation           | negative | DENY             | PARENT_SCOPE_VIOLATION                         |
| chain-exceeds-max-depth          | negative | DENY             | PARENT_SCOPE_VIOLATION                         |

---

## SDK denial code registry

Constants exported from `src/pre-execution-verifier.js`:

| constant                     | value                        | trigger                                                 |
|------------------------------|------------------------------|---------------------------------------------------------|
| `RECEIPT_ALREADY_CONSUMED`   | `'RECEIPT_ALREADY_CONSUMED'` | oneTimeUse receipt presented more than once             |
| `CONSUMPTION_STORE_REQUIRED` | `'CONSUMPTION_STORE_REQUIRED'` | oneTimeUse receipt with no durable store configured   |
| `MAX_CHAIN_DEPTH`            | `3`                          | default max delegation chain depth                      |

Other blockedReason strings (not exported as constants):

| blockedReason prefix                            | trigger                                         |
|-------------------------------------------------|-------------------------------------------------|
| `Receipt signature invalid`                     | Check 1: ECDSA P-256 signature fails            |
| `Receipt expired at`                            | Check 3: timeWindow.end is in the past          |
| `Scope violation`                               | Check 4: action not permitted by ScopeSchema    |
| `Operator instructions do not match receipt`    | Check 5: instructionsHash mismatch              |
| `Replay attack detected`                        | Concurrent check() with same receiptHash        |
| `PARENT_SCOPE_VIOLATION`                        | Check 14: child scope exceeds parent, bad sig,  |
|                                                 | time window violation, or chain too deep        |
| `REVOCATION_CHECK_REQUIRED`                     | offline mode + receipt.revocationRequired=true  |
| `AUTHORITY_STATE_DRIFT`                         | Check 15: authority state changed, policy=block |

---

## Notes for implementers

- Receipts are signed with ECDSA P-256. The `signerPublicKey` (JWK, `kty/crv/x/y`)
  is embedded in every signed receipt body.
- The signed body is `JSON.stringify(body)` with keys in insertion order (NOT
  sorted). Only the canonicalization vectors use sorted-key JSON.
- `receiptId` is `SHA-256(JSON.stringify(receipt))` where `receipt` includes the
  `signature` field but excludes nothing else.
- Sub-receipts carry `orchestratorSignature` over the string
  `"orchestrator-delegation:" + parentReceiptId + ":" + receiptId`.
  This field is excluded from the signed body.
- For `invalid-signature`, the stored receipt has a mutated `scope` field while
  the original signature is kept. The DelegationLog key is the SHA-256 of the
  original (pre-mutation) receipt.
- For `chain-exceeds-max-depth`, the runner must register all `chainReceipts`
  (root through c3) in the DelegationLog before checking c4.

---

Generated from reference SDK: `sdk-features` branch, commit `1f173d3`

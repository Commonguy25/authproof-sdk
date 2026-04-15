# authproof-py

Python SDK for [AuthProof](https://github.com/Commonguy25/authproof-sdk) — cryptographic delegation receipts for AI agents.

Mirrors the JavaScript `authproof-sdk` primitives with a Pythonic async API:

| JS primitive | Python module |
|---|---|
| `AuthProofClient` | `authproof.client` |
| `ScopeSchema` | `authproof.client` |
| `PreExecutionVerifier` | `authproof.verifier` |
| `ModelStateAttestation` | `authproof.attestation` |
| `DelegationChain` | `authproof.chain` |
| `authproofMiddleware` | `authproof.middleware.langchain` |

---

## Installation

```bash
pip install authproof-py
```

Or from source:

```bash
git clone https://github.com/Commonguy25/authproof-sdk
cd authproof-sdk/sdk-python
pip install -e .
```

**Requirements:** Python 3.9+, `cryptography>=41.0.0`

---

## Quick start

```python
import asyncio
from authproof import AuthProofClient, ScopeSchema, PreExecutionVerifier

async def main():
    # 1. Create a client (generates ECDSA P-256 key pair)
    client = AuthProofClient()

    # 2. Delegate — produce a signed receipt
    receipt = await client.delegate(
        scope=ScopeSchema(
            allowed_actions=[{"operation": "read", "resource": "email"}],
            denied_actions=[{"operation": "delete", "resource": "*"}],
        ),
        operator_instructions="Summarize inbox only",
        expires_in="2h",
    )
    print("receipt.hash:", receipt.hash)
    print("expires_at:",   receipt.expires_at)

    # 3. Verify — gate an agent action
    verifier = PreExecutionVerifier()
    verifier.register(receipt)

    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    print("allowed:", result.allowed)   # True

asyncio.run(main())
```

---

## Primitives

### `AuthProofClient`

Generates an ECDSA P-256 key pair and creates signed delegation receipts.

```python
client = AuthProofClient()

receipt = await client.delegate(
    scope=ScopeSchema(
        allowed_actions=[{"operation": "read",  "resource": "email"}],
        denied_actions= [{"operation": "delete","resource": "*"}],
    ),
    operator_instructions="Summarize inbox only",
    expires_in="2h",   # supports s / m / h / d
)

# receipt fields:
receipt.hash                        # SHA-256 of canonical receipt JSON
receipt.scope                       # ScopeSchema instance
receipt.expires_at                  # datetime (UTC)
receipt.operator_instructions       # raw instructions string
receipt.operator_instructions_hash  # SHA-256 of canonical instructions
```

### `ScopeSchema`

Machine-readable scope with wildcard support.

```python
schema = ScopeSchema(
    allowed_actions=[
        {"operation": "read",  "resource": "email"},
        {"operation": "write", "resource": "calendar/*"},
    ],
    denied_actions=[
        {"operation": "delete", "resource": "*"},
    ],
)

result = schema.validate({"operation": "read", "resource": "email"})
# {"valid": True, "reason": "..."}
```

### `PreExecutionVerifier`

Six-check gate: signature → revocation → time window → scope → instructions → (optional) model state.

```python
verifier = PreExecutionVerifier()
verifier.register(receipt)              # add a receipt to the store
verifier.revoke(receipt.hash, "reason") # mark revoked

result = await verifier.check(
    receipt_hash=receipt.hash,
    action={"operation": "read", "resource": "email"},
    operator_instructions="Summarize inbox only",
)
# result.allowed          bool
# result.checks           dict of check_name -> bool
# result.blocked_reason   str or None
# result.verified_at      ISO-8601 string
```

### `ModelStateAttestation`

Cryptographically bind a receipt to a specific model version.

```python
from authproof import ModelStateAttestation

attestation = ModelStateAttestation(provider_update_policy="reauthorize")

commitment_id = await attestation.commit(
    model_id="gpt-4",
    model_version="0613",
    system_prompt_hash="<sha256-of-system-prompt>",
    runtime_config_hash="<sha256-of-config>",
    receipt_hash=receipt.hash,
)

result = await attestation.verify(commitment_id, current_state={
    "model_id": "gpt-4",
    "model_version": "0614",   # changed!
    "system_prompt_hash": "...",
    "runtime_config_hash": "...",
})
# result.valid                   False
# result.mismatch_type           "PROVIDER_UPDATE_DETECTED"
# result.requires_reauthorization True

await attestation.reauthorize(commitment_id)   # accept the new version
```

`provider_update_policy` values:
- `"block"` — any state change immediately blocks execution
- `"reauthorize"` — version updates require explicit re-approval; model-ID swaps always block (`MaliciousSubstitution`)

### `DelegationChain`

Multi-hop delegation with scope attenuation enforcement.

```python
from authproof import DelegationChain, ScopeAttenuationError, MaxDepthExceededError

chain = DelegationChain(root_receipt=receipt, max_depth=3)

child = await chain.delegate(
    parent_receipt_hash=receipt.hash,
    child_scope=ScopeSchema(
        allowed_actions=[{"operation": "read", "resource": "email"}],
    ),
    child_agent="agent-public-key-or-id",
    private_key=client.private_key,
)

result = await chain.verify(child.hash)
# result.valid            True
# result.depth            1
# result.scope_attenuation bool

await chain.revoke(receipt.hash, cascade_to_children=True)
```

### LangChain middleware

```python
from authproof.middleware.langchain import authproof_middleware, AuthProofBlockedError

verifier = PreExecutionVerifier()
verifier.register(receipt)

guarded_agent = authproof_middleware(
    agent,
    receipt_hash=receipt.hash,
    verifier=verifier,
    operator_instructions="Summarize inbox only",
)

try:
    result = await guarded_agent.invoke("summarize my email")
except AuthProofBlockedError as e:
    print("Blocked:", e.reason)
```

Every call to `invoke()`, `run()`, or `call()` passes through `PreExecutionVerifier.check()` before reaching the agent. Blocked calls raise `AuthProofBlockedError(reason=...)`.

---

## Running the tests

```bash
cd sdk-python
pip install -r requirements.txt
python -m pytest tests/ -v
```

Expected: **36 tests, all passing**.

---

## PyPI publish

```bash
pip install build twine
python -m build
twine upload dist/*
```

Set `TWINE_USERNAME` / `TWINE_PASSWORD` or use a PyPI API token.

"""tests/test_middleware.py — 5 tests for authproof_middleware."""

import pytest

from authproof.client import AuthProofClient, ScopeSchema
from authproof.verifier import PreExecutionVerifier
from authproof.middleware.langchain import authproof_middleware, AuthProofBlockedError


# ─────────────────────────────────────────────
# FAKE AGENTS (sync and async)
# ─────────────────────────────────────────────

class _SyncAgent:
    """Synchronous test agent."""

    def invoke(self, input_str: str) -> str:
        return f"sync-result: {input_str}"

    def run(self, input_str: str) -> str:
        return f"sync-run: {input_str}"


class _AsyncAgent:
    """Asynchronous test agent."""

    async def invoke(self, input_str: str) -> str:
        return f"async-result: {input_str}"


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

async def _make_guarded(
    agent,
    allowed=None,
    denied=None,
    instructions="Allowed op",
):
    client = AuthProofClient()
    # Use resource="*" so the default get_action (which uses input[:64] as resource)
    # always matches regardless of what string the test passes to invoke().
    scope = ScopeSchema(
        allowed_actions=allowed or [{"operation": "invoke", "resource": "*"}],
        denied_actions=denied or [],
    )
    receipt = await client.delegate(
        scope=scope,
        operator_instructions=instructions,
        expires_in="2h",
    )
    verifier = PreExecutionVerifier()
    verifier.register(receipt)
    guarded = authproof_middleware(
        agent,
        receipt_hash=receipt.hash,
        verifier=verifier,
        operator_instructions=instructions,
    )
    return guarded, receipt, verifier


# ─────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────

async def test_allowed_action_passes_through_to_agent():
    """When action is allowed, invoke() returns the agent's result."""
    guarded, _, _ = await _make_guarded(_AsyncAgent())
    result = await guarded.invoke("hello")
    assert result == "async-result: hello"


async def test_blocked_action_raises_authproof_blocked_error():
    """When the receipt is revoked, invoke() raises AuthProofBlockedError."""
    agent = _AsyncAgent()
    guarded, receipt, verifier = await _make_guarded(agent)
    verifier.revoke(receipt.hash, reason="testing block")

    with pytest.raises(AuthProofBlockedError):
        await guarded.invoke("do something")


async def test_blocked_reason_is_propagated():
    """The blocked_reason from the verifier is accessible on AuthProofBlockedError."""
    agent = _AsyncAgent()
    guarded, receipt, verifier = await _make_guarded(agent)
    verifier.revoke(receipt.hash, reason="policy violation")

    try:
        await guarded.invoke("do something")
        pytest.fail("Expected AuthProofBlockedError was not raised")
    except AuthProofBlockedError as exc:
        assert "revoked" in str(exc).lower() or "policy violation" in str(exc).lower()
        assert exc.reason is not None


async def test_non_async_agent_wrapped_correctly():
    """A synchronous agent can be wrapped; invoke() still works as async."""
    guarded, _, _ = await _make_guarded(_SyncAgent())
    result = await guarded.invoke("hello sync")
    assert result == "sync-result: hello sync"


async def test_other_attributes_delegated_to_agent():
    """Accessing an attribute not in invoke/run/call passes through to the original agent."""

    class _AgentWithExtra:
        name = "my-agent"

        async def invoke(self, x):
            return x

    guarded, _, _ = await _make_guarded(_AgentWithExtra())
    assert guarded.name == "my-agent"

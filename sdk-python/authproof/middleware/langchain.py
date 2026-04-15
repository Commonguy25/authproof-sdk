"""
AuthProof LangChain middleware.

Wraps any agent that exposes invoke() / run() / call() so that every
invocation is gated by PreExecutionVerifier before reaching the agent.

Example::

    from authproof.middleware.langchain import authproof_middleware

    verifier = PreExecutionVerifier()
    verifier.register(receipt)

    guarded = authproof_middleware(
        agent,
        receipt_hash=receipt.hash,
        verifier=verifier,
        operator_instructions="Summarize inbox only",
    )

    # Raises AuthProofBlockedError if the action is not allowed
    result = await guarded.invoke("Summarize my inbox")
"""

import asyncio
import inspect
from typing import Callable, Optional

from authproof.verifier import PreExecutionVerifier


# ─────────────────────────────────────────────
# ERROR
# ─────────────────────────────────────────────

class AuthProofBlockedError(Exception):
    """
    Raised when PreExecutionVerifier blocks an action.

    Attributes
    ----------
    reason : str
        The blocked_reason returned by the verifier.
    """

    def __init__(self, reason: str):
        super().__init__(f"[AuthProof] Action blocked: {reason}")
        self.reason = reason


# ─────────────────────────────────────────────
# GUARDED AGENT WRAPPER
# ─────────────────────────────────────────────

class _GuardedAgent:
    """
    Internal proxy that wraps an agent and gates every call through
    PreExecutionVerifier.  Transparently delegates all other attribute
    accesses to the original agent.
    """

    def __init__(
        self,
        agent,
        receipt_hash: str,
        verifier: PreExecutionVerifier,
        operator_instructions: Optional[str],
        get_action: Optional[Callable],
    ):
        self._agent = agent
        self._receipt_hash = receipt_hash
        self._verifier = verifier
        self._operator_instructions = operator_instructions
        self._get_action = get_action or self._default_get_action

    @staticmethod
    def _default_get_action(input_value) -> dict:
        if isinstance(input_value, str):
            resource = input_value[:64] if input_value else "agent/invoke"
        else:
            resource = "agent/invoke"
        return {"operation": "invoke", "resource": resource}

    async def _guard(self, input_value) -> None:
        """Run the verifier; raise AuthProofBlockedError if blocked."""
        action = self._get_action(input_value)
        result = await self._verifier.check(
            receipt_hash=self._receipt_hash,
            action=action,
            operator_instructions=self._operator_instructions,
        )
        if not result.allowed:
            raise AuthProofBlockedError(result.blocked_reason)

    async def invoke(self, *args, **kwargs):
        """Gate invoke() through the verifier, then call the original."""
        input_value = args[0] if args else kwargs.get("input", "")
        await self._guard(input_value)
        orig = self._agent.invoke
        if inspect.iscoroutinefunction(orig):
            return await orig(*args, **kwargs)
        return orig(*args, **kwargs)

    async def run(self, *args, **kwargs):
        """Gate run() through the verifier, then call the original."""
        input_value = args[0] if args else kwargs.get("input", "")
        await self._guard(input_value)
        orig = self._agent.run
        if inspect.iscoroutinefunction(orig):
            return await orig(*args, **kwargs)
        return orig(*args, **kwargs)

    async def call(self, *args, **kwargs):
        """Gate call() through the verifier, then call the original."""
        input_value = args[0] if args else kwargs.get("input", "")
        await self._guard(input_value)
        orig = self._agent.call
        if inspect.iscoroutinefunction(orig):
            return await orig(*args, **kwargs)
        return orig(*args, **kwargs)

    def __getattr__(self, name: str):
        """Delegate any other attribute access to the wrapped agent."""
        return getattr(self._agent, name)

    def __repr__(self) -> str:  # pragma: no cover
        return f"_GuardedAgent(agent={self._agent!r}, receipt={self._receipt_hash[:8]}…)"


# ─────────────────────────────────────────────
# PUBLIC FACTORY
# ─────────────────────────────────────────────

def authproof_middleware(
    agent,
    *,
    receipt_hash: str,
    verifier: PreExecutionVerifier,
    operator_instructions: Optional[str] = None,
    get_action: Optional[Callable] = None,
) -> _GuardedAgent:
    """
    Wrap an agent so every invoke/run/call is gated by PreExecutionVerifier.

    Parameters
    ----------
    agent:
        Any object with an invoke(), run(), or call() method.
    receipt_hash:
        Hash of the delegation receipt to verify against.
    verifier:
        An initialized PreExecutionVerifier with the receipt registered.
    operator_instructions:
        Current operator instructions (optional; defaults to receipt's).
    get_action:
        Optional callable ``(input) -> {"operation": ..., "resource": ...}``.
        Defaults to ``{"operation": "invoke", "resource": input[:64]}``.

    Returns
    -------
    _GuardedAgent
        A wrapped agent whose invoke/run/call methods run through the gate.
    """
    if agent is None:
        raise ValueError("authproof_middleware: agent is required")
    if not receipt_hash:
        raise ValueError("authproof_middleware: receipt_hash is required")
    if verifier is None:
        raise ValueError("authproof_middleware: verifier is required")

    return _GuardedAgent(
        agent=agent,
        receipt_hash=receipt_hash,
        verifier=verifier,
        operator_instructions=operator_instructions,
        get_action=get_action,
    )

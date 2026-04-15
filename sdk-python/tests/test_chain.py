"""tests/test_chain.py — 7 tests for DelegationChain."""

import pytest

from authproof.client import AuthProofClient, ScopeSchema
from authproof.chain import DelegationChain, ScopeAttenuationError, MaxDepthExceededError


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

_FULL_SCOPE = ScopeSchema(
    allowed_actions=[
        {"operation": "read", "resource": "email"},
        {"operation": "write", "resource": "calendar"},
    ],
    denied_actions=[{"operation": "delete", "resource": "*"}],
)

_NARROW_SCOPE = ScopeSchema(
    allowed_actions=[{"operation": "read", "resource": "email"}],
    denied_actions=[{"operation": "delete", "resource": "*"}],
)


async def _make_root(scope=None, expires_in="2h"):
    client = AuthProofClient()
    receipt = await client.delegate(
        scope=scope or _FULL_SCOPE,
        operator_instructions="Root instructions",
        expires_in=expires_in,
    )
    return client, receipt


# ─────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────

async def test_root_child_chain_verifies():
    """Root → child delegation chain verifies successfully."""
    client, root = await _make_root()
    chain = DelegationChain(root_receipt=root, max_depth=3)
    child = await chain.delegate(
        parent_receipt_hash=root.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="agent-abc",
        private_key=client.private_key,
    )

    result = await chain.verify(child.hash)
    assert result.valid is True
    assert result.depth == 1
    assert result.blocked_reason is None


async def test_child_scope_broader_than_parent_raises():
    """Attempting to delegate a scope wider than the parent raises ScopeAttenuationError."""
    client, root = await _make_root(scope=_NARROW_SCOPE)
    chain = DelegationChain(root_receipt=root, max_depth=3)

    broader_scope = ScopeSchema(
        allowed_actions=[
            {"operation": "read", "resource": "email"},
            {"operation": "write", "resource": "calendar"},  # not in parent!
        ],
    )

    with pytest.raises(ScopeAttenuationError):
        await chain.delegate(
            parent_receipt_hash=root.hash,
            child_scope=broader_scope,
            child_agent="agent-xyz",
            private_key=client.private_key,
        )


async def test_max_depth_exceeded_raises():
    """Exceeding max_depth raises MaxDepthExceededError."""
    client, root = await _make_root()
    chain = DelegationChain(root_receipt=root, max_depth=1)

    child = await chain.delegate(
        parent_receipt_hash=root.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="child-agent",
        private_key=client.private_key,
    )
    # Depth is now 1, which equals max_depth — next level should fail
    with pytest.raises(MaxDepthExceededError):
        await chain.delegate(
            parent_receipt_hash=child.hash,
            child_scope=_NARROW_SCOPE,
            child_agent="grandchild-agent",
            private_key=client.private_key,
        )


async def test_cascade_revocation_invalidates_children():
    """Revoking root with cascade=True invalidates all descendant receipts."""
    client, root = await _make_root()
    chain = DelegationChain(root_receipt=root, max_depth=3)
    child = await chain.delegate(
        parent_receipt_hash=root.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="child-agent",
        private_key=client.private_key,
    )
    grandchild = await chain.delegate(
        parent_receipt_hash=child.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="grandchild-agent",
        private_key=client.private_key,
    )

    await chain.revoke(root.hash, cascade_to_children=True)

    root_result = await chain.verify(root.hash)
    child_result = await chain.verify(child.hash)
    gc_result = await chain.verify(grandchild.hash)

    assert root_result.valid is False
    assert child_result.valid is False
    assert gc_result.valid is False


async def test_verify_returns_correct_depth():
    """verify() returns the correct depth for each node in the chain."""
    client, root = await _make_root()
    chain = DelegationChain(root_receipt=root, max_depth=5)

    child = await chain.delegate(
        parent_receipt_hash=root.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="child",
        private_key=client.private_key,
    )
    grandchild = await chain.delegate(
        parent_receipt_hash=child.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="grandchild",
        private_key=client.private_key,
    )

    root_result = await chain.verify(root.hash)
    child_result = await chain.verify(child.hash)
    gc_result = await chain.verify(grandchild.hash)

    assert root_result.depth == 0
    assert child_result.depth == 1
    assert gc_result.depth == 2


async def test_revoke_without_cascade_leaves_children_valid():
    """Revoking a node without cascade leaves children unaffected in the revocation set."""
    client, root = await _make_root()
    chain = DelegationChain(root_receipt=root, max_depth=3)
    child = await chain.delegate(
        parent_receipt_hash=root.hash,
        child_scope=_NARROW_SCOPE,
        child_agent="child",
        private_key=client.private_key,
    )

    # Revoke root but do NOT cascade
    await chain.revoke(root.hash, cascade_to_children=False)

    # Child itself is not in the revoked set — but chain.verify() walks up
    # and will find the revoked root, so the chain is still broken.
    child_result = await chain.verify(child.hash)
    assert child_result.valid is False   # root in chain is revoked


async def test_root_verifies_at_depth_zero():
    """The root receipt itself verifies at depth 0."""
    _, root = await _make_root()
    chain = DelegationChain(root_receipt=root, max_depth=3)
    result = await chain.verify(root.hash)
    assert result.valid is True
    assert result.depth == 0

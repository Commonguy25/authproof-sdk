"""
DelegationChain — multi-hop delegation with scope attenuation enforcement.

A DelegationChain tracks a tree of delegation receipts rooted at one
"root" receipt. Each child receipt can delegate a *subset* of the
parent's permissions; attempting to grant broader scope raises
``ScopeAttenuationError``.

Example::

    client = AuthProofClient()
    root = await client.delegate(
        scope=ScopeSchema(
            allowed_actions=[{"operation": "read", "resource": "email"}],
        ),
        operator_instructions="Read emails",
        expires_in="2h",
    )

    chain = DelegationChain(root_receipt=root, max_depth=3)
    child = await chain.delegate(
        parent_receipt_hash=root.hash,
        child_scope=ScopeSchema(
            allowed_actions=[{"operation": "read", "resource": "email"}],
        ),
        child_agent="agent-public-key-or-id",
        private_key=client.private_key,
    )
    result = await chain.verify(child.hash)
    # result.valid == True, result.depth == 1
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from authproof.client import (
    AuthProofClient,
    DelegationReceipt,
    ScopeSchema,
    _canonical_json,
    _public_key_to_dict,
    _sha256,
    _sign,
    canonicalize_hash,
)


# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────

class ScopeAttenuationError(Exception):
    """Raised when a child scope is broader than its parent scope."""


class MaxDepthExceededError(Exception):
    """Raised when the chain would exceed its configured max_depth."""


# ─────────────────────────────────────────────
# RESULT TYPES
# ─────────────────────────────────────────────

@dataclass
class ChainVerifyResult:
    """Result returned by DelegationChain.verify()."""
    valid: bool
    depth: int
    scope_attenuation: bool   # True if the scope was narrowed at any hop
    blocked_reason: Optional[str]


# ─────────────────────────────────────────────
# SCOPE ATTENUATION CHECK
# ─────────────────────────────────────────────

def _check_scope_attenuation(parent: ScopeSchema, child: ScopeSchema) -> None:
    """
    Raise ScopeAttenuationError if child grants any action not covered by parent.

    Each allowed_action in the child must be validated against the parent schema.
    """
    for action in child.allowed_actions:
        result = parent.validate(action)
        if not result["valid"]:
            raise ScopeAttenuationError(
                f"Child scope includes action not permitted by parent: "
                f"{action.get('operation')} on {action.get('resource')}. "
                f"Reason: {result['reason']}"
            )


# ─────────────────────────────────────────────
# DELEGATION CHAIN
# ─────────────────────────────────────────────

class DelegationChain:
    """
    Multi-hop delegation chain rooted at a single receipt.

    Parameters
    ----------
    root_receipt:
        The top-level DelegationReceipt (from AuthProofClient.delegate()).
    max_depth:
        Maximum allowed chain depth. Root is depth 0; first child is depth 1.
        Default: 3.
    """

    def __init__(self, root_receipt: DelegationReceipt, max_depth: int = 3):
        if not isinstance(root_receipt, DelegationReceipt):
            raise TypeError("root_receipt must be a DelegationReceipt")
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")

        self._max_depth = max_depth
        self._root_hash = root_receipt.hash

        # receipt_hash -> node dict
        self._nodes: Dict[str, dict] = {}
        # receipt_hash -> list of child receipt hashes
        self._children: Dict[str, List[str]] = {}
        # revoked receipt hashes
        self._revoked: Set[str] = set()

        # Register the root node
        self._nodes[root_receipt.hash] = {
            "receipt_hash": root_receipt.hash,
            "raw": root_receipt._raw,
            "scope": root_receipt.scope,
            "parent_hash": None,
            "depth": 0,
        }
        self._children[root_receipt.hash] = []

    # ── Delegate ─────────────────────────────────────────────────────────

    async def delegate(
        self,
        parent_receipt_hash: str,
        child_scope: ScopeSchema,
        child_agent: str,
        private_key,
    ) -> DelegationReceipt:
        """
        Create a child delegation under an existing receipt in the chain.

        Parameters
        ----------
        parent_receipt_hash:
            Hash of the parent receipt (must already be in the chain).
        child_scope:
            Scope for the child — must be a subset of the parent's scope.
        child_agent:
            Identifier (string) for the child agent.
        private_key:
            Private key to sign the child receipt with.

        Raises
        ------
        KeyError
            If parent_receipt_hash is not in the chain.
        ScopeAttenuationError
            If child_scope is broader than the parent's scope.
        MaxDepthExceededError
            If adding this node would exceed max_depth.
        """
        parent_node = self._nodes.get(parent_receipt_hash)
        if parent_node is None:
            raise KeyError(f"Parent receipt not found in chain: {parent_receipt_hash[:8]}…")

        parent_depth = parent_node["depth"]
        child_depth = parent_depth + 1
        if child_depth > self._max_depth:
            raise MaxDepthExceededError(
                f"Chain max depth {self._max_depth} exceeded. "
                f"Parent is at depth {parent_depth}."
            )

        # Scope attenuation check
        parent_scope: ScopeSchema = parent_node["scope"]
        _check_scope_attenuation(parent_scope, child_scope)

        # Build child receipt body
        now = datetime.now(timezone.utc)
        delegation_id = f"auth-{int(now.timestamp() * 1000)}-{secrets.token_hex(4)}"

        # Inherit time window from parent (child can't outlive parent)
        parent_raw = parent_node["raw"]
        parent_end = parent_raw["time_window"]["end"]

        # Use a placeholder instructions string for child receipts
        child_instructions = f"Delegated by {parent_receipt_hash[:8]}"
        instructions_hash = canonicalize_hash(child_instructions)

        public_key = private_key.public_key()
        public_key_dict = _public_key_to_dict(public_key)

        body: dict = {
            "delegation_id": delegation_id,
            "issued_at": now.isoformat(),
            "parent_hash": parent_receipt_hash,
            "depth": child_depth,
            "scope": child_scope.to_dict(),
            "time_window": {
                "start": now.isoformat(),
                "end": parent_end,
            },
            "child_agent": child_agent,
            "operator_instructions": child_instructions,
            "instructions_hash": instructions_hash,
            "signer_public_key": public_key_dict,
        }

        body_json = _canonical_json(body)
        signature = _sign(private_key, body_json)
        raw = {**body, "signature": signature}
        receipt_hash = _sha256(_canonical_json(raw))

        # Record in chain
        self._nodes[receipt_hash] = {
            "receipt_hash": receipt_hash,
            "raw": raw,
            "scope": child_scope,
            "parent_hash": parent_receipt_hash,
            "depth": child_depth,
        }
        self._children[receipt_hash] = []
        self._children.setdefault(parent_receipt_hash, []).append(receipt_hash)

        # Return as a DelegationReceipt-compatible object
        expires_at = datetime.fromisoformat(parent_end)
        return DelegationReceipt(
            hash=receipt_hash,
            scope=child_scope,
            expires_at=expires_at,
            operator_instructions=child_instructions,
            operator_instructions_hash=instructions_hash,
            _raw=raw,
            _public_key=public_key,
        )

    # ── Verify ───────────────────────────────────────────────────────────

    async def verify(self, receipt_hash: str) -> ChainVerifyResult:
        """
        Verify a receipt exists in the chain and trace back to the root.

        Returns a ChainVerifyResult with:
        * valid          — True if chain is intact and unrevoked
        * depth          — Distance from root (root itself is 0)
        * scope_attenuation — True if any hop narrowed the scope
        * blocked_reason — Explanation when valid=False
        """
        node = self._nodes.get(receipt_hash)
        if node is None:
            return ChainVerifyResult(
                valid=False,
                depth=0,
                scope_attenuation=False,
                blocked_reason=f"Receipt not found in chain: {receipt_hash[:8]}…",
            )

        depth = node["depth"]
        scope_attenuation = False

        # Walk the chain from this node back to root, checking each hop
        current_hash = receipt_hash
        visited = []
        while current_hash is not None:
            if current_hash in self._revoked:
                return ChainVerifyResult(
                    valid=False,
                    depth=depth,
                    scope_attenuation=scope_attenuation,
                    blocked_reason=f"Receipt in chain is revoked: {current_hash[:8]}…",
                )
            visited.append(current_hash)
            cur_node = self._nodes[current_hash]
            parent_hash = cur_node["parent_hash"]
            if parent_hash is not None:
                parent_node = self._nodes.get(parent_hash)
                if parent_node is None:
                    return ChainVerifyResult(
                        valid=False,
                        depth=depth,
                        scope_attenuation=scope_attenuation,
                        blocked_reason=f"Parent receipt missing: {parent_hash[:8]}…",
                    )
                # Check if scope was attenuated at this hop
                try:
                    _check_scope_attenuation(parent_node["scope"], cur_node["scope"])
                except ScopeAttenuationError:
                    # This shouldn't happen if delegate() was used properly,
                    # but if someone injected a node externally it could
                    return ChainVerifyResult(
                        valid=False,
                        depth=depth,
                        scope_attenuation=scope_attenuation,
                        blocked_reason="Scope attenuation violation detected in chain",
                    )
                # Detect actual attenuation (child has fewer permissions)
                if len(cur_node["scope"].allowed_actions) < len(parent_node["scope"].allowed_actions):
                    scope_attenuation = True
            current_hash = parent_hash

        return ChainVerifyResult(
            valid=True,
            depth=depth,
            scope_attenuation=scope_attenuation,
            blocked_reason=None,
        )

    # ── Revoke ───────────────────────────────────────────────────────────

    async def revoke(
        self,
        receipt_hash: str,
        cascade_to_children: bool = False,
    ) -> None:
        """
        Revoke a receipt in the chain.

        Parameters
        ----------
        receipt_hash:
            Hash of the receipt to revoke.
        cascade_to_children:
            If True, recursively revoke all descendant receipts too.
        """
        if receipt_hash not in self._nodes:
            raise KeyError(f"Receipt not found in chain: {receipt_hash[:8]}…")

        self._revoked.add(receipt_hash)

        if cascade_to_children:
            self._revoke_subtree(receipt_hash)

    def _revoke_subtree(self, receipt_hash: str) -> None:
        """Recursively revoke all children of a receipt."""
        for child_hash in self._children.get(receipt_hash, []):
            self._revoked.add(child_hash)
            self._revoke_subtree(child_hash)

    # ── Accessors ────────────────────────────────────────────────────────

    def is_revoked(self, receipt_hash: str) -> bool:
        return receipt_hash in self._revoked

    def get_depth(self, receipt_hash: str) -> Optional[int]:
        node = self._nodes.get(receipt_hash)
        return node["depth"] if node else None

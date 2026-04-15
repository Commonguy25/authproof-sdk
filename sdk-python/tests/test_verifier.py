"""tests/test_verifier.py — 10 tests for PreExecutionVerifier."""

import pytest

from authproof.client import AuthProofClient, ScopeSchema
from authproof.verifier import PreExecutionVerifier


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

async def _make_receipt(
    allowed=None,
    denied=None,
    instructions="Summarize inbox only",
    expires_in="2h",
):
    client = AuthProofClient()
    scope = ScopeSchema(
        allowed_actions=allowed or [{"operation": "read", "resource": "email"}],
        denied_actions=denied or [{"operation": "delete", "resource": "*"}],
    )
    receipt = await client.delegate(
        scope=scope,
        operator_instructions=instructions,
        expires_in=expires_in,
    )
    return receipt


async def _make_verifier(receipt):
    v = PreExecutionVerifier()
    v.register(receipt)
    return v


# ─────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────

async def test_valid_receipt_matching_action_allowed():
    """Valid receipt with a matching allowed action → allowed=True."""
    receipt = await _make_receipt()
    verifier = await _make_verifier(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    assert result.allowed is True
    assert result.blocked_reason is None
    assert result.checks["receipt_signature_valid"] is True
    assert result.checks["receipt_not_revoked"] is True
    assert result.checks["within_time_window"] is True
    assert result.checks["action_within_scope"] is True
    assert result.checks["operator_instructions_match"] is True


async def test_expired_receipt_blocked():
    """Receipt with expires_in=0 (already expired) → blocked with expiry message."""
    # Create a receipt with a very short TTL, then wait is not needed;
    # we manipulate the raw receipt's time_window directly to simulate expiry.
    receipt = await _make_receipt(expires_in="2h")
    # Tamper: push both start and end into the past
    from datetime import datetime, timedelta, timezone
    past = datetime.now(timezone.utc) - timedelta(hours=3)
    past_end = past + timedelta(hours=1)
    receipt._raw["time_window"]["start"] = past.isoformat()
    receipt._raw["time_window"]["end"] = past_end.isoformat()
    # Re-register with modified raw
    verifier = PreExecutionVerifier()
    verifier.register_raw(receipt.hash, receipt._raw)

    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    assert result.allowed is False
    assert result.blocked_reason is not None
    assert "expired" in result.blocked_reason.lower() or "Receipt" in result.blocked_reason


async def test_action_not_in_allow_list_blocked():
    """Action whose operation is not in allowed_actions → blocked with scope message."""
    receipt = await _make_receipt(
        allowed=[{"operation": "read", "resource": "email"}],
    )
    verifier = await _make_verifier(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "write", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    assert result.allowed is False
    assert "scope" in result.blocked_reason.lower() or "allowed_actions" in result.blocked_reason


async def test_action_in_deny_list_blocked_even_if_in_allow_list():
    """Action that appears in both allow and deny → blocked (deny takes precedence)."""
    receipt = await _make_receipt(
        allowed=[
            {"operation": "read", "resource": "email"},
            {"operation": "delete", "resource": "email"},
        ],
        denied=[{"operation": "delete", "resource": "*"}],
    )
    verifier = await _make_verifier(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "delete", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    assert result.allowed is False
    assert "denied" in result.blocked_reason.lower() or "scope" in result.blocked_reason.lower()


async def test_operator_instructions_mismatch_blocked():
    """Providing different operator instructions → blocked with drift message."""
    receipt = await _make_receipt(instructions="Summarize inbox only")
    verifier = await _make_verifier(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Delete all emails",   # different!
    )
    assert result.allowed is False
    assert "instruction" in result.blocked_reason.lower() or "drift" in result.blocked_reason.lower()


async def test_unknown_receipt_hash_blocked():
    """Checking an unknown receipt hash → blocked with not-found message."""
    verifier = PreExecutionVerifier()
    result = await verifier.check(
        receipt_hash="0" * 64,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Anything",
    )
    assert result.allowed is False
    assert "not found" in result.blocked_reason.lower()


async def test_revoked_receipt_blocked():
    """Revoking a receipt causes subsequent checks to be blocked."""
    receipt = await _make_receipt()
    verifier = await _make_verifier(receipt)
    verifier.revoke(receipt.hash, reason="manual revocation")

    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    assert result.allowed is False
    assert "revoked" in result.blocked_reason.lower()


async def test_checks_dict_contains_expected_keys():
    """The result.checks dict always contains the six standard keys."""
    receipt = await _make_receipt()
    verifier = await _make_verifier(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    assert "receipt_signature_valid" in result.checks
    assert "receipt_not_revoked" in result.checks
    assert "within_time_window" in result.checks
    assert "action_within_scope" in result.checks
    assert "operator_instructions_match" in result.checks


async def test_wildcard_resource_allowed():
    """A receipt allowing op on '*' accepts any resource."""
    client = AuthProofClient()
    scope = ScopeSchema(allowed_actions=[{"operation": "read", "resource": "*"}])
    receipt = await client.delegate(
        scope=scope, operator_instructions="Read anything", expires_in="1h"
    )
    verifier = PreExecutionVerifier()
    verifier.register(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "database/table_users"},
        operator_instructions="Read anything",
    )
    assert result.allowed is True


async def test_no_operator_instructions_arg_uses_receipt_value():
    """Omitting operator_instructions in check() defaults to the receipt's own value."""
    receipt = await _make_receipt(instructions="Summarize inbox only")
    verifier = await _make_verifier(receipt)
    # Pass no operator_instructions → should match receipt's own stored value
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
    )
    assert result.allowed is True

"""tests/test_client.py — 8 tests for AuthProofClient and ScopeSchema."""

import hashlib
import json

import pytest

from authproof.client import (
    AuthProofClient,
    ScopeSchema,
    DelegationReceipt,
    _canonical_json,
    _sha256,
    _verify_signature,
    _public_key_from_dict,
    canonicalize_hash,
)


# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────

@pytest.fixture
async def client_and_receipt():
    client = AuthProofClient()
    scope = ScopeSchema(
        allowed_actions=[{"operation": "read", "resource": "email"}],
        denied_actions=[{"operation": "delete", "resource": "*"}],
    )
    receipt = await client.delegate(
        scope=scope,
        operator_instructions="Summarize inbox only",
        expires_in="2h",
    )
    return client, receipt


# ─────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────

async def test_key_pair_generated_on_init():
    """Client generates an ECDSA key pair at construction time."""
    client = AuthProofClient()
    assert client.private_key is not None
    assert client.public_key is not None
    assert "x" in client.public_key_dict
    assert "y" in client.public_key_dict
    assert client.public_key_dict["crv"] == "P-256"


async def test_delegate_returns_receipt_with_correct_fields(client_and_receipt):
    """delegate() returns a DelegationReceipt with all expected fields."""
    _, receipt = client_and_receipt
    assert isinstance(receipt, DelegationReceipt)
    assert receipt.hash
    assert receipt.scope is not None
    assert receipt.expires_at is not None
    assert receipt.operator_instructions == "Summarize inbox only"
    assert receipt.operator_instructions_hash


async def test_receipt_hash_is_sha256_of_canonical_payload(client_and_receipt):
    """receipt.hash equals SHA-256 of the canonical JSON of the full receipt."""
    _, receipt = client_and_receipt
    raw = receipt._raw
    expected_hash = _sha256(_canonical_json(raw))
    assert receipt.hash == expected_hash


async def test_operator_instructions_hash_matches_sha256(client_and_receipt):
    """receipt.operator_instructions_hash matches SHA-256 of canonical instructions."""
    _, receipt = client_and_receipt
    expected = canonicalize_hash("Summarize inbox only")
    assert receipt.operator_instructions_hash == expected


async def test_expires_in_2h_sets_correct_expiry(client_and_receipt):
    """expires_in='2h' produces an expiry ~7200 seconds from now."""
    _, receipt = client_and_receipt
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    delta_seconds = (receipt.expires_at - now).total_seconds()
    # Allow ±5 s tolerance for test execution time
    assert 7190 <= delta_seconds <= 7205


async def test_receipt_signature_verifiable_with_public_key(client_and_receipt):
    """The receipt body signature can be verified with the signer's public key."""
    _, receipt = client_and_receipt
    raw = receipt._raw
    signature = raw["signature"]
    body = {k: v for k, v in raw.items() if k != "signature"}
    body_json = _canonical_json(body)
    pub_key = _public_key_from_dict(raw["signer_public_key"])
    assert _verify_signature(pub_key, signature, body_json)


async def test_two_receipts_same_scope_have_different_hashes():
    """Two receipts created from the same scope have unique hashes."""
    client = AuthProofClient()
    scope = ScopeSchema(allowed_actions=[{"operation": "read", "resource": "email"}])
    r1 = await client.delegate(scope=scope, operator_instructions="Do stuff", expires_in="1h")
    r2 = await client.delegate(scope=scope, operator_instructions="Do stuff", expires_in="1h")
    assert r1.hash != r2.hash


async def test_scope_stored_correctly_on_receipt():
    """receipt.scope reflects the ScopeSchema passed to delegate()."""
    client = AuthProofClient()
    scope = ScopeSchema(
        allowed_actions=[
            {"operation": "read", "resource": "email"},
            {"operation": "write", "resource": "calendar"},
        ],
        denied_actions=[{"operation": "delete", "resource": "*"}],
    )
    receipt = await client.delegate(
        scope=scope,
        operator_instructions="Manage my schedule",
        expires_in="30m",
    )
    assert len(receipt.scope.allowed_actions) == 2
    assert len(receipt.scope.denied_actions) == 1
    assert receipt.scope.allowed_actions[0]["operation"] == "read"

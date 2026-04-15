"""tests/test_attestation.py — 6 tests for ModelStateAttestation."""

import pytest

from authproof.client import AuthProofClient, ScopeSchema
from authproof.attestation import ModelStateAttestation


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

_BASE_STATE = {
    "model_id": "gpt-4",
    "model_version": "0613",
    "system_prompt_hash": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
    "runtime_config_hash": "def456abc123def456abc123def456abc123def456abc123def456abc123def4",
}


async def _make_receipt():
    client = AuthProofClient()
    scope = ScopeSchema(allowed_actions=[{"operation": "read", "resource": "email"}])
    return await client.delegate(
        scope=scope, operator_instructions="Do stuff", expires_in="1h"
    )


async def _make_commitment(policy="block", state=None):
    state = state or _BASE_STATE
    attestation = ModelStateAttestation(provider_update_policy=policy)
    receipt = await _make_receipt()
    commitment_id = await attestation.commit(
        model_id=state["model_id"],
        model_version=state["model_version"],
        system_prompt_hash=state["system_prompt_hash"],
        runtime_config_hash=state["runtime_config_hash"],
        receipt_hash=receipt.hash,
    )
    return attestation, commitment_id


# ─────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────

async def test_matching_state_is_valid():
    """Same state as committed → valid=True, no mismatch."""
    attestation, commitment_id = await _make_commitment()
    result = await attestation.verify(commitment_id, current_state=_BASE_STATE)
    assert result.valid is True
    assert result.mismatch_type is None
    assert result.requires_reauthorization is False


async def test_model_version_change_policy_reauthorize():
    """Version change with policy=reauthorize → PROVIDER_UPDATE_DETECTED, reauth required."""
    attestation, commitment_id = await _make_commitment(policy="reauthorize")
    changed = {**_BASE_STATE, "model_version": "0614"}
    result = await attestation.verify(commitment_id, current_state=changed)
    assert result.valid is False
    assert result.mismatch_type == "PROVIDER_UPDATE_DETECTED"
    assert result.requires_reauthorization is True


async def test_model_version_change_policy_block():
    """Version change with policy=block → blocked, no reauth opportunity."""
    attestation, commitment_id = await _make_commitment(policy="block")
    changed = {**_BASE_STATE, "model_version": "0614"}
    result = await attestation.verify(commitment_id, current_state=changed)
    assert result.valid is False
    assert result.mismatch_type == "PROVIDER_UPDATE_DETECTED"
    assert result.requires_reauthorization is False


async def test_model_id_change_is_malicious_substitution():
    """Model ID swap → MaliciousSubstitution regardless of policy."""
    attestation, commitment_id = await _make_commitment(policy="reauthorize")
    changed = {**_BASE_STATE, "model_id": "claude-opus-4-6"}
    result = await attestation.verify(commitment_id, current_state=changed)
    assert result.valid is False
    assert result.mismatch_type == "MaliciousSubstitution"
    # Even with reauthorize policy, model-id swap is never reauthorizable
    assert result.requires_reauthorization is False


async def test_reauthorize_clears_pending_flag():
    """After reauthorize(), verify with the new state returns valid=True."""
    attestation, commitment_id = await _make_commitment(policy="reauthorize")
    changed = {**_BASE_STATE, "model_version": "0614"}

    # First verify — should require reauth
    result1 = await attestation.verify(commitment_id, current_state=changed)
    assert result1.requires_reauthorization is True

    # Reauthorize
    await attestation.reauthorize(commitment_id)

    # Verify again with the new version — should now be valid
    result2 = await attestation.verify(commitment_id, current_state=changed)
    assert result2.valid is True
    assert result2.requires_reauthorization is False


async def test_reauthorize_without_pending_raises():
    """Calling reauthorize() when no reauth is pending raises ValueError."""
    attestation, commitment_id = await _make_commitment(policy="reauthorize")

    # No state change has been detected yet — no pending reauth
    with pytest.raises(ValueError, match="No pending reauthorization"):
        await attestation.reauthorize(commitment_id)

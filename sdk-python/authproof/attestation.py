"""
ModelStateAttestation — cryptographic binding between a delegation receipt
and the exact model state authorized to act on it.

Closes the model-substitution gap: a receipt proves a human authorized an
agent, but does NOT prove the executing model is the one authorized.
ModelStateAttestation binds the delegation to a measurement of the model
state at issuance time and verifies it still matches at execution time.

Mirrors the JS ModelStateAttestation API:

  * commit() — capture and seal current model state
  * verify() — check that current state matches the commitment
  * reauthorize() — accept a new model version (policy=reauthorize only)

provider_update_policy values:

  * "block"        — any change immediately blocks execution
  * "reauthorize"  — version updates require explicit human re-approval;
                     model-id swaps are always blocked (MaliciousSubstitution)
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional

from authproof.client import _sha256, canonicalize_text


# ─────────────────────────────────────────────
# RESULT TYPE
# ─────────────────────────────────────────────

@dataclass
class AttestationResult:
    """Result returned by ModelStateAttestation.verify()."""
    valid: bool
    mismatch_type: Optional[str]          # None on success; e.g. 'PROVIDER_UPDATE_DETECTED'
    requires_reauthorization: bool


# ─────────────────────────────────────────────
# MEASUREMENT HELPER
# ─────────────────────────────────────────────

def _compute_measurement(
    model_id: str,
    model_version: str,
    system_prompt_hash: str,
    runtime_config_hash: str,
    receipt_hash: str,
) -> str:
    """
    SHA-256 of five canonical components concatenated (same order as JS):
      1. canonicalize(model_id)
      2. canonicalize(model_version)
      3. system_prompt_hash
      4. runtime_config_hash
      5. receipt_hash
    """
    canonical = "".join([
        canonicalize_text(model_id),
        canonicalize_text(model_version),
        system_prompt_hash,
        runtime_config_hash,
        receipt_hash,
    ])
    return _sha256(canonical)


# ─────────────────────────────────────────────
# MODEL STATE ATTESTATION
# ─────────────────────────────────────────────

class ModelStateAttestation:
    """
    Commit to and verify model state.

    Example::

        attestation = ModelStateAttestation(provider_update_policy="reauthorize")
        commitment_id = await attestation.commit(
            model_id="gpt-4",
            model_version="0613",
            system_prompt_hash="abc123",
            runtime_config_hash="def456",
            receipt_hash=receipt.hash,
        )
        result = await attestation.verify(commitment_id, current_state={
            "model_id": "gpt-4",
            "model_version": "0614",   # changed
            "system_prompt_hash": "abc123",
            "runtime_config_hash": "def456",
        })
        # result.valid == False
        # result.mismatch_type == "PROVIDER_UPDATE_DETECTED"
        # result.requires_reauthorization == True
    """

    def __init__(self, provider_update_policy: str = "block"):
        if provider_update_policy not in ("block", "reauthorize"):
            raise ValueError(
                'provider_update_policy must be "block" or "reauthorize"'
            )
        self._policy = provider_update_policy
        # commitment_id -> commitment dict
        self._commitments: Dict[str, dict] = {}
        # commitment_id -> new measurement hash (pending human approval)
        self._pending_reauth: Dict[str, str] = {}
        # commitment_id -> set of approved measurement hashes
        self._approved_measurements: Dict[str, set] = {}

    async def commit(
        self,
        model_id: str,
        model_version: str,
        system_prompt_hash: str,
        runtime_config_hash: str,
        receipt_hash: str,
    ) -> str:
        """
        Capture model state at delegation time.

        Returns
        -------
        str
            A ``commitment_id`` string (e.g. ``"msc-1713000000-a1b2c3d4"``).
        """
        if not model_id:
            raise ValueError("model_id is required")
        if not model_version:
            raise ValueError("model_version is required")
        if not system_prompt_hash:
            raise ValueError("system_prompt_hash is required")
        if not runtime_config_hash:
            raise ValueError("runtime_config_hash is required")
        if not receipt_hash:
            raise ValueError("receipt_hash is required")

        now = datetime.now(timezone.utc)
        commitment_id = f"msc-{int(now.timestamp() * 1000)}-{secrets.token_hex(4)}"

        measurement = _compute_measurement(
            model_id, model_version, system_prompt_hash, runtime_config_hash, receipt_hash
        )

        self._commitments[commitment_id] = {
            "commitment_id": commitment_id,
            "model_id": model_id,
            "model_version": model_version,
            "system_prompt_hash": system_prompt_hash,
            "runtime_config_hash": runtime_config_hash,
            "receipt_hash": receipt_hash,
            "measurement": measurement,
            "committed_at": now.isoformat(),
        }
        self._approved_measurements[commitment_id] = {measurement}

        return commitment_id

    async def verify(
        self,
        commitment_id: str,
        current_state: Dict,
    ) -> AttestationResult:
        """
        Verify that the current model state matches the commitment.

        ``current_state`` keys (all optional — missing keys fall back to
        committed values, so a partial dict checks only the supplied fields):

        * model_id
        * model_version
        * system_prompt_hash
        * runtime_config_hash

        Returns an AttestationResult with ``valid``, ``mismatch_type``,
        and ``requires_reauthorization``.
        """
        commitment = self._commitments.get(commitment_id)
        if commitment is None:
            return AttestationResult(
                valid=False,
                mismatch_type="COMMITMENT_NOT_FOUND",
                requires_reauthorization=False,
            )

        cur_model_id = current_state.get("model_id", commitment["model_id"])
        cur_model_version = current_state.get("model_version", commitment["model_version"])
        cur_sp_hash = current_state.get("system_prompt_hash", commitment["system_prompt_hash"])
        cur_rc_hash = current_state.get("runtime_config_hash", commitment["runtime_config_hash"])

        current_measurement = _compute_measurement(
            cur_model_id, cur_model_version, cur_sp_hash, cur_rc_hash,
            commitment["receipt_hash"],
        )

        # Approved measurement — valid
        if current_measurement in self._approved_measurements.get(commitment_id, set()):
            return AttestationResult(valid=True, mismatch_type=None, requires_reauthorization=False)

        # Classify the drift
        mismatch_type: str
        if canonicalize_text(cur_model_id) != canonicalize_text(commitment["model_id"]):
            # Model ID swap — always treated as malicious substitution
            mismatch_type = "MaliciousSubstitution"
        elif canonicalize_text(cur_model_version) != canonicalize_text(commitment["model_version"]):
            mismatch_type = "PROVIDER_UPDATE_DETECTED"
        elif cur_sp_hash != commitment["system_prompt_hash"]:
            mismatch_type = "SYSTEM_PROMPT_CHANGED"
        else:
            mismatch_type = "RUNTIME_CONFIG_CHANGED"

        # policy=reauthorize: version updates can be re-approved;
        # model-id swaps are always blocked regardless of policy
        if self._policy == "reauthorize" and mismatch_type != "MaliciousSubstitution":
            self._pending_reauth[commitment_id] = current_measurement
            return AttestationResult(
                valid=False,
                mismatch_type=mismatch_type,
                requires_reauthorization=True,
            )

        return AttestationResult(
            valid=False,
            mismatch_type=mismatch_type,
            requires_reauthorization=False,
        )

    async def reauthorize(self, commitment_id: str) -> None:
        """
        Accept a new model state after policy=reauthorize detection.

        After calling this, subsequent ``verify()`` calls with the
        previously-rejected state will return ``valid=True``.

        Raises
        ------
        ValueError
            If there is no pending reauthorization for ``commitment_id``.
        """
        if commitment_id not in self._pending_reauth:
            raise ValueError(
                f"No pending reauthorization for commitment '{commitment_id}'. "
                "Call verify() first to detect a state change."
            )
        new_measurement = self._pending_reauth.pop(commitment_id)
        self._approved_measurements.setdefault(commitment_id, set()).add(new_measurement)

    def get_commitment(self, commitment_id: str) -> Optional[dict]:
        """Return the stored commitment dict, or None if not found."""
        return self._commitments.get(commitment_id)

"""
PreExecutionVerifier — deterministic gate that runs before any agent action.

Mirrors the JS PreExecutionVerifier with a simpler Python API:
  * No separate DelegationLog / RevocationRegistry classes exposed —
    managed internally via register() and revoke().
  * Six sequential checks; stops at first failure.

Usage::

    verifier = PreExecutionVerifier()
    verifier.register(receipt)
    result = await verifier.check(
        receipt_hash=receipt.hash,
        action={"operation": "read", "resource": "email"},
        operator_instructions="Summarize inbox only",
    )
    if not result.allowed:
        raise RuntimeError(result.blocked_reason)
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from authproof.client import (
    ScopeSchema,
    DelegationReceipt,
    _canonical_json,
    _public_key_from_dict,
    _verify_signature,
    canonicalize_hash,
)


# ─────────────────────────────────────────────
# RESULT TYPE
# ─────────────────────────────────────────────

@dataclass
class VerificationResult:
    """Result returned by PreExecutionVerifier.check()."""
    allowed: bool
    checks: Dict[str, bool]
    blocked_reason: Optional[str]
    verified_at: str


# ─────────────────────────────────────────────
# PRE-EXECUTION VERIFIER
# ─────────────────────────────────────────────

class PreExecutionVerifier:
    """
    Deterministic authorization gate for agent actions.

    All checks run in strict sequential order; stops at first failure.
    The six checks (in order):

    1. Receipt signature valid (ECDSA P-256)
    2. Receipt not revoked
    3. Within time window (not expired, not future-dated)
    4. Action within scope (allow list hit; deny list not hit)
    5. Operator instructions hash matches receipt
    6. Model state attestation (optional — only when configured via
       ``set_model_state_attestation()``)
    """

    def __init__(self):
        # receipt_hash -> raw receipt dict
        self._receipts: Dict[str, dict] = {}
        # receipt_hash -> revocation reason
        self._revoked: Dict[str, str] = {}
        # optional ModelStateAttestation instance
        self._msa: Optional[Any] = None

    # ── Registration / revocation ────────────────────────────────────────

    def register(self, receipt: DelegationReceipt) -> None:
        """Register a DelegationReceipt so it can be referenced by hash."""
        self._receipts[receipt.hash] = receipt._raw

    def register_raw(self, receipt_hash: str, raw_receipt: dict) -> None:
        """Register a raw receipt dict (used by DelegationChain)."""
        self._receipts[receipt_hash] = raw_receipt

    def revoke(self, receipt_hash: str, reason: str = "revoked") -> None:
        """Mark a receipt as revoked."""
        self._revoked[receipt_hash] = reason

    def set_model_state_attestation(self, msa: Any) -> None:
        """
        Attach a ModelStateAttestation instance to enable check 6.
        When set, check() accepts optional ``commitment_id`` and
        ``current_model_state`` keyword arguments.
        """
        self._msa = msa

    # ── Main gate ────────────────────────────────────────────────────────

    async def check(
        self,
        receipt_hash: str,
        action: Dict,
        operator_instructions: Optional[str] = None,
        *,
        commitment_id: Optional[str] = None,
        current_model_state: Optional[Dict] = None,
    ) -> VerificationResult:
        """
        Run all checks and return a VerificationResult.

        Parameters
        ----------
        receipt_hash:
            Hash of the delegation receipt to verify against.
        action:
            Dict with 'operation' and 'resource' keys.
        operator_instructions:
            Current operator instructions. If omitted, the receipt's
            own stored instructions are used (always matches).
        commitment_id:
            Optional — MSA commitment ID for check 6.
        current_model_state:
            Optional dict with model_id, model_version,
            system_prompt_hash, runtime_config_hash for check 6.
        """
        checks: Dict[str, bool] = {
            "receipt_signature_valid": False,
            "receipt_not_revoked": False,
            "within_time_window": False,
            "action_within_scope": False,
            "operator_instructions_match": False,
        }
        if self._msa is not None and commitment_id is not None:
            checks["model_state_valid"] = False

        verified_at = datetime.now(timezone.utc).isoformat()

        # ── Check 1: receipt exists and signature is valid ───────────────
        raw = self._receipts.get(receipt_hash)
        if raw is None:
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason=f"Receipt not found for hash {receipt_hash[:8]}…",
                verified_at=verified_at,
            )

        signature = raw.get("signature")
        body = {k: v for k, v in raw.items() if k != "signature"}
        body_json = _canonical_json(body)
        pub_key_dict = raw.get("signer_public_key", {})
        try:
            public_key = _public_key_from_dict(pub_key_dict)
            sig_valid = _verify_signature(public_key, signature, body_json)
        except Exception:
            sig_valid = False

        checks["receipt_signature_valid"] = sig_valid
        if not sig_valid:
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason="Receipt signature invalid — receipt may be tampered or signed with wrong key",
                verified_at=verified_at,
            )

        # ── Check 2: not revoked ─────────────────────────────────────────
        if receipt_hash in self._revoked:
            checks["receipt_not_revoked"] = False
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason=f"Receipt revoked: {self._revoked[receipt_hash]}",
                verified_at=verified_at,
            )
        checks["receipt_not_revoked"] = True

        # ── Check 3: time window ─────────────────────────────────────────
        now = datetime.now(timezone.utc)
        tw = raw.get("time_window", {})
        try:
            start = datetime.fromisoformat(tw["start"])
            end = datetime.fromisoformat(tw["end"])
        except (KeyError, ValueError):
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason="Receipt has invalid or missing time_window",
                verified_at=verified_at,
            )

        in_window = start <= now <= end
        checks["within_time_window"] = in_window
        if not in_window:
            if now > end:
                reason = f"Receipt expired at {end.isoformat()}"
            else:
                reason = f"Receipt not yet valid — starts {start.isoformat()}"
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason=reason,
                verified_at=verified_at,
            )

        # ── Check 4: scope validation ────────────────────────────────────
        scope_data = raw.get("scope")
        if scope_data:
            schema = ScopeSchema.from_dict(scope_data)
            sv = schema.validate(action)
            scope_valid = sv["valid"]
            scope_reason = sv["reason"]
        else:
            # No structured scope — default deny
            scope_valid = False
            scope_reason = "No scope defined in receipt"

        checks["action_within_scope"] = scope_valid
        if not scope_valid:
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason=f"Scope violation: {scope_reason}",
                verified_at=verified_at,
            )

        # ── Check 5: operator instructions hash ─────────────────────────
        instructions = (
            operator_instructions
            if operator_instructions is not None
            else raw.get("operator_instructions", "")
        )
        provided_hash = canonicalize_hash(instructions)
        stored_hash = raw.get("instructions_hash", "")
        instructions_match = provided_hash == stored_hash
        checks["operator_instructions_match"] = instructions_match
        if not instructions_match:
            return VerificationResult(
                allowed=False,
                checks=checks,
                blocked_reason="Operator instructions do not match receipt — operator drift detected",
                verified_at=verified_at,
            )

        # ── Check 6: model state attestation (optional) ──────────────────
        if self._msa is not None and commitment_id is not None:
            state = current_model_state or {}
            msa_result = await self._msa.verify(commitment_id, state)
            model_state_valid = msa_result.valid
            checks["model_state_valid"] = model_state_valid
            if not model_state_valid:
                drift = msa_result.mismatch_type or "measurement mismatch"
                return VerificationResult(
                    allowed=False,
                    checks=checks,
                    blocked_reason=f"ModelDriftDetected: {drift}",
                    verified_at=verified_at,
                )

        return VerificationResult(
            allowed=True,
            checks=checks,
            blocked_reason=None,
            verified_at=verified_at,
        )

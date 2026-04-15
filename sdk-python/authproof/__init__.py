"""
authproof-py — Python SDK for AuthProof cryptographic delegation receipts.

Quick start::

    from authproof import AuthProofClient, ScopeSchema, PreExecutionVerifier
    from authproof import ModelStateAttestation, DelegationChain

    client = AuthProofClient()
    receipt = await client.delegate(
        scope=ScopeSchema(
            allowed_actions=[{"operation": "read", "resource": "email"}],
            denied_actions=[{"operation": "delete", "resource": "*"}],
        ),
        operator_instructions="Summarize inbox only",
        expires_in="2h",
    )
"""

from authproof.client import AuthProofClient, ScopeSchema, DelegationReceipt
from authproof.verifier import PreExecutionVerifier, VerificationResult
from authproof.attestation import ModelStateAttestation, AttestationResult
from authproof.chain import DelegationChain, ScopeAttenuationError, MaxDepthExceededError

__version__ = "1.6.0"
__all__ = [
    "AuthProofClient",
    "ScopeSchema",
    "DelegationReceipt",
    "PreExecutionVerifier",
    "VerificationResult",
    "ModelStateAttestation",
    "AttestationResult",
    "DelegationChain",
    "ScopeAttenuationError",
    "MaxDepthExceededError",
]

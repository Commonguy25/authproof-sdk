"""
AuthProofClient and ScopeSchema — core delegation primitives.

Mirrors the JavaScript authproof.js API with Python idioms:
  - ECDSA P-256 via the `cryptography` library
  - async/await for signing operations
  - snake_case naming throughout
"""

import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ─────────────────────────────────────────────
# CRYPTO HELPERS
# ─────────────────────────────────────────────

def _sha256(text: str) -> str:
    """SHA-256 of a UTF-8 string, returned as 64-char hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _int_to_base64url(n: int, length: int = 32) -> str:
    b = n.to_bytes(length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _base64url_to_int(s: str) -> int:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return int.from_bytes(base64.urlsafe_b64decode(s), "big")


def _public_key_to_dict(public_key) -> dict:
    """Export an EC public key as a JWK-style dict {kty, crv, x, y}."""
    nums = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_base64url(nums.x),
        "y": _int_to_base64url(nums.y),
    }


def _public_key_from_dict(key_dict: dict):
    """Import an EC public key from a JWK-style dict."""
    x = _base64url_to_int(key_dict["x"])
    y = _base64url_to_int(key_dict["y"])
    nums = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
    return nums.public_key()


def _sign(private_key, message: str) -> str:
    """ECDSA P-256/SHA-256 sign; return DER signature as hex."""
    sig_bytes = private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return sig_bytes.hex()


def _verify_signature(public_key, sig_hex: str, message: str) -> bool:
    """Verify a DER hex ECDSA P-256/SHA-256 signature."""
    try:
        public_key.verify(
            bytes.fromhex(sig_hex),
            message.encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, Exception):
        return False


def _canonical_json(obj: dict) -> str:
    """Deterministic JSON: sorted keys, no extra spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


# ─────────────────────────────────────────────
# CANONICALIZER  (mirrors Canonicalizer in authproof.js)
# ─────────────────────────────────────────────

def _sort_kv_pairs(text: str) -> str:
    """Sort key-value pairs alphabetically when 2+ are detected."""
    kv_regex = re.compile(r"\b([\w-]+)(?::\s+|=)(\S+)")
    raw_matches = list(kv_regex.finditer(text))
    if len(raw_matches) < 2:
        return text

    remainder = text
    for m in raw_matches:
        remainder = remainder.replace(m.group(0), "\x00", 1)
    remainder = re.sub(r"\x00", " ", remainder)
    remainder = re.sub(r"\s+", " ", remainder).strip()

    pairs = []
    for m in raw_matches:
        uses_equals = "=" in m.group(0) and ": " not in m.group(0)
        pairs.append({"key": m.group(1), "value": m.group(2), "sep": "=" if uses_equals else ": "})
    pairs.sort(key=lambda p: p["key"])
    sorted_str = " ".join(f"{p['key']}{p['sep']}{p['value']}" for p in pairs)
    return f"{remainder} {sorted_str}".strip() if remainder else sorted_str


def canonicalize_text(text: str) -> str:
    """
    Normalize instruction text (mirrors Canonicalizer.normalize):
      1. Trim
      2. Lowercase
      3. Collapse whitespace
      4. Remove neutral punctuation
      5. Sort key-value pairs
    """
    if not isinstance(text, str):
        raise TypeError("canonicalize_text: input must be a string")
    s = text.strip().lower()
    s = re.sub(r"\s+", " ", s)
    s = s.replace(",", "")
    s = re.sub(r"\.(?=\s|$)", "", s)
    s = re.sub(r'["""\'\u2018\u2019\u201c\u201d`]', "", s)
    s = re.sub(r"\s+", " ", s).strip()
    s = _sort_kv_pairs(s)
    return s


def canonicalize_hash(text: str) -> str:
    """Normalize then SHA-256 hash (mirrors Canonicalizer.hash)."""
    return _sha256(canonicalize_text(text))


# ─────────────────────────────────────────────
# EXPIRES_IN PARSER
# ─────────────────────────────────────────────

def parse_expires_in(s: str) -> int:
    """Parse duration string ('2h', '30m', '1d', '45s') into seconds."""
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise ValueError(f"Invalid expires_in format: {s!r}. Expected e.g. '2h', '30m', '1d'.")
    value, unit = int(m.group(1)), m.group(2)
    return value * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


# ─────────────────────────────────────────────
# SCOPE SCHEMA
# ─────────────────────────────────────────────

def _match_op(pattern: str, operation: str) -> bool:
    return pattern == "*" or pattern == operation


def _match_resource(pattern: str, resource: str) -> bool:
    if pattern == "*":
        return True
    if "*" not in pattern:
        return pattern == resource
    regex = re.escape(pattern).replace(r"\*", ".*")
    return bool(re.fullmatch(regex, resource))


class ScopeSchema:
    """
    Machine-readable scope definition — mirrors JS ScopeSchema.

    Example::

        schema = ScopeSchema(
            allowed_actions=[
                {"operation": "read",  "resource": "email"},
                {"operation": "write", "resource": "calendar"},
            ],
            denied_actions=[
                {"operation": "delete", "resource": "*"},
            ],
        )
    """

    def __init__(
        self,
        allowed_actions: Optional[List[Dict]] = None,
        denied_actions: Optional[List[Dict]] = None,
        version: str = "1.0",
        max_duration: Optional[str] = None,
    ):
        self.version = version
        self.allowed_actions: List[Dict] = allowed_actions or []
        self.denied_actions: List[Dict] = denied_actions or []
        self.max_duration = max_duration

        for action in self.allowed_actions + self.denied_actions:
            if not isinstance(action.get("operation"), str):
                raise ValueError("Each action entry must have an 'operation' string")
            if not isinstance(action.get("resource"), str):
                raise ValueError("Each action entry must have a 'resource' string")

    def validate(self, action: Dict) -> Dict:
        """
        Validate whether an action is permitted.
        Denial always takes precedence over allowance.
        Returns ``{"valid": bool, "reason": str}``.
        """
        op = action.get("operation")
        res = action.get("resource")

        if not op:
            return {"valid": False, "reason": "action.operation is required"}
        if not res:
            return {"valid": False, "reason": "action.resource is required"}

        # Denial first
        for denied in self.denied_actions:
            if _match_op(denied["operation"], op) and _match_resource(denied["resource"], res):
                return {
                    "valid": False,
                    "reason": f'operation "{op}" on resource "{res}" is explicitly denied',
                }

        # Allow list
        for allowed in self.allowed_actions:
            if _match_op(allowed["operation"], op) and _match_resource(allowed["resource"], res):
                return {
                    "valid": True,
                    "reason": f'operation "{op}" on resource "{res}" is allowed',
                }

        return {
            "valid": False,
            "reason": f'operation "{op}" on resource "{res}" is not in allowed_actions',
        }

    def to_dict(self) -> dict:
        d: dict = {
            "version": self.version,
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
        }
        if self.max_duration is not None:
            d["max_duration"] = self.max_duration
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeSchema":
        return cls(
            version=data.get("version", "1.0"),
            allowed_actions=data.get("allowed_actions", []),
            denied_actions=data.get("denied_actions", []),
            max_duration=data.get("max_duration"),
        )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"ScopeSchema(allowed={len(self.allowed_actions)}, "
            f"denied={len(self.denied_actions)})"
        )


# ─────────────────────────────────────────────
# DELEGATION RECEIPT
# ─────────────────────────────────────────────

@dataclass
class DelegationReceipt:
    """Immutable signed delegation receipt returned by AuthProofClient.delegate()."""

    hash: str                           # SHA-256 of the full receipt JSON
    scope: ScopeSchema
    expires_at: datetime
    operator_instructions: str
    operator_instructions_hash: str     # SHA-256 of canonicalized instructions
    _raw: dict = field(repr=False)      # Full receipt dict (body + signature)
    _public_key: Any = field(repr=False)  # cryptography EC public key object


# ─────────────────────────────────────────────
# AUTH PROOF CLIENT
# ─────────────────────────────────────────────

class AuthProofClient:
    """
    High-level client for creating cryptographic delegation receipts.

    Generates an ECDSA P-256 key pair on initialisation. Call
    ``await client.delegate(...)`` to produce a signed receipt.

    Example::

        client = AuthProofClient()
        receipt = await client.delegate(
            scope=ScopeSchema(
                allowed_actions=[{"operation": "read", "resource": "email"}],
                denied_actions=[{"operation": "delete", "resource": "*"}],
            ),
            operator_instructions="Summarize inbox only",
            expires_in="2h",
        )
        print(receipt.hash)
    """

    def __init__(self):
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._public_key = self._private_key.public_key()
        self._public_key_dict = _public_key_to_dict(self._public_key)

    @property
    def private_key(self):
        """The raw ``cryptography`` ECDSA private key."""
        return self._private_key

    @property
    def public_key(self):
        """The raw ``cryptography`` ECDSA public key."""
        return self._public_key

    @property
    def public_key_dict(self) -> dict:
        """JWK-style {kty, crv, x, y} public key dict."""
        return self._public_key_dict

    async def delegate(
        self,
        scope: ScopeSchema,
        operator_instructions: str,
        expires_in: str = "1h",
    ) -> DelegationReceipt:
        """
        Create and return a signed DelegationReceipt.

        Parameters
        ----------
        scope:
            ScopeSchema defining allowed/denied actions.
        operator_instructions:
            Human-readable instructions locked into the receipt.
        expires_in:
            Duration string: '2h', '30m', '1d', etc.  Default: '1h'.
        """
        if not isinstance(scope, ScopeSchema):
            raise TypeError("scope must be a ScopeSchema instance")
        if not operator_instructions:
            raise ValueError("operator_instructions is required")

        now = datetime.now(timezone.utc)
        ttl_seconds = parse_expires_in(expires_in)
        expires_at = now + timedelta(seconds=ttl_seconds)

        delegation_id = f"auth-{int(now.timestamp() * 1000)}-{secrets.token_hex(4)}"
        instructions_hash = canonicalize_hash(operator_instructions)

        body: dict = {
            "delegation_id": delegation_id,
            "issued_at": now.isoformat(),
            "scope": scope.to_dict(),
            "time_window": {
                "start": now.isoformat(),
                "end": expires_at.isoformat(),
            },
            "operator_instructions": operator_instructions,
            "instructions_hash": instructions_hash,
            "signer_public_key": self._public_key_dict,
        }

        body_json = _canonical_json(body)
        signature = _sign(self._private_key, body_json)
        receipt = {**body, "signature": signature}
        receipt_hash = _sha256(_canonical_json(receipt))

        return DelegationReceipt(
            hash=receipt_hash,
            scope=scope,
            expires_at=expires_at,
            operator_instructions=operator_instructions,
            operator_instructions_hash=instructions_hash,
            _raw=receipt,
            _public_key=self._public_key,
        )

"""Data models for agent capability attestations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class Attestation:
    """A capability attestation issued by one agent to another.

    Every attestation must carry a TTL. Missing TTL = expired (fail closed).
    """

    issuer: str
    subject: str
    capability: str
    issued_at: datetime
    ttl_seconds: int
    state_hash: Optional[str] = None
    expires_at: Optional[datetime] = None
    provenance: list[str] = field(default_factory=list)
    signature: Optional[str] = None

    def __post_init__(self) -> None:
        if self.expires_at is None and self.ttl_seconds is not None:
            self.expires_at = self.issued_at + timedelta(seconds=self.ttl_seconds)

    @classmethod
    def from_dict(cls, data: dict) -> "Attestation":
        """Parse from a JSON-serializable dictionary."""
        issued_at = _parse_datetime(data["issued_at"])
        return cls(
            issuer=data["issuer"],
            subject=data["subject"],
            capability=data["capability"],
            issued_at=issued_at,
            ttl_seconds=data.get("ttl_seconds", 0),
            state_hash=data.get("state_hash"),
            provenance=data.get("provenance", []),
            signature=data.get("signature"),
        )

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dictionary."""
        result = {
            "issuer": self.issuer,
            "subject": self.subject,
            "capability": self.capability,
            "issued_at": self.issued_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
        }
        if self.state_hash:
            result["state_hash"] = self.state_hash
        if self.expires_at:
            result["expires_at"] = self.expires_at.isoformat()
        if self.provenance:
            result["provenance"] = self.provenance
        if self.signature:
            result["signature"] = self.signature
        return result


@dataclass
class ValidationResult:
    """Result of validating an attestation."""

    attestation: Attestation
    is_valid: bool
    is_stale: bool
    stale_by_seconds: Optional[float] = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.is_valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


@dataclass
class DelegationChain:
    """A chain of capability delegations: issuer → subject → ..."""

    attestations: list[Attestation]

    def validate_monotonicity(self) -> list[ValidationResult]:
        """Verify each hop narrows (never expands) the capability scope."""
        results: list[ValidationResult] = []
        for i, att in enumerate(self.attestations):
            result = ValidationResult(attestation=att, is_valid=True, is_stale=False)
            if i > 0:
                parent = self.attestations[i - 1]
                if not _scope_is_subscope(parent.capability, att.capability):
                    result.add_error(
                        f"Hop {i}: capability expanded — "
                        f"{parent.capability} → {att.capability}"
                    )
            results.append(result)
        return results


class AttestationValidator:
    """Validate capability attestations with TTL-based freshness checking."""

    def __init__(
        self,
        max_ttl: int = 300,
        now: Optional[datetime] = None,
    ) -> None:
        self.max_ttl = max_ttl
        self._now = now

    @property
    def now(self) -> datetime:
        if self._now is not None:
            return self._now
        return datetime.now(timezone.utc)

    def validate(self, attestation: Attestation) -> ValidationResult:
        """Validate a single attestation."""
        result = ValidationResult(
            attestation=attestation,
            is_valid=True,
            is_stale=False,
        )

        # TTL check (fail closed)
        if attestation.ttl_seconds <= 0 or attestation.expires_at is None:
            result.add_error("Missing TTL — attestation considered expired (fail closed)")
            result.is_stale = True
            return result

        if attestation.ttl_seconds > self.max_ttl:
            result.add_warning(
                f"TTL {attestation.ttl_seconds}s exceeds max {self.max_ttl}s"
            )

        age = (self.now - attestation.issued_at).total_seconds()
        if age > attestation.ttl_seconds:
            result.is_stale = True
            result.stale_by_seconds = age - attestation.ttl_seconds
            result.add_error(
                f"Attestation stale by {result.stale_by_seconds:.1f}s "
                f"(issued {age:.1f}s ago, TTL {attestation.ttl_seconds}s)"
            )

        return result

    def verify_signature(
        self,
        attestation: Attestation,
        public_key: ed25519.Ed25519PublicKey,
    ) -> bool:
        """Verify the Ed25519 signature of an attestation."""
        if not attestation.signature:
            return False
        try:
            data = json.dumps(
                attestation.to_dict(), exclude={"signature"}
            ).encode()
            public_key.verify(
                bytes.fromhex(attestation.signature), data
            )
            return True
        except (InvalidSignature, ValueError):
            return False


def compute_state_hash(capabilities: dict) -> str:
    """Compute a deterministic hash of agent capabilities."""
    canonical = json.dumps(capabilities, sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _parse_datetime(value) -> datetime:
    """Parse an ISO 8601 datetime string."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    raise ValueError(f"Cannot parse datetime: {value!r}")


def _scope_is_subscope(parent: str, child: str) -> bool:
    """Check if child capability is a subscope of parent capability.

    Supports wildcards: "CAN_WRITE(store:*)" matches "CAN_WRITE(store:partition_1)".
    """
    if child == parent:
        return True
    if parent.endswith("*"):
        return child.startswith(parent[:-1])
    if child.startswith(parent):
        return True
    parent_parts = set(parent.split(":"))
    child_parts = set(child.split(":"))
    return child_parts.issubset(parent_parts)

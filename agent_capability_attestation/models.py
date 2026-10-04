"""Data models for agent capability attestations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

#: The attestation's signature was verified against a trusted public key.
SIGNATURE_VERIFIED = "verified"

#: A signature is present but could not be verified: no trusted key for the
#: issuer, a malformed signature, or a payload that does not match.
SIGNATURE_UNVERIFIED = "unverified"

#: The attestation carries no signature at all.
SIGNATURE_UNSIGNED = "unsigned"

#: No signature check was performed (e.g. a monotonicity-only chain check).
SIGNATURE_UNCHECKED = "unchecked"

#: Trusted-keys mapping key that applies to every issuer.
ANY_ISSUER = "*"

# How far into the future an issued_at may sit and still be believable.
#
# A negative age (issued_at ahead of now) used to pass every check, which made
# a future-dated attestation an unbounded-validity primitive: the deadline is
# derived from issued_at, so shifting it forward keeps the attestation "fresh"
# until the wall clock catches up — years, or forever.
#
# Zero tolerance would reject hosts whose clock legitimately runs a little fast,
# so the bound is deliberately small but non-zero. Sixty seconds is roughly six
# times the worst drift of an NTP-synced host (single-digit seconds; leap-second
# and VM-snapshot effects are the outliers) and an order of magnitude below any
# useful attack shift, while staying well under the smallest TTL this tool
# considers meaningful. Deployments with known drift can widen it explicitly via
# ``max_skew_seconds`` rather than by shipping a forged receipt.
DEFAULT_MAX_SKEW_SECONDS = 60


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
        declared_expires_at = data.get("expires_at")
        return cls(
            issuer=data["issuer"],
            subject=data["subject"],
            capability=data["capability"],
            issued_at=issued_at,
            ttl_seconds=data.get("ttl_seconds", 0),
            state_hash=data.get("state_hash"),
            expires_at=(
                _parse_datetime(declared_expires_at) if declared_expires_at else None
            ),
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
    #: One of SIGNATURE_VERIFIED / SIGNATURE_UNVERIFIED / SIGNATURE_UNSIGNED /
    #: SIGNATURE_UNCHECKED. Callers that gate on capability authority should
    #: require SIGNATURE_VERIFIED rather than is_valid alone.
    signature_status: str = SIGNATURE_UNCHECKED

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.is_valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)


@dataclass
class DelegationChain:
    """A chain of capability delegations: issuer → subject → ..."""

    attestations: list[Attestation]

    def validate_monotonicity(
        self,
        validator: Optional["AttestationValidator"] = None,
    ) -> list[ValidationResult]:
        """Verify each hop narrows (never expands) the capability scope.

        When a ``validator`` is supplied, every hop is also run through
        ``validator.validate()`` — the full single-attestation check covering
        the TTL floor, the declared ``expires_at``, staleness, the
        future-``issued_at`` skew bound and the signature — and its errors and
        warnings are merged into the same per-hop result that carries the
        monotonicity verdict.

        Both checks are necessary and neither substitutes for the other. Scope
        monotonicity only compares capabilities against each other, so on its
        own it cannot tell an honest narrowing chain from one whose first hop
        was rewritten to claim admin rights: a forged payload can be perfectly
        monotonic and still be a forgery. Conversely, a per-attestation
        validator only judges each hop in isolation and says nothing about
        whether hop N widened what hop N-1 granted, so a chain can be entirely
        fresh at every hop and still expand the authority as it descends.

        Merging is what closes the fail-open this method used to have on the
        time axis. It previously applied only ``check_signature``, so a chain
        whose every hop had expired, was dated far in the future, or carried no
        TTL at all still came back valid at every hop — the caller passed a
        validator configured with ``max_ttl`` and ``max_skew_seconds`` and those
        settings had no effect whatsoever.

        Without a ``validator`` this stays a pure scope check, for callers that
        want monotonicity alone.
        """
        results: list[ValidationResult] = []
        for i, att in enumerate(self.attestations):
            if validator is None:
                result = ValidationResult(attestation=att, is_valid=True, is_stale=False)
            else:
                # Seed from the full per-attestation verdict (it already runs
                # check_signature), then layer the chain-level check on top.
                # add_error() only ever clears is_valid, so the two verdicts
                # combine rather than overwrite one another.
                result = validator.validate(att)
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
    """Validate capability attestations with TTL and signature checking.

    Args:
        max_ttl: TTLs above this are reported as a warning, not an error.
        now: Freeze the validation clock (tests).
        trusted_keys: Ed25519 public keys keyed by issuer. The special key
            ``ANY_ISSUER`` ("*") matches any issuer. An attestation carrying a
            signature whose issuer has no trusted key is **rejected**: an
            unverifiable signature is not evidence of anything, and accepting
            it would leave the fail-open hole this check exists to close.
        require_signature: Reject unsigned attestations outright. Off by
            default so the documented unsigned workflow keeps working; the
            verdict is still surfaced as ``signature_status == "unsigned"``
            plus a warning, so a caller can see what was not checked.
    """

    def __init__(
        self,
        max_ttl: int = 300,
        now: Optional[datetime] = None,
        max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
        trusted_keys: Optional[Mapping[str, ed25519.Ed25519PublicKey]] = None,
        require_signature: bool = False,
    ) -> None:
        self.max_ttl = max_ttl
        self._now = now
        self.max_skew_seconds = max_skew_seconds
        self.trusted_keys: dict[str, ed25519.Ed25519PublicKey] = dict(
            trusted_keys or {}
        )
        self.require_signature = require_signature

    @property
    def now(self) -> datetime:
        if self._now is not None:
            return self._now
        return datetime.now(timezone.utc)

    def validate(self, attestation: Attestation) -> ValidationResult:
        """Validate a single attestation.

        The signature check runs FIRST and always runs, including on the
        early-return paths below: an unverifiable or forged payload must be
        reported even when a TTL error would have ended validation anyway.
        """
        result = ValidationResult(
            attestation=attestation,
            is_valid=True,
            is_stale=False,
        )
        self.check_signature(attestation, result)

        # TTL check (fail closed)
        if attestation.ttl_seconds <= 0 or attestation.expires_at is None:
            result.add_error("Missing TTL — attestation considered expired (fail closed)")
            result.is_stale = True
            return result

        if attestation.ttl_seconds > self.max_ttl:
            result.add_warning(
                f"TTL {attestation.ttl_seconds}s exceeds max {self.max_ttl}s"
            )

        # The declared expires_at is authoritative when present; the TTL-derived
        # deadline is the fallback. Comparing now against the deadline (rather
        # than against ttl_seconds) is what keeps an attestation that declares
        # its own short expiry from being stretched by a long TTL.
        #
        # Both sides are normalized to UTC first: an Attestation built directly
        # (bypassing _parse_datetime) can still carry a naive issued_at, and
        # validate must return a result rather than raise.
        issued_at = _as_utc(attestation.issued_at)
        now = _as_utc(self.now)
        deadline = _as_utc(attestation.expires_at)

        # An issued_at ahead of the validation clock is a forgery or replay
        # signal, not a fresh attestation. Every other bound in this function is
        # measured against issued_at, so shifting it forward is exactly what
        # keeps an attestation alive: a deadline of now + 80 years never
        # arrives. The bound is an explicit window rather than a hard zero so a
        # host running a few seconds fast is not mistaken for an attacker.
        age = (now - issued_at).total_seconds()
        if age < -self.max_skew_seconds:
            result.add_error(
                f"Attestation issued {-age:.1f}s in the future "
                f"(allowed skew {self.max_skew_seconds}s) — "
                "forged or clock-skewed issued_at"
            )
            return result

        ttl_deadline = issued_at + timedelta(seconds=attestation.ttl_seconds)
        if deadline != ttl_deadline:
            result.add_warning(
                f"expires_at {deadline.isoformat()} disagrees with "
                f"issued_at + ttl_seconds ({ttl_deadline.isoformat()}); "
                "honoring the declared expiry"
            )

        remaining = (deadline - now).total_seconds()
        if remaining < 0:
            result.is_stale = True
            result.stale_by_seconds = -remaining
            result.add_error(
                f"Attestation stale by {result.stale_by_seconds:.1f}s "
                f"(issued {age:.1f}s ago, expires {deadline.isoformat()})"
            )

        return result

    def check_signature(
        self,
        attestation: Attestation,
        result: ValidationResult,
    ) -> ValidationResult:
        """Verify the attestation signature, recording the verdict on ``result``.

        Sets ``result.signature_status`` to one of SIGNATURE_VERIFIED /
        SIGNATURE_UNVERIFIED / SIGNATURE_UNSIGNED, and adds an error or a
        warning as follows:

        * signature present and verified  -> verified, no message;
        * signature present, no trusted key for the issuer, or a mismatch
          -> unverified, **error** (fail closed: an unverifiable signature is
          not evidence of authenticity, and silently accepting one is exactly
          the fail-open hole this closes);
        * no signature, ``require_signature`` off -> unsigned, warning;
        * no signature, ``require_signature`` on  -> unsigned, error.

        Callers embedding this into their own result construction (e.g. the
        delegation-chain check) can reuse it instead of re-implementing the
        policy.
        """
        if not attestation.signature:
            result.signature_status = SIGNATURE_UNSIGNED
            if self.require_signature:
                result.add_error(
                    "Unsigned attestation and require_signature is enabled "
                    "(fail closed)"
                )
            else:
                result.add_warning(
                    "Unsigned attestation — signature not verified; "
                    "pass trusted_keys to verify it, or require_signature=True "
                    "to reject unsigned attestations"
                )
            return result

        public_key = self._key_for(attestation.issuer)
        if public_key is None:
            result.signature_status = SIGNATURE_UNVERIFIED
            result.add_error(
                f"No trusted public key for issuer {attestation.issuer!r} — "
                "signature present but unverifiable (fail closed)"
            )
            return result

        if self.verify_signature(attestation, public_key):
            result.signature_status = SIGNATURE_VERIFIED
            return result

        result.signature_status = SIGNATURE_UNVERIFIED
        result.add_error(
            "Signature does not match payload — attestation may be forged"
        )
        return result

    def _key_for(self, issuer: str) -> Optional[ed25519.Ed25519PublicKey]:
        """Return the trusted key for an issuer, honouring the wildcard."""
        key = self.trusted_keys.get(issuer)
        if key is not None:
            return key
        return self.trusted_keys.get(ANY_ISSUER)

    def verify_signature(
        self,
        attestation: Attestation,
        public_key: ed25519.Ed25519PublicKey,
    ) -> bool:
        """Verify the Ed25519 signature of an attestation.

        The signed payload is ``to_dict()`` with the ``signature`` key
        removed, serialized with ``json.dumps``. ``exclude`` is not a
        ``json.dumps`` argument, so the field has to be dropped from the
        dict before serialization.

        Every failure mode returns ``False``: a missing, non-string, odd-length
        or non-hex signature is bad data, never a reason to raise out of a
        validation path.
        """
        if not isinstance(attestation.signature, str):
            return False
        try:
            signature = bytes.fromhex(attestation.signature)
        except ValueError:
            return False
        body = {
            key: value
            for key, value in attestation.to_dict().items()
            if key != "signature"
        }
        try:
            data = json.dumps(body).encode()
            public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False


def compute_state_hash(capabilities: dict) -> str:
    """Compute a deterministic hash of agent capabilities."""
    canonical = json.dumps(capabilities, sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _as_utc(value: datetime) -> datetime:
    """Coerce a datetime to a timezone-aware UTC datetime.

    A naive datetime is interpreted as UTC, which is the consistent reading:
    the README documents timestamps as UTC-suffixed, so a missing offset is a
    missing suffix rather than a different timezone.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value) -> datetime:
    """Parse an ISO 8601 datetime string, normalizing to UTC.

    Normalizing here covers both input paths — a naive string and a naive
    ``datetime`` passed programmatically — so a mixed-aware comparison can
    never be built from a parsed value.
    """
    if isinstance(value, datetime):
        return _as_utc(value)
    if isinstance(value, str):
        return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    raise ValueError(f"Cannot parse datetime: {value!r}")


def _scope_is_subscope(parent: str, child: str) -> bool:
    """Check if child capability is a subscope of parent capability.

    Supports wildcards: "store:*" matches any child starting with "store:".
    """
    if child == parent:
        return True
    # Handle wildcard suffix
    if parent.endswith("*"):
        wildcard_prefix = parent[:-1]
        return child.startswith(wildcard_prefix)
    # Direct prefix match
    if child.startswith(parent):
        return True
    # Check if child's scope is a subset of parent's
    parent_scope = parent.split(":")[-1] if ":" in parent else parent
    child_scope = child.split(":")[-1] if ":" in child else child
    parent_parts = set(parent_scope.strip("()").split(","))
    child_parts = set(child_scope.strip("()").split(","))
    if parent_parts == {"*"}:
        return True
    return child_parts.issubset(parent_parts)

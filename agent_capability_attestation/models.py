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

# The algorithm-prefixed form the README's Attestation Schema documents for the
# ``signature`` field (``"signature": "ed25519:def456..."``). It is accepted on
# input; what gets signed and verified is always the bare hex digest.
ED25519_SIGNATURE_PREFIX = "ed25519:"


def canonical_bytes(obj: dict) -> bytes:
    """Canonical JSON serialization used for signing and hashing.

    This is the single serialization contract: the bytes an issuer signs and
    the bytes a verifier checks are both produced here, so a signer written in
    another language (Go, Rust, JS) has exactly one documented form to
    reproduce. These settings are part of the wire format and must not change
    without a version bump:

    * ``sort_keys=True`` — key order cannot change the bytes;
    * ``separators=(",", ":")`` — no insignificant whitespace, so the default
      ``", "`` / ``": "`` spacing a compact signer does not emit is not a
      different byte string;
    * ``ensure_ascii=False`` — UTF-8 output, so a non-ASCII capability or
      resource name hashes to the same digest regardless of the caller's
      locale or encoder defaults;
    * ``allow_nan=False`` — ``NaN``/``Infinity`` are not valid JSON and would
      produce bytes no other JSON reader accepts, so they are rejected.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


#: The fields every attestation document must carry. A document missing one of
#: them is structurally malformed rather than stale or forged, so the CLI
#: reports it as a bad input (exit 2) rather than as a failing attestation
#: (exit 1) — the distinction ``McpConfigError`` already draws for a malformed
#: MCP config, and the one the README's ``2 = malformed input`` line promises.
REQUIRED_FIELDS = ("issuer", "subject", "capability", "issued_at")


def json_type(value: object) -> str:
    """Name a value's JSON type the way the CLI's error messages read it."""
    if value is None:
        return "null"
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


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
    #: The document this attestation was parsed from, verbatim. It is the
    #: signing payload (``from_dict`` is not the inverse of ``to_dict``: the
    #: round trip injects ``expires_at``, rewrites a ``Z`` offset as
    #: ``+00:00`` and drops present-but-empty optional fields, so verifying a
    #: re-serialized model would reject every wire-format attestation written
    #: to the documented schema). ``None`` for an attestation built
    #: programmatically, where the model is the only description of the
    #: payload. Excluded from ``to_dict()``, equality and ``repr``.
    _raw: Optional[dict] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.expires_at is None and self.ttl_seconds is not None:
            self.expires_at = self.issued_at + timedelta(seconds=self.ttl_seconds)

    @classmethod
    def from_dict(cls, data: dict) -> "Attestation":
        """Parse from a JSON-serializable dictionary.

        Validation happens here, once, so every caller — ``aca validate``,
        ``check-chain``, ``check-mcp`` and ``scan`` — inherits it. Reading the
        required fields by subscript without this guard let ``KeyError`` (a
        missing key) and ``TypeError`` (a non-object payload) escape the
        parser: an unhandled traceback whose exit code ``1`` is the very code a
        genuine validation failure uses, so a malformed document was
        indistinguishable from a stale or forged one. A ``ValueError`` is
        raised instead, and the CLI maps it to exit 2 (bad input) — which is
        what the README's ``2 = malformed input`` line already promises.
        """
        if not isinstance(data, dict):
            raise ValueError(
                f"Attestation must be a JSON object, got {json_type(data)}"
            )
        missing = [name for name in REQUIRED_FIELDS if name not in data]
        if missing:
            raise ValueError(
                "Attestation is missing required field(s): " + ", ".join(missing)
            )
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
            _raw=dict(data),
        )

    def signing_body(self) -> dict:
        """The payload a signature is computed over: the document minus ``signature``.

        For an attestation parsed from a document (``from_dict``) that document
        *is* the payload — verbatim, key for key, exactly as the issuer wrote
        it. Re-serializing the model instead would change the bytes: the round
        trip injects ``expires_at`` when the document omitted it, re-emits both
        timestamps via ``.isoformat()`` (``Z`` becomes ``+00:00``), and drops
        optional fields that are present but empty. Verifying those bytes
        rejected every attestation following the documented schema and
        reported it as forged.

        An attestation built programmatically has no document, so its
        ``to_dict()`` is the only description of the payload it can verify.
        """
        if self._raw is not None:
            return {k: v for k, v in self._raw.items() if k != "signature"}
        return {k: v for k, v in self.to_dict().items() if k != "signature"}

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
        max_ttl: Policy ceiling on how long an attestation may live, in
            seconds. Exceeding it is an error (``is_valid`` becomes ``False``).
            The ceiling is measured against the deadline ``validate`` actually
            uses — the declared ``expires_at`` when present, otherwise
            ``issued_at + ttl_seconds`` — so an attestation whose own declared
            expiry cuts a long ``ttl_seconds`` short is still inside it.
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
        enforce_max_ttl: Report an over-ceiling deadline as an error (the
            default) rather than as a warning. The escape hatch exists for an
            operator who knowingly runs a permissive policy; the default exists
            because a bound that only warns is not a bound.
    """

    def __init__(
        self,
        max_ttl: int = 300,
        now: Optional[datetime] = None,
        max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
        trusted_keys: Optional[Mapping[str, ed25519.Ed25519PublicKey]] = None,
        require_signature: bool = False,
        enforce_max_ttl: bool = True,
    ) -> None:
        self.max_ttl = max_ttl
        self._now = now
        self.max_skew_seconds = max_skew_seconds
        self.trusted_keys: dict[str, ed25519.Ed25519PublicKey] = dict(
            trusted_keys or {}
        )
        self.require_signature = require_signature
        self.enforce_max_ttl = enforce_max_ttl

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

        # A declared expires_at may shorten an attestation's life but never
        # extend it: when it is present and later than the TTL-derived deadline
        # it is rejected below and the deadline is pulled back to that bound.
        # The TTL-derived deadline is therefore the ceiling, and the derived
        # value is the fallback when the field is absent. Comparing now against
        # the deadline (rather than against ttl_seconds) is what keeps an
        # attestation that declares its own short expiry from being stretched
        # by a long TTL.
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
        if deadline > ttl_deadline:
            result.add_error(
                f"expires_at {deadline.isoformat()} outlives the TTL deadline "
                f"{ttl_deadline.isoformat()} (issued_at + ttl_seconds "
                f"{attestation.ttl_seconds}s) — a declared expiry may shorten an "
                "attestation's life but never extend it; rejecting"
            )
            deadline = ttl_deadline
        elif deadline != ttl_deadline:
            result.add_warning(
                f"expires_at {deadline.isoformat()} disagrees with "
                f"issued_at + ttl_seconds ({ttl_deadline.isoformat()}); "
                "honoring the declared expiry"
            )

        # ``max_ttl`` is the operator's policy ceiling and is enforced rather
        # than narrated (#18): an attestation that can outlive
        # ``issued_at + max_ttl`` is rejected. A missing TTL was already fail
        # closed, and an oversized one was not — which is the more dangerous
        # half, because raising a number in the file is all it takes.
        #
        # The comparison is against ``deadline``, the deadline this function
        # actually uses, not against the nominal ``ttl_seconds`` field: a
        # declared ``expires_at`` may legitimately shorten a long TTL, and
        # rejecting such an attestation would undo that rule. An attestation
        # whose *life* is inside the ceiling is inside the ceiling, whatever
        # its TTL field says.
        policy_deadline = issued_at + timedelta(seconds=self.max_ttl)
        if deadline > policy_deadline:
            message = (
                f"TTL {attestation.ttl_seconds}s exceeds max {self.max_ttl}s — "
                f"expires_at {deadline.isoformat()} is "
                f"{(deadline - policy_deadline).total_seconds():.0f}s past "
                f"issued_at + max_ttl ({policy_deadline.isoformat()})"
            )
            if self.enforce_max_ttl:
                result.add_error(
                    f"{message}; max_ttl is a policy ceiling, not a note — "
                    "rejecting"
                )
            else:
                result.add_warning(message)

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

        The signed payload is the attestation document minus the ``signature``
        key (see :meth:`Attestation.signing_body`), serialized with
        :func:`canonical_bytes`. The signature is computed over exactly those
        bytes, so an issuer that reproduces the documented canonical form
        (sorted keys, compact separators, UTF-8) verifies regardless of the
        JSON encoder it used — and regardless of which optional fields its
        document carried or how it spelled its timestamps.

        ``signature`` arrives from a file the attacker can edit, so a verifier
        that answers a yes/no question has to be total over that input: every
        malformed shape is ``False``, never an exception. ``bytes.fromhex``
        raises ``ValueError`` for a string that is not hex (or has odd length),
        but ``TypeError`` for a value that is not a string at all — a JSON
        number, array or object — so both are caught. The README's schema
        documents the algorithm-prefixed form ``"ed25519:<hex>"``; it is
        accepted alongside the bare hex digest described in the docstring
        above.
        """
        signature = attestation.signature
        if not isinstance(signature, str):
            return False
        if signature.startswith(ED25519_SIGNATURE_PREFIX):
            signature = signature[len(ED25519_SIGNATURE_PREFIX):]
        try:
            public_key.verify(
                bytes.fromhex(signature),
                canonical_bytes(attestation.signing_body()),
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            # TypeError is retained alongside the isinstance() guard on
            # purpose: it is the same contract, and it also covers a public_key
            # of the wrong type reaching verify().
            return False


def compute_state_hash(capabilities: dict) -> str:
    """Compute a deterministic hash of agent capabilities.

    Uses :func:`canonical_bytes`, the same serialization the signature is
    computed over, so the two can never disagree and the digest no longer
    depends on ambient ``json.dumps`` defaults (separators, ``ensure_ascii``).
    """
    return f"sha256:{hashlib.sha256(canonical_bytes(capabilities)).hexdigest()}"


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

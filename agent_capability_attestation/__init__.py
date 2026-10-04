"""Agent Capability Attestation - Validate capability freshness in AI agent delegation chains."""

from .models import (  # noqa: F401
    ANY_ISSUER,
    DEFAULT_MAX_SKEW_SECONDS,
    ED25519_SIGNATURE_PREFIX,
    SIGNATURE_UNCHECKED,
    SIGNATURE_UNSIGNED,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
    Attestation,
    AttestationValidator,
    DelegationChain,
    ValidationResult,
    compute_state_hash,
)

__version__ = "0.1.0"

__all__ = [
    "ANY_ISSUER",
    "DEFAULT_MAX_SKEW_SECONDS",
    "ED25519_SIGNATURE_PREFIX",
    "SIGNATURE_UNCHECKED",
    "SIGNATURE_UNSIGNED",
    "SIGNATURE_UNVERIFIED",
    "SIGNATURE_VERIFIED",
    "Attestation",
    "AttestationValidator",
    "DelegationChain",
    "ValidationResult",
    "compute_state_hash",
    "__version__",
]
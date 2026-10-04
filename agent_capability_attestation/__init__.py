"""Agent Capability Attestation - Validate capability freshness in AI agent delegation chains."""

from .models import (
    ANY_ISSUER,
    DEFAULT_MAX_SKEW_SECONDS,
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

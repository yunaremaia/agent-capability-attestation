"""Regression tests for issue #15: validate() never enforced the signature.

``AttestationValidator.verify_signature()`` existed and worked, but nothing in
the library called it: ``validate()`` inspected only TTL, ``expires_at`` and
``issued_at``. An attacker could therefore rewrite the signed payload on disk —
escalate ``db:read`` to ``db:admin``, swap the tool schema, stretch the TTL —
and every consumer (``AttestationValidator.validate``, ``aca validate``,
``aca scan``, ``aca check-chain``, ``aca check-mcp``) still reported
``is_valid=True`` and exited ``0``.

These tests pin the enforcement contract:

* an attestation that carries a signature must be verified, and a mismatch is
  an error (fail closed) — never a warning;
* a signature whose issuer has no trusted key is an error, not a pass;
* an attestation with **no** signature is only a warning by default, so the
  documented unsigned workflow keeps working, but it is reported as
  ``signature_status == "unsigned"`` and can be made fatal with
  ``require_signature=True``;
* ``verify_signature`` returns ``False`` for a non-string signature instead of
  raising ``TypeError``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_capability_attestation.models import Attestation, AttestationValidator

ISSUER = "agent://planner-v2"


def _attestation(**overrides) -> Attestation:
    """A fresh attestation, inside its TTL."""
    fields = {
        "issuer": ISSUER,
        "subject": "agent://worker-v3",
        "capability": "CAN_READ(db:orders)",
        "issued_at": datetime.now(timezone.utc) - timedelta(seconds=5),
        "ttl_seconds": 120,
        "provenance": [ISSUER],
    }
    fields.update(overrides)
    return Attestation(**fields)


def _signed(attestation: Attestation, key: ed25519.Ed25519PrivateKey) -> Attestation:
    """Attach a valid signature over the current payload."""
    attestation.signature = key.sign(_signed_body(attestation)).hex()
    return attestation


def _signed_body(attestation: Attestation) -> bytes:
    """The exact bytes an issuer signs: to_dict() minus the signature field."""
    body = {k: v for k, v in attestation.to_dict().items() if k != "signature"}
    return json.dumps(body).encode()


def _validator(
    key: ed25519.Ed25519PublicKey | None = None,
    issuer: str = ISSUER,
    **kwargs,
) -> AttestationValidator:
    trusted = None if key is None else {issuer: key}
    return AttestationValidator(trusted_keys=trusted, **kwargs)


class TestTamperedPayloadIsRejected:
    """The vulnerability itself: swap a signed field, keep the signature."""

    def test_escalated_capability_is_rejected(self):
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        attestation.capability = "CAN_ADMIN(db:orders)"  # forged on disk

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert any("Signature does not match" in e for e in result.errors), (
            result.errors
        )
        assert result.signature_status == "unverified"

    def test_swapped_subject_is_rejected(self):
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        attestation.subject = "agent://attacker"

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert result.signature_status == "unverified"

    def test_ttl_stretched_after_signing_is_rejected(self):
        """A longer TTL keeps the attestation fresh, so only the signature can
        catch it."""
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(ttl_seconds=120), key)

        attestation.ttl_seconds = 86_400
        attestation.expires_at = attestation.issued_at + timedelta(seconds=86_400)

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert any("Signature does not match" in e for e in result.errors)
        assert not result.is_stale  # the forgery is invisible to the TTL check

    def test_appended_state_hash_is_rejected(self):
        """The tool schema an attestation vouches for is signed too."""
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        attestation.state_hash = "sha256:" + "0" * 64

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert result.signature_status == "unverified"

    def test_ttl_error_does_not_short_circuit_signature_check(self):
        """A missing-TTL attestation returns early; the signature verdict must
        still be reported, not left unset."""
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(ttl_seconds=0), key)

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert result.signature_status == "verified"

    def test_verified_signature_does_not_mask_a_ttl_error(self):
        """Positive control on the other side: an honestly signed but stale
        attestation is still stale."""
        key = ed25519.Ed25519PrivateKey.generate()
        issued = datetime.now(timezone.utc) - timedelta(seconds=600)
        attestation = _signed(_attestation(issued_at=issued, ttl_seconds=60), key)

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert result.is_stale
        assert result.signature_status == "verified"


class TestUnverifiableSignatures:
    def test_signature_with_no_trusted_key_for_the_issuer_fails_closed(self):
        """A key held for a different issuer must not vouch for this one."""
        key = ed25519.Ed25519PrivateKey.generate()
        other = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        validator = _validator(other.public_key(), issuer="agent://someone-else")
        result = validator.validate(attestation)

        assert not result.is_valid
        assert any("No trusted public key" in e for e in result.errors), result.errors
        assert result.signature_status == "unverified"

    def test_signed_attestation_with_no_keys_configured_at_all_fails_closed(self):
        """The default constructor trusts nobody, so a signed payload cannot be
        verified and must not be reported VALID."""
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        result = AttestationValidator().validate(attestation)

        assert not result.is_valid
        assert result.signature_status == "unverified"

    def test_garbage_signature_is_an_error_not_a_crash(self):
        attestation = _attestation(signature="not-hex-at-all")
        key = ed25519.Ed25519PrivateKey.generate()

        result = _validator(key.public_key()).validate(attestation)

        assert not result.is_valid
        assert result.signature_status == "unverified"

    @pytest.mark.parametrize("signature", [12345, ["aa"], {"a": 1}, 3.5])
    def test_non_string_signature_is_rejected_without_raising(self, signature):
        """Bad data must return False, never raise TypeError out of validate()."""
        attestation = _attestation(signature=signature)
        key = ed25519.Ed25519PrivateKey.generate()

        assert (
            AttestationValidator().verify_signature(attestation, key.public_key())
            is False
        )
        result = _validator(key.public_key()).validate(attestation)
        assert not result.is_valid


class TestHonestSignaturesStillValidate:
    def test_correctly_signed_attestation_is_valid_and_verified(self):
        """Positive control: the fix must not deny an honest signature."""
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        result = _validator(key.public_key()).validate(attestation)

        assert result.is_valid, result.errors
        assert not result.is_stale
        assert result.signature_status == "verified"

    def test_signature_survives_a_json_round_trip(self):
        """The canonical signed payload is to_dict() minus signature, so a file
        written by to_dict() must still verify after from_dict()."""
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        reloaded = Attestation.from_dict(json.loads(json.dumps(attestation.to_dict())))

        result = _validator(key.public_key()).validate(reloaded)

        assert result.is_valid, result.errors
        assert result.signature_status == "verified"

    def test_wildcard_trusted_keys_accepts_any_issuer(self):
        key = ed25519.Ed25519PrivateKey.generate()
        attestation = _signed(_attestation(), key)

        validator = AttestationValidator(
            trusted_keys={"*": key.public_key()},
        )

        assert validator.validate(attestation).is_valid


class TestUnsignedAttestations:
    def test_unsigned_is_a_warning_by_default_not_an_error(self):
        """The documented unsigned workflow (README, examples/) must keep
        working, but the caller must be able to see it was not verified."""
        result = AttestationValidator().validate(_attestation())

        assert result.is_valid, result.errors
        assert result.signature_status == "unsigned"
        assert any("not verified" in w.lower() for w in result.warnings)

    def test_unsigned_is_an_error_when_require_signature_is_set(self):
        result = AttestationValidator(require_signature=True).validate(_attestation())

        assert not result.is_valid
        assert result.signature_status == "unsigned"
        assert any("Unsigned attestation" in e for e in result.errors)

    def test_unsigned_without_require_signature_has_no_errors(self):
        """A warning must not leak into errors and flip is_valid."""
        result = AttestationValidator().validate(_attestation())

        assert result.errors == []


class TestPublicKeyHelper:
    def test_public_key_hex_round_trips_through_the_cli_format(self):
        """The CLI stores keys as hex; the validator consumes raw bytes."""
        key = ed25519.Ed25519PrivateKey.generate()
        hex_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

        loaded = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_key))
        attestation = _signed(_attestation(), key)

        result = AttestationValidator(
            trusted_keys={ISSUER: loaded}
        ).validate(attestation)

        assert result.is_valid, result.errors
        assert result.signature_status == "verified"
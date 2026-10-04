"""Tests for Ed25519 signature verification on attestations."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_capability_attestation.models import Attestation, AttestationValidator


def _make_attestation(signature: str | None = None) -> Attestation:
    return Attestation(
        issuer="agent://planner-v2",
        subject="agent://worker-v3",
        capability="CAN_WRITE(store:p1)",
        issued_at=datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc),
        ttl_seconds=120,
        signature=signature,
    )


def _signed_body(attestation: Attestation) -> bytes:
    """The exact bytes an issuer signs: to_dict() minus the signature field."""
    body = {k: v for k, v in attestation.to_dict().items() if k != "signature"}
    return json.dumps(body).encode()


class TestVerifySignature:
    def test_correctly_signed_attestation_verifies(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        attestation.signature = private_key.sign(_signed_body(attestation)).hex()

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is True

    def test_tampered_signature_is_rejected(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        other_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        # Signed by a key the verifier does not hold the public half of.
        attestation.signature = other_key.sign(_signed_body(attestation)).hex()

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is False

    def test_tampered_payload_is_rejected(self):
        """Changing any signed field after signing must fail verification."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        attestation.signature = private_key.sign(_signed_body(attestation)).hex()

        attestation.capability = "CAN_WRITE(store:*)"
        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is False

    def test_missing_signature_is_rejected(self):
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation(signature=None)

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is False

    def test_malformed_hex_signature_returns_false_not_exception(self):
        """A non-hex signature is bad data, not a reason to raise."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation(signature="not-hex-at-all")

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is False

    @pytest.mark.parametrize(
        "bad_signature",
        [12345, 1.5, ["ab"], {"sig": "ab"}, True],
        ids=["int", "float", "list", "dict", "bool"],
    )
    def test_non_string_signature_returns_false_not_exception(self, bad_signature):
        """A signature value that is not a string must be rejected, not raise.

        The signature is read from a file the attacker can edit, and
        ``bytes.fromhex`` raises ``TypeError`` — not ``ValueError`` — for a
        non-string, so the guard above, which catches only
        ``(InvalidSignature, ValueError)``, let a JSON number, array or object
        escape as an uncaught ``TypeError``. The malformed-hex test next door
        exercises the string arm only, which is why this arm stayed uncovered.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        attestation.signature = bad_signature

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is False

    def test_documented_ed25519_prefixed_signature_verifies(self):
        """README's Attestation Schema documents ``"ed25519:<hex>"``.

        A signature in the form the project's own schema advertises must
        verify; ``bytes.fromhex("ed25519:...")`` used to raise ``ValueError``
        (unprefixed) and return ``False``, so every attestation produced per
        the documented wire format failed verification.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        attestation.signature = (
            "ed25519:" + private_key.sign(_signed_body(attestation)).hex()
        )

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is True

    def test_prefixed_signature_from_wrong_key_is_still_rejected(self):
        """Control arm: stripping the prefix must not turn the check into a pass."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        other_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        attestation.signature = (
            "ed25519:" + other_key.sign(_signed_body(attestation)).hex()
        )

        assert AttestationValidator().verify_signature(
            attestation, private_key.public_key()
        ) is False

    @pytest.mark.parametrize(
        "optional_field",
        ["state_hash", "provenance"],
    )
    def test_optional_fields_are_covered_by_the_signature(self, optional_field):
        """A field added after signing must invalidate the signature.

        to_dict() only emits optional fields when they are truthy, so an
        attacker could otherwise append state_hash/provenance to a signed
        attestation and have it still verify.
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        attestation = _make_attestation()
        attestation.signature = private_key.sign(_signed_body(attestation)).hex()

        if optional_field == "state_hash":
            attestation.state_hash = "sha256:" + "0" * 64
        else:
            attestation.provenance = ["agent://supervisor"]

        assert (
            AttestationValidator().verify_signature(
                attestation, private_key.public_key()
            )
            is False
        )
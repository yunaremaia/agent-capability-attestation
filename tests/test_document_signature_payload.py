"""Issue #43: the signature must be verified over the *document*, not over a
re-serialized model.

``verify_signature()`` used to rebuild the signed payload from
``attestation.to_dict()``. ``from_dict()`` is not the inverse of
``to_dict()``: it injects ``expires_at`` when the field is absent, rewrites a
``Z`` timestamp offset as ``+00:00`` on the way back out, and drops present-but-
empty optional fields. The bytes the verifier checked were therefore never the
bytes the issuer wrote, and every wire-format attestation built to the
documented schema came back ``attestation may be forged`` — the one diagnosis
an implementor cannot rule out.

The document is now the signing payload. These tests sign the document exactly
as it is written (the issue's own reproduction) and require it to verify, plus
one guard that the fix must not blunt: a document tampered with *after* signing
still fails.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import (
    Attestation,
    AttestationValidator,
    canonical_bytes,
)

from click.testing import CliRunner

ISSUER = "agent://planner-v2"


def _z_timestamp(offset: timedelta = timedelta(0)) -> str:
    """The README's documented timestamp form: UTC with a ``Z`` suffix."""
    moment = datetime.now(timezone.utc).replace(microsecond=0) + offset
    return moment.isoformat().replace("+00:00", "Z")


def _document(**overrides) -> dict:
    """A document exactly as the README's schema allows it to be written."""
    document = {
        "issuer": ISSUER,
        "subject": "agent://worker-v3",
        "capability": "CAN_WRITE(state_store:partition_3)",
        "issued_at": _z_timestamp(),
        "ttl_seconds": 120,
    }
    document.update(overrides)
    return document


def _sign_document(key: ed25519.Ed25519PrivateKey, document: dict) -> dict:
    """The issuer side of the issue's reproduction: sign the document itself."""
    body = {k: v for k, v in document.items() if k != "signature"}
    return dict(document, signature=key.sign(canonical_bytes(body)).hex())


def _validator(key: ed25519.Ed25519PrivateKey) -> AttestationValidator:
    return AttestationValidator(trusted_keys={ISSUER: key.public_key()})


def _verify(document: dict, key: ed25519.Ed25519PrivateKey) -> bool:
    signed = _sign_document(key, document)
    return _validator(key).verify_signature(
        Attestation.from_dict(signed), key.public_key()
    )


class TestTheDocumentIsTheSignedPayload:
    def test_a_z_timestamp_without_expires_at_verifies(self, tmp_path):
        """The issue's headline case: ``Z`` offset, ``expires_at`` omitted.

        ``__post_init__`` injects ``expires_at = issued_at + ttl_seconds`` and
        ``to_dict()`` re-emits both timestamps via ``.isoformat()``, so the
        verified payload had six keys and ``+00:00`` where the document had
        five keys and ``Z``.
        """
        assert _verify(_document(), ed25519.Ed25519PrivateKey.generate()) is True

    def test_an_explicit_expires_at_in_z_form_verifies(self, tmp_path):
        """A declared expiry is optional but must verify in the documented form."""
        document = _document(expires_at=_z_timestamp(timedelta(seconds=120)))

        assert _verify(document, ed25519.Ed25519PrivateKey.generate()) is True

    def test_an_empty_provenance_list_stays_in_the_signed_payload(self, tmp_path):
        """``to_dict()`` guards on truthiness, so ``"provenance": []`` vanished."""
        document = _document(provenance=[])

        assert _verify(document, ed25519.Ed25519PrivateKey.generate()) is True

    def test_an_empty_state_hash_stays_in_the_signed_payload(self, tmp_path):
        """Same truthiness guard, same disappearance, same forged verdict."""
        document = _document(state_hash="")

        assert _verify(document, ed25519.Ed25519PrivateKey.generate()) is True

    def test_a_tampered_document_still_fails(self, tmp_path):
        """The guard the fix must not blunt: the payload is still covered.

        Verifying the document is only safe while the document is still the
        thing the issuer signed — an attacker who edits a field after the fact
        must be rejected exactly as before.
        """
        key = ed25519.Ed25519PrivateKey.generate()
        signed = _sign_document(key, _document())
        signed["capability"] = "CAN_ADMIN(state_store:partition_3)"

        assert _verify_signed(signed, key) is False


def _verify_signed(signed: dict, key: ed25519.Ed25519PrivateKey) -> bool:
    return _validator(key).verify_signature(
        Attestation.from_dict(signed), key.public_key()
    )


class TestTheRawDocumentIsNotPartOfTheModel:
    def test_it_is_not_serialized(self, tmp_path):
        document = _document()
        attestation = Attestation.from_dict(document)

        assert "_raw" not in attestation.to_dict()

    def test_it_does_not_change_equality(self, tmp_path):
        """A parsed document and the model built from the same fields compare
        equal — the raw mapping is bookkeeping, not attestation content."""
        document = _document()
        parsed = Attestation.from_dict(document)
        rebuilt = Attestation(
            issuer=document["issuer"],
            subject=document["subject"],
            capability=document["capability"],
            issued_at=parsed.issued_at,
            ttl_seconds=document["ttl_seconds"],
        )

        assert parsed == rebuilt


class TestTheDocumentedWorkflowEndToEnd:
    def test_validate_exits_zero_on_the_issues_own_reproduction(self, tmp_path):
        """``aca validate`` on the file the issue writes, signed as written."""
        key = ed25519.Ed25519PrivateKey.generate()
        (tmp_path / "pub.hex").write_text(
            key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
        )
        (tmp_path / "attestation.json").write_text(json.dumps(_sign_document(key, _document())))

        result = CliRunner().invoke(
            cli,
            [
                "validate",
                str(tmp_path / "attestation.json"),
                "--public-key-file",
                str(tmp_path / "pub.hex"),
            ],
        )

        assert result.exit_code == 0, result.output
        assert "VERIFIED" in result.output, result.output

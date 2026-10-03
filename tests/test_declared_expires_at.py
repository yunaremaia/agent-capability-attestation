"""Tests that a declared ``expires_at`` is parsed and treated as authoritative.

``Attestation.from_dict`` never read ``expires_at``, so ``__post_init__``
recomputed it as ``issued_at + ttl_seconds``. An attestation that declared
itself expired 10 seconds after issue, while carrying a one-year
``ttl_seconds``, was silently granted a year of validity — a fail-OPEN.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_capability_attestation.models import Attestation, AttestationValidator

ONE_YEAR = 31536000


def _declaring_short_expiry():
    return {
        "issuer": "agent://planner-v2",
        "subject": "agent://worker-v3",
        "capability": "CAN_WRITE(state_store:partition_3)",
        "issued_at": "2026-09-21T12:00:00Z",
        "expires_at": "2026-09-21T12:00:10Z",
        "ttl_seconds": ONE_YEAR,
    }


class TestDeclaredExpiresAtIsParsed:
    def test_from_dict_preserves_declared_expires_at(self):
        att = Attestation.from_dict(_declaring_short_expiry())

        assert att.expires_at == datetime(2026, 9, 21, 12, 0, 10, tzinfo=timezone.utc)

    def test_declared_expiry_is_not_overwritten_by_a_long_ttl(self):
        """The one-year TTL must not stretch a 10-second declared expiry."""
        att = Attestation.from_dict(_declaring_short_expiry())

        assert att.expires_at != datetime(
            2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc
        ) + timedelta(seconds=ONE_YEAR)

    def test_round_trip_preserves_expires_at(self):
        """to_dict() emits expires_at, so the declared value must survive it."""
        att = Attestation.from_dict(_declaring_short_expiry())
        declared = att.to_dict()["expires_at"]

        assert declared == "2026-09-21T12:00:10+00:00"
        assert Attestation.from_dict(att.to_dict()).expires_at == att.expires_at

    def test_absent_expires_at_still_falls_back_to_ttl(self):
        """The derived path is unchanged when the file declares nothing."""
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00Z",
            "ttl_seconds": 120,
        }

        att = Attestation.from_dict(data)

        assert att.expires_at == datetime(2026, 9, 21, 12, 2, tzinfo=timezone.utc)

    def test_direct_construction_still_derives_expires_at(self):
        att = Attestation(
            issuer="a",
            subject="b",
            capability="X",
            issued_at=datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc),
            ttl_seconds=120,
        )

        assert att.expires_at == datetime(2026, 9, 21, 12, 2, tzinfo=timezone.utc)


class TestDeclaredExpiresAtIsAuthoritative:
    def test_expired_declared_expiry_fails_validation(self):
        """Five minutes past the declared expiry: invalid and stale."""
        att = Attestation.from_dict(_declaring_short_expiry())
        now = datetime(2026, 9, 21, 12, 5, 0, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert result.is_stale
        assert result.stale_by_seconds == pytest.approx(290.0)

    def test_short_ttl_alongside_declared_expiry_is_still_invalid(self):
        """A one-year TTL must not rescue an attestation past its real deadline."""
        att = Attestation.from_dict(_declaring_short_expiry())
        now = datetime(2026, 9, 21, 13, 0, 0, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert result.stale_by_seconds == pytest.approx(3590.0)

    def test_fresh_declared_expiry_still_validates(self):
        """Positive control: honoring expires_at must not deny everything."""
        att = Attestation.from_dict(_declaring_short_expiry())
        now = datetime(2026, 9, 21, 12, 0, 5, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert result.is_valid
        assert not result.is_stale

    def test_derived_expiry_behaviour_is_unchanged(self):
        """No declared expiry: staleness still measured from issued_at + TTL."""
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00Z",
            "ttl_seconds": 60,
        }
        att = Attestation.from_dict(data)
        now = datetime(2026, 9, 21, 13, 0, 0, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert result.is_stale
        assert result.stale_by_seconds == pytest.approx(3540.0)

    def test_ttl_exceeding_max_still_only_warns(self):
        """The TTL warning is unchanged; only the deadline is now authoritative."""
        att = Attestation.from_dict(_declaring_short_expiry())
        now = datetime(2026, 9, 21, 12, 0, 5, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert result.is_valid
        assert any("exceeds max" in w for w in result.warnings)
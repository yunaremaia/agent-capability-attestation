"""Tests that a timezone-naive timestamp is normalized instead of crashing.

``_parse_datetime`` only rewrote ``Z`` and never attached a timezone, so
``"2026-09-21T12:00:00"`` — valid ISO 8601 — parsed into a naive datetime.
``AttestationValidator.now`` is always tz-aware, so the subtraction in
``validate`` raised ``TypeError: can't subtract offset-naive and
offset-aware datetimes`` and the command died with a traceback instead of
returning a validation result.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import (
    Attestation,
    AttestationValidator,
    _parse_datetime,
)


def _naive_attestation(ttl_seconds=120):
    return {
        "issuer": "agent://planner-v2",
        "subject": "agent://worker-v3",
        "capability": "CAN_WRITE(state_store:partition_3)",
        "issued_at": "2026-09-21T12:00:00",
        "ttl_seconds": ttl_seconds,
    }


class TestParseDatetimeNormalization:
    def test_naive_string_is_made_aware_as_utc(self):
        parsed = _parse_datetime("2026-09-21T12:00:00")

        assert parsed.tzinfo is not None
        assert parsed == datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def test_naive_datetime_object_is_made_aware_as_utc(self):
        """The isinstance early-return had the same gap as the string path."""
        parsed = _parse_datetime(datetime(2026, 9, 21, 12, 0, 0))

        assert parsed.tzinfo is not None
        assert parsed == datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)

    def test_z_suffix_still_parsed_as_utc(self):
        assert _parse_datetime("2026-09-21T12:00:00Z") == datetime(
            2026, 9, 21, 12, 0, tzinfo=timezone.utc
        )

    def test_offset_timestamp_is_converted_to_utc(self):
        assert _parse_datetime("2026-09-21T14:00:00+02:00") == datetime(
            2026, 9, 21, 12, 0, tzinfo=timezone.utc
        )

    def test_non_datetime_value_still_raises_value_error(self):
        with pytest.raises(ValueError):
            _parse_datetime(12345)


class TestNaiveIssuedAtDoesNotCrashValidate:
    def test_validate_returns_a_result_instead_of_raising(self):
        att = Attestation.from_dict(_naive_attestation())
        now = datetime(2026, 9, 21, 12, 1, 0, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert result.is_valid
        assert not result.is_stale

    def test_naive_issued_at_is_evaluated_as_utc(self):
        """A naive 12:00 with a 60s TTL is stale at 12:05 UTC."""
        att = Attestation.from_dict(_naive_attestation(ttl_seconds=60))
        now = datetime(2026, 9, 21, 12, 5, 0, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert result.is_stale
        assert result.stale_by_seconds == pytest.approx(240.0)

    def test_derived_expires_at_is_also_aware(self):
        att = Attestation.from_dict(_naive_attestation())

        assert att.expires_at.tzinfo is not None

    def test_naive_now_does_not_crash_validate(self):
        """AttestationValidator(now=...) accepted a naive value unchecked."""
        att = Attestation.from_dict(_naive_attestation())

        result = AttestationValidator(now=datetime(2026, 9, 21, 12, 1, 0)).validate(att)

        assert result.is_valid

    def test_non_datetime_value_is_reported_as_an_error_not_a_crash(self):
        """Bad data is a validation error, never an unhandled exception."""
        data = _naive_attestation()
        data["issued_at"] = 12345
        with pytest.raises(ValueError):
            Attestation.from_dict(data)


class TestNaiveIssuedAtThroughTheCli:
    def test_validate_command_does_not_traceback(self, tmp_path):
        path = tmp_path / "naive.json"
        path.write_text(json.dumps(_naive_attestation()))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 1
        assert "Traceback" not in result.output
        assert "TypeError" not in result.output
        # Stale (issued 2026-09-21 with a 120s TTL, checked today).
        assert "STALE" in result.output

    def test_scan_reports_the_file_as_invalid_not_as_an_error_reading_it(
        self, tmp_path
    ):
        """scan catches per-file exceptions, so a naive timestamp used to be
        swallowed as `ERROR reading ...` instead of a validation verdict."""
        path = tmp_path / "naive.attestation.json"
        path.write_text(json.dumps(_naive_attestation()))

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert "ERROR reading" not in result.output
        assert "STALE" in result.output
        assert "1 attestations scanned, 1 stale" in result.output


class TestUnparseableTimestampDoesNotCrashValidate:
    def test_validate_returns_error_for_directly_built_naive_attestation(self):
        """Building Attestation directly bypasses _parse_datetime entirely, so
        validate itself has to survive a naive issued_at rather than raise."""
        att = Attestation(
            issuer="a",
            subject="b",
            capability="X",
            issued_at=datetime(2026, 9, 21, 12, 0, 0),
            ttl_seconds=60,
        )
        now = datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc)

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert result.is_stale
        assert result.stale_by_seconds == pytest.approx(3540.0)
        assert result.errors

    def test_bad_issued_at_type_is_rejected_at_parse_time(self):
        """A non-datetime value is a ValueError, not a silent acceptance."""
        data = _naive_attestation()
        data["issued_at"] = 12345

        with pytest.raises(ValueError):
            Attestation.from_dict(data)


class TestTtLDeadlineIsStillEnforcedAfterNormalization:
    def test_offset_and_naive_inputs_agree(self):
        """12:00 naive and 12:00Z must produce identical verdicts."""
        naive = Attestation.from_dict(_naive_attestation(ttl_seconds=60))
        aware = Attestation.from_dict(
            {**_naive_attestation(ttl_seconds=60), "issued_at": "2026-09-21T12:00:00Z"}
        )
        now = datetime(2026, 9, 21, 12, 5, 0, tzinfo=timezone.utc)

        naive_result = AttestationValidator(now=now).validate(naive)
        aware_result = AttestationValidator(now=now).validate(aware)

        assert naive_result.is_valid == aware_result.is_valid
        assert naive_result.stale_by_seconds == aware_result.stale_by_seconds
        assert naive_result.stale_by_seconds == pytest.approx(240.0)
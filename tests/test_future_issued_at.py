"""Tests that a future-dated ``issued_at`` is rejected, not trusted forever.

``validate`` computed ``age = now - issued_at`` and only ever rejected when
``age`` was large. A negative ``age`` — an ``issued_at`` in the future — fell
through every branch, so an attestation dated 80 years ahead reported
``is_valid=True``, ``is_stale=False``, zero errors and CLI exit 0. Because the
deadline is derived from ``issued_at``, such an attestation stays "fresh" until
the wall clock catches up, which makes it an unbounded-validity primitive: a
replayed receipt stays valid forever without forging a signature.

The fix bounds how far into the future an ``issued_at`` may sit
(``max_skew_seconds``) rather than rejecting every future timestamp outright,
because a host with a slightly drifting clock is legitimate — NTP offset is
seconds, not zero.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import (
    DEFAULT_MAX_SKEW_SECONDS,
    Attestation,
    AttestationValidator,
)


def _issued_at(**kwargs) -> str:
    """An ISO timestamp ``kwargs`` of seconds from now (positive = future)."""
    offset = timedelta(seconds=kwargs.pop("offset_seconds", 0))
    assert not kwargs, f"unexpected keyword arguments: {kwargs}"
    return (datetime.now(timezone.utc) + offset).isoformat()


def _attestation(issued_at: str, ttl_seconds: int = 120, **extra) -> dict:
    data = {
        "issuer": "agent://planner-v2",
        "subject": "agent://worker-v3",
        "capability": "CAN_WRITE(root)",
        "issued_at": issued_at,
        "ttl_seconds": ttl_seconds,
    }
    data.update(extra)
    return data


def _future_attestation(years: float = 80, ttl_seconds: int = 120) -> Attestation:
    return Attestation.from_dict(
        _attestation(
            issued_at=(datetime.now(timezone.utc) + timedelta(days=365 * years)).isoformat(),
            ttl_seconds=ttl_seconds,
        )
    )


class TestFutureIssuedAtIsRejected:
    def test_attestation_issued_80_years_ahead_is_invalid(self):
        """The headline bug: is_valid=True, is_stale=False, no errors."""
        result = AttestationValidator(max_ttl=300).validate(_future_attestation())

        assert not result.is_valid

    @pytest.mark.parametrize("years", [0.001, 1, 10, 80])
    def test_every_past_the_tolerance_is_invalid(self, years):
        """One second past the window is as forged as eighty years past it."""
        result = AttestationValidator(max_ttl=300).validate(
            _future_attestation(years=years)
        )

        assert not result.is_valid
        assert any("in the future" in err for err in result.errors)

    def test_the_error_names_the_offset_and_the_allowed_skew(self):
        """The operator needs to know how far off the clock looked."""
        result = AttestationValidator(max_ttl=300).validate(
            _future_attestation(years=1)
        )

        assert any(
            f"allowed skew {DEFAULT_MAX_SKEW_SECONDS}s" in err
            for err in result.errors
        )

    def test_a_long_ttl_cannot_buy_validity(self):
        """An absurd TTL plus a future issued_at is still rejected.

        This is the pair the issue is named for: the TTL looks expired long
        before the attestation does, so checking the TTL alone says nothing.
        """
        att = _future_attestation(years=80, ttl_seconds=80 * 365 * 24 * 3600)

        result = AttestationValidator(max_ttl=300).validate(att)

        assert not result.is_valid

    def test_future_issued_at_is_not_reported_as_stale(self):
        """It is not yet valid — that is different from having expired."""
        result = AttestationValidator(max_ttl=300).validate(_future_attestation())

        assert result.is_stale is False
        assert result.stale_by_seconds is None

    def test_naive_future_issued_at_is_rejected(self):
        """A naive issued_at is normalized to UTC before the skew check."""
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation(
            issuer="a",
            subject="b",
            capability="X",
            issued_at=datetime(2026, 9, 21, 12, 5),
            ttl_seconds=120,
        )

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert any("in the future" in err for err in result.errors)

    def test_a_past_declared_expiry_does_not_excuse_a_future_issued_at(self):
        """An expiry in the past alongside a future issued_at is rejected."""
        att = Attestation.from_dict(
            _attestation(
                issued_at=_issued_at(offset_seconds=3600),
                ttl_seconds=120,
                expires_at=_issued_at(offset_seconds=-3600),
            )
        )

        result = AttestationValidator(max_ttl=300).validate(att)

        assert not result.is_valid


class TestClockSkewTolerance:
    def test_a_small_forward_skew_is_still_accepted(self):
        """NTP drift is legitimate; rejecting it would break real hosts."""
        att = Attestation.from_dict(_attestation(issued_at=_issued_at(offset_seconds=5)))

        result = AttestationValidator(max_ttl=300).validate(att)

        assert result.is_valid
        assert not result.is_stale

    def test_offset_exactly_at_the_tolerance_is_accepted(self):
        """The window is inclusive so a boundary is not a coin flip."""
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(issued_at=(now + timedelta(seconds=DEFAULT_MAX_SKEW_SECONDS)).isoformat())
        )

        result = AttestationValidator(now=now).validate(att)

        assert result.is_valid

    def test_offset_just_past_the_tolerance_is_rejected(self):
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(
                issued_at=(
                    now + timedelta(seconds=DEFAULT_MAX_SKEW_SECONDS + 1)
                ).isoformat()
            )
        )

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid

    def test_the_window_is_configurable(self):
        """A deployment with known drift widens it explicitly."""
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(issued_at=(now + timedelta(seconds=300)).isoformat())
        )

        narrow = AttestationValidator(now=now).validate(att)
        wide = AttestationValidator(now=now, max_skew_seconds=600).validate(att)

        assert not narrow.is_valid
        assert wide.is_valid

    def test_the_default_window_is_sixty_seconds(self):
        """Documented value, so the bound is reviewable and testable."""
        assert DEFAULT_MAX_SKEW_SECONDS == 60

    def test_tolerance_does_not_extend_validity_past_the_ttl(self):
        """Inside the window the deadline is still issued_at + ttl_seconds.

        Skew tolerance decides whether a timestamp is believable; it must not
        turn into free lifetime for the attestation.
        """
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(
                issued_at=(now + timedelta(seconds=30)).isoformat(), ttl_seconds=60
            )
        )

        just_inside = AttestationValidator(
            now=now + timedelta(seconds=89)
        ).validate(att)
        just_outside = AttestationValidator(
            now=now + timedelta(seconds=91)
        ).validate(att)

        assert just_inside.is_valid
        assert not just_outside.is_valid
        assert just_outside.stale_by_seconds == pytest.approx(1.0)


class TestUnchangedBehaviour:
    def test_a_recently_issued_attestation_still_validates(self):
        att = Attestation.from_dict(_attestation(issued_at=_issued_at(offset_seconds=-10)))

        result = AttestationValidator(max_ttl=300).validate(att)

        assert result.is_valid

    def test_an_expired_attestation_is_still_stale(self):
        """The pre-existing staleness branch must be untouched."""
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(
                issued_at=(now - timedelta(seconds=600)).isoformat(), ttl_seconds=60
            )
        )

        result = AttestationValidator(now=now).validate(att)

        assert not result.is_valid
        assert result.is_stale
        assert result.stale_by_seconds == pytest.approx(540.0)

    def test_a_declared_short_expiry_is_still_authoritative(self):
        """Regression guard for the expires_at-authoritative fix."""
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(
                issued_at=now.isoformat(),
                expires_at=(now + timedelta(seconds=10)).isoformat(),
                ttl_seconds=31536000,
            )
        )

        assert not AttestationValidator(now=now + timedelta(seconds=15)).validate(
            att
        ).is_valid
        assert AttestationValidator(now=now + timedelta(seconds=5)).validate(
            att
        ).is_valid

    def test_max_ttl_remains_advisory(self):
        """Not in scope here: an over-ceiling TTL still only warns (#18)."""
        now = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
        att = Attestation.from_dict(
            _attestation(issued_at=now.isoformat(), ttl_seconds=31536000)
        )

        result = AttestationValidator(now=now, max_ttl=300).validate(att)

        assert result.is_valid
        assert any("exceeds max" in w for w in result.warnings)


class TestFutureIssuedAtThroughTheCli:
    def test_validate_exits_one_and_explains_itself(self, tmp_path):
        path = tmp_path / "future.attestation.json"
        path.write_text(json.dumps(_attestation(issued_at=_issued_at(offset_seconds=86400))))

        result = CliRunner().invoke(cli, ["validate", str(path)])

        assert result.exit_code == 1
        assert "in the future" in result.output
        assert "Traceback" not in result.output

    def test_json_output_reports_the_attestation_as_invalid(self, tmp_path):
        path = tmp_path / "future.attestation.json"
        path.write_text(json.dumps(_attestation(issued_at=_issued_at(offset_seconds=86400))))

        result = CliRunner().invoke(cli, ["validate", str(path), "--json-output"])

        payload = json.loads(result.output)
        assert payload["is_valid"] is False
        assert payload["errors"]

    def test_scan_counts_the_future_dated_file_as_invalid(self, tmp_path):
        path = tmp_path / "future.attestation.json"
        path.write_text(json.dumps(_attestation(issued_at=_issued_at(offset_seconds=86400))))

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert "ERROR reading" not in result.output
        assert "in the future" in result.output
        assert "1 attestations scanned, 1 stale" in result.output

    def test_max_skew_option_widens_the_window(self, tmp_path):
        path = tmp_path / "future.attestation.json"
        path.write_text(json.dumps(_attestation(issued_at=_issued_at(offset_seconds=300))))

        narrow = CliRunner().invoke(cli, ["validate", str(path)])
        wide = CliRunner().invoke(
            cli, ["validate", str(path), "--max-skew-seconds", "600"]
        )

        assert narrow.exit_code == 1
        assert wide.exit_code == 0, wide.output

    def test_check_mcp_flags_a_future_dated_server_attestation(self, tmp_path):
        """check-mcp builds its own validator, so it must inherit the bound."""
        path = tmp_path / "mcp-future.json"
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "filesystem": {
                            "command": "npx",
                            "args": ["-y", "server-filesystem", "/tmp"],
                            "capabilityAttestation": _attestation(
                                issued_at=_issued_at(offset_seconds=86400)
                            ),
                        }
                    }
                }
            )
        )

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "in the future" in result.output

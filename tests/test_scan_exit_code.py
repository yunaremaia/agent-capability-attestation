"""Tests that ``aca scan``'s exit code reflects the verdict it just printed.

``scan`` validated every file in a directory, printed the correct per-file
verdict (``✗ STALE`` / ``✗ INVALID``, ``ERROR:`` lines) and then threw the
verdict away: ``all_valid`` was only consulted when ``--fail-on-stale`` was
passed, so the command exited ``0`` by default. A directory holding nothing but
forged and expired attestations therefore produced a green build — the tool
detected the forgery and the process boundary discarded the detection, which is
the only place a CI system reads.

These tests pin the exit *code*, not the output: the verdict lines were already
correct before the fix, so an output assertion alone cannot catch this class of
defect (see ``tests/test_naive_timestamps.py`` and ``tests/test_future_issued_at.py``,
whose ``scan`` tests assert only on stdout).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli


def _iso(offset: timedelta) -> str:
    return (datetime.now(timezone.utc) + offset).isoformat()


def _attestation(issued_at: str, ttl: int = 300, **extra) -> dict:
    document = {
        "issuer": "agent://planner",
        "subject": "agent://worker",
        "capability": "CAN_READ(store)",
        "issued_at": issued_at,
        "ttl_seconds": ttl,
    }
    document.update(extra)
    return document


def _write(directory, name: str, document: dict):
    path = directory / name
    path.write_text(json.dumps(document))
    return path


def _stale(directory, name: str = "stale.attestation.json"):
    """An attestation that expired long ago — invalid without any flag."""
    return _write(directory, name, _attestation(_iso(timedelta(days=-30)), ttl=60))


def _fresh_unsigned(directory, name: str = "fresh.attestation.json"):
    """A live, unsigned attestation: valid (an absent signature is a warning)."""
    return _write(directory, name, _attestation(_iso(timedelta(0))))


class TestScanExitCode:
    def test_scan_exits_one_when_any_attestation_is_invalid(self, tmp_path):
        """The reported defect: one invalid file, no flag, exit must be 1."""
        _stale(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "STALE" in result.output

    def test_scan_exits_one_for_a_forged_attestation_alongside_a_stale_one(
        self, tmp_path
    ):
        """The issue's exact directory: one expired, one carrying a bogus
        signature. The second file's ERROR is the whole point — it used to be
        printed and then discarded by an exit status of 0."""
        _stale(tmp_path, "a-stale.attestation.json")
        _write(
            tmp_path,
            "b-forged.attestation.json",
            _attestation(
                _iso(timedelta(0)),
                ttl=120,
                subject="agent://mallory",
                capability="CAN_DELETE_ALL(state)",
                signature="ed25519:" + "ab" * 60,
            ),
        )

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output

    def test_scan_exits_one_when_a_real_signature_covers_a_tampered_payload(
        self, tmp_path
    ):
        """The forgery the CHANGELOG entry actually describes.

        The test above supplies a signature no key can ever verify, so the
        verdict it produces is 'no trusted key for this issuer' — the
        *unverifiable* path. That is a real defect class, but it is not the one
        this PR claims to fix: it cannot distinguish 'the verifier had nothing
        to check against' from 'the verifier checked and the bytes did not
        match'. Here the issuer's real public key is trusted and the signature
        is valid over the original payload; the attacker then rewrites
        ``capability`` on disk. That is the attack the signature exists to
        stop, it produces the distinct
        ``Signature does not match payload`` error, and before the fix it
        exited 0.

        Signing follows ``models.verify_signature``: the signed body is
        ``to_dict()`` minus ``signature``, serialized with ``json.dumps``.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        from agent_capability_attestation.models import Attestation

        key = ed25519.Ed25519PrivateKey.generate()
        keyfile = tmp_path / "issuer-pubkey.hex"
        keyfile.write_text(
            key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
            + "\n"
        )

        honest = Attestation(
            issuer="agent://planner-v2",
            subject="agent://worker-v3",
            capability="CAN_READ(db:orders)",
            issued_at=datetime.now(timezone.utc) - timedelta(seconds=5),
            ttl_seconds=120,
        )
        signed = honest.to_dict()
        body = json.dumps({k: v for k, v in signed.items() if k != "signature"})
        signed["signature"] = key.sign(body.encode()).hex()
        # The attacker rewrites the capability after signing.
        forged = dict(signed, capability="CAN_ADMIN(db:orders)")
        (tmp_path / "forged.attestation.json").write_text(json.dumps(forged))

        result = CliRunner().invoke(
            cli,
            ["scan", str(tmp_path), "--public-key-file", str(keyfile)],
        )

        assert "Signature does not match" in result.output, result.output
        assert result.exit_code == 1, result.output

    def test_scan_exits_zero_when_every_attestation_is_valid(self, tmp_path):
        """Guard the guard: a clean directory must still pass the gate."""
        _fresh_unsigned(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 0, result.output

    def test_scan_exits_one_when_a_file_cannot_be_read(self, tmp_path):
        """The ``except`` path also feeds the exit code: an unreadable file is
        an invalid result, not a reason to exit 0."""
        (tmp_path / "broken.attestation.json").write_text("{ not json")

        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output

    def test_empty_directory_exits_one(self, tmp_path):
        """A directory holding nothing to validate is not a clean run.

        This asserted ``0`` once, which is the #31/#46 vacuous-pass class: a CI
        gate pointed at the wrong directory — or one whose filenames did not
        match a hardcoded ``*.attestation.json`` glob — passed green having
        inspected nothing. Finding no attestations now fails closed, the same
        way ``check-chain`` and ``check-mcp`` do.
        """
        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])

        assert result.exit_code == 1, result.output
        assert "nothing was validated" in result.output, result.output

    def test_report_only_forces_exit_zero_and_still_prints_the_verdict(
        self, tmp_path
    ):
        """The explicit opt-out: the finding is still reported on stdout, only
        the exit status is relaxed."""
        _stale(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--report-only"])

        assert result.exit_code == 0, result.output
        assert "STALE" in result.output

    def test_deprecated_fail_on_stale_is_still_accepted(self, tmp_path):
        """Kept for one release so the documented CI recipe keeps working: it
        is now redundant, but it must not be rejected or change the outcome."""
        _stale(tmp_path)

        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--fail-on-stale"])

        assert result.exit_code == 1, result.output

    def test_fail_on_stale_and_report_only_are_mutually_exclusive(self, tmp_path):
        _fresh_unsigned(tmp_path)

        result = CliRunner().invoke(
            cli, ["scan", str(tmp_path), "--fail-on-stale", "--report-only"]
        )

        assert result.exit_code == 2, result.output
        assert "mutually exclusive" in result.output


class TestScanFlagContract:
    """The flags that decide the exit code are advertised in ``--help``."""

    def test_help_names_report_only(self):
        result = CliRunner().invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--report-only" in result.output

    def test_help_marks_fail_on_stale_deprecated(self):
        result = CliRunner().invoke(cli, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--fail-on-stale" in result.output
        assert "Deprecated" in result.output

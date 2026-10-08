"""The MCP verdicts ``check_mcp`` used to collapse into a single answer (#20).

Two states had no representation in ``ValidationResult``. A server that carries
**no** attestation and one whose attestation merely **expired** were both
``is_valid=False, is_stale=True`` with the same "Missing TTL" error, because the
scanner encoded absence as a synthetic ``ttl_seconds=0`` attestation that lands
in the staleness branch. And a server whose declared surface (``command`` /
``args`` / ``tools``) changed under a still-fresh attestation reported
``✓ VALID``: ``state_hash`` was never read.

The three want different remediation — create an attestation, re-issue one, or
find out what changed — so each now gets its own ``status``, absence reports
``is_stale=None`` rather than ``True``, and drift is a comparison rather than a
claim the docstring made and the code did not keep.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.mcp_scanner import check_mcp
from agent_capability_attestation.models import (
    STATUS_DRIFTED,
    STATUS_EXPIRED,
    STATUS_UNATTESTED,
    compute_state_hash,
)

#: A plausible filesystem server: the surface an attestation would cover.
SURFACE = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/sandbox"],
    "tools": ["read_file", "write_file"],
}


def _hash_of(surface: dict) -> str:
    """The digest ``_check_state_drift`` computes, spelled out independently."""
    return compute_state_hash(
        {
            "command": surface["command"],
            "args": surface["args"],
            "tools": surface["tools"],
        }
    )


def _write(tmp_path, server: dict, name: str = "mcp.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"mcpServers": {"filesystem": server}}))
    return path


def _attested(state_hash: str | None = None, *, age: int = 1, ttl_seconds: int = 300, **surface):
    """A server entry whose attestation covers ``surface`` (default: SURFACE)."""
    declared = {**SURFACE, **surface}
    attestation = {
        "issuer": "mcp://filesystem",
        "subject": "mcp://filesystem/consumer",
        "capability": "MCP_SERVER_ATTACHED:filesystem",
        "issued_at": (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat(),
        "ttl_seconds": ttl_seconds,
    }
    if state_hash is not None:
        attestation["state_hash"] = state_hash
    return {**declared, "capabilityAttestation": attestation}


class TestAbsenceIsNotStaleness:
    def test_an_unattested_server_gets_its_own_status(self, tmp_path):
        path = _write(tmp_path, dict(SURFACE))

        (result,) = check_mcp(str(path))

        assert result.status == STATUS_UNATTESTED
        assert result.is_valid is False  # still fail closed

    def test_an_unattested_server_is_not_reported_as_stale(self, tmp_path):
        """``is_stale`` is tri-state — ``None`` is the whole point of the fix."""
        path = _write(tmp_path, dict(SURFACE))

        (result,) = check_mcp(str(path))

        assert result.is_stale is None

    def test_unattested_and_expired_are_distinguishable(self, tmp_path):
        """The defect: these two used to be identical in every field."""
        unattested = _write(tmp_path, dict(SURFACE), name="unattested.json")
        expired = _write(
            tmp_path, _attested(age=900, ttl_seconds=60), name="expired.json"
        )

        (u,) = check_mcp(str(unattested))
        (e,) = check_mcp(str(expired))

        assert u.is_valid is False and e.is_valid is False
        assert u.status != e.status
        assert e.status == STATUS_EXPIRED
        assert u.is_stale is None and e.is_stale is True

    def test_the_error_names_the_absence_not_a_missing_ttl(self, tmp_path):
        """The old message blamed a TTL that was never supposed to be there."""
        path = _write(tmp_path, dict(SURFACE))

        (result,) = check_mcp(str(path))

        assert any("capabilityAttestation" in err for err in result.errors)
        assert not any("Missing TTL" in err for err in result.errors)


class TestUnattestedReachesTheCaller:
    def test_cli_prints_unattested_not_stale(self, tmp_path):
        path = _write(tmp_path, dict(SURFACE))

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "UNATTESTED" in result.output
        assert "STALE" not in result.output

    def test_json_output_carries_the_status(self, tmp_path):
        path = _write(tmp_path, dict(SURFACE))

        result = CliRunner().invoke(cli, ["check-mcp", str(path), "--json-output"])

        payload = json.loads(result.output)
        assert payload[0]["status"] == STATUS_UNATTESTED
        assert payload[0]["is_stale"] is None


class TestDriftIsActuallyChecked:
    def test_a_matching_hash_is_valid(self, tmp_path):
        path = _write(tmp_path, _attested(state_hash=_hash_of(SURFACE)))

        (result,) = check_mcp(str(path))

        assert result.is_valid is True
        assert result.status != STATUS_DRIFTED

    @pytest.mark.parametrize(
        "widened",
        [
            {"args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]},
            {"tools": ["read_file", "write_file", "delete_file"]},
            {"command": "node"},
        ],
        ids=["args-widened", "tool-added", "command-swapped"],
    )
    def test_a_changed_surface_is_drift(self, tmp_path, widened):
        """The attestation is still fresh; what moved is what it attests to."""
        path = _write(tmp_path, _attested(state_hash=_hash_of(SURFACE), **widened))

        (result,) = check_mcp(str(path))

        assert result.status == STATUS_DRIFTED
        assert result.is_valid is False
        assert any("drift" in err for err in result.errors)

    def test_drift_exits_one_from_the_cli(self, tmp_path):
        path = _write(
            tmp_path,
            _attested(
                state_hash=_hash_of(SURFACE),
                args=["-y", "@modelcontextprotocol/server-filesystem", "/"],
            ),
        )

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "DRIFTED" in result.output

    def test_a_missing_hash_warns_that_drift_is_unchecked(self, tmp_path):
        """A receipt that cannot detect drift is surfaced, not silently skipped."""
        path = _write(tmp_path, _attested())

        (result,) = check_mcp(str(path))

        assert result.is_valid is True
        assert any("drift cannot be checked" in w for w in result.warnings)

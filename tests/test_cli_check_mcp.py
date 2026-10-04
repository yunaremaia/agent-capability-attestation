"""Tests for the ``aca check-mcp`` CLI command.

The command function in ``cli.py`` used to share its name with the
``mcp_scanner.check_mcp`` helper it imported, so the name inside the function
body resolved to the click ``Command`` object instead of the scanner. Every
invocation died with
``TypeError: Context.__init__() got an unexpected keyword argument 'max_ttl'``.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli


def _write_config(tmp_path, *, ttl_seconds=120, with_attestation=True, age=1):
    """Write an MCP config whose attached server carries an attestation."""
    server = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    }
    if with_attestation:
        server["capabilityAttestation"] = {
            "issuer": "mcp://filesystem",
            "subject": "mcp://filesystem/consumer",
            "capability": "MCP_SERVER_ATTACHED:filesystem",
            "issued_at": (
                datetime.now(timezone.utc) - timedelta(seconds=age)
            ).isoformat(),
            "ttl_seconds": ttl_seconds,
        }
    path = tmp_path / "mcp-valid.json"
    path.write_text(json.dumps({"mcpServers": {"filesystem": server}}))
    return path


class TestCheckMcp:
    def test_freshly_attested_config_does_not_crash(self, tmp_path):
        """A valid config must be scanned, not turned into a click TypeError."""
        path = _write_config(tmp_path)

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert "Context.__init__" not in result.output
        assert result.exit_code == 0, result.output
        assert "VALID" in result.output
        assert "MCP_SERVER_ATTACHED:filesystem" in result.output

    def test_json_output_is_a_list_of_results(self, tmp_path):
        path = _write_config(tmp_path)

        result = CliRunner().invoke(
            cli, ["check-mcp", str(path), "--json-output"]
        )

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert isinstance(payload, list)
        assert payload[0]["is_valid"] is True
        assert payload[0]["capability"] == "MCP_SERVER_ATTACHED:filesystem"

    def test_max_ttl_option_is_forwarded_to_the_scanner(self, tmp_path):
        """--max-ttl must reach the scanner, not be dropped or misrouted."""
        path = _write_config(tmp_path, ttl_seconds=600)

        result = CliRunner().invoke(
            cli, ["check-mcp", str(path), "--max-ttl", "300"]
        )

        assert result.exit_code == 0, result.output
        # TTL 600s over max 300s is a warning, and the attestation is fresh.
        assert "exceeds max 300s" in result.output

    def test_stale_attestation_exits_one(self, tmp_path):
        path = _write_config(tmp_path, ttl_seconds=1, age=600)

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "STALE" in result.output

    def test_missing_config_exits_two_without_traceback(self, tmp_path):
        """click's exists=True check rejects the path — cleanly, exit 2."""
        result = CliRunner().invoke(cli, ["check-mcp", str(tmp_path / "nope.json")])

        assert result.exit_code == 2
        assert "Traceback" not in result.output
        assert "does not exist" in result.output

    def test_invalid_json_reports_error_without_traceback(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not json")

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 2
        assert "invalid JSON" in result.output
        assert "Traceback" not in result.output

    def test_server_without_attestation_is_flagged_not_crashed(self, tmp_path):
        path = _write_config(tmp_path, with_attestation=False)

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "Missing TTL" in result.output
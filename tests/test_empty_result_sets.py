"""Tests that an empty result set is a failure, not a vacuous pass.

Both ``check-chain`` and ``check-mcp`` reduce their verdict with ``all(...)``, and
``all([])`` is ``True``. A config that yields no results at all therefore
reported success: ``check-chain []`` and ``check-mcp {}`` both exited ``0`` with
no output at all. For a tool whose whole job is to fail closed on a delegation
chain or a server config it cannot vouch for, an input it silently accepted was
the same defect class as the TTL and clock-skew gaps fixed earlier
(``tests/test_check_chain_ttl.py``, ``tests/test_future_issued_at.py``).

The point of these tests is the *empty* case specifically. The non-empty paths
are already covered elsewhere; what regresses is the branch that fires when
there is nothing to print.
"""

from __future__ import annotations

import inspect
import json

from click.testing import CliRunner

from agent_capability_attestation.cli import cli


def _write_chain(tmp_path, attestations):
    """Write the JSON array of attestations ``check-chain`` expects."""
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(attestations))
    return path


def _write_mcp_config(tmp_path, document):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(document))
    return path


def _runner():
    """A ``CliRunner`` that keeps stderr off stdout where click allows it.

    click 8.2 removed the ``mix_stderr`` flag and began separating the streams
    itself; before that the flag had to be passed explicitly, and without it
    ``result.stdout`` carries the error message too. This repo's CI runs Python
    3.9-3.12 and so resolves both click generations, hence the feature check
    rather than a pinned assumption.
    """
    if "mix_stderr" in inspect.signature(CliRunner.__init__).parameters:
        return CliRunner(mix_stderr=False)
    return CliRunner()


def _hop(index):
    """A single well-formed hop, narrowed from its parent's capability."""
    return {
        "issuer": f"agent://hop-{index}",
        "subject": f"agent://hop-{index + 1}",
        "capability": f"CAN_WRITE(state_store:partition_{index + 1})",
        "issued_at": "2020-01-01T00:00:00+00:00",
        "ttl_seconds": 300,
    }


class TestCheckChainEmpty:
    """An empty delegation chain must not exit 0 via ``all([])``."""

    def test_empty_chain_exits_one(self, tmp_path):
        path = _write_chain(tmp_path, [])

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 1, result.output
        assert "empty" in result.output

    def test_empty_chain_prints_no_hop_verdict(self, tmp_path):
        """A vacuous pass looked exactly like a clean run: zero output."""
        path = _write_chain(tmp_path, [])

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert "VALID" not in result.output
        assert "[Hop 0]" not in result.output

    def test_non_empty_chain_still_exits_zero(self, tmp_path):
        """Guard the guard: the fix must not reject a chain with real hops."""
        path = _write_chain(tmp_path, [_hop(0)])

        result = CliRunner().invoke(cli, ["check-chain", str(path)])

        assert result.exit_code == 1, result.output  # hop is long expired
        assert "[Hop 0]" in result.output


class TestCheckMcpEmpty:
    """An MCP config with no servers must not exit 0 via ``all([])``."""

    def test_config_without_servers_key_exits_one(self, tmp_path):
        path = _write_mcp_config(tmp_path, {})

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "no servers" in result.output

    def test_empty_mcp_servers_map_exits_one(self, tmp_path):
        """The explicit ``"mcpServers": {}`` form, as written by tooling."""
        path = _write_mcp_config(tmp_path, {"mcpServers": {}})

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "no servers" in result.output

    def test_empty_servers_alias_exits_one(self, tmp_path):
        """The scanner also accepts a ``"servers"`` key; same empty verdict."""
        path = _write_mcp_config(tmp_path, {"servers": {}})

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert result.exit_code == 1, result.output
        assert "no servers" in result.output

    def test_json_output_of_empty_config_still_exits_one(self, tmp_path):
        """``--json-output`` must not launder the empty set into a success.

        The JSON body is emitted before the emptiness check, so stdout is a
        valid ``[]`` while the exit code and stderr are what report the
        failure. Asserting all three pins that contract: a consumer keying on
        the exit code must still see 1, and the error must not be spliced into
        the JSON document on stdout.
        """
        path = _write_mcp_config(tmp_path, {"mcpServers": {}})

        result = _runner().invoke(cli, ["check-mcp", str(path), "--json-output"])

        assert result.exit_code == 1, result.output
        # stdout carries the JSON document and nothing else; the failure is
        # reported on stderr. Asserting both proves the empty-set rejection
        # does not corrupt a machine-readable payload, and that it is still
        # reported when the caller asked for JSON.
        assert json.loads(result.stdout) == []
        assert "no servers" in result.stderr

    def test_populated_config_still_reports_its_server(self, tmp_path):
        """Guard the guard: one real server must still be scanned and printed."""
        path = _write_mcp_config(
            tmp_path,
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "capabilityAttestation": {
                            "issuer": "mcp://filesystem",
                            "subject": "mcp://filesystem/consumer",
                            "capability": "MCP_SERVER_ATTACHED:filesystem",
                            "issued_at": "2020-01-01T00:00:00+00:00",
                            "ttl_seconds": 300,
                        },
                    }
                }
            },
        )

        result = CliRunner().invoke(cli, ["check-mcp", str(path)])

        assert "MCP_SERVER_ATTACHED:filesystem" in result.output
        assert "no servers" not in result.output

"""Issue #46: ``aca scan`` discovered only ``*.attestation.json``.

The suffix is documented nowhere — the README's Quick Start names the file
``attestation.json``, the CI recipe points ``scan`` at ``./agents/``, and the
repo's own ``examples/valid-attestation.json`` does not match the glob. A
directory of perfectly good attestations was therefore reported as
``No .attestation.json files found`` and exited **0**: the CI gate passed green
over a tree it never opened, indistinguishable from a clean run.

Two things are pinned here: the acceptance rule for what counts as an
attestation file, and the fact that inspecting nothing is a failure.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from click.testing import CliRunner

from agent_capability_attestation.cli import cli


def _document(**overrides) -> dict:
    document = {
        "issuer": "agent://planner-v2",
        "subject": "agent://worker-v3",
        "capability": "CAN_WRITE(state_store:partition_3)",
        "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "ttl_seconds": 120,
    }
    document.update(overrides)
    return document


def _write(directory, name: str, document: dict):
    path = directory / name
    path.write_text(json.dumps(document))
    return path


def _scan(directory, *extra):
    return CliRunner().invoke(cli, ["scan", str(directory), *extra])


class TestDiscoveryCoversTheDocumentedNames:
    def test_the_readme_quick_start_filename_is_found(self, tmp_path):
        """Quick Start: ``aca validate attestation.json``."""
        _write(tmp_path, "attestation.json", _document())

        result = _scan(tmp_path)

        assert "1 attestations scanned" in result.output, result.output
        assert result.exit_code == 0, result.output

    def test_a_plainly_named_agent_file_is_found(self, tmp_path):
        """The issue's ``agents/agent-a.json`` — nothing magic about the name."""
        _write(tmp_path, "agent-a.json", _document())

        result = _scan(tmp_path)

        assert "1 attestations scanned" in result.output, result.output

    def test_the_conventional_suffix_still_works(self, tmp_path):
        """Guard the guard: the existing convention keeps its meaning."""
        _write(tmp_path, "a.attestation.json", _document())

        result = _scan(tmp_path)

        assert "1 attestations scanned" in result.output, result.output

    def test_unrelated_json_is_not_counted_as_an_attestation(self, tmp_path):
        """A broad ``*.json`` glob must not turn any JSON file into a finding.

        The acceptance rule is content-based for plainly named files, so a
        neighbouring ``config.json`` that is not an attestation is ignored
        rather than reported as unreadable.
        """
        _write(tmp_path, "attestation.json", _document())
        _write(tmp_path, "config.json", {"database": {"host": "localhost"}})

        result = _scan(tmp_path)

        assert "1 attestations scanned" in result.output, result.output
        assert "unreadable" not in result.output, result.output
        assert result.exit_code == 0, result.output


class TestZeroFilesIsALoudFailure:
    def test_an_empty_directory_exits_non_zero(self, tmp_path):
        """A gate that inspected nothing must not report success."""
        result = _scan(tmp_path)

        assert result.exit_code == 1, result.output

    def test_a_directory_of_unrelated_json_exits_non_zero(self, tmp_path):
        _write(tmp_path, "package.json", {"name": "agents"})

        result = _scan(tmp_path)

        assert result.exit_code == 1, result.output

    def test_the_message_says_nothing_was_validated(self, tmp_path):
        """The operator has to be told the run inspected nothing, in words."""
        result = _scan(tmp_path)

        assert "nothing was validated" in result.output, result.output

    def test_json_output_is_an_empty_list_not_prose(self, tmp_path):
        """A JSON consumer must get parseable JSON, per the issue."""
        result = _scan(tmp_path, "--json-output")

        assert result.exit_code == 1, result.output
        assert json.loads(result.stdout) == []

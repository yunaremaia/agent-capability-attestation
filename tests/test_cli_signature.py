"""Regression tests for issue #15 at the CLI boundary.

``validate()`` enforcing the signature is only half the fix: the CLI is how
operators actually run this tool, and before the fix every command printed
``✓ VALID`` and exited ``0`` for a forged attestation. These tests pin the CLI
contract:

* ``--public-key-file`` supplies the trusted Ed25519 key;
* a forged or unverifiable attestation exits ``1`` and says so;
* an unsigned attestation is never printed as a bare ``✓ VALID`` — its
  unverified state is always visible;
* ``--require-signature`` makes unsigned a hard failure;
* ``scan``, ``check-chain`` and ``check-mcp`` inherit the same enforcement.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_capability_attestation.cli import cli

ISSUER = "agent://planner-v2"


def _key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def _key_hex(key: ed25519.Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _signed_body(attestation) -> bytes:
    body = {k: v for k, v in attestation.to_dict().items() if k != "signature"}
    return json.dumps(body).encode()


def _attestation(**overrides):
    from agent_capability_attestation.models import Attestation

    fields = {
        "issuer": ISSUER,
        "subject": "agent://worker-v3",
        "capability": "CAN_READ(db:orders)",
        "issued_at": datetime.now(timezone.utc) - timedelta(seconds=5),
        "ttl_seconds": 120,
        "provenance": [ISSUER],
    }
    fields.update(overrides)
    return Attestation(**fields)


def _sign(attestation, key):
    attestation.signature = key.sign(_signed_body(attestation)).hex()
    return attestation


def _write_attestation(tmp_path, attestation, name="attestation.json"):
    path = tmp_path / name
    path.write_text(json.dumps(attestation.to_dict(), indent=2))
    return path


def _write_key(tmp_path, key, name="pubkey.hex"):
    path = tmp_path / name
    path.write_text(_key_hex(key) + "\n")
    return path


def _run(*args):
    return CliRunner().invoke(cli, list(args))


class TestValidateCommand:
    def test_forged_capability_exits_one_with_a_trusted_key(self, tmp_path):
        key = _key()
        attestation = _sign(_attestation(), key)
        attestation.capability = "CAN_ADMIN(db:orders)"  # attacker rewrites the file
        path = _write_attestation(tmp_path, attestation)
        keyfile = _write_key(tmp_path, key)

        result = _run("validate", str(path), "--public-key-file", str(keyfile))

        assert result.exit_code == 1, result.output
        assert "Signature does not match" in result.output
        assert "✓ VALID" not in result.output

    def test_honest_signature_exits_zero_and_reports_verified(self, tmp_path):
        key = _key()
        path = _write_attestation(tmp_path, _sign(_attestation(), key))
        keyfile = _write_key(tmp_path, key)

        result = _run("validate", str(path), "--public-key-file", str(keyfile))

        assert result.exit_code == 0, result.output
        assert "✓ VALID" in result.output
        assert "signature: VERIFIED" in result.output

    def test_signed_attestation_without_a_key_file_is_rejected(self, tmp_path):
        """The signature claims authority nobody has checked — fail closed."""
        key = _key()
        path = _write_attestation(tmp_path, _sign(_attestation(), key))

        result = _run("validate", str(path))

        assert result.exit_code == 1, result.output
        assert "No trusted public key" in result.output

    def test_unsigned_is_never_a_bare_valid(self, tmp_path):
        path = _write_attestation(tmp_path, _attestation())

        result = _run("validate", str(path))

        assert result.exit_code == 0, result.output
        assert "NOT VERIFIED" in result.output
        assert "signature: UNSIGNED" in result.output

    def test_require_signature_rejects_an_unsigned_attestation(self, tmp_path):
        path = _write_attestation(tmp_path, _attestation())

        result = _run("validate", str(path), "--require-signature")

        assert result.exit_code == 1, result.output
        assert "Unsigned attestation" in result.output

    def test_require_signature_still_accepts_a_verified_one(self, tmp_path):
        key = _key()
        path = _write_attestation(tmp_path, _sign(_attestation(), key))
        keyfile = _write_key(tmp_path, key)

        result = _run(
            "validate",
            str(path),
            "--public-key-file",
            str(keyfile),
            "--require-signature",
        )

        assert result.exit_code == 0, result.output

    def test_json_output_exposes_the_signature_status(self, tmp_path):
        forged = _sign(_attestation(), _key())
        forged.capability = "CAN_ADMIN(db:orders)"
        path = _write_attestation(tmp_path, forged)

        result = _run("validate", str(path), "--json-output")

        payload = json.loads(result.output)
        assert payload["signature_status"] == "unverified"
        assert payload["is_valid"] is False

    def test_json_output_reports_unsigned_as_unsigned(self, tmp_path):
        path = _write_attestation(tmp_path, _attestation())

        result = _run("validate", str(path), "--json-output")

        payload = json.loads(result.output)
        assert payload["signature_status"] == "unsigned"
        assert payload["is_valid"] is True

    def test_unusable_key_file_exits_two_without_a_traceback(self, tmp_path):
        path = _write_attestation(tmp_path, _attestation())
        bad = tmp_path / "bad.hex"
        bad.write_text("not-a-key\n")

        result = _run("validate", str(path), "--public-key-file", str(bad))

        assert result.exit_code == 2
        assert "Traceback" not in result.output
        assert "public key" in result.output.lower()

    def test_truncated_key_file_exits_two(self, tmp_path):
        path = _write_attestation(tmp_path, _attestation())
        short = tmp_path / "short.hex"
        short.write_text("aabb\n")

        result = _run("validate", str(path), "--public-key-file", str(short))

        assert result.exit_code == 2
        assert "Traceback" not in result.output


class TestScanCommand:
    def test_forged_attestation_in_a_directory_is_reported_and_fails_the_gate(
        self, tmp_path
    ):
        key = _key()
        forged = _sign(_attestation(), key)
        forged.capability = "CAN_ADMIN(db:orders)"
        _write_attestation(tmp_path, forged, name="forged.attestation.json")
        keyfile = _write_key(tmp_path, key)

        result = _run(
            "scan",
            str(tmp_path),
            "--public-key-file",
            str(keyfile),
            "--fail-on-stale",
        )

        assert "Signature does not match" in result.output
        assert result.exit_code == 1, result.output

    def test_unsigned_attestation_is_labelled_in_a_scan(self, tmp_path):
        _write_attestation(tmp_path, _attestation(), name="a.attestation.json")

        result = _run("scan", str(tmp_path))

        assert "signature: UNSIGNED" in result.output


class TestCheckChainCommand:
    def test_forged_hop_exits_one(self, tmp_path):
        key = _key()
        forged = _sign(_attestation(), key)
        forged.capability = "CAN_WRITE(db:orders)"  # escalation inside the chain
        path = tmp_path / "chain.json"
        path.write_text(json.dumps([forged.to_dict()]))
        keyfile = _write_key(tmp_path, key)

        result = _run("check-chain", str(path), "--public-key-file", str(keyfile))

        assert result.exit_code == 1, result.output
        assert "Signature does not match" in result.output

    def test_honest_chain_exits_zero(self, tmp_path):
        key = _key()
        path = tmp_path / "chain.json"
        path.write_text(json.dumps([_sign(_attestation(), key).to_dict()]))
        keyfile = _write_key(tmp_path, key)

        result = _run("check-chain", str(path), "--public-key-file", str(keyfile))

        assert result.exit_code == 0, result.output
        assert "signature: VERIFIED" in result.output

    def test_unsigned_hop_is_labelled(self, tmp_path):
        path = tmp_path / "chain.json"
        path.write_text(json.dumps([_attestation().to_dict()]))

        result = _run("check-chain", str(path))

        assert "signature: UNSIGNED" in result.output


class TestCheckMcpCommand:
    def _config(self, tmp_path, attestation):
        path = tmp_path / "mcp.json"
        path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "filesystem": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                            "capabilityAttestation": attestation.to_dict(),
                        }
                    }
                }
            )
        )
        return path

    def test_forged_attestation_in_an_mcp_config_exits_one(self, tmp_path):
        key = _key()
        forged = _sign(_attestation(issuer="mcp://filesystem"), key)
        forged.capability = "CAN_ADMIN(db:orders)"
        path = self._config(tmp_path, forged)
        keyfile = _write_key(tmp_path, key)

        result = _run("check-mcp", str(path), "--public-key-file", str(keyfile))

        assert result.exit_code == 1, result.output
        assert "Signature does not match" in result.output

    def test_signed_config_without_a_key_file_is_rejected(self, tmp_path):
        key = _key()
        path = self._config(tmp_path, _sign(_attestation(issuer="mcp://filesystem"), key))

        result = _run("check-mcp", str(path))

        assert result.exit_code == 1, result.output
        assert "No trusted public key" in result.output

    def test_unsigned_mcp_attestation_is_labelled(self, tmp_path):
        path = self._config(tmp_path, _attestation(issuer="mcp://filesystem"))

        result = _run("check-mcp", str(path))

        assert result.exit_code == 0, result.output
        assert "signature: UNSIGNED" in result.output
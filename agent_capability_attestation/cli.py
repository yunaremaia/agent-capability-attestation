"""CLI for agent-capability-attestation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from cryptography.hazmat.primitives.asymmetric import ed25519

from .mcp_scanner import check_mcp as scan_mcp_config
from .models import (
    ANY_ISSUER,
    DEFAULT_MAX_SKEW_SECONDS,
    SIGNATURE_UNSIGNED,
    SIGNATURE_UNVERIFIED,
    SIGNATURE_VERIFIED,
    Attestation,
    AttestationValidator,
    DelegationChain,
    ValidationResult,
)
from . import __version__

SKEW_HELP = (
    "Tolerance for clock drift between issuer and validator, in seconds. "
    f"An issued_at further in the future than this is rejected as forged "
    f"(default: {DEFAULT_MAX_SKEW_SECONDS})"
)


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Validate agent capability attestations — detect stale delegation chains."""


# Shared signature options. A signed attestation is only trustworthy if its
# signature is checked against a key the operator actually trusts, so every
# command that validates an attestation accepts the same two knobs.
_TRUST_OPTIONS = [
    click.option(
        "--public-key-file",
        type=click.Path(exists=True, dir_okay=False),
        default=None,
        help=(
            "File holding the issuer's Ed25519 public key as 64 hex characters. "
            "The key is trusted for any issuer it is presented against."
        ),
    ),
    click.option(
        "--require-signature",
        is_flag=True,
        help="Reject attestations that carry no signature (fail closed)",
    ),
]


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds (default: 300)")
@click.option(
    "--max-skew-seconds",
    default=DEFAULT_MAX_SKEW_SECONDS,
    type=int,
    help=SKEW_HELP,
)
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def validate(
    file: str,
    max_ttl: int,
    max_skew_seconds: int,
    json_output: bool,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Validate a single attestation file."""
    data = _load_json(file)
    attestation = Attestation.from_dict(data)

    validator = _build_validator(
        max_ttl, max_skew_seconds, public_key_file, require_signature
    )
    result = validator.validate(attestation)

    if json_output:
        _output_json(result)
    else:
        _print_result(result)

    sys.exit(0 if result.is_valid else 1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option(
    "--max-skew-seconds",
    default=DEFAULT_MAX_SKEW_SECONDS,
    type=int,
    help=SKEW_HELP,
)
@click.option("--fail-on-stale", is_flag=True, help="Exit 1 if any attestation is stale")
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def scan(
    directory: str,
    max_ttl: int,
    max_skew_seconds: int,
    fail_on_stale: bool,
    json_output: bool,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Scan a directory for attestation files and validate them all."""
    dir_path = Path(directory)
    attestation_files = sorted(dir_path.glob("**/*.attestation.json"))

    if not attestation_files:
        click.echo(f"No .attestation.json files found in {directory}")
        sys.exit(0)

    results = []
    all_valid = True

    validator = _build_validator(
        max_ttl, max_skew_seconds, public_key_file, require_signature
    )

    for f in attestation_files:
        try:
            data = json.loads(f.read_text())
            att = Attestation.from_dict(data)
            result = validator.validate(att)
            results.append(result)
            if not result.is_valid:
                all_valid = False
        except Exception as e:
            click.echo(f"ERROR reading {f}: {e}", err=True)
            all_valid = False

    if json_output:
        click.echo(json.dumps([_result_to_dict(r) for r in results], indent=2))
    else:
        for result in results:
            _print_result(result)
        click.echo(
            f"\n{len(results)} attestations scanned, "
            f"{sum(1 for r in results if not r.is_valid)} stale"
        )

    if fail_on_stale and not all_valid:
        sys.exit(1)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option(
    "--max-skew-seconds",
    default=DEFAULT_MAX_SKEW_SECONDS,
    type=int,
    help=SKEW_HELP,
)
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def check_chain(
    file: str,
    max_ttl: int,
    max_skew_seconds: int,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Validate a delegation chain (array of attestations in order)."""
    data = _load_json(file)

    if not isinstance(data, list):
        click.echo("ERROR: delegation chain must be a JSON array", err=True)
        sys.exit(2)

    attestations = [Attestation.from_dict(item) for item in data]
    chain = DelegationChain(attestations=attestations)
    validator = _build_validator(
        max_ttl, max_skew_seconds, public_key_file, require_signature
    )

    results = chain.validate_monotonicity(validator=validator)
    if not results:
        click.echo("ERROR: delegation chain is empty — nothing to validate", err=True)
        sys.exit(1)
    all_valid = all(r.is_valid for r in results)

    for i, result in enumerate(results):
        sys.stdout.write(f"[Hop {i}] ")
        _print_result(result)

    sys.exit(0 if all_valid else 1)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option(
    "--max-skew-seconds",
    default=DEFAULT_MAX_SKEW_SECONDS,
    type=int,
    help=SKEW_HELP,
)
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def check_mcp(
    file: str,
    max_ttl: int,
    max_skew_seconds: int,
    json_output: bool,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Scan an MCP server configuration for capability attestations."""
    trusted_keys = _load_trusted_keys(public_key_file)
    try:
        results = scan_mcp_config(
            file,
            max_ttl=max_ttl,
            max_skew_seconds=max_skew_seconds,
            trusted_keys=trusted_keys,
            require_signature=require_signature,
        )
    except FileNotFoundError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    except json.JSONDecodeError as e:
        click.echo(f"ERROR: invalid JSON: {e}", err=True)
        sys.exit(2)

    if json_output:
        click.echo(json.dumps([_result_to_dict(r) for r in results], indent=2))
    else:
        for result in results:
            _print_result(result)

    if not results:
        click.echo("ERROR: no servers found in MCP config — nothing to validate", err=True)
        sys.exit(1)
    all_valid = all(r.is_valid for r in results)
    if not all_valid:
        sys.exit(1)


def _load_trusted_keys(public_key_file: Optional[str]) -> dict:
    """Load the trusted public key from a hex file, or {} when not given.

    The file holds the raw 32-byte Ed25519 public key as 64 hex characters
    (optionally ``ed25519:``-prefixed), which is what
    ``Ed25519PublicKey.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()``
    produces. Anything else is an operator mistake and exits 2 rather than
    silently downgrading to "no trusted keys".
    """
    if not public_key_file:
        return {}

    raw = Path(public_key_file).read_text().strip()
    if raw.startswith("ed25519:"):
        raw = raw[len("ed25519:"):]
    try:
        key_bytes = bytes.fromhex(raw)
    except ValueError:
        click.echo(
            f"ERROR: {public_key_file} is not a hex-encoded Ed25519 public key",
            err=True,
        )
        sys.exit(2)

    if len(key_bytes) != 32:
        click.echo(
            f"ERROR: {public_key_file} holds {len(key_bytes)} bytes; "
            "an Ed25519 public key is 32 bytes (64 hex characters)",
            err=True,
        )
        sys.exit(2)

    return {ANY_ISSUER: ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)}


def _build_validator(
    max_ttl: int,
    max_skew_seconds: int,
    public_key_file: Optional[str],
    require_signature: bool,
) -> AttestationValidator:
    """Construct a validator wired to the operator's trust configuration."""
    return AttestationValidator(
        max_ttl=max_ttl,
        max_skew_seconds=max_skew_seconds,
        trusted_keys=_load_trusted_keys(public_key_file),
        require_signature=require_signature,
    )


def _load_json(path: str) -> dict:
    """Load and parse a JSON file."""
    try:
        return json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        click.echo(f"ERROR: invalid JSON in {path}: {e}", err=True)
        sys.exit(2)


def _output_json(result: ValidationResult) -> None:
    """Output a validation result as JSON."""
    click.echo(json.dumps(_result_to_dict(result), indent=2))


def _result_to_dict(result: ValidationResult) -> dict:
    """Convert a ValidationResult to a JSON-serializable dict."""
    return {
        "issuer": result.attestation.issuer,
        "subject": result.attestation.subject,
        "capability": result.attestation.capability,
        "is_valid": result.is_valid,
        "is_stale": result.is_stale,
        "stale_by_seconds": result.stale_by_seconds,
        "signature_status": result.signature_status,
        "errors": result.errors,
        "warnings": result.warnings,
    }


_SIGNATURE_LABELS = {
    SIGNATURE_VERIFIED: "VERIFIED",
    SIGNATURE_UNVERIFIED: "NOT VERIFIED",
    SIGNATURE_UNSIGNED: "UNSIGNED — NOT VERIFIED",
}


def _print_result(result: ValidationResult) -> None:
    """Print a validation result to stdout.

    The signature verdict is always printed, so an attestation nobody could
    verify is never reported as a bare "✓ VALID" — the operator reading the
    output (or the CI log) can see exactly what was and was not checked.
    """
    att = result.attestation
    if result.is_valid:
        status = "✓ VALID"
    elif result.is_stale:
        status = "✗ STALE"
    else:
        status = "✗ INVALID"
    click.echo(
        f"{status} | {att.issuer} → {att.subject} | "
        f"{att.capability} (TTL {att.ttl_seconds}s)"
    )
    label = _SIGNATURE_LABELS.get(result.signature_status)
    if label:
        click.echo(f"    signature: {label}")
    if result.stale_by_seconds:
        click.echo(f"    stale by {result.stale_by_seconds:.1f}s")
    for err in result.errors:
        click.echo(f"    ERROR: {err}")
    for warn in result.warnings:
        click.echo(f"    WARN: {warn}")


if __name__ == "__main__":
    cli()

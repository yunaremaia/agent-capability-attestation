"""CLI for agent-capability-attestation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click

from .mcp_scanner import check_mcp
from .models import Attestation, AttestationValidator, DelegationChain, ValidationResult
from . import __version__


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """Validate agent capability attestations — detect stale delegation chains."""


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds (default: 300)")
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
def validate(file: str, max_ttl: int, json_output: bool) -> None:
    """Validate a single attestation file."""
    data = _load_json(file)
    attestation = Attestation.from_dict(data)

    validator = AttestationValidator(max_ttl=max_ttl)
    result = validator.validate(attestation)

    if json_output:
        _output_json(result)
    else:
        _print_result(result)

    sys.exit(0 if result.is_valid else 1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option("--fail-on-stale", is_flag=True, help="Exit 1 if any attestation is stale")
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
def scan(directory: str, max_ttl: int, fail_on_stale: bool, json_output: bool) -> None:
    """Scan a directory for attestation files and validate them all."""
    dir_path = Path(directory)
    attestation_files = sorted(dir_path.glob("**/*.attestation.json"))

    if not attestation_files:
        click.echo(f"No .attestation.json files found in {directory}")
        sys.exit(0)

    results = []
    all_valid = True

    validator = AttestationValidator(max_ttl=max_ttl)

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
def check_chain(file: str, max_ttl: int) -> None:
    """Validate a delegation chain (array of attestations in order)."""
    data = _load_json(file)

    if not isinstance(data, list):
        click.echo("ERROR: delegation chain must be a JSON array", err=True)
        sys.exit(2)

    attestations = [Attestation.from_dict(item) for item in data]
    chain = DelegationChain(attestations=attestations)
    validator = AttestationValidator(max_ttl=max_ttl)

    results = chain.validate_monotonicity()
    all_valid = all(r.is_valid for r in results)

    for i, result in enumerate(results):
        sys.stdout.write(f"[Hop {i}] ")
        _print_result(result)

    sys.exit(0 if all_valid else 1)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
def check_mcp(file: str, max_ttl: int, json_output: bool) -> None:
    """Scan an MCP server configuration for capability attestations."""
    try:
        results = check_mcp(file, max_ttl=max_ttl)
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

    all_valid = all(r.is_valid for r in results)
    if not all_valid:
        sys.exit(1)


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
        "errors": result.errors,
        "warnings": result.warnings,
    }


def _print_result(result: ValidationResult) -> None:
    """Print a validation result to stdout."""
    att = result.attestation
    status = "✓ VALID" if result.is_valid else "✗ STALE"
    click.echo(
        f"{status} | {att.issuer} → {att.subject} | "
        f"{att.capability} (TTL {att.ttl_seconds}s)"
    )
    if result.stale_by_seconds:
        click.echo(f"    stale by {result.stale_by_seconds:.1f}s")
    for err in result.errors:
        click.echo(f"    ERROR: {err}")
    for warn in result.warnings:
        click.echo(f"    WARN: {warn}")


if __name__ == "__main__":
    cli()

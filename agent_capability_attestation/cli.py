"""CLI for agent-capability-attestation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import click
from cryptography.hazmat.primitives.asymmetric import ed25519

from .mcp_scanner import McpConfigError
from .mcp_scanner import check_mcp as scan_mcp_config
from .models import (
    ANY_ISSUER,
    DEFAULT_MAX_SKEW_SECONDS,
    REQUIRED_FIELDS,
    SIGNATURE_UNCHECKED,
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

# ``--max-ttl`` is a policy ceiling, so exceeding it is an error by default
# (#18). This opt-in restores the old advisory behaviour for an operator who
# wants it — deliberately, rather than as the only thing the flag does.
_WARN_ON_EXCEEDING_MAX_TTL = click.option(
    "--warn-on-exceeding-max-ttl",
    is_flag=True,
    help=(
        "Report an attestation that can outlive --max-ttl as a warning "
        "instead of an error. Off by default: --max-ttl is a policy "
        "ceiling, so a life beyond it is rejected."
    ),
)


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
@_WARN_ON_EXCEEDING_MAX_TTL
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def validate(
    file: str,
    max_ttl: int,
    max_skew_seconds: int,
    json_output: bool,
    warn_on_exceeding_max_ttl: bool,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Validate a single attestation file."""
    data = _load_json(file)
    attestation = _parse_attestation(data)

    validator = _build_validator(
        max_ttl,
        max_skew_seconds,
        public_key_file,
        require_signature,
        warn_on_exceeding_max_ttl,
    )
    result = validator.validate(attestation)

    if json_output:
        _output_json(result)
    else:
        _print_result(result)

    sys.exit(0 if result.is_valid else 1)


def _discover_attestations(dir_path: Path) -> list[Path]:
    """Every attestation document under ``dir_path``, at any depth.

    The filename is not the acceptance rule. A file counts when it is a
    ``.json`` file *and* it parses as a JSON object carrying the required
    attestation fields — so ``attestation.json`` (the README's Quick Start
    name), ``agent-a.json`` and ``valid-attestation.json`` are all found, and a
    neighbouring ``config.json`` in the same tree is not mistaken for one.

    The one exception is a file named ``*.attestation.json``: that suffix is an
    explicit claim to be an attestation, so such a file is always returned even
    if it turns out to be malformed — the scan loop reports it as unreadable
    rather than silently skipping it, which is the #30/#44 undercount this
    replaces.
    """
    found: list[Path] = []
    for path in sorted(dir_path.glob("**/*.json")):
        if path.name.endswith(".attestation.json"):
            found.append(path)
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and all(f in data for f in REQUIRED_FIELDS):
            found.append(path)
    return found


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option(
    "--max-skew-seconds",
    default=DEFAULT_MAX_SKEW_SECONDS,
    type=int,
    help=SKEW_HELP,
)
@click.option(
    "--report-only",
    is_flag=True,
    help=(
        "Always exit 0 and report findings on stdout only. Off by default: a "
        "scan fails closed (exit 1) whenever any attestation is invalid."
    ),
)
@click.option(
    "--fail-on-stale",
    is_flag=True,
    help=(
        "Deprecated and redundant: scan now fails closed on any invalid "
        "attestation, not only on stale ones. Accepted for backwards "
        "compatibility."
    ),
)
@click.option("--json-output", "json_output", is_flag=True, help="Output as JSON")
@_WARN_ON_EXCEEDING_MAX_TTL
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def scan(
    directory: str,
    max_ttl: int,
    max_skew_seconds: int,
    report_only: bool,
    fail_on_stale: bool,
    json_output: bool,
    warn_on_exceeding_max_ttl: bool,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Scan a directory for attestation files and validate them all.

    Exits 1 if any attestation is invalid — stale, forged, unverifiable or
    unreadable — so this command can back a CI gate. Pass ``--report-only`` to
    always exit 0 and read the findings from stdout instead.
    """
    if fail_on_stale and report_only:
        click.echo(
            "ERROR: --fail-on-stale and --report-only are mutually exclusive",
            err=True,
        )
        sys.exit(2)

    dir_path = Path(directory)
    attestation_files = _discover_attestations(dir_path)

    if not attestation_files:
        # A gate that opened nothing has not validated anything, so it must not
        # exit 0: `No .attestation.json files found` over a directory of
        # perfectly good attestations named any other way was indistinguishable
        # from a clean run. ``--json-output`` still gets parseable JSON.
        message = (
            f"no attestations found in {directory} — nothing was validated. "
            "Accepted: any *.json file holding an attestation document "
            "(issuer, subject, capability, issued_at), at any depth."
        )
        if json_output:
            click.echo(json.dumps([], indent=2))
        click.echo(f"ERROR: {message}", err=True)
        sys.exit(1)

    results = []
    # Files that could not be read at all (bad JSON, or a malformed attestation
    # payload). They are kept out of ``results`` — there is no verdict to give —
    # but they must not vanish from the readings: the summary count describes
    # the directory, and it used to name only the files it managed to parse.
    unreadable: list[tuple[Path, str]] = []
    all_valid = True

    validator = _build_validator(
        max_ttl,
        max_skew_seconds,
        public_key_file,
        require_signature,
        warn_on_exceeding_max_ttl,
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
            unreadable.append((f, str(e)))
            all_valid = False

    if json_output:
        entries = [_result_to_dict(r) for r in results]
        entries += [_unreadable_to_dict(f, msg) for f, msg in unreadable]
        click.echo(json.dumps(entries, indent=2))
    else:
        for result in results:
            _print_result(result)
        invalid = [r for r in results if not r.is_valid]
        scanned = len(results) + len(unreadable)
        summary = (
            f"\n{scanned} attestations scanned, "
            f"{len(invalid) + len(unreadable)} invalid "
            f"({sum(1 for r in invalid if r.is_stale)} stale)"
        )
        if unreadable:
            summary += f", {len(unreadable)} unreadable"
        click.echo(summary)

    # The default is fail-closed. Before this, --fail-on-stale was the *only*
    # way to make a scan fail: a forged or unverifiable attestation printed
    # `ERROR: ... may be forged` and then exited 0, so a CI gate keyed on the
    # exit status passed a directory full of forged and expired attestations.
    # The flag is kept for one release so the documented CI recipe keeps
    # working, but it is now redundant — --report-only is its explicit
    # opposite, and the two are rejected together above.
    if not all_valid and not report_only:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--max-ttl", default=300, help="Maximum allowed TTL in seconds")
@click.option(
    "--max-skew-seconds",
    default=DEFAULT_MAX_SKEW_SECONDS,
    type=int,
    help=SKEW_HELP,
)
@_WARN_ON_EXCEEDING_MAX_TTL
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def check_chain(
    file: str,
    max_ttl: int,
    max_skew_seconds: int,
    warn_on_exceeding_max_ttl: bool,
    public_key_file: Optional[str],
    require_signature: bool,
) -> None:
    """Validate a delegation chain (array of attestations in order)."""
    data = _load_json(file)

    if not isinstance(data, list):
        click.echo("ERROR: delegation chain must be a JSON array", err=True)
        sys.exit(2)

    # The chain *element* is the level a malformed document hides at: the list
    # itself is checked above, but each item was parsed unchecked, so an element
    # missing a required field escaped as a traceback and exit 1 — the code a
    # genuinely invalid chain uses. Naming the index is what lets an operator
    # find the offending hop.
    attestations = []
    for index, item in enumerate(data):
        try:
            attestations.append(Attestation.from_dict(item))
        except ValueError as e:
            click.echo(f"ERROR: chain[{index}]: {e}", err=True)
            sys.exit(2)

    chain = DelegationChain(attestations=attestations)
    validator = _build_validator(
        max_ttl,
        max_skew_seconds,
        public_key_file,
        require_signature,
        warn_on_exceeding_max_ttl,
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
@_WARN_ON_EXCEEDING_MAX_TTL
@_TRUST_OPTIONS[0]
@_TRUST_OPTIONS[1]
def check_mcp(
    file: str,
    max_ttl: int,
    max_skew_seconds: int,
    json_output: bool,
    warn_on_exceeding_max_ttl: bool,
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
            enforce_max_ttl=not warn_on_exceeding_max_ttl,
        )
    except FileNotFoundError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)
    except json.JSONDecodeError as e:
        click.echo(f"ERROR: invalid JSON: {e}", err=True)
        sys.exit(2)
    except McpConfigError as e:
        click.echo(f"ERROR: {e}", err=True)
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
    warn_on_exceeding_max_ttl: bool = False,
) -> AttestationValidator:
    """Construct a validator wired to the operator's trust configuration."""
    return AttestationValidator(
        max_ttl=max_ttl,
        max_skew_seconds=max_skew_seconds,
        trusted_keys=_load_trusted_keys(public_key_file),
        require_signature=require_signature,
        enforce_max_ttl=not warn_on_exceeding_max_ttl,
    )


def _load_json(path: str) -> dict:
    """Load and parse a JSON file."""
    try:
        return json.loads(Path(path).read_text())
    except json.JSONDecodeError as e:
        click.echo(f"ERROR: invalid JSON in {path}: {e}", err=True)
        sys.exit(2)


def _parse_attestation(data) -> Attestation:
    """Parse one attestation document, reporting a malformed one as exit 2.

    ``Attestation.from_dict`` raises ``ValueError`` for a payload that is not a
    JSON object or that omits a required field. That is a bad *input*, not a
    failing attestation, so it must exit 2 — the code the README documents for
    malformed input — rather than escaping as an unhandled traceback whose exit
    code 1 means "this attestation is invalid".
    """
    try:
        return Attestation.from_dict(data)
    except ValueError as e:
        click.echo(f"ERROR: {e}", err=True)
        sys.exit(2)


def _unreadable_to_dict(path: Path, message: str) -> dict:
    """A scan entry for a file that could not be read at all.

    ``scan --json-output`` used to emit an entry only for the files it managed
    to parse, so a malformed file left no trace in the document and a consumer
    reading it saw a smaller directory than the disk holds. This entry keeps
    the JSON list and the summary count describing the same set of files.
    """
    return {
        "file": str(path),
        "is_valid": False,
        "is_stale": False,
        "stale_by_seconds": None,
        "signature_status": SIGNATURE_UNCHECKED,
        "errors": [message],
        "warnings": [],
        "unreadable": True,
    }


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

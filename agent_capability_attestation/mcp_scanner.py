"""Tool to scan MCP server configurations for capability drift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import (
    DEFAULT_MAX_SKEW_SECONDS,
    STATUS_DRIFTED,
    STATUS_UNATTESTED,
    Attestation,
    AttestationValidator,
    ValidationResult,
    compute_state_hash,
    json_type,
)


class McpConfigError(ValueError):
    """An MCP config is not the nested JSON object the scanner reads.

    ``check_mcp`` walks a config as *document → server collection → server
    entry*. When one of those levels is a JSON array, string, number or null
    the walk escaped as an uncaught ``AttributeError``, which exits 1 — the
    same code a genuine validation failure uses, so a malformed config was
    indistinguishable from a stale one. The CLI maps this error to exit 2,
    which is what its other malformed-input paths already report.
    """


def check_mcp(
    config_path: str,
    max_ttl: int = 300,
    now: Any = None,
    max_skew_seconds: int = DEFAULT_MAX_SKEW_SECONDS,
    trusted_keys: Any = None,
    require_signature: bool = False,
    enforce_max_ttl: bool = True,
) -> list["ValidationResult"]:
    """Scan an MCP server configuration for capability attestations.

    Each server is judged two ways. Its attestation is run through the
    per-attestation validator — TTL, declared expiry, staleness, future-``issued_at``
    skew, signature — and, when the attestation carries a ``state_hash``, the
    server's declared surface (``command``/``args``/``tools``) is hashed and
    compared against it so that a tool schema which changed under a still-fresh
    attestation is reported (:func:`_check_state_drift`).

    Three outcomes are distinct rather than collapsed into "invalid": a server
    that carries **no** attestation is ``STATUS_UNATTESTED`` (``is_stale`` is
    ``None`` — absence is not expiry), a server whose attestation has expired is
    ``STATUS_EXPIRED``, and a server whose declared surface no longer matches its
    attestation is ``STATUS_DRIFTED``. The three need different remediation —
    create an attestation, re-issue one, or investigate what changed — so a
    caller that could not tell them apart could not act on the result.

    ``trusted_keys`` and ``require_signature`` are forwarded to the validator
    so a signature check configured by the caller applies to every attestation
    embedded in the config — without them an MCP attestation could be rewritten
    to claim a wider tool schema and would still be reported VALID.
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"MCP config not found: {config_path}")

    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise McpConfigError(
            f"MCP config must be a JSON object, got {json_type(data)}"
        )
    results = []
    validator = AttestationValidator(
        max_ttl=max_ttl,
        now=now,
        max_skew_seconds=max_skew_seconds,
        trusted_keys=trusted_keys,
        require_signature=require_signature,
        enforce_max_ttl=enforce_max_ttl,
    )

    # MCP configs can list servers under a "mcpServers" or similar key
    servers = data.get("mcpServers", data.get("servers", {}))
    servers_key = "mcpServers" if "mcpServers" in data else "servers"
    if not isinstance(servers, dict):
        raise McpConfigError(
            f'MCP config "{servers_key}" must be a JSON object, '
            f"got {json_type(servers)}"
        )

    for server_name, server_config in servers.items():
        if not isinstance(server_config, dict):
            raise McpConfigError(
                f'MCP server "{server_name}" must be a JSON object, '
                f"got {json_type(server_config)}"
            )
        att_data = server_config.get("capabilityAttestation")
        if att_data is None:
            # No attestation at all — absence, not expiry. This used to route a
            # synthetic ``ttl_seconds=0`` attestation through ``validate``, which
            # lands in the same branch a genuinely expired attestation takes, so
            # an unattested server was reported as ``is_stale=True`` and counted
            # among expired ones (#20). Nothing was examined here, so there is
            # nothing to call stale: the verdict gets its own class and
            # ``is_stale`` is left unset. The marker attestation is kept only so
            # the result still names the server and the capability that went
            # unattested; it is never validated.
            att = Attestation(
                issuer=f"mcp://{server_name}",
                subject=f"mcp://{server_name}/consumer",
                capability=f"MCP_SERVER_ATTACHED:{server_name}",
                issued_at=__import__("datetime").datetime(
                    2020, 1, 1, tzinfo=__import__("datetime").timezone.utc
                ),
                ttl_seconds=0,
                state_hash=None,
            )
            result = ValidationResult(
                attestation=att,
                is_valid=False,
                is_stale=None,
                status=STATUS_UNATTESTED,
            )
            result.add_error(
                f'No "capabilityAttestation" present for MCP server '
                f"{server_name!r} — nothing was examined (fail closed)"
            )
            results.append(result)
            continue

        try:
            att = Attestation.from_dict(att_data)
        except ValueError as e:
            # The last level of the walk is the one that carries
            # attacker-supplied content, and it was the one level left
            # unguarded: a malformed ``capabilityAttestation`` escaped as an
            # uncaught ``KeyError`` / ``TypeError`` and the process exited 1 —
            # the code a stale attestation uses — while the container levels
            # above it already reported exit 2. Raising the typed error keeps
            # the two apart, and it is a ``ValueError`` subclass so a caller
            # that already catches ``ValueError`` still works.
            raise McpConfigError(
                f'MCP server "{server_name}" has a malformed '
                f'"capabilityAttestation": {e}'
            ) from e
        result = validator.validate(att)
        _check_state_drift(server_config, result)
        results.append(result)

    return results


def _check_state_drift(server_config: dict, result: ValidationResult) -> None:
    """Compare the server's declared surface against the attestation's hash.

    The module docstring and the README both promise drift detection, but the
    scanner only ever ran the TTL/signature check, so a server whose ``command``
    or ``args`` were widened under a still-fresh attestation — its tool surface
    changed while the receipt stayed put — reported ``✓ VALID`` with no warning
    at all (#20). ``state_hash`` was never read by this module.

    The digest is computed over the server's declared surface with
    :func:`~agent_capability_attestation.models.compute_state_hash`, the same
    canonical serialization the signature is computed over, so the comparison
    cannot drift from the rest of the package's hashing. On a mismatch the hop is
    reported as ``STATUS_DRIFTED`` — the attestation is well formed; it is the
    thing it was issued for that moved.

    When the attestation carries no ``state_hash`` there is nothing to compare
    against, so the check is surfaced as a warning rather than silently skipped:
    a receipt that cannot detect drift is a fact the operator should see, and
    an empty digest is not the same as a matching one.
    """
    att = result.attestation
    declared = {
        "command": server_config.get("command"),
        "args": server_config.get("args", []),
        "tools": server_config.get("tools", []),
    }
    if not att.state_hash:
        result.add_warning(
            "no state_hash in attestation — tool-schema drift cannot be checked"
        )
        return

    actual = compute_state_hash(declared)
    if actual != att.state_hash:
        result.add_error(
            f"tool schema drift: the attestation was issued for "
            f"{att.state_hash}, but the server's declared surface "
            f"(command/args/tools) hashes to {actual}"
        )
        result.status = STATUS_DRIFTED

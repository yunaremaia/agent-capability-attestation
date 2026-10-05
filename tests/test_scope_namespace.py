"""Tests that ``check-chain`` compares a hop's scope against its parent's namespace.

The scope-subset check took only the *last* ``:``-segment of each capability and
normalised it with ``str.strip("()")``, which removes a *character set* rather
than a matched pair. So the documented capability form ``CAN_WRITE(store:*)``
collapsed to a bare ``*`` and the ``parent_parts == {"*"}`` short-circuit that
followed answered ``True`` for any child at all — including one in a different
resource namespace. ``CAN_WRITE(store:*)`` -> ``CAN_WRITE(other:admin)`` is a
capability *expansion*: the grant moves off ``store`` onto ``other`` — and
``check-chain`` printed ``✓ VALID`` for both hops and exited ``0``.

The namespace is now compared along with the segment, so a wildcard grants only
inside the namespace that carries it. The positive rows are the guard against an
over-broad fix: a genuinely narrowed child must still pass.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import _scope_is_subscope


def _hop(subject: str, capability: str, issued_at: str) -> dict:
    """One live hop of a delegation chain."""
    return {
        "issuer": "agent://planner",
        "subject": subject,
        "capability": capability,
        "issued_at": issued_at,
        "ttl_seconds": 120,
    }


def _chain_file(tmp_path, parent: str, child: str, name="chain.json"):
    """Write a two-hop chain delegating ``child`` out of ``parent``."""
    issued = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    path = tmp_path / name
    path.write_text(
        json.dumps(
            [
                _hop("agent://worker", parent, issued),
                _hop("agent://mallory", child, issued),
            ]
        )
    )
    return path


ESCALATIONS = [
    # The reported defect: a different resource namespace behind a wildcard.
    ("CAN_WRITE(store:*)", "CAN_WRITE(other:admin)"),
    # Same hole, arbitrary namespace on both sides.
    ("CAN_WRITE(a:*)", "CAN_WRITE(other:admin)"),
    # A bare wildcard segment must not leak either.
    ("db:*", "db2:drop"),
    # A non-wildcard parent already rejected these; keep it that way.
    ("CAN_WRITE(store:read)", "CAN_WRITE(other:admin)"),
    # Wildcards do not grant a different verb.
    ("CAN_WRITE(store:*)", "CAN_ADMIN(store:x)"),
    # Nor a different verb under a bare wildcard.
    ("CAN_WRITE(*)", "CAN_DELETE_ALL(prod)"),
]


NARROWINGS = [
    ("CAN_WRITE(store:*)", "CAN_WRITE(store:partition_1)"),
    ("CAN_WRITE(store:*)", "CAN_WRITE(store:read)"),
    ("CAN_WRITE(*)", "CAN_WRITE(store:admin)"),
    ("CAN_WRITE(store:read,write)", "CAN_WRITE(store:write)"),
    ("db:*", "db:read"),
    ("CAN_WRITE(root)", "CAN_WRITE(root)"),
    ("X", "X"),
]


@pytest.mark.parametrize("parent,child", ESCALATIONS)
def test_an_expansion_is_not_a_subscope(parent, child):
    """A hop that leaves the parent's namespace is an expansion."""
    assert not _scope_is_subscope(parent, child)


@pytest.mark.parametrize("parent,child", NARROWINGS)
def test_a_narrowing_is_still_a_subscope(parent, child):
    """The namespace check must not reject a legitimately narrowed child."""
    assert _scope_is_subscope(parent, child)


def test_check_chain_exits_one_on_a_namespace_escape(tmp_path):
    """The CLI verdict, not just the helper: an escape hop is invalid."""
    path = _chain_file(tmp_path, "CAN_WRITE(store:*)", "CAN_WRITE(other:admin)")

    result = CliRunner().invoke(cli, ["check-chain", str(path)])

    assert result.exit_code == 1, result.output
    assert "capability expanded" in result.output


def test_check_chain_exits_zero_on_a_narrowed_hop(tmp_path):
    """Positive control: the documented wildcard -> partition narrowing passes."""
    path = _chain_file(
        tmp_path, "CAN_WRITE(store:*)", "CAN_WRITE(store:partition_1)", "narrow.json"
    )

    result = CliRunner().invoke(cli, ["check-chain", str(path)])

    assert result.exit_code == 0, result.output
    assert "capability expanded" not in result.output
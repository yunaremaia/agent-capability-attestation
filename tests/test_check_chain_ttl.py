"""Tests that ``check-chain`` enforces TTL, expiry and clock skew per hop.

``check-chain`` builds an :class:`AttestationValidator` from the operator's
``--max-ttl`` / ``--max-skew-seconds`` and hands it to
``DelegationChain.validate_monotonicity()``, which applied only the *signature*
check to each hop. The rest of the validator — the TTL floor, the declared
``expires_at``, the staleness comparison and the future-``issued_at`` skew
bound — was never invoked on this path.

``validate_monotonicity()`` compares each hop's capability against its parent's
and nothing else, so a chain is "monotonic" no matter how old, how forged or
how unbounded its attestations are. The result was a fail-open: ``check-chain``
exited **0** and printed ``✓ VALID`` for a chain whose every hop had expired
thirty days ago, for one dated eighty years in the future, and for one carrying
no TTL at all — while ``validate`` on the very same file exited **1**.

This is the same defect class as #22 (declared ``expires_at`` ignored), #23
(naive timestamps crashed the validator) and #24 (future-dated ``issued_at``
validated forever): those hardened ``AttestationValidator.validate()`` on the
single-attestation path and left the delegation-chain path unhardened.

The fix runs the validator per hop and merges its verdict into the
monotonicity result, so one ``ValidationResult`` per hop carries both.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli
from agent_capability_attestation.models import (
    DEFAULT_MAX_SKEW_SECONDS,
    Attestation,
    AttestationValidator,
    DelegationChain,
)

#: A narrowing parent scope, so monotonicity passes for every chain built here.
PARENT_SCOPE = "CAN_WRITE(store:*)"
#: A strict sub-scope of ``PARENT_SCOPE``.
CHILD_SCOPE = "CAN_WRITE(store:partition_1)"


def _at(**kwargs) -> str:
    """An ISO timestamp ``kwargs`` of seconds from now (positive = future)."""
    offset = timedelta(seconds=kwargs.pop("offset_seconds", 0))
    assert not kwargs, f"unexpected keyword arguments: {kwargs}"
    return (datetime.now(timezone.utc) + offset).isoformat()


def _hop(subject: str, capability: str, issued_at: str, **extra) -> dict:
    """One hop of a delegation chain, with a TTL of 60s unless overridden."""
    data = {
        "issuer": "agent://planner-v2",
        "subject": subject,
        "capability": capability,
        "issued_at": issued_at,
        "ttl_seconds": 60,
    }
    data.update(extra)
    return data


def _chain(hops):
    """Wrap ``hops`` as the JSON document ``check-chain`` expects."""
    return hops


def _fresh_chain(**hop_extra) -> list:
    """A two-hop chain whose hops are both live and narrowing (the happy path)."""
    issued = _at(offset_seconds=-10)
    return _chain(
        [
            _hop("agent://orchestrator", PARENT_SCOPE, issued, **hop_extra),
            _hop("agent://worker", CHILD_SCOPE, issued, **hop_extra),
        ]
    )


def _write(tmp_path, chain, name="chain.json"):
    path = tmp_path / name
    path.write_text(json.dumps(chain))
    return path


def _check_chain(path, *args):
    return CliRunner().invoke(cli, ["check-chain", str(path), *args])


class TestCheckChainFailsClosedOnTime:
    """The headline defect: hostile timestamps exited 0 through ``check-chain``."""

    def test_a_chain_of_long_expired_attestations_exits_one(self, tmp_path):
        """Both hops expired 30 days ago; monotonicity still passes."""
        issued = _at(offset_seconds=-30 * 24 * 3600)
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, issued),
                    _hop("agent://worker", CHILD_SCOPE, issued),
                ]
            ),
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        assert "Traceback" not in result.output

    def test_the_hop_line_says_stale_not_valid(self, tmp_path):
        """A per-hop verdict must never read ``✓ VALID`` for an expired hop."""
        issued = _at(offset_seconds=-30 * 24 * 3600)
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, issued),
                    _hop("agent://worker", CHILD_SCOPE, issued),
                ]
            ),
        )

        output = _check_chain(path).output

        assert "✓ VALID" not in output
        assert "✗ STALE" in output
        assert "stale by" in output

    def test_a_future_dated_chain_exits_one(self, tmp_path):
        """A chain dated 80 years ahead is an unbounded-validity primitive."""
        issued = _at(offset_seconds=365 * 24 * 3600 * 80)
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, issued),
                    _hop("agent://worker", CHILD_SCOPE, issued),
                ]
            ),
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        assert "in the future" in result.output

    def test_a_chain_with_no_ttl_exits_one(self, tmp_path):
        """``ttl_seconds: 0`` is missing TTL, which ``validate`` treats as expired."""
        path = _write(tmp_path, _fresh_chain(ttl_seconds=0))

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        assert "Missing TTL" in result.output

    def test_a_declared_expiry_in_the_past_is_honoured(self, tmp_path):
        """A declared ``expires_at`` beats a generous ``ttl_seconds`` (#22)."""
        path = _write(
            tmp_path,
            _fresh_chain(
                expires_at=_at(offset_seconds=-3600), ttl_seconds=31536000
            ),
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output

    def test_only_the_expired_hop_is_reported_invalid(self, tmp_path):
        """A live parent does not launder a dead child."""
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, _at(offset_seconds=-5)),
                    _hop(
                        "agent://worker",
                        CHILD_SCOPE,
                        _at(offset_seconds=-30 * 24 * 3600),
                    ),
                ]
            ),
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        lines = [line for line in result.output.splitlines() if line.startswith("[Hop ")]
        assert len(lines) == 2, result.output
        assert "[Hop 0] ✓ VALID" in lines[0], result.output
        assert "[Hop 1] ✗ STALE" in lines[1], result.output


class TestMonotonicityAndFreshnessAreMerged:
    """One result per hop carries both verdicts; neither masks the other."""

    def _chain_from(self, results):
        return DelegationChain(attestations=results)

    def test_an_expanding_and_expired_hop_reports_both_errors(self, tmp_path):
        """Scope expansion must not swallow the staleness verdict."""
        issued = _at(offset_seconds=-30 * 24 * 3600)
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", CHILD_SCOPE, issued),
                    _hop("agent://worker", PARENT_SCOPE, issued),
                ]
            ),
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        assert "expanded" in result.output
        assert "stale by" in result.output

    def test_the_expanding_hop_alone_still_fails(self, tmp_path):
        """Regression guard for the pre-existing monotonicity error text."""
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", CHILD_SCOPE, _at(offset_seconds=-5)),
                    _hop("agent://worker", PARENT_SCOPE, _at(offset_seconds=-5)),
                ]
            ),
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        assert "capability expanded" in result.output

    def test_the_signature_verdict_still_reaches_every_hop(self, tmp_path):
        """Regression guard for #25: the chain path must keep checking signatures."""
        path = _write(tmp_path, _fresh_chain())

        output = _check_chain(path).output

        assert "UNSIGNED — NOT VERIFIED" in output

    def test_a_signed_chain_with_an_untrusted_issuer_still_fails(self, tmp_path):
        """A forged signature on a monotonic chain must not be accepted."""
        path = _write(
            tmp_path, _fresh_chain(signature="ed25519:" + "ab" * 32)
        )

        result = _check_chain(path)

        assert result.exit_code == 1, result.output
        assert "unverifiable" in result.output

    def test_one_result_per_hop_is_still_returned(self, tmp_path):
        """The merged path must not double the results or drop the first hop."""
        attestations = [Attestation.from_dict(h) for h in _fresh_chain()]
        chain = DelegationChain(attestations=attestations)
        validator = AttestationValidator(max_ttl=300)

        results = chain.validate_monotonicity(validator=validator)

        assert len(results) == 2
        assert all(r.is_valid for r in results), [r.errors for r in results]

    def test_a_stale_hop_is_invalid_when_validated_through_the_chain(self):
        """The model-level entry point enforces freshness too, not just the CLI."""
        issued = _at(offset_seconds=-30 * 24 * 3600)
        attestations = [
            Attestation.from_dict(h)
            for h in _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, issued),
                    _hop("agent://worker", CHILD_SCOPE, issued),
                ]
            )
        ]

        results = DelegationChain(attestations=attestations).validate_monotonicity(
            validator=AttestationValidator(max_ttl=300)
        )

        assert not any(r.is_valid for r in results)
        assert all(r.is_stale for r in results)

    def test_monotonicity_without_a_validator_is_unchanged(self):
        """``validate_monotonicity()`` with no validator stays scope-only.

        Two existing tests (``tests/test_models.py``) pin the old scope-only
        behaviour with timestamps from 2026, which are now long expired. The
        validator stays opt-in for that call path so those tests keep meaning
        what they mean.
        """
        chain_data = [
            {
                "issuer": "a",
                "subject": "b",
                "capability": PARENT_SCOPE,
                "issued_at": "2026-09-21T12:00:00+00:00",
                "ttl_seconds": 60,
            },
            {
                "issuer": "b",
                "subject": "c",
                "capability": CHILD_SCOPE,
                "issued_at": "2026-09-21T12:00:10+00:00",
                "ttl_seconds": 60,
            },
        ]
        attestations = [Attestation.from_dict(d) for d in chain_data]

        results = DelegationChain(attestations=attestations).validate_monotonicity()

        assert all(r.is_valid for r in results)


class TestOptionsAdvertisedInHelpNowHaveEffect:
    """``--max-ttl`` and ``--max-skew-seconds`` are documented for this command."""

    def test_max_ttl_still_warns_through_the_chain(self, tmp_path):
        """An over-ceiling TTL is advisory everywhere, chain included (#18)."""
        path = _write(tmp_path, _fresh_chain(ttl_seconds=31536000))

        result = _check_chain(path, "--max-ttl", "300")

        assert result.exit_code == 0, result.output
        assert "exceeds max" in result.output

    def test_max_skew_seconds_widens_the_window_through_the_chain(self, tmp_path):
        """The option must reach the chain path, not just ``validate``."""
        path = _write(tmp_path, _fresh_chain(ttl_seconds=60), name="future.json")
        # Move both hops past the default window but inside a widened one.
        issued = _at(offset_seconds=DEFAULT_MAX_SKEW_SECONDS + 60)
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, issued),
                    _hop("agent://worker", CHILD_SCOPE, issued),
                ]
            ),
            name="skew.json",
        )

        narrow = _check_chain(path)
        wide = _check_chain(path, "--max-skew-seconds", "600")

        assert narrow.exit_code == 1, narrow.output
        assert wide.exit_code == 0, wide.output

    def test_max_ttl_zero_does_not_silently_pass_a_chain(self, tmp_path):
        """``--max-ttl 0`` must not become a blanket pass on the chain path."""
        path = _write(tmp_path, _fresh_chain())

        result = _check_chain(path, "--max-ttl", "0")

        # max_ttl is advisory, so a live chain stays valid — but the warning
        # proves the option reached the per-hop validator at all.
        assert "exceeds max" in result.output


class TestUnchangedBehaviour:
    """Positive controls: the fix must not deny everything."""

    def test_a_fresh_narrowing_chain_still_exits_zero(self, tmp_path):
        path = _write(tmp_path, _fresh_chain())

        result = _check_chain(path)

        assert result.exit_code == 0, result.output
        assert "[Hop 0] ✓ VALID" in result.output
        assert "[Hop 1] ✓ VALID" in result.output

    @pytest.mark.parametrize("offset", [-1, -30, -59])
    def test_a_chain_inside_its_ttl_still_exits_zero(self, tmp_path, offset):
        path = _write(tmp_path, _fresh_chain(), name=f"chain-{offset}.json")
        issued = _at(offset_seconds=offset)
        path = _write(
            tmp_path,
            _chain(
                [
                    _hop("agent://orchestrator", PARENT_SCOPE, issued),
                    _hop("agent://worker", CHILD_SCOPE, issued),
                ]
            ),
            name=f"chain-{offset}.json",
        )

        assert _check_chain(path).exit_code == 0

    def test_the_per_hop_output_format_is_preserved(self, tmp_path):
        """``[Hop i] `` prefixes stay, one per hop, in order."""
        path = _write(tmp_path, _fresh_chain())

        output = _check_chain(path).output

        hops = [
            line.split("]")[0] + "]"
            for line in output.splitlines()
            if line.startswith("[Hop ")
        ]
        assert hops == ["[Hop 0]", "[Hop 1]"]

    def test_a_non_array_chain_still_exits_two(self, tmp_path):
        """The pre-existing input-validation contract is untouched."""
        path = tmp_path / "not-a-chain.json"
        path.write_text(json.dumps({"issuer": "a"}))

        result = _check_chain(path)

        assert result.exit_code == 2
        assert "must be a JSON array" in result.output

    def test_a_single_hop_chain_still_validates(self, tmp_path):
        path = _write(
            tmp_path, _chain([_hop("agent://worker", CHILD_SCOPE, _at(offset_seconds=-5))])
        )

        result = _check_chain(path)

        assert result.exit_code == 0, result.output
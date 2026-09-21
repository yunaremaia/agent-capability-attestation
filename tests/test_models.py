"""Tests for agent capability attestation validation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from agent_capability_attestation import __version__
from agent_capability_attestation.models import (
    Attestation,
    AttestationValidator,
    DelegationChain,
    ValidationResult,
    _scope_is_subscope,
    compute_state_hash,
)


class TestAttestation:
    """Test Attestation data model."""

    def test_from_dict_basic(self):
        data = {
            "issuer": "agent://planner",
            "subject": "agent://worker",
            "capability": "CAN_WRITE(store:main)",
            "issued_at": "2026-09-21T12:00:00+00:00",
            "ttl_seconds": 60,
        }
        att = Attestation.from_dict(data)
        assert att.issuer == "agent://planner"
        assert att.ttl_seconds == 60

    def test_expires_at_computed(self):
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00+00:00",
            "ttl_seconds": 120,
        }
        att = Attestation.from_dict(data)
        assert att.expires_at == datetime(2026, 9, 21, 12, 2, tzinfo=timezone.utc)

    def test_missing_ttl_fails_closed(self):
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00+00:00",
            "ttl_seconds": 0,
        }
        att = Attestation.from_dict(data)
        validator = AttestationValidator()
        result = validator.validate(att)
        assert not result.is_valid
        assert result.is_stale
        assert "Missing TTL" in result.errors[0]

    def test_stale_attestation_detected(self):
        now = datetime(2026, 9, 21, 13, 0, 0, tzinfo=timezone.utc)
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00+00:00",
            "ttl_seconds": 60,
        }
        att = Attestation.from_dict(data)
        validator = AttestationValidator(now=now)
        result = validator.validate(att)
        assert not result.is_valid
        assert result.is_stale
        assert result.stale_by_seconds == 2940.0  # 3540 - 60

    def test_fresh_attestation_valid(self):
        now = datetime(2026, 9, 21, 12, 0, 30, tzinfo=timezone.utc)
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00+00:00",
            "ttl_seconds": 60,
        }
        att = Attestation.from_dict(data)
        validator = AttestationValidator(now=now)
        result = validator.validate(att)
        assert result.is_valid

    def test_ttl_exceeds_max_warning(self):
        now = datetime(2026, 9, 21, 12, 0, 0, tzinfo=timezone.utc)
        data = {
            "issuer": "a",
            "subject": "b",
            "capability": "X",
            "issued_at": "2026-09-21T12:00:00+00:00",
            "ttl_seconds": 600,
        }
        att = Attestation.from_dict(data)
        validator = AttestationValidator(max_ttl=300, now=now)
        result = validator.validate(att)
        assert result.is_valid
        assert len(result.warnings) == 1
        assert "exceeds max" in result.warnings[0]


class TestDelegationChain:
    """Test delegation chain monotonicity validation."""

    def test_scope_narrowing_valid(self):
        chain_data = [
            {
                "issuer": "a",
                "subject": "b",
                "capability": "CAN_WRITE(store:*)",
                "issued_at": "2026-09-21T12:00:00+00:00",
                "ttl_seconds": 60,
            },
            {
                "issuer": "b",
                "subject": "c",
                "capability": "CAN_WRITE(store:partition_1)",
                "issued_at": "2026-09-21T12:00:10+00:00",
                "ttl_seconds": 60,
            },
        ]
        attestations = [Attestation.from_dict(d) for d in chain_data]
        chain = DelegationChain(attestations=attestations)
        results = chain.validate_monotonicity()
        assert all(r.is_valid for r in results)

    def test_scope_expansion_invalid(self):
        chain_data = [
            {
                "issuer": "a",
                "subject": "b",
                "capability": "CAN_WRITE(store:partition_1)",
                "issued_at": "2026-09-21T12:00:00+00:00",
                "ttl_seconds": 60,
            },
            {
                "issuer": "b",
                "subject": "c",
                "capability": "CAN_WRITE(store:*)",
                "issued_at": "2026-09-21T12:00:10+00:00",
                "ttl_seconds": 60,
            },
        ]
        attestations = [Attestation.from_dict(d) for d in chain_data]
        chain = DelegationChain(attestations=attestations)
        results = chain.validate_monotonicity()
        assert not results[1].is_valid
        assert "expanded" in results[1].errors[0]


class TestHelpers:
    """Test helper functions."""

    def test_scope_is_subscope(self):
        assert _scope_is_subscope("CAN_WRITE(store:*)", "CAN_WRITE(store:partition_1)")
        assert _scope_is_subscope("X", "X")
        assert not _scope_is_subscope("CAN_WRITE(store:p1)", "CAN_WRITE(store:*)")

    def test_compute_state_hash(self):
        caps = {"tools": ["search", "write"], "max_tokens": 1000}
        h = compute_state_hash(caps)
        assert h.startswith("sha256:")
        assert len(h) == 7 + 64  # "sha256:" + hex

    def test_version(self):
        assert __version__ == "0.1.0"

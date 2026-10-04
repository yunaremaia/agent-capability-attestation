# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- A `lint` job in CI running `ruff check .` (package **and** `tests/`), with the
  rule set pinned in a new `ruff.toml` at the repo root.

- `AttestationValidator(max_skew_seconds=...)` and a `--max-skew-seconds` option on
  `validate`, `scan`, `check-chain` and `check-mcp` to bound how far into the future an
  `issued_at` may sit. Defaults to `DEFAULT_MAX_SKEW_SECONDS` (60s).
- `AttestationValidator(trusted_keys=..., require_signature=...)`: signature
  verification is now part of validation, and the verdict is reported as
  `ValidationResult.signature_status` (`verified` / `unverified` / `unsigned` /
  `unchecked`).
- `--public-key-file` and `--require-signature` on `aca validate`, `aca scan`,
  `aca check-chain` and `aca check-mcp`.
- `DelegationChain.validate_monotonicity(validator=...)` runs the validator over
  every hop when one is given — not just its signature check, but the full
  per-attestation validation.

### Changed

- The CLI always prints the signature verdict alongside `VALID`/`STALE`, so an
  unverified attestation is never reported as a bare `✓ VALID`.
- `--json-output` includes `signature_status`.
- A non-stale invalid attestation now prints `✗ INVALID` instead of `✗ STALE`.

### Fixed

- `check-chain` never checked TTL, expiry or clock skew: it built an
  `AttestationValidator` from the operator's `--max-ttl` / `--max-skew-seconds`
  and applied only its signature check to each hop, so those options had no
  effect at all on this command. `validate_monotonicity()` compared each hop's
  capability against its parent's and nothing else, which made a chain
  "monotonic" regardless of age. `check-chain` therefore exited `0` and printed
  `✓ VALID` for a chain whose every hop had expired, for one dated 80 years in
  the future, and for one carrying no TTL — the same defect class as #22, #23
  and #24, which hardened `AttestationValidator.validate()` on the
  single-attestation path and left the chain path unhardened. Each hop is now
  validated in full and its verdict merged with the monotonicity one, so one
  `ValidationResult` per hop carries both.

- `verify_signature()` was never called by `validate()` or any CLI command, so a
  tampered attestation (`db:read` → `db:admin`, swapped tool schema, stretched
  TTL) was reported `VALID` with exit code 0 (fixes #15).
- `verify_signature()` returned an uncaught `TypeError` for a non-string
  signature instead of `False`.

- A future-dated `issued_at` is now rejected instead of validating forever. `validate()`
  computed a negative `age` for a timestamp ahead of the clock and had no branch for it,
  so an attestation dated 80 years in the future reported `is_valid=True`, `is_stale=False`
  and CLI exit `0` — and, because the deadline is derived from `issued_at`, could not expire
  until the wall clock caught up. Rejected beyond the skew window with
  `Attestation issued <n>s in the future (allowed skew 60s)`.

## [Initial Release]

- Initial project release

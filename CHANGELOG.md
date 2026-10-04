# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `AttestationValidator(max_skew_seconds=...)` and a `--max-skew-seconds` option on
  `validate`, `scan`, `check-chain` and `check-mcp` to bound how far into the future an
  `issued_at` may sit. Defaults to `DEFAULT_MAX_SKEW_SECONDS` (60s).

### Changed

### Fixed

- A future-dated `issued_at` is now rejected instead of validating forever. `validate()`
  computed a negative `age` for a timestamp ahead of the clock and had no branch for it,
  so an attestation dated 80 years in the future reported `is_valid=True`, `is_stale=False`
  and CLI exit `0` — and, because the deadline is derived from `issued_at`, could not expire
  until the wall clock caught up. Rejected beyond the skew window with
  `Attestation issued <n>s in the future (allowed skew 60s)`.

## [Initial Release]

- Initial project release

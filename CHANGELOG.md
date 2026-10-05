# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- `check-chain` no longer reports a capability expansion out of the parent
  resource namespace as monotonic. The scope-subset check compared only the last
  `:`-segment and normalised it with `str.strip("()")`, which removes a character
  set rather than a matched pair — so the documented form `CAN_WRITE(store:*)`
  collapsed to a bare `*` and matched *any* child. `CAN_WRITE(store:*)` ->
  `CAN_WRITE(other:admin)` is now `Hop N: capability expanded`, exit `1`.

## [0.1.0] - 2026-10-05

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

- The `README`'s Signature Verification section now states the signing contract: the signed
  bytes are the canonical serialization of every field except `signature` — sorted keys, no
  insignificant whitespace, UTF-8, i.e. `canonical_bytes()` — cross-linked to the `ed25519:`
  prefix in the schema. The section previously named the fields but not the serialization, so
  an issuer written from the README alone signed `json.dumps(body)` and was told its
  attestation "may be forged" — the one diagnosis the section gave no way to rule out. A new
  `tests/test_readme_signing_contract.py` runs the recipe the section shows, so the section
  cannot silently drift back to describing the fields without the bytes (#41).

### Fixed

- A malformed attestation payload is reported as a bad input — exit `2` — instead of
  escaping as an unhandled traceback with exit `1`. `Attestation.from_dict` read
  `issuer`, `subject`, `capability` and `issued_at` by subscript with no validation, so
  a document that was not a JSON object, or that omitted a required field, raised
  `KeyError` / `TypeError` out of the parser. `validate` and `check-chain` called it
  outside any `try`, and `check-mcp` guarded every level of its walk except the
  attestation element itself, so the process exited `1` — the code a genuine validation
  failure uses — and a broken file could not be told apart from a stale or forged one.
  The README already documents `2 = malformed input`; the payload was the one level
  that did not honour it. `from_dict` now raises `ValueError` naming the problem, every
  command maps it to exit `2` (and `check-chain` names the offending index), and `scan`
  counts the files it could not read instead of dropping them from both its summary
  line and its `--json-output` list (#44).

- `ttl_seconds` is type-checked, so a non-integer value is a bad input — exit `2` — instead
  of an unhandled `TypeError` with exit `1`, which is what the field produced through
  `validate`, `check-chain` and `check-mcp` alike. A JSON string, `null`, array or object
  reached `timedelta(seconds=...)` and the `<= 0` comparison with no check between them; a
  boolean was worse, because Python's `bool` subclasses `int`, so `ttl_seconds: true` was
  read as the integer `1` and a one-second TTL was then *validated* — a wrong answer rather
  than an error. The check runs in `__post_init__`, the value's point of use, so it covers
  every path into the model rather than only `from_dict`, and the message names the field
  and the type received. An integer is accepted whatever its sign: `0` and a negative still
  reach `validate`'s `<= 0` branch and are reported as missing TTL (exit `1`), a verdict on
  a well-formed attestation rather than a malformed document, and an integral float
  (`300.0`) is accepted verbatim (#48).

- A declared `expires_at` can no longer extend an attestation's life past
  `issued_at + ttl_seconds`. The field is attacker-controlled — it is one of the
  values an editor of the file chooses — and it was used as *the* deadline, so an
  attestation issued 30 days ago with `ttl_seconds: 1` and `expires_at: 2099`
  reported `✓ VALID`, `is_valid` was `True`, `errors` was empty and `aca validate`
  exited `0`; the only trace was a warning saying the tool was deliberately
  honouring the declared value. No value of `--max-ttl` closed it, because
  `max_ttl` is compared against `ttl_seconds`, which no longer decided expiry once
  the field was present. A declared expiry later than the TTL-derived deadline is
  now an error, and the staleness reading is recomputed against that deadline, so
  the verdict is `STALE` rather than merely `INVALID`. The opposite direction is
  unchanged: an attestation that declares itself expired is still honoured even
  when its TTL has not run out (#11), and a live chain hop with a declared expiry
  in the past is still rejected (#22). `max_ttl` was left advisory by this fix;
  it is enforced now, and the bound here stays the TTL-derived deadline rather
  than the policy ceiling so the two remain independent.

- `max_ttl` is enforced instead of narrated (#18). `AttestationValidator(max_ttl=...)` —
  the `--max-ttl` option on `validate`, `scan`, `check-chain` and `check-mcp` — appended a
  warning and left `is_valid` `True`, so an attestation declaring `ttl_seconds: 315360000`
  (ten years) was reported `✓ VALID` under a 300-second ceiling, `errors` was empty and
  `aca validate` exited `0`. A missing TTL was fail-closed; the TTL *ceiling* was the one TTL
  rule that was not, which is the more dangerous half — an attacker who can edit the file only
  has to raise the number, and the README's own CI recipe (`aca scan ./agents/ --fail-on-stale`)
  passed it. An attestation that can outlive `issued_at + max_ttl` is now an error (`is_valid`
  `False`, exit `1`). The ceiling is measured against the deadline the validator uses — the
  declared `expires_at` when present, otherwise `issued_at + ttl_seconds` — rather than against
  the `ttl_seconds` field, because a declared expiry that shortens a long TTL is the rule
  above, and rejecting such an attestation would undo it. `--warn-on-exceeding-max-ttl` (and
  `enforce_max_ttl=False` on the validator) restores the advisory behaviour as a deliberate
  opt-in. `aca scan`'s summary now reports the invalid count and breaks out how many of those
  are stale, so it no longer calls a future-dated attestation "stale".

- `aca scan` now exits `1` when any attestation it scanned is invalid, instead
  of exiting `0` unless `--fail-on-stale` was passed. The verdict lines were
  already correct — a forged signature reported `ERROR: Signature does not match
  payload — attestation may be forged` — but `all_valid` was computed and then
  discarded at the process boundary, so a CI gate that ran `aca scan ./agents/`
  and checked the exit status passed a directory full of forged and expired
  attestations. That made `scan` the only validating command whose exit code
  disagreed with its own findings (`validate`, `check-chain` and `check-mcp` all
  fail closed). The default is now fail-closed; `--report-only` is the explicit
  opt-out, and `--fail-on-stale` is kept as a deprecated, redundant alias for one
  release so the documented CI recipe keeps working. The two flags are
  mutually exclusive (exit `2`).

- `check-mcp` now reports exit `2` for a config whose structure is not the nested
  JSON object the scanner reads, instead of dying with an uncaught
  `AttributeError` and exiting `1`. A `"mcpServers"` (or `"servers"`) value that is
  an array, string, number or null — and a server entry that is not an object —
  escaped from the walk as a traceback, and the process then exited `1`, the same
  code a genuine validation failure uses: an operator with a malformed config
  could not tell it apart from one whose attestations were stale. The scanner
  raises `McpConfigError` for each of those levels, naming the key and the JSON
  type it found, and the CLI maps it to exit `2` like its other malformed-input
  paths. The attestation payload's own shape (`capabilityAttestation` not an
  object, or missing a required field) is a separate site with the same root
  cause, reached through `check-chain` as well, and is not covered here.

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

- An empty result set is now a failure instead of a vacuous pass. `check-chain`
  and `check-mcp` both reduce their verdict with `all(...)`, and `all([])` is
  `True`, so `check-chain []` and `check-mcp {}` exited `0` having printed
  nothing at all. A run that inspected nothing was indistinguishable from a
  clean one. Both now report the empty set on stderr and exit `1`.

- A future-dated `issued_at` is now rejected instead of validating forever. `validate()`
  computed a negative `age` for a timestamp ahead of the clock and had no branch for it,
  so an attestation dated 80 years in the future reported `is_valid=True`, `is_stale=False`
  and CLI exit `0` — and, because the deadline is derived from `issued_at`, could not expire
  until the wall clock caught up. Rejected beyond the skew window with
  `Attestation issued <n>s in the future (allowed skew 60s)`.
- `verify_signature()` no longer raises `TypeError` for a `signature` value that is not a
  string. `bytes.fromhex()` raises `TypeError` — not `ValueError` — for a JSON number,
  array or object, so the previous `except (InvalidSignature, ValueError)` let
  attacker-controlled input escape as an uncaught exception instead of returning `False`.
  It also accepts the algorithm-prefixed `"ed25519:<hex>"` form documented by the README's
  Attestation Schema, which `bytes.fromhex` rejected with `ValueError` — so every
  signature written in the project's own documented wire format failed verification.

## [Initial Release]

- Initial project release

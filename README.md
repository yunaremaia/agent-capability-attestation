# Agent Capability Attestation

> Detect capability drift and stale attestations in AI agent delegation chains. TTL-based freshness validation for agent-to-agent capability negotiation.

## The Problem

When Agent A delegates a task to Agent B, the capability attestation that authorized the delegation has a half-life. After deployment, context changes, or capability revocation, the cached attestation becomes a liability — Agent B may still hold permissions it shouldn't, or Agent A may operate under the false belief that the chain is still valid.

**Real-world impact:**
- 18% of "phantom capabilities" appear in the first 2 seconds after a deployment rollout (cached receipt looks fresh, backend is dead)
- 13% of agent handshakes in production meshes have silent capability mismatches
- Multi-hop delegation chains compound the staleness: A→B→C→D, if any link is stale, the entire downstream delegation operates on fiction

**Current gap:** No open-source tool validates capability attestation TTLs or detects drift in delegation chains.

## What This Tool Does

`agent-capability-attestation` validates that agent capability attestations:

1. **Carry TTL metadata** — every attestation must include `{capability, agent_state_hash, timestamp, ttl}`
2. **Are fresh** — TTL must not have expired at validation time
3. **Match the current agent state** — the state hash must match the agent's current declared capabilities
4. **Delegate monotonically** — each hop in a delegation chain must narrow (never expand) the scope
5. **Fail closed** — missing TTL = expired attestation (assume stale unless freshly attested)

## Installation

```bash
pip install git+https://github.com/yunaremaia/agent-capability-attestation.git
```

## Quick Start

```bash
# Validate a single attestation file
aca validate attestation.json

# Widen the accepted clock drift if issuer and validator clocks disagree
aca validate attestation.json --max-skew-seconds 300

# Scan a directory; exits 1 if any attestation it finds is invalid
# (--report-only forces exit 0 and reports on stdout instead)
aca scan ./delegation-chain/

# Validate a delegation chain file (array of attestations, in order)
aca check-chain chain.json

# Check MCP server capability attestations
aca check-mcp mcp-config.json --max-ttl 300

# Verify the issuer's Ed25519 signature
aca validate attestation.json --public-key-file issuer-pubkey.hex

# Exit code: 0 = all fresh, 1 = invalid (stale, forged or unreadable)
# detected, 2 = malformed input
echo $?
```

## Delegation Chains

`aca check-chain` takes a JSON array of attestations in delegation order and checks two
independent things about each hop:

1. **Scope monotonicity** — hop *N*'s capability must be a sub-scope of hop *N-1*'s. A hop
   that widens what its parent granted is reported as `capability expanded`.
2. **Freshness** — every hop is validated in full: TTL must be present and positive, the
   declared `expires_at` must not have passed, and `issued_at` must not sit further into
   the future than the skew tolerance allows.

Both verdicts are merged into a single per-hop result, so a hop that is both expired and
scope-expanding reports both errors rather than one masking the other:

```console
$ aca check-chain chain.json
[Hop 0] ✗ STALE | agent://planner-v2 → agent://orchestrator | CAN_WRITE(store:*) (TTL 60s)
    signature: UNSIGNED — NOT VERIFIED
    stale by 2591940.1s
    ERROR: Attestation stale by 2591940.1s (issued 2592000.1s ago, expires 2026-09-04T01:45:27+00:00)
[Hop 1] ✗ STALE | agent://orchestrator → agent://worker | CAN_WRITE(store:partition_1) (TTL 60s)
    signature: UNSIGNED — NOT VERIFIED
    stale by 2591940.1s
    ERROR: Attestation stale by 2591940.1s (issued 2592000.1s ago, expires 2026-09-04T01:45:27+00:00)
$ echo $?
1
```

`--max-ttl` and `--max-skew-seconds` apply to every hop, exactly as they do for `validate`
and `scan`. A chain in which every hop is live and every hop narrows the scope exits `0`.

## Clock Skew

An `issued_at` ahead of the validation clock is treated as a forgery or replay signal, not
as a fresh attestation. Because the expiry deadline is derived from `issued_at`, a shifted
timestamp is what keeps an attestation alive indefinitely — so a future-dated one is
rejected outright.

Validators do not require a *perfect* clock. A small window absorbs legitimate drift:

| | |
|---|---|
| Default tolerance | 60s (`DEFAULT_MAX_SKEW_SECONDS`) |
| Widened | `AttestationValidator(max_skew_seconds=300)` |
| Widened from the CLI | `--max-skew-seconds 300` |

Widen the window explicitly when a deployment's clock is known to drift. Lowering it toward
`0` is valid if every host is NTP-locked tightly.

## Declared Expiry

`expires_at` is optional. When it is absent the deadline is `issued_at + ttl_seconds`, and
that derived deadline is the ceiling the `ttl_seconds` policy is measured against.

A declared `expires_at` may **shorten** an attestation's life — an attestation that says it
expired is honoured even when its TTL has not run out — but it may never **extend** it. A
declared expiry later than `issued_at + ttl_seconds` is an internally inconsistent record,
and it is resolved against the shorter life:

```console
$ aca validate forged.attestation.json
✗ STALE | agent://planner → agent://attacker | CAN_DELETE_ALL(state) (TTL 1s)
    signature: UNSIGNED — NOT VERIFIED
    ERROR: expires_at 2099-01-01T00:00:00+00:00 outlives the TTL deadline 2026-09-04T12:00:01+00:00 (issued_at + ttl_seconds 1s) — a declared expiry may shorten an attestation's life but never extend it; rejecting
$ echo $?
1
```

The bound is exact rather than a tolerance, because a tolerance could only come from
`--max-skew-seconds`, which is operator-controlled: widening the clock-skew window must not
widen what a declaration is allowed to claim.

## Signature Verification

An attestation's `signature` is an Ed25519 signature over the whole payload (every field
except `signature` itself). **Validation enforces it.** Swapping the capability, subject,
TTL or tool schema after signing makes validation fail:

```console
$ aca validate attestation.json --public-key-file issuer-pubkey.hex
✗ INVALID | agent://planner-v2 → agent://worker-v3 | CAN_DELETE_ALL(state_store) (TTL 120s)
    signature: NOT VERIFIED
    ERROR: Signature does not match payload — attestation may be forged
$ echo $?
1
```

`--public-key-file` takes the issuer's Ed25519 public key as 64 hex characters, which is
what `public_bytes(Encoding.Raw, PublicFormat.Raw).hex()` produces:

```bash
# Publish the key (issuer side)
python -c "import json,serialization; from cryptography.hazmat.primitives.asymmetric import ed25519; \
print(ed25519.Ed25519PublicKey.from_private_bytes(open('issuer.key','rb').read()).public_bytes( \
encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex())" > issuer-pubkey.hex

# Consume it (verifier side)
aca validate attestation.json --public-key-file issuer-pubkey.hex
```

Both options are accepted by `validate`, `scan`, `check-chain` and `check-mcp`.

### What happens without a key

| attestation | default | `--require-signature` |
|---|---|---|
| correctly signed | `signature: VERIFIED`, exit 0 | `VERIFIED`, exit 0 |
| signed but tampered with | `NOT VERIFIED`, **exit 1** | exit 1 |
| signed, no trusted key for the issuer | `NOT VERIFIED`, **exit 1** | exit 1 |
| no signature at all | `UNSIGNED — NOT VERIFIED`, warning, exit 0 | **exit 1** |

The rule is: **a signature that cannot be verified is treated as no evidence at all and
rejected** — accepting it would reintroduce the hole the signature exists to close. An
attestation with *no* signature is a different case: it never claimed to be signed, so
nothing about it was tampered with. It is still reported as unverified, is never printed as
a bare `✓ VALID`, and `--require-signature` turns it into a hard failure for deployments
that require signed attestations.

## Attestation Schema

```json
{
  "issuer": "agent://planner-v2",
  "subject": "agent://worker-v3",
  "capability": "CAN_WRITE(state_store:partition_3)",
  "issued_at": "2026-09-21T12:00:00Z",
  "expires_at": "2026-09-21T12:02:00Z",
  "ttl_seconds": 120,
  "state_hash": "sha256:abc123...",
  "provenance": ["agent://planner-v2", "agent://coordinator-v1"],
  "signature": "ed25519:def456..."
}
```

## Integration

### CI/CD Gate

```yaml
- name: Validate agent capability attestations
  run: |
    pip install git+https://github.com/yunaremaia/agent-capability-attestation.git
    aca scan ./agents/ --require-signature \
      --public-key-file ./keys/issuer-pubkey.hex
```

`aca scan` exits `1` as soon as any attestation is invalid, so the gate needs no
extra flag; `--report-only` is the opt-out for a non-blocking report.

### Pre-delegation Check

`AttestationValidator` takes the trusted public keys so the signature is verified as part
of validation:

```python
from agent_capability_attestation import AttestationValidator

validator = AttestationValidator(
    max_ttl=300,
    trusted_keys={"agent://planner-v2": planner_public_key},
)
result = validator.validate(attestation)

if result.is_stale:
    raise CapabilityExpiredError(
        f"Attestation expired {result.stale_by_seconds}s ago"
    )

# A signed payload that could not be verified is already invalid; an
# attestation that never claimed a signature is reported as such.
if result.signature_status != "verified":
    raise CapabilityNotAttested(result.signature_status)
```

## Roadmap

- [ ] A2A protocol integration (validate Agent Card capability declarations)
- [ ] MCP server capability scanning
- [ ] Delegation chain visualization
- [ ] SARIF output for GitHub Code Scanning
- [ ] Policy engine integration (OPA/Rego)
- [ ] Prometheus metrics exporter

## License

MIT

# Agent Capability Attestation

![CI](https://github.com/yunaremaia/agent-capability-attestation/actions/workflows/ci.yml/badge.svg)

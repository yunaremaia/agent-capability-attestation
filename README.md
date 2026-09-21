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

# Scan a delegation chain directory
aca scan ./delegation-chain/

# Check MCP server capability attestations
aca check-mcp mcp-config.json --ttl-max-age 300

# Exit code: 0 = all fresh, 1 = stale/drift detected
echo $?
```

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
    pip install agent-capability-attestation
    aca scan ./agents/ --fail-on-stale
```

### Pre-delegation Check

```python
from agent_capability_attestation import AttestationValidator

validator = AttestationValidator(max_ttl=300)
result = validator.validate(attestation)

if result.is_stale:
    raise CapabilityExpiredError(
        f"Attestation expired {result.stale_by_seconds}s ago"
    )
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

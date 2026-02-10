# Uniplex Python SDK

Official Python client for the [Uniplex](https://uniplex.ai) trust infrastructure platform. Manage gates, passports, attestations, constraints, catalogs, enforcement, discovery, billing, and SLA compliance for AI agents.

## Installation

```bash
pip install uniplex
```

## Quick Start

### Synchronous

```python
from uniplex import UniplexClient

client = UniplexClient(api_key="uni_live_xxx")

# Create a gate
gate = client.create_gate(name="My Service", gate_id="gate_my-service")

# Issue a passport
passport = client.issue_passport(
    "gate_my-service",
    agent_id="agent-001",
    agent_name="My Agent",
    permissions=["read", "write"],
    expires_in="7d",
)

# Check authorization
result = client.check_gate(
    "gate_my-service",
    action="read",
    passport_id=passport["passport_id"],
)
print(result["allowed"])  # True

# Enforce with constraints
enforcement = client.enforce_action(
    passport_id=passport["passport_id"],
    action="write",
    cost_cents=500,
)
print(enforcement["decision"])  # "PERMIT"

client.close()
```

### Async

```python
import asyncio
from uniplex import AsyncUniplexClient

async def main():
    async with AsyncUniplexClient(api_key="uni_live_xxx") as client:
        gates = await client.list_gates()
        print(f"Found {len(gates)} gates")

        for gate in gates:
            passports = await client.list_passports(gate["gate_id"])
            print(f"  {gate['name']}: {len(passports)} passports")

asyncio.run(main())
```

### Context Manager

Both clients support context managers for automatic cleanup:

```python
with UniplexClient(api_key="uni_live_xxx") as client:
    gates = client.list_gates()
```

## API Coverage

### Gates

```python
client.list_gates()
client.get_gate("gate_my-service")
client.create_gate(name="My Service", gate_id="gate_my-service")
client.update_gate("gate_my-service", name="Updated Name")
client.delete_gate("gate_my-service")
```

### Passports

```python
client.list_passports("gate_my-service")
client.get_passport("gate_my-service", "pp_xxx")
client.issue_passport("gate_my-service", agent_id="agent-001", permissions=["read"])
client.revoke_passport("gate_my-service", "pp_xxx")
client.reissue_passport("pp_xxx", accept_catalog_version=2)
```

### Attestations

```python
client.list_attestations("gate_my-service", limit=50)
client.record_attestation("gate_my-service", passport_id="pp_xxx", permission="read", tool_name="search", result="allowed")
```

### Permission Catalog

```python
client.get_catalog("gate_my-service")
client.create_catalog("gate_my-service", permissions=[...])
client.publish_catalog("gate_my-service", change_summary="Added search permission")
client.list_catalog_versions("gate_my-service")
client.get_catalog_version("gate_my-service", version=1)
```

### Constraints

```python
client.get_constraints("pp_xxx")
client.set_constraints("pp_xxx", {"read": {"core:rate:max_per_minute": 100}})
client.list_constraint_types(category="cost")
client.list_constraint_templates(category="security")
client.apply_constraint_template("pp_xxx", "conservative-agent")
```

### Enforcement (CEL)

```python
client.enforce_action(passport_id="pp_xxx", action="write", cost_cents=500)
client.list_enforcement_attestations("pp_xxx", decision="BLOCK")
client.get_enforcement_attestation("enf_xxx")
client.verify_enforcement_attestation("enf_xxx")
```

### Anonymous Access

```python
client.get_anonymous_policy("gate_my-service")
client.set_anonymous_policy("gate_my-service", enabled=True, allowed_actions=["read"])
```

### Commerce

```python
# Service discovery
results = client.discover_services("flights:search", max_price_cents=100, sort="price_asc")

# Consumption metering
attestation = client.issue_consumption_attestation(
    passport_id="pp_xxx",
    gate_id="gate_my-service",
    action="flights:search",
    outcome="success",
)

# Billing & settlement
client.generate_settlement(gate_id="gate_my-service", period_type="monthly", period_start="2025-01-01", period_end="2025-01-31")
client.list_settlements(gate_id="gate_my-service", status="pending")
client.update_settlement_status("stl_xxx", "invoiced")

# SLA compliance
sla = client.get_sla_compliance("gate_my-service", period_start="2025-01-01", period_end="2025-01-31")
```

### Cumulative State

```python
client.get_cumulative_state("pp_xxx")
client.reset_cumulative_state("pp_xxx", window_type="daily")
```

## Cryptographic Verification

The SDK includes local verification utilities:

```python
from uniplex import verify_attestation_signature, verify_content_hash, compute_content_hash

# Verify an attestation signature locally
valid = verify_attestation_signature(
    attestation_json='{"gate_id":"gate_my-service",...}',
    signature_b64="base64-sig...",
    public_key_b64="base64-key...",
)

# Verify a catalog content hash
matches = verify_content_hash(catalog_snapshot, expected_hash)

# Compute a content hash (RFC 8785 canonical JSON + SHA-256)
hash_hex = compute_content_hash({"key": "value"})
```

## Error Handling

All API errors are raised as typed exceptions:

```python
from uniplex import (
    UniplexError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
    ConflictError,
)

try:
    client.get_gate("gate_nonexistent")
except NotFoundError as e:
    print(f"Not found: {e}")
    print(f"Status: {e.status_code}")  # 404
except RateLimitError as e:
    print(f"Rate limited, retry after: {e.retry_after}s")
except UniplexError as e:
    print(f"API error: {e} (HTTP {e.status_code})")
```

## Requirements

- Python 3.10+
- httpx
- pydantic v2
- pynacl (Ed25519 verification)
- canonicaljson (RFC 8785)

## License

MIT

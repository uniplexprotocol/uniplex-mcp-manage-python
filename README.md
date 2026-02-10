# uniplex-mcp-manage

<!-- mcp-name: io.github.uniplexprotocol/manage -->

[![PyPI version](https://img.shields.io/pypi/v/uniplex-mcp-manage)](https://pypi.org/project/uniplex-mcp-manage/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-green)](https://modelcontextprotocol.io)

**The trust layer for AI agents.** Gates protect your tools. Passports authorize your agents. Everything verified locally.

Create & manage passports, gates, issuers, and attestations for the [Uniplex](https://uniplex.ai) protocol — directly from Claude, Cursor, or any MCP client.

---

## What is Uniplex?

[Uniplex](https://uniplex.ai) is an open protocol that adds a lightweight trust layer for the agentic web. It has two sides:

**Gates** protect your tools, APIs, and MCP servers. A Gate is a verification checkpoint — you define a permission catalog of what's allowed, and incoming agent requests are checked against it locally, with no network round-trip. Every decision produces a signed attestation for a tamper-evident audit trail.

**Passports** are signed credentials that agents carry. Each passport specifies who issued it, what the agent is allowed to do, and under what constraints — scoped to specific actions, resources, and time windows.

This MCP server lets you manage both sides — gates, passports, issuers, and attestations — conversationally from any MCP client.

> [Protocol specification](https://github.com/uniplexprotocol/uniplex) · [Documentation](https://uniplex.io) · [SDK (Python)](https://pypi.org/project/uniplex-mcp-manage/) · [SDK (TypeScript)](https://www.npmjs.com/package/uniplex-mcp-manage)

---

## Prerequisites

- A **Uniplex account** — sign up at the [Uniplex Dashboard](https://dashboard.uniplex.ai)
- **Claude Desktop**, **Claude Code**, **Cursor**, or any MCP-compatible client
- For local MCP clients: an **API key** (generate one from the dashboard)

---

## Quick Start

### Connect with OAuth (Claude.ai, Claude Code, Cursor)

If your MCP client supports remote integrations, just connect directly — no API key needed:

1. Search for **Uniplex** in your client's integrations directory
2. Click **Connect**
3. Sign in to your Uniplex account and click **Authorize**

That's it — you're connected.

### Connect with API Key (Claude Desktop, any MCP client)

For local MCP clients, add Uniplex to your configuration file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

**Using npm (npx):**

```json
{
  "mcpServers": {
    "uniplex": {
      "command": "npx",
      "args": ["uniplex-mcp-manage"],
      "env": {
        "UNIPLEX_API_KEY": "uni_live_xxxxxxxx"
      }
    }
  }
}
```

**Using Python (uvx):**

```json
{
  "mcpServers": {
    "uniplex": {
      "command": "uvx",
      "args": ["uniplex-mcp-manage"],
      "env": {
        "UNIPLEX_API_KEY": "uni_live_xxxxxxxx"
      }
    }
  }
}
```

### Add to Claude Code

```bash
# via npm
claude mcp add uniplex \
  --scope user \
  -- npx uniplex-mcp-manage \
  --env UNIPLEX_API_KEY=uni_live_xxxxxxxx

# via Python
claude mcp add uniplex \
  --scope user \
  -- uvx uniplex-mcp-manage \
  --env UNIPLEX_API_KEY=uni_live_xxxxxxxx
```

### 3. Restart and Use

Restart your client and try asking:

> "Show me my Uniplex account info"

> "Create a new issuer called acme-prod"

> "Issue a passport for my research agent with read access to flights:search"

---

## Example Interactions

**Create an issuer and issue a passport:**

> **You:** Create a new issuer called acme-prod
> **Claude:** Created issuer `iss_7f3a` (acme-prod) with an Ed25519 keypair. This issuer can now issue passports to your agents.

> **You:** Issue a passport for my data-collector agent with read access to weather:forecast, TTL 24 hours
> **Claude:** Issued passport `pp_b91c` for agent data-collector via issuer acme-prod. Permissions: `read` on `weather:forecast`. Expires in 24 hours.

**Verify a passport against a gate:**

> **You:** Check passport pp_b91c against the weather-api gate
> **Claude:** Allowed — passport pp_b91c has `read` permission on `weather:forecast`, which matches the gate's catalog. The passport is valid and unexpired.

---

## Available Tools

### Account

| Tool | Description |
|------|-------------|
| `whoami` | Get current account info and API key metadata |

### Issuers

Issuers are the entities that sign and issue passports to agents. Each issuer holds a cryptographic keypair used to sign the passports it creates.

| Tool | Description |
|------|-------------|
| `list_issuers` | List all issuers in your account |
| `create_issuer` | Create a new issuer with a generated Ed25519 keypair |
| `get_issuer` | Get issuer details, including public key and passport count |

### Passports

Passports are signed, scoped credentials that agents carry. Each passport specifies exactly which actions and resources the agent is authorized to access.

| Tool | Description |
|------|-------------|
| `list_passports` | List passports with optional filters (issuer, status, agent) |
| `create_passport` | Issue a new passport with action + resource permissions and TTL |
| `get_passport` | Get passport details including permissions, expiry, and signature |
| `revoke_passport` | Revoke a passport immediately, preventing further use |

### Gates

Gates are verification checkpoints. Any tool or API configures a gate with a permission catalog, and incoming passports are checked against it — locally, with no network call.

| Tool | Description |
|------|-------------|
| `list_gates` | List all gates in your account |
| `create_gate` | Create a new gate with a trust profile (L1/L2/L3) |
| `get_gate` | Get gate details including its permission catalog |
| `update_gate_catalog` | Update which actions and resources a gate accepts |
| `check_gate` | Test a passport against a gate to preview the allow/deny decision |

### Attestations

Attestations are signed records of verification decisions — a tamper-evident audit trail of every gate check.

| Tool | Description |
|------|-------------|
| `list_attestations` | Query attestation history with filters |
| `get_attestation` | Get full attestation details including decision and evidence |

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `UNIPLEX_API_KEY` | Yes | — | Your Uniplex API key (`uni_live_*` or `uni_test_*`) |
| `UNIPLEX_API_URL` | No | `https://api.uniplex.ai` | API base URL (override for local dev) |

---

## Python Library Usage

In addition to the MCP server, this package exports a full Python client for the Uniplex REST API. Use it to integrate Uniplex into your own applications, scripts, and agent frameworks.

```bash
pip install uniplex-mcp-manage
```

### Synchronous

```python
from uniplex import UniplexClient

client = UniplexClient(api_key="uni_live_xxxxxxxx")

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
    async with AsyncUniplexClient(api_key="uni_live_xxxxxxxx") as client:
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
with UniplexClient(api_key="uni_live_xxxxxxxx") as client:
    gates = client.list_gates()
```

### API Coverage

#### Gates

```python
client.list_gates()
client.get_gate("gate_my-service")
client.create_gate(name="My Service", gate_id="gate_my-service")
client.update_gate("gate_my-service", name="Updated Name")
client.delete_gate("gate_my-service")
```

#### Passports

```python
client.list_passports("gate_my-service")
client.get_passport("gate_my-service", "pp_xxx")
client.issue_passport("gate_my-service", agent_id="agent-001", permissions=["read"])
client.revoke_passport("gate_my-service", "pp_xxx")
client.reissue_passport("pp_xxx", accept_catalog_version=2)
```

#### Attestations

```python
client.list_attestations("gate_my-service", limit=50)
client.record_attestation("gate_my-service", passport_id="pp_xxx", permission="read", tool_name="search", result="allowed")
```

#### Permission Catalog

```python
client.get_catalog("gate_my-service")
client.create_catalog("gate_my-service", permissions=[...])
client.publish_catalog("gate_my-service", change_summary="Added search permission")
client.list_catalog_versions("gate_my-service")
client.get_catalog_version("gate_my-service", version=1)
```

#### Constraints

```python
client.get_constraints("pp_xxx")
client.set_constraints("pp_xxx", {"read": {"core:rate:max_per_minute": 100}})
client.list_constraint_types(category="cost")
client.list_constraint_templates(category="security")
client.apply_constraint_template("pp_xxx", "conservative-agent")
```

#### Enforcement (CEL)

```python
client.enforce_action(passport_id="pp_xxx", action="write", cost_cents=500)
client.list_enforcement_attestations("pp_xxx", decision="BLOCK")
client.get_enforcement_attestation("enf_xxx")
client.verify_enforcement_attestation("enf_xxx")
```

#### Anonymous Access

```python
client.get_anonymous_policy("gate_my-service")
client.set_anonymous_policy("gate_my-service", enabled=True, allowed_actions=["read"])
```

#### Commerce

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

#### Cumulative State

```python
client.get_cumulative_state("pp_xxx")
client.reset_cumulative_state("pp_xxx", window_type="daily")
```

### Cryptographic Verification

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

### Error Handling

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

---

## Local Development

For local testing against a development dashboard:

**npm:**

```json
{
  "mcpServers": {
    "uniplex": {
      "command": "npx",
      "args": ["uniplex-mcp-manage"],
      "env": {
        "UNIPLEX_API_URL": "http://localhost:3000",
        "UNIPLEX_API_KEY": "uni_test_xxxxxxxx"
      }
    }
  }
}
```

**Python:**

```json
{
  "mcpServers": {
    "uniplex": {
      "command": "uvx",
      "args": ["uniplex-mcp-manage"],
      "env": {
        "UNIPLEX_API_URL": "http://localhost:3000",
        "UNIPLEX_API_KEY": "uni_test_xxxxxxxx"
      }
    }
  }
}
```

---

## Troubleshooting

**Server doesn't appear in Claude Desktop**
Make sure you've restarted Claude Desktop after editing the config file. Check for JSON syntax errors in your config — a trailing comma or missing bracket will silently fail.

**"Invalid API key" error**
Verify your key starts with `uni_live_` (production) or `uni_test_` (development) and hasn't been revoked in the dashboard.

**Tools aren't showing up**
Run `uvx uniplex-mcp-manage` directly in your terminal to check for startup errors. Ensure you're running Python 3.10+.

---

## Learn More

- [Uniplex Protocol Specification](https://github.com/uniplexprotocol/uniplex)
- [Documentation & Guides](https://uniplex.io)
- [Python SDK](https://pypi.org/project/uniplex-mcp-manage/) · [TypeScript SDK](https://www.npmjs.com/package/uniplex-mcp-manage)
- [Discussions](https://github.com/uniplexprotocol/uniplex/discussions) — Questions and ideas
- [@uniplexprotocol](https://x.com/uniplexprotocol) — Updates and announcements

---

## License

MIT — [Standard Logic Co.](https://standardlogic.ai)

Building the trust infrastructure for AI agents.

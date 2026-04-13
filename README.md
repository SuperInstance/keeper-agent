# 🛡️ Keeper Agent

> The secret proxy and security guardian for the Pelagic AI fleet.
> Holds ALL secrets for a SuperInstance and ensures they never leak outside the secure network.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    Pelagic AI Fleet                              │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Agent A  │  │ Agent B  │  │ Agent C  │  │ Agent D  │        │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│       │              │              │              │              │
│       └──────────────┴──────┬───────┴──────────────┘              │
│                              │                                   │
│                    ┌─────────▼─────────┐                         │
│                    │   Keeper Proxy    │  ◄── HTTP :8877         │
│                    │   (proxy.py)      │                         │
│                    └─────────┬─────────┘                         │
│                              │                                   │
│                    ┌─────────▼─────────┐                         │
│                    │   Keeper Agent    │  ◄── Core Engine        │
│                    │   (keeper.py)     │                         │
│                    │                   │                         │
│                    │  ┌─────────────┐  │                         │
│                    │  │ Secret Vault│  │  ◄── Encrypted at rest │
│                    │  └─────────────┘  │                         │
│                    │  ┌─────────────┐  │                         │
│                    │  │Agent Registry│ │  ◄── Auth + Scopes      │
│                    │  └─────────────┘  │                         │
│                    │  ┌─────────────┐  │                         │
│                    │  │Leak Detector│  │  ◄── Pattern scanning   │
│                    │  └─────────────┘  │                         │
│                    │  ┌─────────────┐  │                         │
│                    │  │Rate Limiter │  │  ◄── Per-agent limits   │
│                    │  └─────────────┘  │                         │
│                    │  ┌─────────────┐  │                         │
│                    │  │ Audit Trail │  │  ◄── JSONL log          │
│                    │  └─────────────┘  │                         │
│                    └─────────┬─────────┘                         │
│                              │                                   │
│                    ┌─────────▼─────────┐                         │
│                    │  External APIs    │  ◄── GitHub, AWS, etc.  │
│                    └───────────────────┘                         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## How It Works

1. **Registration** — Fleet agents register with the Keeper and receive an auth token.
2. **Secret Storage** — Agents store secrets (API keys, tokens, certs) in the encrypted vault.
3. **Reference Tokens** — Agents request opaque reference tokens instead of raw secrets.
4. **Proxy Requests** — Agents send outbound requests through the Keeper proxy, embedding reference tokens (`$SECRET_REF:<token>`).
5. **Secret Injection** — The Keeper resolves reference tokens and injects real secrets server-side.
6. **Double-Check** — Before forwarding, the LeakDetector scans the entire request for accidental secret leakage.
7. **Audit** — Every operation is logged to an append-only JSONL audit trail.

## Quick Start

```bash
# Set the master encryption key
export KEEPER_MASTER_KEY="your-very-strong-master-key-here"

# Start the Keeper proxy server
python -m keeper_agent start --port 8877

# In another terminal — check status
python -m keeper_agent status

# Register an agent
curl -X POST http://localhost:8877/register \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent-001", "public_key": "ssh-rsa AAAA..."}'

# Store a secret
curl -X POST http://localhost:8877/secret/store \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent-001", "token": "<token>", "secret_id": "gh-token", "value": "ghp_..."}'

# Get a secret reference
curl -X POST http://localhost:8877/secret/reference \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "agent-001", "token": "<token>", "secret_id": "gh-token"}'

# Review audit trail
python -m keeper_agent audit
python -m keeper_agent export-audit --format csv --output audit.csv
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `start` | Start the Keeper proxy server |
| `status` | Show Keeper health and stats |
| `audit` | Review the audit trail |
| `list-agents` | List all registered agents |
| `revoke-agent <id>` | Emergency-revoke an agent |
| `revoke-secret <id>` | Revoke a specific secret |
| `export-audit` | Export audit trail to JSON/CSV |
| `rotate-key` | Rotate the master encryption key |

## Project Structure

```
keeper-agent/
├── __main__.py          # Entry point (python -m keeper_agent)
├── cli.py               # CLI argument parser and subcommands
├── keeper.py            # Core KeeperAgent engine
├── leak_detector.py     # Pattern-based secret leak detection
├── proxy.py             # HTTP proxy server (stdlib http.server)
├── tests/
│   ├── __init__.py
│   └── test_keeper.py   # Comprehensive test suite
├── pyproject.toml       # Package configuration
└── README.md            # This file
```

## Leak Detection Patterns

The LeakDetector catches:

- GitHub PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- AWS Access Key IDs (`AKIA...`)
- Bearer tokens and Authorization headers
- PEM private keys (RSA, EC, DSA, OpenSSH)
- Database connection strings (postgres, mysql, mongodb, redis, amqp)
- JSON Web Tokens (JWTs)
- Slack tokens (`xoxb-`, `xoxp-`)
- Stripe keys (`sk_test_`, `pk_live_`)
- Google API keys (`AIza...`)
- Environment variable secrets in `.env` format
- External IP addresses (in PARANOID mode)

## Security Model

- **Encryption at rest**: AES-GCM (via `cryptography` package) with PBKDF2-derived key
- **Fallback**: XOR + HMAC-SHA256 if `cryptography` is unavailable
- **Agent isolation**: Agent A cannot access Agent B's secrets
- **Reference tokens**: Secrets never leave the vault — agents receive opaque tokens
- **Double-checker**: Every proxied request is scanned for accidental leakage
- **Revocation**: Instant agent and secret revocation
- **Audit trail**: Append-only JSONL log of all operations
- **Rate limiting**: Per-agent rate limits prevent abuse

## License

MIT

# keeper-agent

> **Secret-keeper proxy for FLUX Fleet standalone agents.**
> Holds all API keys centrally, issues scoped tokens, and double-checks that no secrets leave the SuperInstance.

## The Problem

When you give an agent an API key, that key lives on the agent's machine. If the agent is compromised, the key leaks. If the agent sends the key to a third-party API, it's gone.

## The Solution

**Keeper-agent** is a centralized proxy that sits between standalone agents and external APIs.

```
Standalone Agent ──▶ Keeper-Agent ──▶ External API
                        │
                   ┌────▼────┐
                   │  Vault   │  ← Real API keys live here
                   │ Scanner  │  ← Double-checks every request/response
                   │  Audit   │  ← Logs everything
                   └──────────┘
```

Agents never hold real API keys. They get scoped JWT tokens from the keeper. All API calls go through the keeper, which injects credentials, scans for leakage, and logs everything.

## Core Components

### Vault (`src/vault.ts`)
Encrypted secret storage. Holds real API keys (OpenAI, Anthropic, GitHub PATs, etc.) loaded from environment variables (`KEEPER_SECRET_*`). Never exposes raw secrets to agents — only injects them into outbound API calls.

### Auth (`src/auth.ts`)
Token lifecycle management. Registers agents, issues scoped JWT tokens (RS256), validates tokens, and supports instant revocation — per-token or per-agent.

### Secret Scanner (`src/scanner.ts`)
The "double-checker." Scans every request and response for potential secret leakage using:
- **Pattern matching**: GitHub PATs, OpenAI keys, AWS keys, Slack tokens, private keys, etc.
- **Vault comparison**: Checks if any text matches a vault secret
- **Entropy analysis**: Detects high-entropy strings that look like randomly generated secrets
- **Header inspection**: Catches auth headers being accidentally forwarded

### Proxy Engine (`src/proxy.ts`)
The core request pipeline. For every proxied call:
1. Validate JWT token + check revocation
2. Check scope permissions (e.g. `openai:chat`, `github:read`)
3. Scan incoming request for leaked secrets → BLOCK if unsafe
4. Inject real API key from vault (strips any auth from agent)
5. Forward to target API
6. Scan response for leaked secrets → REDACT if found
7. Audit log everything

### Audit Log (`src/audit.ts`)
Structured logging with risk levels (0=info, 1=warning, 2=critical). Filterable by agent, event type, or risk level. Exportable as JSON for SIEM integration.

## API Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/status` | Keeper status (agents, secrets, audit count) |
| `POST` | `/api/v1/auth/register` | Register a new agent |
| `POST` | `/api/v1/auth/token` | Issue a scoped JWT token |
| `POST` | `/api/v1/auth/validate` | Validate a token |
| `POST` | `/api/v1/auth/revoke` | Revoke a token or agent |
| `POST` | `/api/v1/proxy/:provider/*` | Proxy an API call |
| `GET` | `/api/v1/vault` | List vault entries (masked) |
| `POST` | `/api/v1/vault` | Add a secret to the vault |
| `DELETE` | `/api/v1/vault/:provider` | Remove a vault secret |
| `GET` | `/api/v1/agents` | List registered agents |
| `GET` | `/api/v1/audit` | Get audit log entries |
| `POST` | `/api/v1/scan` | Test the secret scanner |

## Security Model

### What Agents Get
- A scoped JWT token (e.g. `openai:chat`, `github:read`)
- The keeper's URL
- Their agent identity

### What Agents NEVER Get
- Real API keys
- GitHub PATs
- Other agents' tokens
- Vault contents

### What the Keeper Does
- Holds all real credentials in encrypted storage
- Injects credentials into outbound API calls
- Strips all auth headers from incoming agent requests
- Scans every byte that enters or leaves the system
- Blocks requests that contain potential secrets
- Redacts secrets found in API responses
- Logs every operation with risk levels
- Can revoke any agent or token instantly

### Compromise Containment
If a standalone agent is compromised:
1. The attacker gets a scoped JWT — not the real API key
2. The token has limited scopes and expiry
3. The keeper can revoke the token instantly
4. The audit log shows exactly what the compromised agent did
5. The real API keys were never on the agent's machine

## Quick Start

```bash
# Install
npm install

# Set secrets (in production, use GitHub Secrets or a secrets manager)
export KEEPER_SECRET_OPENAI_API_KEY=sk-...
export KEEPER_SECRET_GITHUB_PAT=ghp_...

# Run
npm run dev

# Test
npm test
```

## Standalone Agent Integration

A standalone agent connecting to this keeper would:

1. **Register**: `POST /api/v1/auth/register` with agentId, agentName
2. **Get token**: `POST /api/v1/auth/token` with agentId and desired scopes
3. **Make API calls**: `POST /api/v1/proxy/openai/v1/chat/completions` with token and request body
4. The keeper validates, scans, injects credentials, forwards, scans response, and returns

## Token Scopes

Format: `provider:permission`

Examples:
- `openai:chat` — Can call OpenAI chat completions
- `openai:*` — Can call any OpenAI endpoint
- `github:read` — Can read from GitHub API
- `github:write` — Can write to GitHub API
- `*` — Superuser (admin only)

## Tests

54 comprehensive tests covering:
- Vault: CRUD, agent restrictions, masking, case insensitivity
- Auth: Registration, token lifecycle, scope checking, revocation, wildcards
- Scanner: GitHub PATs, OpenAI keys, AWS keys, private keys, Bearer tokens, vault matching, sanitization, HTTP headers
- Audit: Event logging, filtering, risk levels, export
- Proxy: Token validation, scope enforcement, secret blocking, vault injection, revocation
- HTTP API: All endpoints, error handling

## License

MIT

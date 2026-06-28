# Agent Provider

The Agent Provider is an AAuth server role responsible for agent lifecycle management, including registration, key management, and token issuance.

## Overview

The Agent Provider implements the following responsibilities:

- **Agent Registration**: Register new agents with the system
- **Key Management**: Manage agent public keys for token verification
- **Token Issuance**: Issue `aa-agent+jwt` tokens for registered agents
- **Discovery Metadata**: Publish `.well-known/aauth-agent-provider` for client discovery

## Quick Start

```go
import (
    "github.com/plexusone/agentauth/server/agentprovider"
    "github.com/plexusone/agentauth/store"
)

// Create store
db, _ := store.NewSQLite("agents.db")
db.EnsureAgentProviderTables()

// Create Agent Provider
provider, _ := agentprovider.New(
    db,
    "https://auth.example.com",
    signingKey,
    "key-1",
    agentprovider.WithTokenTTL(time.Hour),
    agentprovider.WithLogger(logger),
)

// Register HTTP handlers
mux := http.NewServeMux()
provider.RegisterHandlers(mux)

http.ListenAndServe(":8080", mux)
```

## Endpoints

### Discovery

#### GET /.well-known/aauth-agent-provider

Returns Agent Provider metadata for client discovery.

**Response:**

```json
{
  "issuer": "https://auth.example.com",
  "token_endpoint": "https://auth.example.com/token",
  "registration_endpoint": "https://auth.example.com/agents",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "token_types_supported": ["aa-agent+jwt"],
  "signing_algs_supported": ["ES256", "ES384", "ES512", "EdDSA"],
  "grant_types_supported": ["client_credentials"]
}
```

#### GET /.well-known/jwks.json

Returns the Agent Provider's public signing keys in JWK Set format.

### Agent Registration

#### POST /agents

Register a new agent.

**Request:**

```json
{
  "id": "aauth:my-agent@example.com",
  "name": "My Agent",
  "description": "An example agent",
  "public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  },
  "metadata": {
    "version": "1.0.0"
  }
}
```

**Response:**

```json
{
  "id": "aauth:my-agent@example.com",
  "issuer": "https://auth.example.com",
  "key_id": "generated-key-id",
  "token_url": "https://auth.example.com/token"
}
```

#### GET /agents/{id}

Get agent information.

**Response:**

```json
{
  "id": "aauth:my-agent@example.com",
  "name": "My Agent",
  "description": "An example agent",
  "issuer": "https://auth.example.com",
  "status": "active",
  "created_at": "2026-06-27T10:00:00Z",
  "keys": [
    {
      "key_id": "key-1",
      "algorithm": "ES256",
      "created_at": "2026-06-27T10:00:00Z"
    }
  ]
}
```

#### DELETE /agents/{id}

Revoke an agent. Returns 204 No Content on success.

### Key Management

#### POST /agents/{id}/keys

Add a new key to an agent.

**Request:**

```json
{
  "public_key": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  },
  "expires_in": 86400
}
```

**Response:**

```json
{
  "key_id": "new-key-id",
  "created_at": "2026-06-27T10:00:00Z",
  "expires_at": "2026-06-28T10:00:00Z"
}
```

#### GET /agents/{id}/keys

List agent keys.

**Response:**

```json
{
  "keys": [
    {
      "key_id": "key-1",
      "algorithm": "ES256",
      "created_at": "2026-06-27T10:00:00Z",
      "expires_at": null
    }
  ]
}
```

#### DELETE /agents/{id}/keys/{kid}

Revoke a specific key. Returns 204 No Content on success.

### Token Issuance

#### POST /token

Issue an agent token.

**Request (JSON):**

```json
{
  "grant_type": "client_credentials",
  "agent_id": "aauth:my-agent@example.com",
  "audience": "https://api.example.com"
}
```

**Request (Form):**

```
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&agent_id=aauth:my-agent@example.com&audience=https://api.example.com
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImFhLWFnZW50K2p3dCIsImtpZCI6ImtleS0xIn0...",
  "token_type": "aa-agent+jwt",
  "expires_in": 3600
}
```

## Configuration

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithLogger(logger)` | Set structured logger | `slog.Default()` |
| `WithTokenTTL(ttl)` | Default token lifetime | `1 hour` |
| `WithAlgorithm(alg)` | Signing algorithm | `ES256` |

### Example

```go
provider, err := agentprovider.New(
    store,
    "https://auth.example.com",
    privateKey,
    "signing-key-1",
    agentprovider.WithTokenTTL(2 * time.Hour),
    agentprovider.WithAlgorithm("ES384"),
    agentprovider.WithLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
)
```

## Storage

The Agent Provider uses the `AgentProviderStorer` interface:

```go
type AgentProviderStorer interface {
    Storer // Embeds base storer

    // Agent operations
    RegisterAgent(ctx context.Context, agent *RegisteredAgent) error
    GetRegisteredAgent(ctx context.Context, id string) (*RegisteredAgent, error)
    ListRegisteredAgents(ctx context.Context, ownerID string) ([]*RegisteredAgent, error)
    RevokeRegisteredAgent(ctx context.Context, id string) error

    // Key operations
    CreateAgentKey(ctx context.Context, key *AgentKey) error
    GetAgentKey(ctx context.Context, agentID, keyID string) (*AgentKey, error)
    ListAgentKeys(ctx context.Context, agentID string) ([]*AgentKey, error)
    RevokeAgentKey(ctx context.Context, agentID, keyID string) error

    // Token operations
    CreateIssuedAgentToken(ctx context.Context, token *IssuedAgentToken) error
    GetIssuedAgentToken(ctx context.Context, jti string) (*IssuedAgentToken, error)
    RevokeIssuedAgentToken(ctx context.Context, jti string) error
}
```

### SQLite Implementation

```go
import "github.com/plexusone/agentauth/store"

db, err := store.NewSQLite("agents.db")
if err != nil {
    log.Fatal(err)
}

// Create Agent Provider tables
if err := db.EnsureAgentProviderTables(); err != nil {
    log.Fatal(err)
}
```

## Token Format

Agent tokens issued by the Agent Provider follow the AAuth specification:

```json
{
  "typ": "aa-agent+jwt",
  "alg": "ES256",
  "kid": "key-1"
}
{
  "iss": "https://auth.example.com",
  "sub": "aauth:my-agent@example.com",
  "aud": ["https://api.example.com"],
  "iat": 1719489600,
  "exp": 1719493200,
  "jti": "unique-token-id",
  "cnf": {
    "jkt": "thumbprint-of-agent-public-key"
  }
}
```

## Related

- [Token Verification](../orchestration/verifier.md) - Verify agent tokens
- [Unified Client](../client/getting-started.md) - Client SDK for agents
- [Storage](../storage/overview.md) - Storage backends

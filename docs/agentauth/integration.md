# OmniAgent Integration

This guide shows how to integrate AgentAuth tokens with [OmniAgent](https://github.com/plexusone/omniagent), an OpenAI-compatible API server.

## Overview

OmniAgent supports both ID-JAG (automatic) and AAuth (human consent) tokens through a unified verifier with action-based routing:

- **ID-JAG**: Automatic authorization for low-risk actions (read, chat, list)
- **AAuth**: Human consent required for sensitive actions (write, delete, admin)

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│   Agent     │────>│   OmniAgent     │────>│   LLM       │
│             │     │ (AgentAuth)     │     │  Backend    │
└─────────────┘     └─────────────────┘     └─────────────┘
       │                    │
       │ ID-JAG or         │ Validates + Routes
       │ AAuth Token       │ by Action
       v                    v
┌─────────────────────────────────────────┐
│          AgentAuth Server               │
│  (AuthzServer for ID-JAG)              │
│  (PersonServer for AAuth)               │
└─────────────────────────────────────────┘
```

## Configuration

### AgentAuth Configuration (Recommended)

The unified `AgentAuth` configuration supports both protocols with action-based routing:

```go
import (
    "github.com/plexusone/omniagent/api/openai"
    "github.com/plexusone/omniagent/api/openai/auth"
)

// Configure unified agent authentication
agentAuthCfg := &auth.AgentAuthConfig{
    Enabled: true,

    // ID-JAG configuration (automatic authorization)
    IDJAGEnabled: true,
    IDJAGIssuers: map[string]string{
        "https://idp.example.com": "", // JWKS URL auto-discovered
    },
    IDJAGAudience: "https://omniagent.example.com",

    // AAuth configuration (human consent)
    AAuthEnabled: true,
    AAuthIssuers: map[string]string{
        "https://ps.example.com": "", // JWKS URL auto-discovered
    },
    AAuthAudience: "https://omniagent.example.com",

    // Actions requiring AAuth (human consent)
    SensitiveActions: []string{
        "write", "delete", "update", "create",
        "send", "upload", "admin",
    },
}

server, _ := openai.New(handler,
    openai.WithAgentAuth(agentAuthCfg),
)
```

### Environment Variables

```bash
# Enable AgentAuth (unified)
export AGENTAUTH_ENABLED=true

# ID-JAG issuers (comma-separated issuer URLs)
export AGENTAUTH_IDJAG_ISSUERS=https://idp.example.com
export AGENTAUTH_IDJAG_AUDIENCE=https://omniagent.example.com

# AAuth issuers (comma-separated issuer URLs)
export AGENTAUTH_AAUTH_ISSUERS=https://ps.example.com
export AGENTAUTH_AAUTH_AUDIENCE=https://omniagent.example.com

# Sensitive actions (comma-separated)
export AGENTAUTH_SENSITIVE_ACTIONS=write,delete,update,create,send,upload,admin

# Start OmniAgent
omniagent openai serve --port 8081
```

### Legacy AAuth Configuration (Deprecated)

For backward compatibility, the original AAuth-only configuration still works:

```bash
# Deprecated: Use AgentAuth instead
export AUTH_AAUTH_ENABLED=true
export AUTH_AAUTH_ISSUER=http://localhost:8080
export AUTH_AAUTH_AUDIENCE=http://localhost:8081
```

## Action-Based Routing

The unified verifier routes tokens based on the action being performed:

| Action Contains | Required Protocol | Example Actions |
|-----------------|-------------------|-----------------|
| `write` | AAuth | write_file, data_write |
| `delete` | AAuth | delete_user, remove_item |
| `update` | AAuth | update_profile, edit_config |
| `create` | AAuth | create_account, new_item |
| `send` | AAuth | send_email, send_message |
| `upload` | AAuth | upload_file, upload_image |
| `admin` | AAuth | admin_panel, admin_config |
| (other) | ID-JAG | read, chat, list, view |

### Custom Action Policy

Override routing for specific actions:

```go
agentAuthCfg := &auth.AgentAuthConfig{
    // ...
    ActionPolicy: map[string]agentauth.Protocol{
        "read_sensitive_data": auth.ProtocolAAuth,  // Upgrade to AAuth
        "safe_batch_write":    auth.ProtocolIDJAG,  // Note: still matches "write"
    },
}
```

**Note:** Sensitive action patterns take precedence over custom action policy.

## Token Flow

### ID-JAG Flow (Automatic)

For non-sensitive actions, agents use ID-JAG for automatic authorization:

```bash
# 1. Agent creates signed assertion
# 2. Exchange assertion for access token
curl -X POST https://authz.example.com/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=eyJ..."

# 3. Use token with OmniAgent (read action)
curl -X GET http://localhost:8081/v1/models \
  -H "Authorization: Bearer eyJ..."
```

### AAuth Flow (Human Consent)

For sensitive actions, agents use AAuth requiring human approval:

```bash
# 1. Request authorization
curl -X POST http://localhost:8080/aauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "agent_token": "demo-agent",
    "user_id": "demo-user",
    "scope": "files:write",
    "mission_name": "Update Configuration"
  }'

# Response (pending consent)
{
  "status": "pending",
  "consent_uri": "http://localhost:8080/aauth/consent/mission-uuid"
}

# 2. Human approves via consent_uri

# 3. Poll for token
curl http://localhost:8080/aauth/consent/status/mission-uuid

# 4. Use token with OmniAgent (write action)
curl -X POST http://localhost:8081/api/files \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"content": "..."}'
```

## Accessing Claims in Handlers

### Get AgentAuth Claims (Recommended)

```go
import "github.com/plexusone/omniagent/api/openai"

func handler(ctx context.Context, req *Request) (*Response, error) {
    // Get unified claims (works for both ID-JAG and AAuth)
    claims := openai.GetAgentAuthClaims(ctx)
    if claims != nil {
        log.Printf("Agent: %s, Protocol: %s", claims.Subject, claims.Protocol)
        log.Printf("Scopes: %v", claims.Scopes)

        if claims.Actor != nil {
            log.Printf("Acting on behalf of: %s", claims.Actor.Subject)
        }
    }
    // ...
}
```

### Check Protocol Type

```go
claims := openai.GetAgentAuthClaims(ctx)
if claims != nil {
    switch claims.Protocol {
    case auth.ProtocolIDJAG:
        // Automatic authorization - may have more limited trust
        log.Println("ID-JAG authenticated agent")
    case auth.ProtocolAAuth:
        // Human-consented - higher trust for sensitive operations
        log.Println("AAuth authenticated with human consent")
    }
}
```

### Check Scopes

```go
claims := openai.GetAgentAuthClaims(ctx)
if claims != nil {
    if claims.HasScope("files:write") {
        // Agent has write permission
    }
    if claims.HasAnyScope("admin", "superuser") {
        // Agent has admin access
    }
}
```

## Client SDK Integration

### Go Agent with Protocol Selection

```go
package main

import (
    "context"
    "log"

    "github.com/aistandardsio/agent-protocols/agentauth"
)

func main() {
    ctx := context.Background()

    // Create provider with both protocols
    provider, _ := agentauth.NewHybridProvider(agentauth.HybridConfig{
        IDJAG: &agentauth.IDJAGConfig{
            Issuer:       "https://idp.example.com",
            TokenURL:     "https://authz.example.com/token",
            PrivateKey:   privateKey,
        },
        AAuth: &agentauth.AAuthConfig{
            AgentID:      "my-agent",
            PersonServer: "https://ps.example.com",
            PrivateKey:   privateKey,
        },
        Policy: agentauth.DefaultPolicy(), // Routes based on scopes
    })

    // For read operations - automatically uses ID-JAG
    readResult, _ := provider.Authorize(ctx, &agentauth.AuthRequest{
        Scopes:   []string{"files:read"},
        Resource: "https://omniagent.example.com",
    })
    log.Printf("Read token (ID-JAG): %s", readResult.Token)

    // For write operations - automatically uses AAuth
    writeResult, _ := provider.Authorize(ctx, &agentauth.AuthRequest{
        Scopes:      []string{"files:write"},
        Resource:    "https://omniagent.example.com",
        MissionName: "Update Files",
    })

    if writeResult.Status == agentauth.StatusPending {
        log.Printf("Human consent required: %s", writeResult.ConsentURI)
        // Wait for consent
        writeResult, _ = provider.WaitForConsent(ctx, writeResult.StatusURI, 5*time.Minute)
    }
    log.Printf("Write token (AAuth): %s", writeResult.Token)
}
```

## Pre-Authorization

For AAuth, you can pre-authorize agents to skip the consent flow:

```bash
# Pre-authorize agent for user
curl -X POST http://localhost:8080/aauth/preauthorize \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "demo-user",
    "agent_id": "demo-agent",
    "scopes": "files:write files:read"
  }'
```

**Note:** Pre-authorization uses exact scope matching. If you pre-authorize `files:*`, the agent must request exactly `files:*`, not `files:read`.

## Demo Script

A complete demo script is available:

```bash
cd examples/omniagent-aauth
./demo.sh
```

This demonstrates:

1. Starting AgentAuth server with demo data
2. ID-JAG token exchange for read operations
3. AAuth consent flow for write operations
4. Making authenticated requests to OmniAgent

## Token Validation

OmniAgent validates agent tokens by:

1. **Detecting protocol** - Checks token structure and issuer
2. **Fetching JWKS** - Downloads public keys from issuer's JWKS endpoint
3. **Verifying signature** - Ensures token was signed by trusted issuer
4. **Checking claims** - Validates `iss`, `aud`, `exp`, `scope`
5. **Action routing** - Verifies token protocol matches action requirements

### Token Structure (ID-JAG)

```json
{
  "iss": "https://idp.example.com",
  "sub": "agent-123",
  "aud": ["https://omniagent.example.com"],
  "client_id": "agent-123",
  "scope": "files:read models:list",
  "exp": 1234567890,
  "iat": 1234564290,
  "jti": "assertion-uuid"
}
```

### Token Structure (AAuth)

```json
{
  "iss": "https://ps.example.com",
  "sub": "agent-123",
  "aud": ["https://omniagent.example.com"],
  "scope": "files:write",
  "exp": 1234567890,
  "iat": 1234564290,
  "jti": "token-uuid",
  "act": {
    "sub": "user-456"
  },
  "mission_id": "mission-uuid"
}
```

## Security Considerations

1. **Use HTTPS** - Always use TLS in production
2. **Validate audience** - Ensure tokens are meant for your service
3. **Short token TTL** - Use short-lived tokens (1-2 hours)
4. **Scope restrictions** - Grant minimal required scopes
5. **Action enforcement** - Verify token protocol matches action sensitivity
6. **Separate issuers** - Use different issuers for ID-JAG and AAuth for clarity

## Troubleshooting

### Token Validation Fails

1. Check issuer URL matches token's `iss` claim
2. Verify JWKS endpoint is accessible
3. Check token hasn't expired
4. Verify audience matches token's `aud` claim

### Wrong Protocol for Action

If you receive "action requires AAuth (human consent), got idjag token":

1. Check `SensitiveActions` configuration
2. Ensure sensitive operations use AAuth tokens
3. Verify action name doesn't inadvertently match sensitive patterns

### JWKS Fetch Fails

```bash
# Test JWKS endpoint
curl https://issuer.example.com/.well-known/jwks.json
```

## Migration from AAuth-Only

To migrate from the legacy AAuth-only configuration:

1. Replace `WithAAuth` with `WithAgentAuth`
2. Move AAuth issuer to `AAuthIssuers` map
3. Add ID-JAG issuers if using automatic authorization
4. Configure `SensitiveActions` for action-based routing

```go
// Before (legacy)
openai.WithAAuth(&auth.AAuthConfig{
    Enabled:   true,
    IssuerURL: "https://ps.example.com",
    Audience:  "https://omniagent.example.com",
})

// After (unified)
openai.WithAgentAuth(&auth.AgentAuthConfig{
    Enabled:      true,
    IDJAGEnabled: true,
    IDJAGIssuers: map[string]string{"https://idp.example.com": ""},
    IDJAGAudience: "https://omniagent.example.com",
    AAuthEnabled: true,
    AAuthIssuers: map[string]string{"https://ps.example.com": ""},
    AAuthAudience: "https://omniagent.example.com",
})
```

## Next Steps

- [Deployment](deployment.md) - Deploy AgentAuth to production
- [API Reference](api-reference.md) - Full endpoint documentation
- [Overview](overview.md) - Architecture and concepts

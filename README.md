# AgentAuth

[![Go CI][go-ci-svg]][go-ci-url]
[![Go Lint][go-lint-svg]][go-lint-url]
[![Go SAST][go-sast-svg]][go-sast-url]
[![Go Report Card][goreport-svg]][goreport-url]
[![Docs][docs-godoc-svg]][docs-godoc-url]
[![Docs][docs-mkdoc-svg]][docs-mkdoc-url]
[![Visualization][viz-svg]][viz-url]
[![License][license-svg]][license-url]

 [go-ci-svg]: https://github.com/plexusone/agentauth/actions/workflows/go-ci.yaml/badge.svg?branch=main
 [go-ci-url]: https://github.com/plexusone/agentauth/actions/workflows/go-ci.yaml
 [go-lint-svg]: https://github.com/plexusone/agentauth/actions/workflows/go-lint.yaml/badge.svg?branch=main
 [go-lint-url]: https://github.com/plexusone/agentauth/actions/workflows/go-lint.yaml
 [go-sast-svg]: https://github.com/plexusone/agentauth/actions/workflows/go-sast-codeql.yaml/badge.svg?branch=main
 [go-sast-url]: https://github.com/plexusone/agentauth/actions/workflows/go-sast-codeql.yaml
 [goreport-svg]: https://goreportcard.com/badge/github.com/plexusone/agentauth
 [goreport-url]: https://goreportcard.com/report/github.com/plexusone/agentauth
 [docs-godoc-svg]: https://pkg.go.dev/badge/github.com/plexusone/agentauth
 [docs-godoc-url]: https://pkg.go.dev/github.com/plexusone/agentauth
 [docs-mkdoc-svg]: https://img.shields.io/badge/Go-dev%20guide-blue.svg
 [docs-mkdoc-url]: https://plexusone.dev/agentauth
 [viz-svg]: https://img.shields.io/badge/Go-visualizaton-blue.svg
 [viz-url]: https://mango-dune-07a8b7110.1.azurestaticapps.net/?repo=plexusone%2Fagentauth
 [loc-svg]: https://tokei.rs/b1/github/plexusone/agentauth
 [repo-url]: https://github.com/plexusone/agentauth
 [license-svg]: https://img.shields.io/badge/license-MIT-blue.svg
 [license-url]: https://github.com/plexusone/agentauth/blob/main/LICENSE

Layered identity composition for AI agents, combining AAuth, ID-JAG, and SPIFFE.

## Overview

AgentAuth provides a composition layer for AI agent authentication that properly combines three complementary identity protocols:

| Protocol | Identity Layer | Purpose |
|----------|---------------|---------|
| **AAuth** | Agent | "Which autonomous agent is this? What mission is it executing?" |
| **ID-JAG** | Human | "Which user is this agent acting for?" |
| **SPIFFE** | Workload | "Which workload/service is hosting this?" |

These protocols operate at **different layers** and should be **composed**, not chosen between.

### v0.3.0 Features

- **Unified Client SDK** - Single interface for multi-protocol authentication with policy-based routing
- **Unified Verifier** - Multi-protocol token verification with automatic protocol detection and JWKS caching
- **Agent Provider** - Server-side agent registration, key management, and token issuance

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Human Identity                           │
│  OIDC / SAML / Enterprise IdP                                   │
│  ID-JAG (delegated user identity for cross-app access)          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Identity                           │
│  AAuth Protocol                                                 │
│  agent_id, mission_id, delegation, subagents                    │
│  HTTP Message Signatures, Proof-of-Possession                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Workload Identity                          │
│  SPIFFE/SPIRE, mTLS                                             │
│  spiffe://domain/path                                           │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
                    Protected Resources
```

## Installation

```bash
go get github.com/plexusone/agentauth
```

## Usage

### Composed Identity

The core abstraction is `ComposedIdentity`, which links all three identity layers:

```go
import "github.com/plexusone/agentauth/identity"

// Create a composer with verifiers
composer := identity.NewComposer(
    identity.WithAAuthVerifier(aauthVerifier),
    identity.WithIDJAGVerifier(idjagVerifier),
    identity.WithWorkloadVerifier(spiffeVerifier),
)

// Compose identities from credentials
composed, err := composer.Compose(ctx, identity.ComposeOptions{
    AAuthToken:     aauthToken,
    IDJAGAssertion: idjagAssertion,
    IncludeWorkload: true,
})

// Use composed identity for authorization decisions
fmt.Println(composed.AuditString())
// Output: agent:research-agent for-human:alice@example.com on-workload:spiffe://prod/research binding:bind-xyz
```

### Context Integration

```go
// Store identity in context
ctx = identity.WithContext(ctx, composed)

// Later, retrieve it
if id, ok := identity.FromContext(ctx); ok {
    log.Info("processing request",
        "agent", id.Agent.AgentID,
        "user", id.Human.Subject,
        "workload", id.Workload.SPIFFEID,
    )
}
```

### Storage

```go
import "github.com/plexusone/agentauth/store"

// Create SQLite store
db, err := store.NewSQLite("auth.db")

// Create mission (AAuth)
mission := &store.Mission{
    AgentID:         "research-agent",
    UserID:          "user-123",
    Name:            "Research Task",
    Scopes:          "read:docs write:notes",
    InteractionType: "supervised",
}
err = db.CreateMission(ctx, mission)
```

### Unified Token Verification (v0.3.0)

The `verifier` package provides multi-protocol token verification with automatic protocol detection:

```go
import "github.com/plexusone/agentauth/verifier"

// Create verifier with trusted issuers
v, _ := verifier.New(
    verifier.WithTrustedIssuers(
        "https://auth.example.com",
        "https://consent.example.com",
    ),
    verifier.WithProtocols(verifier.ProtocolAAuth, verifier.ProtocolIDJAG),
    verifier.WithJWKSCache(time.Hour),
)

// Verify any token (auto-detects protocol)
claims, err := v.Verify(ctx, tokenString)
if err != nil {
    return err
}

fmt.Printf("Protocol: %s\n", claims.Protocol)   // "aauth" or "idjag"
fmt.Printf("Token Type: %s\n", claims.TokenType) // "aa-agent+jwt", "aa-auth+jwt", etc.
fmt.Printf("Subject: %s\n", claims.Subject)
fmt.Printf("Scopes: %v\n", claims.Scopes)
```

Use HTTP middleware for protected resources:

```go
// Apply to protected routes
mux.Handle("/api/", v.Middleware(apiHandler))
mux.Handle("/api/admin/", v.RequireScopes("admin:*")(adminHandler))
```

### Hybrid Provider (Protocol Routing)

The `HybridProvider` routes authorization requests to ID-JAG or AAuth based on policies:

```go
import "github.com/plexusone/agentauth"

// Configure hybrid provider
config := &agentauth.Config{
    Policy: &agentauth.PolicyConfig{
        Default:   agentauth.ProtocolIDJAG, // Use ID-JAG by default
        Sensitive: agentauth.ProtocolAAuth, // Require AAuth for sensitive scopes
        Rules: map[string]agentauth.Protocol{
            "admin:*":  agentauth.ProtocolAAuth,
            "write:*":  agentauth.ProtocolAAuth,
            "read:*":   agentauth.ProtocolIDJAG,
        },
    },
}

provider, err := agentauth.NewHybridProvider(config,
    agentauth.WithIDJAGProvider(idjagProvider),
    agentauth.WithAAuthProvider(aauthProvider),
)

// Authorization is routed based on scopes
result, err := provider.Authorize(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"read:email"},  // Routes to ID-JAG
})

result, err := provider.Authorize(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"write:profile"},  // Routes to AAuth (requires consent)
})
```

### Unified Client SDK (v0.3.0)

The `UnifiedClient` provides a single interface for multi-protocol authentication with policy-based routing:

```go
import "github.com/plexusone/agentauth/client"

// Create unified client
c, _ := client.NewUnified(
    client.WithAgentID("aauth:my-agent@example.com"),
    client.WithPrivateKey(privateKey, "key-1"),
    client.WithPersonServer("https://consent.example.com"),
    client.WithTokenEndpoint("https://auth.example.com/token"),
    client.WithPolicy(client.PolicyConfig{
        Default:     client.ProtocolIDJAG,                      // Default to automated
        AAuthScopes: []string{"write:*", "delete:*", "admin:*"}, // These require consent
    }),
    client.WithCaching(100),
)

// Request authorization - protocol selected automatically based on scopes
result, err := c.Authorize(ctx, &client.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"read:email"},  // Routes to ID-JAG (automated)
})

result, err := c.Authorize(ctx, &client.AuthRequest{
    Resource:    "https://api.example.com",
    Scopes:      []string{"write:profile"}, // Routes to AAuth (requires consent)
    MissionName: "Update User Profile",
})

if result.IsPending() {
    fmt.Println("Please approve at:", result.ConsentURI)
}

// Get an HTTP client with automatic authorization
httpClient := c.HTTPClient(&client.AuthRequest{
    Scopes: []string{"read:data"},
})
resp, _ := httpClient.Get("https://api.example.com/data")
```

### Legacy Client

The original client is still available for direct protocol usage:

```go
import "github.com/plexusone/agentauth/client"

// Create client
c := client.New("https://authz.example.com",
    client.WithPollTimeout(5 * time.Minute),
)

// ID-JAG token exchange (RFC 8693 - automated)
token, err := c.ExchangeIDJAG(ctx, idjagAssertion, "read:email read:profile")

// AAuth flow (human consent required)
result, err := c.RequestAuthorization(ctx, &client.AuthorizationRequest{
    AgentToken:  agentToken,
    UserID:      "user-123",
    Scopes:      "write:profile",
    MissionName: "Update User Profile",
})
```

### Agent Provider (v0.3.0)

The `server/agentprovider` package implements the AAuth Agent Provider role:

```go
import "github.com/plexusone/agentauth/server/agentprovider"

// Create Agent Provider
provider, _ := agentprovider.New(
    agentStore,
    "https://auth.example.com",
    signingKey,
    "key-1",
    agentprovider.WithTokenTTL(time.Hour),
    agentprovider.WithLogger(logger),
)

// Register HTTP handlers
mux := http.NewServeMux()
provider.RegisterHandlers(mux)
// Endpoints:
// GET  /.well-known/aauth-agent-provider - Discovery metadata
// GET  /.well-known/jwks.json            - Public keys
// POST /agents                           - Register new agent
// GET  /agents/{id}                      - Get agent info
// DELETE /agents/{id}                    - Revoke agent
// POST /agents/{id}/keys                 - Add key to agent
// POST /token                            - Issue agent token

http.ListenAndServe(":8080", mux)
```

## Package Structure

```
plexusone/agentauth/
├── identity/              # Layered identity composition
│   ├── types.go           # ComposedIdentity, HumanIdentity, AgentIdentity, WorkloadIdentity
│   └── composer.go        # Identity composer
├── store/                 # Storage abstractions
│   ├── interface.go       # Storer, AgentProviderStorer interfaces
│   ├── types.go           # User, Agent, Mission, Token, RegisteredAgent, etc.
│   ├── sqlite.go          # SQLite core implementation
│   └── sqlite_agentprovider.go  # SQLite Agent Provider implementation
├── client/                # Agent SDK for authentication
│   ├── client.go          # Legacy client (token exchange, consent flow)
│   └── unified.go         # Unified multi-protocol client (v0.3.0)
├── verifier/              # Multi-protocol token verification (v0.3.0)
│   ├── verifier.go        # Unified verifier with auto protocol detection
│   ├── middleware.go      # HTTP middleware
│   └── jwk.go             # JWK parsing utilities
├── server/                # Server-side components
│   └── agentprovider/     # Agent Provider role (v0.3.0)
│       ├── provider.go    # HTTP handlers
│       └── token.go       # Token issuance
├── verifier.go            # Legacy protocol router
├── hybrid.go              # HybridProvider for protocol routing
├── policy.go              # PolicyMatcher for scope-based routing
├── cmd/                   # Server binaries
│   └── agentauth-server/
├── lambda/                # AWS Lambda handlers
└── docs/
    └── specs/
        ├── ROADMAP.md     # Implementation roadmap
        └── PLAN.md        # Tactical implementation plan
```

## Key Concepts

### ComposedIdentity

Links all three identity layers with a unique binding:

- **BindingID**: Unique identifier for this composed identity
- **BoundAt**: When the identities were linked
- **ExpiresAt**: Earliest expiration of component identities
- **TraceID**: For distributed tracing

### Identity Layers

1. **Human Identity** (ID-JAG): User the agent acts for
2. **Agent Identity** (AAuth): The autonomous agent with its mission
3. **Workload Identity** (SPIFFE): Infrastructure hosting the agent

### Request Flow

1. Agent sends request with:
   - AAuth token (agent identity)
   - ID-JAG assertion (human identity)
   - mTLS with SVID (workload identity)

2. Server composes identities:
   - Verify AAuth token → AgentIdentity
   - Verify ID-JAG assertion → HumanIdentity
   - Extract SPIFFE ID from TLS → WorkloadIdentity
   - Create ComposedIdentity with binding

3. Authorization decision uses all three:
   - "Agent X acting for Human Y on Workload Z"
   - Full audit trail with all identities linked

## Related Projects

- [agent-protocols](https://github.com/aistandardsio/agent-protocols) - Pure protocol implementations
- [agent-standards-catalog](https://github.com/aistandardsio/agent-standards-catalog) - Standards catalog

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

MIT License

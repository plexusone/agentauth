# AgentAuth

Layered identity composition for AI agents, combining AAuth, ID-JAG, and SPIFFE.

## Overview

AgentAuth provides a composition layer for AI agent authentication that properly combines three complementary identity protocols:

| Protocol | Identity Layer | Purpose |
|----------|---------------|---------|
| **AAuth** | Agent | "Which autonomous agent is this? What mission is it executing?" |
| **ID-JAG** | Human | "Which user is this agent acting for?" |
| **SPIFFE** | Workload | "Which workload/service is hosting this?" |

These protocols operate at **different layers** and should be **composed**, not chosen between.

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

## Quick Start

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

## Package Structure

```
plexusone/agentauth/
├── identity/              # Layered identity composition
│   ├── types.go           # ComposedIdentity, HumanIdentity, AgentIdentity, WorkloadIdentity
│   └── composer.go        # Identity composer
├── store/                 # Storage abstractions
│   ├── interface.go       # Storer, AgentProviderStorer interfaces
│   ├── types.go           # User, Agent, Mission, Token, etc.
│   ├── sqlite.go          # SQLite implementation
│   └── sqlite_agentprovider.go  # Agent Provider store (v0.3.0)
├── client/                # Agent SDK
│   ├── client.go          # Token exchange, consent flow
│   └── unified.go         # Unified multi-protocol client (v0.3.0)
├── verifier/              # Token verification (v0.3.0)
│   ├── verifier.go        # Multi-protocol verifier
│   └── middleware.go      # HTTP middleware
├── server/                # Server components
│   └── agentprovider/     # Agent Provider (v0.3.0)
├── cmd/                   # CLI tools
│   └── agentauth-server/
├── lambda/                # AWS Lambda handlers
│   └── peopleserver/
└── examples/              # Example applications
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

## Related Projects

- [agent-protocols](https://github.com/aistandardsio/agent-protocols) - Pure protocol implementations (AAuth, ID-JAG, AIMS)
- [agent-standards-catalog](https://github.com/aistandardsio/agent-standards-catalog) - Standards catalog

## Next Steps

- [AgentAuth Overview](agentauth/overview.md) - Unified authorization layer
- [Getting Started](agentauth/getting-started.md) - Quick start guide
- [Agent Provider](agentauth/agent-provider.md) - Agent registration and token issuance (v0.3.0)
- [Deployment](agentauth/deployment.md) - AWS Lambda deployment
- [API Reference](agentauth/api-reference.md) - Endpoint documentation
- [Release Notes](releases/v0.3.0.md) - What's new in v0.3.0

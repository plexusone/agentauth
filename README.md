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

## Package Structure

```
plexusone/agentauth/
├── identity/          # Layered identity composition
│   ├── types.go       # ComposedIdentity, HumanIdentity, AgentIdentity, WorkloadIdentity
│   └── composer.go    # Identity composer
├── store/             # Storage abstractions
│   ├── interface.go   # Storer interface
│   ├── types.go       # User, Agent, Mission, Token, etc.
│   └── sqlite.go      # SQLite implementation
├── personserver/      # AAuth Person Server (TODO)
├── authzserver/       # ID-JAG Authorization Server (TODO)
└── docs/
    └── specs/
        └── ROADMAP.md # Implementation roadmap
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

## License

MIT License

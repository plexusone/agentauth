# Open Agent Internet Architecture - Multi-Repo Roadmap

This document outlines the comprehensive plan for restructuring agent authentication and authorization across five repositories, based on the layered identity model where AAuth, ID-JAG, and SPIFFE operate at complementary layers rather than as alternatives.

## Executive Summary

### Key Insight

From the ideation analysis, three identity protocols serve different purposes:

| Protocol | Identity | Layer | Purpose |
|----------|----------|-------|---------|
| **AAuth** | Agent | Mission/Session | "Which autonomous agent is this? What mission is it executing?" |
| **ID-JAG** | Human | User delegation | "Which user is this agent acting for?" |
| **SPIFFE** | Workload | Infrastructure | "Which workload/service is hosting this?" |

These are **complementary layers**, not alternatives. The correct architecture composes them:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Human Identity                            │
│  OIDC / SAML / Enterprise IdP                                   │
│  ID-JAG (delegated user identity for cross-app access)          │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Identity                            │
│  AAuth Protocol                                                  │
│  agent_id, mission_id, delegation, subagents                     │
│  HTTP Message Signatures, Proof-of-Possession                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Workload Identity                           │
│  SPIFFE/SPIRE, mTLS                                              │
│  spiffe://domain/path                                            │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
                    Protected Resources
```

## Repository Overview

### 1. grokify/standards-catalog-framework

**Purpose:** Generic framework for creating and managing standards catalogs.

**Path:** `~/go/src/github.com/grokify/standards-catalog-framework`

**Scope:**

- Schema definitions for standards catalogs (JSON Schema, Go types)
- Validation tools for catalog entries
- CLI for catalog management
- Documentation generation
- Import/export utilities

### 2. aistandardsio/agent-standards-catalog

**Purpose:** Catalog of AI agent-related standards using the framework.

**Path:** `~/go/src/github.com/aistandardsio/agent-standards-catalog`

**Scope:**

- Catalog entries for AAuth, ID-JAG, SPIFFE, SCIM, A2A, MCP, AGNTCY
- Comparison matrices
- Adoption guides
- Implementation status tracking

### 3. aistandardsio/agent-protocols

**Purpose:** Pure protocol implementations (no composition logic).

**Path:** `~/go/src/github.com/aistandardsio/agent-protocols`

**Scope:**

- `aauth/` - AAuth protocol types and client
- `idjag/` - ID-JAG protocol types and client
- `aims/` - AIMS/SPIFFE integration
- `scimext/` - SCIM extensions for agents
- `adapters/` - IdP adapters (Zitadel, Ory, etc.)

### 4. plexusone/agentauth

**Purpose:** Composition layer combining protocols for unified authorization.

**Path:** `~/go/src/github.com/plexusone/agentauth`

**Scope:**

- PersonServer (AAuth authorization server)
- AuthzServer (ID-JAG authorization server)
- Layered identity composition (not alternative routing)
- Storage abstractions (SQLite, DynamoDB)
- Client SDK for composed flows

### 5. aistandardsio/oaiaf

**Purpose:** Open Agent Internet Architecture Framework - canonical agent definitions and multi-protocol orchestration.

**Path:** `~/go/src/github.com/aistandardsio/oaiaf`

**Scope:**

- `agent-spec` canonical definitions
- Identity binding profiles (linking SPIFFE + AAuth + ID-JAG)
- Protocol projections (generate A2A cards, MCP manifests, etc.)
- Architecture documentation
- Reference implementations

---

## Phase 1: Foundation (standards-catalog-framework)

### 1.1 Schema Definition

Create JSON Schema for standards catalog entries:

```yaml
# schema/standard.schema.json
- id: unique identifier
- name: human-readable name
- version: semantic version
- status: draft | proposed | adopted | deprecated
- organization: issuing body
- specUrl: link to specification
- category: authentication | authorization | identity | provisioning | communication
- layer: human | agent | workload | transport
- protocols: list of related protocols
- implementations: list of known implementations
- compatibleWith: list of compatible standards
- supersedes: list of superseded standards
```

### 1.2 Go Types

```go
// standards-catalog-framework/catalog/types.go
type Standard struct {
    ID             string            `json:"id"`
    Name           string            `json:"name"`
    Version        string            `json:"version"`
    Status         StandardStatus    `json:"status"`
    Organization   string            `json:"organization"`
    SpecURL        string            `json:"spec_url"`
    Category       Category          `json:"category"`
    Layer          IdentityLayer     `json:"layer"`
    Protocols      []string          `json:"protocols,omitempty"`
    Implementations []Implementation `json:"implementations,omitempty"`
    CompatibleWith []string          `json:"compatible_with,omitempty"`
    Supersedes     []string          `json:"supersedes,omitempty"`
}

type Catalog struct {
    Version   string     `json:"version"`
    Standards []Standard `json:"standards"`
}
```

### 1.3 CLI Tool

```bash
# Commands
standards-catalog validate <catalog.json>
standards-catalog lint <catalog.json>
standards-catalog generate-docs <catalog.json> -o docs/
standards-catalog export <catalog.json> --format=markdown|html|json
standards-catalog compare <id1> <id2>
```

### 1.4 Deliverables

- [ ] `catalog/types.go` - Core types
- [ ] `catalog/validate.go` - Validation logic
- [ ] `schema/standard.schema.json` - JSON Schema
- [ ] `cmd/standards-catalog/` - CLI tool
- [ ] `README.md` - Documentation
- [ ] Unit tests

---

## Phase 2: Agent Standards Catalog

### 2.1 Initial Catalog Entries

```yaml
standards:
  - id: aauth
    name: AAuth Protocol
    version: "02"
    status: draft
    organization: IETF
    specUrl: https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/
    category: authorization
    layer: agent
    protocols: [oauth2, http-signatures]

  - id: id-jag
    name: Identity Assertion JWT Authorization Grant
    version: "04"
    status: draft
    organization: IETF
    specUrl: https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/
    category: authorization
    layer: human
    protocols: [oauth2, jwt]

  - id: spiffe
    name: SPIFFE
    version: "1.0"
    status: adopted
    organization: CNCF
    specUrl: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
    category: identity
    layer: workload

  - id: a2a
    name: Agent-to-Agent Protocol
    version: "1.0"
    status: proposed
    organization: Google
    specUrl: https://a2a-protocol.org/
    category: communication
    layer: agent

  - id: mcp
    name: Model Context Protocol
    version: "1.0"
    status: adopted
    organization: Anthropic
    specUrl: https://modelcontextprotocol.io/
    category: communication
    layer: agent
```

### 2.2 Comparison Matrices

Create comparison documents:

- AAuth vs OAuth 2.0
- ID-JAG vs OAuth Token Exchange
- SPIFFE vs mTLS
- A2A vs MCP vs AGNTCY

### 2.3 Deliverables

- [ ] `catalog/agent-standards.json` - Main catalog
- [ ] `docs/comparisons/` - Comparison matrices
- [ ] `docs/adoption/` - Adoption guides
- [ ] `README.md` - Documentation

---

## Phase 3: Refactor agent-protocols

### 3.1 Current State

The `agent-protocols` repo currently contains:

```
agent-protocols/
├── aauth/          # AAuth protocol implementation
├── idjag/          # ID-JAG protocol implementation
├── aims/           # AIMS/SPIFFE
├── scimext/        # SCIM extensions
├── adapters/       # IdP adapters
├── agentauth/      # COMPOSITION LAYER (to be moved)
├── bridge/         # Protocol bridges
├── docs/           # Documentation
└── examples/       # Examples
```

### 3.2 Target State

Move `agentauth/` to separate repo, keep only pure protocol implementations:

```
agent-protocols/
├── aauth/          # AAuth protocol types, client, HTTP signatures
│   ├── agent.go
│   ├── mission.go
│   ├── token.go
│   ├── httpsig/
│   └── examples/
├── idjag/          # ID-JAG protocol types, client, token exchange
│   ├── assertion.go
│   ├── verifier.go
│   ├── exchange.go
│   └── examples/
├── aims/           # AIMS/SPIFFE integration
├── scimext/        # SCIM extensions for agents
├── adapters/       # IdP adapters
├── bridge/         # Protocol bridges (lightweight)
└── docs/           # Protocol documentation only
```

### 3.3 Changes Required

1. **Remove `agentauth/`** - Move to plexusone/agentauth
2. **Remove composition examples** - Move to agentauth or oaiaf
3. **Update go.mod** - Remove composition dependencies
4. **Update docs** - Focus on individual protocol usage

### 3.4 Deliverables

- [ ] Move `agentauth/` to new repo
- [ ] Update `go.mod` and imports
- [ ] Update documentation
- [ ] Create migration guide

---

## Phase 4: Create plexusone/agentauth

### 4.1 Architecture

The key change: **Layered composition instead of alternative routing.**

```
OLD (incorrect):
  Request → PolicyMatcher → AAuth OR ID-JAG → Token

NEW (correct):
  Human Identity (ID-JAG) ─────────────┐
                                        │
  Agent Identity (AAuth) ───────────────┼─→ Composed Authorization
                                        │
  Workload Identity (SPIFFE) ──────────┘
```

### 4.2 Package Structure

```
plexusone/agentauth/
├── cmd/
│   └── agentauth-server/    # Combined server binary
├── personserver/            # AAuth PersonServer
│   ├── server.go
│   ├── handlers.go
│   ├── consent.go
│   └── templates/
├── authzserver/             # ID-JAG AuthzServer
│   ├── server.go
│   ├── handlers.go
│   ├── policy.go
│   └── verifier.go
├── identity/                # NEW: Layered identity composition
│   ├── composer.go          # Composes all three identity layers
│   ├── human.go             # ID-JAG human identity
│   ├── agent.go             # AAuth agent identity
│   ├── workload.go          # SPIFFE workload identity
│   └── binding.go           # Cross-protocol identity binding
├── store/                   # Storage abstractions
│   ├── interface.go
│   ├── sqlite.go
│   └── dynamodb.go
├── client/                  # Client SDK
│   ├── client.go
│   └── composed.go
├── config/                  # Configuration
├── docs/
│   └── specs/
│       └── ROADMAP.md       # This file
└── lambda/                  # AWS Lambda deployment
```

### 4.3 Identity Composer

The core new abstraction:

```go
// identity/composer.go
package identity

// ComposedIdentity links all three identity layers
type ComposedIdentity struct {
    // Human identity (from ID-JAG)
    Human *HumanIdentity `json:"human,omitempty"`

    // Agent identity (from AAuth)
    Agent *AgentIdentity `json:"agent"`

    // Workload identity (from SPIFFE)
    Workload *WorkloadIdentity `json:"workload,omitempty"`

    // Binding metadata
    BindingID   string    `json:"binding_id"`
    BoundAt     time.Time `json:"bound_at"`
    TraceID     string    `json:"trace_id,omitempty"`
}

type HumanIdentity struct {
    Subject   string   `json:"sub"`
    Issuer    string   `json:"iss"`
    Email     string   `json:"email,omitempty"`
    Name      string   `json:"name,omitempty"`
    // From ID-JAG assertion
    IDJAGAssertion string `json:"idjag_assertion,omitempty"`
}

type AgentIdentity struct {
    AgentID     string   `json:"agent_id"`
    MissionID   string   `json:"mission_id,omitempty"`
    Issuer      string   `json:"iss"`
    Capabilities []string `json:"capabilities,omitempty"`
    // From AAuth token
    AAuthToken string `json:"aauth_token,omitempty"`
}

type WorkloadIdentity struct {
    SPIFFEID string `json:"spiffe_id"`
    // From SVID
    SVID string `json:"svid,omitempty"`
}

// Composer creates and validates composed identities
type Composer struct {
    idjagVerifier  idjag.Verifier
    aauthVerifier  aauth.Verifier
    spiffeSource   workloadapi.X509Source
}

// Compose creates a ComposedIdentity from available credentials
func (c *Composer) Compose(ctx context.Context, opts ComposeOptions) (*ComposedIdentity, error)

// Verify validates all components of a ComposedIdentity
func (c *Composer) Verify(ctx context.Context, identity *ComposedIdentity) error
```

### 4.4 Request Flow

```
1. Agent sends request with:
   - AAuth token (agent identity)
   - ID-JAG assertion reference (human identity)
   - mTLS with SVID (workload identity)

2. Server composes identities:
   - Verify AAuth token → AgentIdentity
   - Fetch/verify ID-JAG → HumanIdentity
   - Extract SPIFFE ID from TLS → WorkloadIdentity
   - Create ComposedIdentity with binding

3. Authorization decision uses all three:
   - "Agent X acting for Human Y on Workload Z"
   - Full audit trail with all identities linked
```

### 4.5 Deliverables

- [ ] Move `agentauth/` from agent-protocols
- [ ] Refactor to layered model
- [ ] Create `identity/` package
- [ ] Update PersonServer and AuthzServer
- [ ] Update client SDK
- [ ] Create comprehensive tests
- [ ] Update documentation

---

## Phase 5: Create aistandardsio/oaiaf

### 5.1 Purpose

OAIAF (Open Agent Internet Architecture Framework) provides:

1. **agent-spec** - Canonical agent definitions
2. **Identity binding profiles** - How to link SPIFFE + AAuth + ID-JAG
3. **Protocol projections** - Generate A2A cards, MCP manifests from agent-spec
4. **Architecture documentation** - Reference architecture

### 5.2 Package Structure

```
aistandardsio/oaiaf/
├── agentspec/               # Canonical agent specification
│   ├── spec.go              # Core types
│   ├── validate.go          # Validation
│   └── schema/
│       └── agent-spec.schema.json
├── binding/                 # Identity binding profiles
│   ├── profile.go
│   ├── spiffe_aauth.go      # SPIFFE ↔ AAuth binding
│   ├── aauth_idjag.go       # AAuth ↔ ID-JAG binding
│   └── full_chain.go        # Complete binding
├── projection/              # Protocol projections
│   ├── a2a.go               # Generate A2A AgentCard
│   ├── mcp.go               # Generate MCP manifest
│   ├── openapi.go           # Generate OpenAPI extensions
│   └── aauth.go             # Generate AAuth capabilities
├── cmd/
│   └── oaiaf/               # CLI tool
├── docs/
│   ├── architecture.md
│   ├── identity-layers.md
│   └── binding-profiles.md
└── examples/
    └── enterprise-agent/
```

### 5.3 Agent Spec

```yaml
# Example agent-spec.yaml
apiVersion: oaiaf.aistandardsio/v1
kind: AgentSpec
metadata:
  id: research-agent
  version: 1.0.0

identity:
  agentId: research-agent
  issuer: https://agents.example.com
  spiffeId: spiffe://example.com/prod/research-agent

skills:
  - id: summarize.text
    description: Summarize documents
    inputs: [text/markdown, application/pdf]
    outputs: [text/markdown]
  - id: jira.search
    description: Search Jira issues

protocolFeatures:
  a2a:
    streaming: true
    pushNotifications: true
  aauth:
    interaction: true
    clarification: true
    payment: false

security:
  authn:
    - aauth
    - spiffe
  delegation:
    - id-jag
    - oauth-token-exchange

tools:
  - id: jira
    type: api
    scopes: [read:issues]
  - id: github
    type: api
    scopes: [repo:read]

policy:
  humanApprovalRequired:
    - payment
    - production-change
```

### 5.4 Protocol Projections

```go
// projection/a2a.go
func GenerateA2ACard(spec *agentspec.Spec) (*a2a.AgentCard, error)

// projection/mcp.go
func GenerateMCPManifest(spec *agentspec.Spec) (*mcp.Manifest, error)

// projection/aauth.go
func GenerateAAuthCapabilities(spec *agentspec.Spec) ([]string, error)
```

### 5.5 Deliverables

- [ ] `agentspec/` package with schema
- [ ] `binding/` package for identity linking
- [ ] `projection/` package for protocol generation
- [ ] CLI tool
- [ ] Architecture documentation
- [ ] Examples

---

## Implementation Order

### Sprint 1: Foundation

1. **standards-catalog-framework** (2-3 days)
   - Schema and types
   - Validation
   - Basic CLI

2. **agent-standards-catalog** (1-2 days)
   - Initial catalog entries
   - Basic comparisons

### Sprint 2: Protocol Refactoring

3. **agent-protocols cleanup** (2-3 days)
   - Move agentauth to new repo
   - Update imports
   - Documentation

4. **plexusone/agentauth** (3-5 days)
   - Move code from agent-protocols
   - Refactor to layered model
   - Create identity composer
   - Tests

### Sprint 3: Architecture Framework

5. **oaiaf** (3-5 days)
   - agent-spec schema
   - Identity binding
   - Protocol projections
   - CLI and examples

---

## Dependencies

```
standards-catalog-framework
         │
         ▼
agent-standards-catalog

agent-protocols ◄───────────────┐
    │                           │
    │  imports                  │  imports
    ▼                           │
plexusone/agentauth ────────────┤
    │                           │
    │  imports                  │
    ▼                           │
oaiaf ◄─────────────────────────┘
```

---

## Migration Guide

### For agent-protocols Users

```go
// Before
import "github.com/aistandardsio/agent-protocols/agentauth"

// After
import "github.com/plexusone/agentauth"
```

### For OmniAgent

Update `go.mod`:

```go
require (
    github.com/aistandardsio/agent-protocols v0.6.0  // protocols only
    github.com/plexusone/agentauth v0.1.0            // composition layer
)
```

---

## Success Criteria

1. **Clean separation** - Each repo has single responsibility
2. **Layered identity** - AAuth, ID-JAG, SPIFFE compose correctly
3. **No circular deps** - Clear dependency graph
4. **Full audit** - ComposedIdentity enables complete audit trail
5. **Protocol projections** - agent-spec generates all protocol-specific views
6. **Documentation** - Each repo well-documented

---

## Open Questions

1. Should `bridge/` stay in agent-protocols or move to oaiaf?
2. Should lambda deployments stay with agentauth or move to separate repo?
3. Naming: Is "oaiaf" the right name? Alternatives: agent-arch, oaia, agentix

---

## References

- [IDEATION_CHAT_SPIFFE-AAUTH-IDJAG.md](../../IDEATION_CHAT_SPIFFE-AAUTH-IDJAG.md)
- [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- [SPIFFE](https://spiffe.io/)
- [A2A Protocol](https://a2a-protocol.org/)

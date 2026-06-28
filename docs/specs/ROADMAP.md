# Open Agent Internet Architecture - Multi-Repo Roadmap

This document outlines the comprehensive plan for restructuring agent authentication and authorization across five repositories, based on the layered identity model where AAuth, ID-JAG, and SPIFFE operate at complementary layers rather than as alternatives.

## Version Roadmap

| Version | Status | Focus |
|---------|--------|-------|
| **v0.1.0** | Released | Initial release with PersonServer + AuthzServer |
| **v0.2.0** | Released | Orchestration layer moved from agent-protocols, storage adapters |
| **v0.3.0** | **In Progress** | Unified SDK: `client/`, `server/`, `verifier/` packages + Agent Provider role |
| **v0.4.0** | Planned | Enterprise server: SCIM, Cedar/AuthZEN policy, Audit service |
| v0.5.0 | Future | Production hardening, Ent ORM, OpenFGA integration |

### v0.3.0 Progress (Current Focus)

| Component | Status |
|-----------|--------|
| Unified Client (`client/unified.go`) | ✓ Complete |
| Multi-protocol Verifier (`verifier/`) | ✓ Complete |
| Agent Provider (`server/agentprovider/`) | ✓ Complete |
| Store types & interface (`store/types.go`, `store/interface.go`) | ✓ Complete |
| SQLite AgentProviderStorer (`store/sqlite_agentprovider.go`) | ✓ Complete |
| Agent Provider tests | ✓ Complete |
| Update `cmd/agentauth-server` with `--ap` flag | Pending |
| Integration tests | Pending |
| Documentation updates | Pending |

### v0.4.0 Goals (Next)

1. **Person Server refactor** - Clean separation in `server/personserver/`
2. **Access Server refactor** - Clean separation in `server/accessserver/`
3. **Audit Service** - Comprehensive logging for compliance
4. **SCIM Agent Resource** - `/scim/v2/Agents` endpoints
5. **Policy Service** - Cedar policy engine with AuthZEN API
6. **Protected Resource example** - Demo service showing full flow

See [Phase 8](#phase-8-enterprise-server-architecture-v040) for full details.

---

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

## Phase 6: Testing, Quality & OAIAF Implementation

### 6.1 Testing & Quality

Comprehensive testing and quality improvements across all repositories.

#### Testing Tasks

| Task | Repository | Status | Description |
|------|------------|--------|-------------|
| Add tests for `aauth/personserver` | agent-protocols | **Complete** | Unit tests for Person Server handlers (38 tests) |
| Add tests for `store` adapters | plexusone/agentauth | **Complete** | Tests for PersonServerAdapter, AuthzServerAdapter (22 tests) |
| Add DynamoDB integration tests | plexusone/agentauth | Pending | Tests with DynamoDB Local |

#### Code Quality Tasks

| Task | Repository | Status | Description |
|------|------------|--------|-------------|
| Run golangci-lint | agent-protocols | **Complete** | Fixed gofmt/unparam; gosec warnings are OAuth false positives |
| Run golangci-lint | plexusone/agentauth | **Complete** | Fixed errcheck issues (0 issues now) |
| Run golangci-lint | oaiaf | **Complete** | 0 issues |

### 6.2 OAIAF Development

Full implementation of the OAIAF agent framework.

#### Core Implementation

| Task | Status | Description |
|------|--------|-------------|
| Implement token acquisition | **Complete** | Real token acquisition using agent-protocols |
| Add ID-JAG provider | **Complete** | Protocol-specific provider for ID-JAG (17 tests) |
| Add AAuth provider | **Complete** | Protocol-specific provider for AAuth with consent flow |
| Add AIMS provider | **Complete** | SPIFFE-based provider with mTLS support |
| Add provider selection | **Complete** | Automatic protocol selection based on configured protocol |

#### Examples & Documentation

| Task | Status | Description |
|------|--------|-------------|
| Create basic usage example | **Complete** | examples/basic - ID-JAG authorized requests |
| Create multi-protocol example | **Complete** | examples/multiprotocol - Protocol switching demo |
| Create consent flow example | **Complete** | examples/consent - Human-in-the-loop flow |
| Add API reference docs | **Complete** | README updated with API reference |

### 6.3 Infrastructure & CI/CD

Production infrastructure and continuous integration setup.

#### CI/CD Tasks

| Task | Repository | Status | Description |
|------|------------|--------|-------------|
| Set up GitHub Actions | agent-protocols | **Complete** | Build, test, lint with Go 1.22/1.23 |
| Set up GitHub Actions | plexusone/agentauth | **Complete** | Build, test, lint with Go 1.22/1.23 |
| Set up GitHub Actions | oaiaf | **Complete** | Build, test, lint with Go 1.22/1.23 |

#### Release Tasks

| Task | Repository | Status | Description |
|------|------------|--------|-------------|
| Create release tags | agent-protocols | Pending | Tag v0.6.0 with interface-based packages |
| Create release tags | plexusone/agentauth | Pending | Tag v0.1.0 initial release |
| Create release tags | oaiaf | Pending | Tag v0.1.0 initial release |

### 6.4 Documentation

Additional documentation and migration guides.

| Task | Repository | Status | Description |
|------|------------|--------|-------------|
| API reference for interface packages | agent-protocols | Pending | Document aauth/personserver and idjag/authzserver |
| Migration guide | agent-protocols | Pending | Guide from old to new packages |
| Integration guide | plexusone/agentauth | Pending | How to integrate with existing apps |

---

## Phase 7: Unified SDK (v0.3.0)

### 7.1 Motivation

The current architecture splits implementations across repos:

- **agent-protocols/** has protocol types + reference server implementations
- **agentauth/** has orchestration + storage + combined server

This creates friction for consumers like omniagent/ and agent-team-stats/ who must import multiple packages and understand the layering.

**Goal:** Make agentauth the **single integration point** for all agent authentication protocols.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        plexusone/agentauth                               │
│                      (Production-Ready SDK)                              │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   client/   │  │   server/   │  │  verifier/  │  │    store/   │    │
│  │             │  │             │  │             │  │             │    │
│  │ Unified API │  │ AP + PS +AS │  │ Multi-proto │  │ SQLite/Dyn  │    │
│  │ for agents  │  │ combined    │  │ validation  │  │             │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │ imports
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     aistandardsio/agent-protocols                        │
│                     (Protocol Specs + Types)                             │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │   aauth/    │  │   idjag/    │  │    aims/    │  │  scimext/   │    │
│  │   types     │  │   types     │  │   types     │  │   types     │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Package Structure

```
plexusone/agentauth/
├── client/                        # Unified client SDK
│   ├── client.go                  # Single Client type
│   ├── options.go                 # Configuration options
│   ├── transport.go               # HTTP transport with signatures
│   └── client_test.go
├── server/                        # Unified server SDK
│   ├── server.go                  # Combined server builder
│   ├── agentprovider/             # Agent Provider (AP) role
│   │   ├── provider.go            # AP implementation
│   │   ├── handlers.go            # HTTP handlers
│   │   ├── registration.go        # Agent registration
│   │   └── metadata.go            # /.well-known/aauth-agent
│   ├── personserver/              # Person Server (PS) role
│   │   ├── server.go              # Wraps agent-protocols impl
│   │   └── adapter.go             # Store adapter
│   └── authzserver/               # Authorization Server (AS) role
│       ├── server.go              # Wraps agent-protocols impl
│       └── adapter.go             # Store adapter
├── verifier/                      # Unified token verification
│   ├── verifier.go                # Multi-protocol verifier
│   ├── aauth.go                   # AAuth token verification
│   ├── idjag.go                   # ID-JAG token verification
│   ├── jwks.go                    # JWKS fetching/caching
│   └── verifier_test.go
├── store/                         # Storage backends (existing)
│   ├── interface.go               # Extended for AP operations
│   ├── sqlite.go
│   ├── dynamodb.go
│   └── agentprovider_adapter.go   # NEW: AP store adapter
├── identity/                      # Identity composition (existing)
├── cmd/agentauth-server/          # CLI binary
├── lambda/                        # AWS Lambda deployment
└── docs/
```

### 7.3 Unified Client API

Single import, unified API for all protocols:

```go
import "github.com/plexusone/agentauth/client"

// Create client with policy-based routing
c, err := client.New(
    client.WithAgentID("aauth:my-agent@example.com"),
    client.WithPrivateKey(key),
    client.WithPersonServer("https://ps.example.com"),
    client.WithPolicy(client.PolicyConfig{
        Default: client.ProtocolIDJAG,
        AAuthScopes: []string{"write:*", "admin:*", "delete:*"},
    }),
)

// Unified authorization - routes to correct protocol automatically
token, err := c.Authorize(ctx, &client.AuthRequest{
    Scopes:   []string{"read:stats"},
    Resource: "https://api.example.com",
})

// HTTP client with automatic token attachment
httpClient := c.HTTPClient()
resp, err := httpClient.Get("https://api.example.com/data")
```

### 7.4 Unified Server API

Single server combining all roles:

```go
import "github.com/plexusone/agentauth/server"

// Create combined server with selected roles
srv, err := server.New(
    server.WithIssuer("https://auth.example.com"),
    server.WithSigningKey(key, "key-1"),
    server.WithStore(sqliteStore),

    // Enable roles (default: all enabled)
    server.WithAgentProvider(),   // AP role
    server.WithPersonServer(),    // PS role
    server.WithAuthzServer(),     // AS role
)

// Register all handlers
srv.RegisterHandlers(mux)

// Or run standalone
srv.ListenAndServe(":8080")
```

Deployment flexibility via flags:

```bash
# Full identity provider (AP + PS + AS)
agentauth-server

# AAuth only (AP + PS)
agentauth-server --aauth-only

# ID-JAG only (AS)
agentauth-server --idjag-only

# Individual roles
agentauth-server --ap-only
agentauth-server --ps-only
agentauth-server --as-only
```

### 7.5 Unified Verifier API

For resource servers (like omniagent):

```go
import "github.com/plexusone/agentauth/verifier"

// Create multi-protocol verifier
v, err := verifier.New(
    verifier.WithTrustedIssuers("https://ps.example.com", "https://as.example.com"),
    verifier.WithProtocols(verifier.AAuth, verifier.IDJAG),
    verifier.WithJWKSCache(time.Hour),
)

// Verify token (auto-detects protocol)
claims, err := v.Verify(ctx, tokenString)
// claims.Protocol = "aauth" or "idjag"
// claims.Subject, claims.Issuer, claims.Scopes, etc.

// HTTP middleware
mux.Handle("/api/", v.Middleware(protectedHandler))
```

### 7.6 Store Extensions for Agent Provider

New operations in `store/interface.go`:

```go
// Agent Provider operations
RegisterAgent(ctx context.Context, agent *RegisteredAgent) error
GetRegisteredAgent(ctx context.Context, agentID string) (*RegisteredAgent, error)
UpdateAgent(ctx context.Context, agent *RegisteredAgent) error
RevokeAgent(ctx context.Context, agentID string) error
ListRegisteredAgents(ctx context.Context, ownerID string) ([]*RegisteredAgent, error)

// Agent key operations
CreateAgentKey(ctx context.Context, key *AgentKey) error
GetAgentKey(ctx context.Context, agentID, keyID string) (*AgentKey, error)
ListAgentKeys(ctx context.Context, agentID string) ([]*AgentKey, error)
RevokeAgentKey(ctx context.Context, agentID, keyID string) error

// Agent token operations
CreateAgentToken(ctx context.Context, token *AgentToken) error
GetAgentToken(ctx context.Context, jti string) (*AgentToken, error)
RevokeAgentToken(ctx context.Context, jti string) error
```

New types:

```go
type RegisteredAgent struct {
    ID          string            `json:"id"`           // aauth:name@domain
    Name        string            `json:"name"`
    Description string            `json:"description"`
    OwnerID     string            `json:"owner_id"`     // User who owns this agent
    Metadata    map[string]string `json:"metadata"`
    CreatedAt   time.Time         `json:"created_at"`
    RevokedAt   *time.Time        `json:"revoked_at,omitempty"`
}

type AgentKey struct {
    ID        string     `json:"id"`         // Key ID (kid)
    AgentID   string     `json:"agent_id"`
    PublicKey string     `json:"public_key"` // JWK format
    Algorithm string     `json:"algorithm"`  // ES256, EdDSA, etc.
    CreatedAt time.Time  `json:"created_at"`
    ExpiresAt *time.Time `json:"expires_at,omitempty"`
    RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
```

### 7.7 Integration with omniagent

Before (current):

```go
import (
    "github.com/aistandardsio/agent-protocols/aauth"
    "github.com/aistandardsio/agent-protocols/idjag"
    "github.com/plexusone/agentauth"
)

// Multiple verifiers, manual routing
aAuthVerifier := aauth.NewVerifier(...)
idJAGVerifier := idjag.NewVerifier(...)
hybridProvider := agentauth.NewHybridProvider(...)
```

After (v0.3.0):

```go
import "github.com/plexusone/agentauth/verifier"

// Single verifier handles all protocols
v, _ := verifier.New(
    verifier.WithTrustedIssuers("https://auth.example.com"),
)

// In HTTP handler
func (s *Server) authenticate(r *http.Request) (*verifier.Claims, error) {
    token := extractBearerToken(r)
    return s.verifier.Verify(r.Context(), token)
}
```

### 7.8 Deliverables

| Task | Priority | Description |
|------|----------|-------------|
| Create `client/` package | High | Unified client SDK wrapping existing providers |
| Create `verifier/` package | High | Multi-protocol token verification |
| Create `server/agentprovider/` | Medium | Agent Provider role implementation |
| Extend `store/interface.go` | Medium | Add AP operations |
| Update `cmd/agentauth-server` | Medium | Add `--ap` flag and AP endpoints |
| Create migration guide | High | Document upgrade path from v0.2.0 |
| Update omniagent integration | High | Switch to unified verifier |

### 7.9 Migration Path

```go
// v0.2.0 (current)
import "github.com/plexusone/agentauth"

provider := agentauth.NewHybridProvider(config)
result, err := provider.Authorize(ctx, req)

// v0.3.0 (unified)
import "github.com/plexusone/agentauth/client"

c, err := client.New(client.WithConfig(config))
result, err := c.Authorize(ctx, req)
```

Server migration:

```go
// v0.2.0 (current)
// Manual setup of personserver + authzserver

// v0.3.0 (unified)
import "github.com/plexusone/agentauth/server"

srv, err := server.New(
    server.WithStore(store),
    server.WithSigningKey(key, kid),
)
srv.RegisterHandlers(mux)
```

---

## Phase 8: Enterprise Server Architecture (v0.4.0)

Based on the July 2026 identity stack analysis, this phase expands the server architecture to support enterprise deployments with full lifecycle management, fine-grained authorization, and audit capabilities.

### 8.1 July 2026 Identity Stack

The foundational identity architecture for enterprise AI agents:

```
Identity Lifecycle
-------------------
SCIM Agent Resource

↓

Workload Identity
-------------------
WIMSE
    (SPIFFE today)

↓

Agent Identity
-------------------
AAuth

↓

Human Delegation
-------------------
OAuth
ID-JAG

↓

Resource Authorization
-------------------
OAuth
AuthZEN
(Cedar/OpenFGA)
```

### 8.2 Composable Server Architecture

One server binary with composable logical roles:

```
agent-auth-server
├── Agent Provider        # Agent registration, identity, token issuance
├── Person Server         # Human consent, approval, mission authorization
├── Access Server         # Resource-specific access decisions/tokens
├── SCIM Agent Registry   # Agent lifecycle, ownership, provisioning
├── Policy Service        # Cedar/OpenFGA via AuthZEN API
├── Token Service         # JWT/AAuth/OAuth token issuance
├── Key/JWKS Service      # Signing keys and discovery
└── Audit Service         # Comprehensive logging
```

| Role | Purpose |
|------|---------|
| **Agent Provider** | Registers agents, manages agent identity, publishes metadata, issues agent tokens |
| **Person Server** | Represents the human; handles consent, approval, mission authorization, interaction, audit |
| **Access Server** | Issues resource-specific access decisions/tokens; integrates with protected resources |
| **SCIM Agent Registry** | Stores/provisions agent lifecycle, owner, status, risk, entitlements |
| **Policy Service** | Evaluates permissions using Cedar and/or OpenFGA, exposed through AuthZEN |
| **Token Service** | Issues/verifies JWTs, AAuth tokens, OAuth-style access tokens |
| **Key/JWKS Service** | Manages signing keys and public key discovery |
| **Audit Service** | Logs human + agent + workload + mission + resource + decision |

### 8.3 SCIM Agent Resource Integration

SCIM in Agent Provider for demo/prototype, with path to enterprise IGA/IdP:

```
POST /scim/v2/Agents
GET  /scim/v2/Agents/{id}
PATCH /scim/v2/Agents/{id}
DELETE /scim/v2/Agents/{id}

GET  /.well-known/aauth-agent-provider
POST /agents
GET  /agents/{id}
POST /token
GET  /.well-known/jwks.json
```

**Deployment Modes:**

| Mode | SCIM Lives In | Agent Provider Role |
|------|--------------|---------------------|
| **Demo/prototype** | Same Agent Provider server | System of record + token issuer |
| **Enterprise production** | IGA / IdP / SCIM platform | Consumes approved agent records, issues runtime tokens |
| **Hybrid** | Agent Provider exposes SCIM but syncs with IGA | Local runtime registry + enterprise governance |

### 8.4 Policy Service (Cedar + AuthZEN)

Fine-grained authorization using Cedar as the primary policy engine:

```
Agent
   │
   │ AAuth
   ▼
Resource (PEP)
   │
   │ AuthZEN API
   ▼
Policy Decision Point
   │
   │ Cedar + OpenFGA
   ▼
ALLOW / DENY
```

**Why Cedar over OPA:**

- Schema-based validation
- Static policy validation and type checking
- Formal semantics with Lean verification
- Authorization-specific language
- Deterministic evaluation

**Cedar + OpenFGA Combination:**

```
AuthZEN API
      │
      ▼
Authorization Service
      │
      ├──────────────┐
      │              │
      ▼              ▼
   Cedar         OpenFGA
Policies      Relationships
```

Cedar answers: "Does this request satisfy these policies?"
OpenFGA answers: "What relationships exist?"

### 8.5 Package Structure

```
plexusone/agentauth/
├── cmd/
│   └── agentauth-server/     # Combined server binary
├── server/
│   ├── agentprovider/        # Agent Provider (AP) role ✓ (v0.3.0)
│   ├── personserver/         # Person Server (PS) role
│   ├── accessserver/         # Access Server (AS) role
│   ├── scim/                  # SCIM Agent Registry (NEW)
│   │   ├── handler.go
│   │   └── resource.go
│   ├── policy/                # Policy Service (NEW)
│   │   ├── authzen.go         # AuthZEN API handlers
│   │   ├── cedar.go           # Cedar policy evaluator
│   │   └── openfga.go         # OpenFGA relationship checker
│   └── audit/                 # Audit Service (NEW)
│       ├── logger.go
│       └── events.go
├── store/                     # Extended for all roles
│   ├── interface.go
│   ├── sqlite.go
│   ├── sqlite_agentprovider.go  ✓ (v0.3.0)
│   ├── sqlite_scim.go           (NEW)
│   └── sqlite_audit.go          (NEW)
├── client/                    # Unified client ✓ (v0.3.0)
├── verifier/                  # Multi-protocol verifier ✓ (v0.3.0)
├── identity/                  # Identity composition
└── docs/
```

### 8.6 Implementation Phases

#### Phase 8a: Core Roles (v0.4.0-alpha)

| Task | Priority | Description |
|------|----------|-------------|
| Review/enhance Person Server | High | Clean separation in `server/personserver/` |
| Review/enhance Access Server | High | Clean separation in `server/accessserver/` |
| Add Audit Service | Medium | Comprehensive logging for compliance |
| Add Protected Resource example | High | Demo service to show full flow |

#### Phase 8b: SCIM Integration (v0.4.0-beta)

| Task | Priority | Description |
|------|----------|-------------|
| Implement SCIM Agent Resource | Medium | `/scim/v2/Agents` endpoints |
| Add SCIM store operations | Medium | Store interface extensions |
| Sync with Agent Provider | Medium | Unified agent model |

#### Phase 8c: Policy Engine (v0.4.0-rc)

| Task | Priority | Description |
|------|----------|-------------|
| Add AuthZEN API | Medium | Standard authorization API |
| Integrate Cedar | Medium | Policy evaluation engine |
| Optional OpenFGA | Low | Relationship-based authorization |

### 8.7 Server Deployment Flags

```bash
# Full identity provider (all roles)
agentauth-server

# AAuth-focused (AP + PS)
agentauth-server --ap --ps

# ID-JAG-focused (AS)
agentauth-server --as

# Individual roles
agentauth-server --ap-only     # Agent Provider only
agentauth-server --ps-only     # Person Server only
agentauth-server --as-only     # Access Server only
agentauth-server --scim        # Enable SCIM endpoints
agentauth-server --audit       # Enable audit logging
agentauth-server --cedar       # Enable Cedar policy engine
```

### 8.8 Full Request Flow

```
1. Agent provisioned via SCIM
   POST /scim/v2/Agents

2. Agent registers with Agent Provider
   POST /agents (public key, metadata)

3. Agent requests mission authorization
   POST /missions (scopes, duration, resource)

4. Human approves mission (Person Server)
   POST /missions/{id}/approve

5. Agent requests access token
   POST /token (AAuth or ID-JAG flow)

6. Agent accesses resource
   GET /api/resource (Bearer token)

7. Resource checks authorization
   POST /authzen/access/v1/evaluation

8. Cedar evaluates policy
   ALLOW / DENY

9. All actions logged to Audit Service
```

### 8.9 Deliverables

| Task | Priority | Status |
|------|----------|--------|
| Agent Provider | High | ✓ Complete (v0.3.0) |
| SQLite AgentProviderStorer | High | ✓ Complete (v0.3.0) |
| Multi-protocol Verifier | High | ✓ Complete (v0.3.0) |
| Unified Client | High | ✓ Complete (v0.3.0) |
| Person Server refactor | High | Pending |
| Access Server refactor | High | Pending |
| Protected Resource example | High | Pending |
| Audit Service | Medium | Pending |
| SCIM Agent Resource | Medium | Pending |
| Policy Service (Cedar) | Low | Pending |
| AuthZEN API | Low | Pending |

---

## Open Questions

1. Should `bridge/` stay in agent-protocols or move to oaiaf?
2. Should lambda deployments stay with agentauth or move to separate repo?
3. Naming: Is "oaiaf" the right name? Alternatives: agent-arch, oaia, agentix
4. Should Cedar policies be embedded or loaded from files/database?
5. SCIM in Agent Provider vs separate service for enterprise?

---

## References

- [IDEATION_CHAT_SPIFFE-AAUTH-IDJAG.md](../../IDEATION_CHAT_SPIFFE-AAUTH-IDJAG.md)
- [draft-hardt-oauth-aauth-protocol](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
- [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
- [SPIFFE](https://spiffe.io/)
- [A2A Protocol](https://a2a-protocol.org/)

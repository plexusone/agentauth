# Implementation Plan

This document provides tactical implementation details for the agentauth roadmap. See [ROADMAP.md](ROADMAP.md) for strategic context.

## Current State (June 2026)

### Completed (v0.3.0)

- [x] `client/unified.go` - Multi-protocol client with policy-based routing
- [x] `verifier/` - Multi-protocol token verifier with JWKS caching
- [x] `server/agentprovider/` - Agent Provider HTTP handlers
- [x] `store/types.go` - RegisteredAgent, AgentKey, IssuedAgentToken types
- [x] `store/interface.go` - AgentProviderStorer interface
- [x] `store/sqlite_agentprovider.go` - SQLite implementation
- [x] `store/sqlite_agentprovider_test.go` - Comprehensive tests
- [x] `server/agentprovider/provider_test.go` - HTTP handler tests

### Pending (v0.3.0 completion)

- [ ] Update `cmd/agentauth-server` with `--ap` flag
- [ ] Integration tests for full flow
- [ ] Documentation updates

---

## v0.4.0 Implementation Plan

### Phase 8a: Core Roles

**Goal:** Clean separation of Person Server and Access Server, add Audit Service and Protected Resource example.

#### Task 1: Review cmd/agentauth-server Structure

```bash
# Current structure
cmd/agentauth-server/
├── main.go
└── handlers.go  # (if exists)
```

**Actions:**
1. Analyze current PS/AS implementation
2. Identify code to refactor into `server/personserver/` and `server/accessserver/`
3. Document current endpoints and behavior

#### Task 2: Person Server Refactor

Create `server/personserver/` package:

```go
// server/personserver/server.go
package personserver

type Server struct {
    store  store.Storer
    logger *slog.Logger
    issuer string
    // ...
}

func New(store store.Storer, issuer string, opts ...Option) (*Server, error)
func (s *Server) RegisterHandlers(mux *http.ServeMux)

// Endpoints
// POST /missions              - Create mission request
// GET  /missions/{id}         - Get mission status
// POST /missions/{id}/approve - Approve mission
// POST /missions/{id}/deny    - Deny mission
// GET  /missions              - List missions (for user)
// POST /consent               - Human consent flow
```

#### Task 3: Access Server Refactor

Create `server/accessserver/` package:

```go
// server/accessserver/server.go
package accessserver

type Server struct {
    store  store.Storer
    logger *slog.Logger
    issuer string
    // ...
}

func New(store store.Storer, issuer string, opts ...Option) (*Server, error)
func (s *Server) RegisterHandlers(mux *http.ServeMux)

// Endpoints
// POST /token                 - Token exchange (ID-JAG flow)
// POST /introspect            - Token introspection
// POST /revoke                - Token revocation
// GET  /.well-known/oauth-authorization-server
```

#### Task 4: Audit Service

Create `server/audit/` package:

```go
// server/audit/service.go
package audit

type Event struct {
    ID          string            `json:"id"`
    Timestamp   time.Time         `json:"timestamp"`
    EventType   EventType         `json:"event_type"`
    ActorType   ActorType         `json:"actor_type"` // human, agent, workload
    ActorID     string            `json:"actor_id"`
    Action      string            `json:"action"`
    Resource    string            `json:"resource"`
    ResourceID  string            `json:"resource_id,omitempty"`
    Result      ResultType        `json:"result"` // success, failure, denied
    Metadata    map[string]string `json:"metadata,omitempty"`
    TraceID     string            `json:"trace_id,omitempty"`
}

type EventType string
const (
    EventAgentRegistered   EventType = "agent.registered"
    EventAgentRevoked      EventType = "agent.revoked"
    EventMissionCreated    EventType = "mission.created"
    EventMissionApproved   EventType = "mission.approved"
    EventMissionDenied     EventType = "mission.denied"
    EventTokenIssued       EventType = "token.issued"
    EventTokenRevoked      EventType = "token.revoked"
    EventAccessGranted     EventType = "access.granted"
    EventAccessDenied      EventType = "access.denied"
)

type Service struct {
    store  store.AuditStorer
    logger *slog.Logger
}

func (s *Service) Log(ctx context.Context, event *Event) error
func (s *Service) Query(ctx context.Context, filter *QueryFilter) ([]*Event, error)
```

Store interface extension:

```go
// store/interface.go
type AuditStorer interface {
    CreateAuditEvent(ctx context.Context, event *AuditEvent) error
    ListAuditEvents(ctx context.Context, filter *AuditFilter) ([]*AuditEvent, error)
}
```

#### Task 5: Protected Resource Example

Create `examples/protected-resource/`:

```go
// examples/protected-resource/main.go
package main

import (
    "github.com/plexusone/agentauth/verifier"
)

func main() {
    // Create verifier
    v, _ := verifier.New(
        verifier.WithTrustedIssuers("http://localhost:8080"),
    )

    // Protected endpoints
    mux := http.NewServeMux()
    mux.Handle("/api/", v.Middleware(apiHandler))
    mux.Handle("/api/admin/", v.RequireScopes("admin:*")(adminHandler))

    http.ListenAndServe(":8081", mux)
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    claims := verifier.ClaimsFromContext(r.Context())
    json.NewEncoder(w).Encode(map[string]any{
        "message": "Hello, agent!",
        "subject": claims.Subject,
        "scopes":  claims.Scopes,
    })
}
```

---

### Phase 8b: SCIM Integration

**Goal:** Add SCIM Agent Resource endpoints for lifecycle management.

#### Task 6: SCIM Handler

Create `server/scim/` package:

```go
// server/scim/handler.go
package scim

// SCIM Agent Resource endpoints
// GET    /scim/v2/Agents           - List agents
// POST   /scim/v2/Agents           - Create agent
// GET    /scim/v2/Agents/{id}      - Get agent
// PUT    /scim/v2/Agents/{id}      - Replace agent
// PATCH  /scim/v2/Agents/{id}      - Update agent
// DELETE /scim/v2/Agents/{id}      - Delete agent

// GET    /scim/v2/ServiceProviderConfig
// GET    /scim/v2/Schemas
// GET    /scim/v2/ResourceTypes

type Handler struct {
    store  store.SCIMStorer
    logger *slog.Logger
}

func (h *Handler) RegisterHandlers(mux *http.ServeMux)
```

SCIM Agent schema (from draft-wzdk-scim-agent-resource):

```go
// server/scim/resource.go
type Agent struct {
    Schemas     []string          `json:"schemas"`
    ID          string            `json:"id"`
    ExternalID  string            `json:"externalId,omitempty"`
    Meta        *Meta             `json:"meta"`
    DisplayName string            `json:"displayName"`
    Active      bool              `json:"active"`
    Owner       *Owner            `json:"owner,omitempty"`
    AgentType   string            `json:"agentType,omitempty"`
    Description string            `json:"description,omitempty"`
    Capabilities []Capability     `json:"capabilities,omitempty"`
    // Extensions for AAuth integration
    AAuthID     string            `json:"urn:ietf:params:scim:schemas:extension:aauth:2.0:Agent:aauth_id,omitempty"`
    PublicKeys  []PublicKey       `json:"urn:ietf:params:scim:schemas:extension:aauth:2.0:Agent:public_keys,omitempty"`
}
```

#### Task 7: SCIM Store Interface

```go
// store/interface.go
type SCIMStorer interface {
    // SCIM Agent operations
    CreateSCIMAgent(ctx context.Context, agent *SCIMAgent) error
    GetSCIMAgent(ctx context.Context, id string) (*SCIMAgent, error)
    UpdateSCIMAgent(ctx context.Context, agent *SCIMAgent) error
    DeleteSCIMAgent(ctx context.Context, id string) error
    ListSCIMAgents(ctx context.Context, filter *SCIMFilter) ([]*SCIMAgent, *ListResponse, error)
}
```

#### Task 8: SCIM ↔ Agent Provider Sync

```go
// server/scim/sync.go

// When SCIM agent is created, also register with Agent Provider
func (h *Handler) syncToAgentProvider(ctx context.Context, scimAgent *Agent) error {
    registered := &store.RegisteredAgent{
        ID:          scimAgent.AAuthID,
        Name:        scimAgent.DisplayName,
        Description: scimAgent.Description,
        OwnerID:     scimAgent.Owner.Value,
        Status:      store.AgentStatusActive,
    }
    return h.apStore.RegisterAgent(ctx, registered)
}
```

---

### Phase 8c: Policy Engine

**Goal:** Add Cedar policy engine with AuthZEN API.

#### Task 9: AuthZEN Handler

Create `server/policy/` package:

```go
// server/policy/authzen.go
package policy

// AuthZEN 1.0 API
// POST /access/v1/evaluation      - Evaluate access request
// POST /access/v1/evaluations     - Batch evaluation

type EvaluationRequest struct {
    Subject  Subject  `json:"subject"`
    Action   Action   `json:"action"`
    Resource Resource `json:"resource"`
    Context  Context  `json:"context,omitempty"`
}

type EvaluationResponse struct {
    Decision bool              `json:"decision"`
    Context  map[string]any    `json:"context,omitempty"`
}

type Handler struct {
    evaluator PolicyEvaluator
    logger    *slog.Logger
}

func (h *Handler) HandleEvaluation(w http.ResponseWriter, r *http.Request)
```

#### Task 10: Cedar Integration

```go
// server/policy/cedar.go
package policy

import "github.com/cedar-policy/cedar-go"

type CedarEvaluator struct {
    policySet *cedar.PolicySet
    entities  *cedar.Entities
}

func NewCedarEvaluator(policies []byte, schema []byte) (*CedarEvaluator, error)

func (e *CedarEvaluator) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResponse, error) {
    // Convert AuthZEN request to Cedar request
    principal := cedar.EntityUID{Type: req.Subject.Type, ID: req.Subject.ID}
    action := cedar.EntityUID{Type: "Action", ID: req.Action.Name}
    resource := cedar.EntityUID{Type: req.Resource.Type, ID: req.Resource.ID}

    decision, _ := e.policySet.IsAuthorized(e.entities, cedar.Request{
        Principal: principal,
        Action:    action,
        Resource:  resource,
        Context:   req.Context,
    })

    return &EvaluationResponse{
        Decision: decision == cedar.Allow,
    }, nil
}
```

Example Cedar policy:

```cedar
// policies/agent-access.cedar

// Agents can read resources in their granted scopes
permit (
    principal is Agent,
    action == Action::"read",
    resource
)
when {
    principal.scopes.contains(resource.scope)
};

// Require human approval for write operations
forbid (
    principal is Agent,
    action in [Action::"write", Action::"delete"],
    resource
)
unless {
    principal.mission.approved == true &&
    principal.mission.scopes.contains(resource.scope)
};

// Admin actions require admin scope
permit (
    principal is Agent,
    action == Action::"admin",
    resource
)
when {
    principal.scopes.contains("admin:*")
};
```

---

## Testing Strategy

### Unit Tests

| Package | Test File | Coverage Target |
|---------|-----------|-----------------|
| `server/agentprovider` | `provider_test.go` | ✓ Complete |
| `server/personserver` | `server_test.go` | Pending |
| `server/accessserver` | `server_test.go` | Pending |
| `server/scim` | `handler_test.go` | Pending |
| `server/policy` | `authzen_test.go` | Pending |
| `server/audit` | `service_test.go` | Pending |
| `store/sqlite_agentprovider` | `sqlite_agentprovider_test.go` | ✓ Complete |

### Integration Tests

```go
// integration_test.go

func TestFullAgentFlow(t *testing.T) {
    // 1. Start server with all roles
    // 2. Register agent via Agent Provider
    // 3. Create mission via Person Server
    // 4. Approve mission (human consent)
    // 5. Get token via Access Server
    // 6. Access protected resource
    // 7. Verify audit logs
}

func TestSCIMToAgentProviderSync(t *testing.T) {
    // 1. Create agent via SCIM
    // 2. Verify agent registered in Agent Provider
    // 3. Get token for SCIM-created agent
}

func TestCedarPolicyEvaluation(t *testing.T) {
    // 1. Load Cedar policies
    // 2. Create agent with specific scopes
    // 3. Test allowed/denied actions via AuthZEN
}
```

---

## CLI Flags Plan

```bash
# Full server (all roles)
agentauth-server \
    --issuer https://auth.example.com \
    --store sqlite:///var/lib/agentauth/db.sqlite \
    --signing-key /etc/agentauth/key.pem \
    --key-id key-1

# Role selection
agentauth-server --ap         # Enable Agent Provider
agentauth-server --ps         # Enable Person Server
agentauth-server --as         # Enable Access Server
agentauth-server --scim       # Enable SCIM endpoints
agentauth-server --audit      # Enable audit logging

# Exclusive modes
agentauth-server --ap-only    # Only Agent Provider
agentauth-server --ps-only    # Only Person Server
agentauth-server --as-only    # Only Access Server

# Policy engine
agentauth-server --cedar /etc/agentauth/policies/
agentauth-server --authzen    # Enable AuthZEN API

# Combined examples
agentauth-server --ap --ps --scim --audit   # AAuth identity provider
agentauth-server --as --authzen --cedar     # Authorization server
```

---

## Dependencies to Add

```go
// go.mod additions for v0.4.0

require (
    // Cedar policy engine
    github.com/cedar-policy/cedar-go v0.x.x

    // SCIM (if using existing library)
    // Or implement from draft-wzdk-scim-agent-resource

    // OpenFGA (optional, Phase 8c)
    github.com/openfga/go-sdk v0.x.x
)
```

---

## Timeline (Estimated)

| Phase | Tasks | Duration |
|-------|-------|----------|
| v0.3.0 completion | cmd/agentauth-server --ap, integration tests | 1-2 days |
| Phase 8a | PS/AS refactor, Audit, Protected Resource example | 3-5 days |
| Phase 8b | SCIM integration | 2-3 days |
| Phase 8c | Cedar/AuthZEN | 3-5 days |

---

## References

- [ROADMAP.md](ROADMAP.md) - Strategic roadmap
- [IDEATION_CHAT_STD2026.md](../../IDEATION_CHAT_STD2026.md) - Architecture discussion
- [draft-wzdk-scim-agent-resource](https://datatracker.ietf.org/doc/draft-wzdk-scim-agent-resource/) - SCIM Agent Resource
- [AuthZEN 1.0](https://openid.github.io/authzen/) - Authorization API
- [Cedar Policy Language](https://docs.cedarpolicy.com/) - Policy engine

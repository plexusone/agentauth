# Layered Identity Composition

AgentAuth's identity model consists of three complementary layers that are composed together, not chosen between.

## Identity Layers

```
┌─────────────────────────────────────────────────────────────────┐
│                        Human Identity                           │
│  "Which user is this agent acting for?"                         │
│  Source: ID-JAG assertions from identity providers              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Agent Identity                           │
│  "Which autonomous agent is this?"                              │
│  Source: AAuth tokens with HTTP message signatures              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Workload Identity                          │
│  "Which workload/service is hosting this?"                      │
│  Source: SPIFFE/SPIRE with mTLS                                 │
└─────────────────────────────────────────────────────────────────┘
```

## ComposedIdentity

The `ComposedIdentity` type links all three identity layers:

```go
type ComposedIdentity struct {
    // Human identity (from ID-JAG delegation)
    Human *HumanIdentity `json:"human,omitempty"`

    // Agent identity (from AAuth)
    Agent *AgentIdentity `json:"agent"`

    // Workload identity (from SPIFFE)
    Workload *WorkloadIdentity `json:"workload,omitempty"`

    // BindingID uniquely identifies this composed identity binding
    BindingID string `json:"binding_id"`

    // BoundAt is when the identities were linked
    BoundAt time.Time `json:"bound_at"`

    // ExpiresAt is when the binding expires
    ExpiresAt time.Time `json:"expires_at,omitempty"`

    // TraceID for distributed tracing
    TraceID string `json:"trace_id,omitempty"`
}
```

## Human Identity

Represents the human user the agent is acting for, obtained from ID-JAG assertions:

```go
type HumanIdentity struct {
    Subject    string    `json:"sub"`           // User identifier
    Issuer     string    `json:"iss"`           // Identity provider
    Email      string    `json:"email,omitempty"`
    Name       string    `json:"name,omitempty"`
    Roles      []string  `json:"roles,omitempty"`
    IDJAGToken string    `json:"idjag_token,omitempty"`
    VerifiedAt time.Time `json:"verified_at,omitempty"`
}
```

## Agent Identity

Represents the autonomous agent, obtained from AAuth tokens:

```go
type AgentIdentity struct {
    AgentID      string    `json:"agent_id"`
    MissionID    string    `json:"mission_id,omitempty"`
    Issuer       string    `json:"iss"`
    Capabilities []string  `json:"capabilities,omitempty"`
    Scopes       []string  `json:"scopes,omitempty"`
    DelegatedBy  string    `json:"delegated_by,omitempty"`
    AAuthToken   string    `json:"aauth_token,omitempty"`
    VerifiedAt   time.Time `json:"verified_at,omitempty"`
}
```

## Workload Identity

Represents the infrastructure workload hosting the agent, from SPIFFE/SPIRE:

```go
type WorkloadIdentity struct {
    SPIFFEID    string    `json:"spiffe_id"`
    TrustDomain string    `json:"trust_domain,omitempty"`
    ServiceName string    `json:"service_name,omitempty"`
    SVID        string    `json:"svid,omitempty"`
    VerifiedAt  time.Time `json:"verified_at,omitempty"`
}
```

## Identity Composer

The `Composer` creates and validates composed identities:

```go
import "github.com/plexusone/agentauth/identity"

// Create composer with verifiers
composer := identity.NewComposer(
    identity.WithAAuthVerifier(aauthVerifier),
    identity.WithIDJAGVerifier(idjagVerifier),
    identity.WithWorkloadVerifier(spiffeVerifier),
)

// Compose from credentials
composed, err := composer.Compose(ctx, identity.ComposeOptions{
    AAuthToken:      aauthToken,
    IDJAGAssertion:  idjagAssertion,
    IncludeWorkload: true,
})
if err != nil {
    return err
}

// Use for authorization
fmt.Println(composed.AuditString())
// agent:research-agent for-human:alice@example.com on-workload:spiffe://prod/research binding:bind-xyz
```

## Context Integration

Store and retrieve composed identity from context:

```go
// Store in context
ctx = identity.WithContext(ctx, composed)

// Retrieve from context
if id, ok := identity.FromContext(ctx); ok {
    // Use identity for authorization decisions
    if id.HasHuman() && id.Human.Subject == expectedUser {
        // Authorized
    }
}
```

## Validation

Check identity validity and expiration:

```go
// Check if identity has required components
if !composed.IsValid() {
    return errors.New("invalid identity: missing agent")
}

// Check if binding has expired
if composed.IsExpired() {
    return errors.New("identity binding expired")
}

// Check for human identity
if !composed.HasHuman() {
    return errors.New("human identity required for this operation")
}
```

// Package identity provides layered identity composition for AI agents.
//
// The identity model consists of three complementary layers:
//   - Human Identity (ID-JAG): "Which user is this agent acting for?"
//   - Agent Identity (AAuth): "Which autonomous agent is this?"
//   - Workload Identity (SPIFFE): "Which workload/service is hosting this?"
//
// These layers are composed, not chosen between. A fully authenticated
// agent request includes all three layers linked together.
package identity

import (
	"time"
)

// ComposedIdentity links all three identity layers together.
// This is the primary abstraction for authenticated agent requests.
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

	// ExpiresAt is when the binding expires (earliest of component expirations)
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// TraceID for distributed tracing
	TraceID string `json:"trace_id,omitempty"`
}

// HumanIdentity represents the human user the agent is acting for.
// This comes from ID-JAG assertions for cross-application access.
type HumanIdentity struct {
	// Subject is the human user's identifier
	Subject string `json:"sub"`

	// Issuer is the identity provider that authenticated the human
	Issuer string `json:"iss"`

	// Email is the user's email (optional)
	Email string `json:"email,omitempty"`

	// Name is the user's display name (optional)
	Name string `json:"name,omitempty"`

	// Roles are the user's roles from the IdP
	Roles []string `json:"roles,omitempty"`

	// IDJAGToken is the original ID-JAG assertion token
	IDJAGToken string `json:"idjag_token,omitempty"`

	// VerifiedAt is when the ID-JAG assertion was verified
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

// AgentIdentity represents the autonomous agent.
// This comes from AAuth authentication.
type AgentIdentity struct {
	// AgentID uniquely identifies the agent
	AgentID string `json:"agent_id"`

	// MissionID identifies the current mission (optional)
	MissionID string `json:"mission_id,omitempty"`

	// Issuer is the authorization server that authenticated the agent
	Issuer string `json:"iss"`

	// Capabilities are what the agent can do
	Capabilities []string `json:"capabilities,omitempty"`

	// Scopes are the granted OAuth scopes
	Scopes []string `json:"scopes,omitempty"`

	// DelegatedBy indicates which agent delegated to this one (for sub-agents)
	DelegatedBy string `json:"delegated_by,omitempty"`

	// AAuthToken is the original AAuth access token
	AAuthToken string `json:"aauth_token,omitempty"`

	// VerifiedAt is when the AAuth token was verified
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

// WorkloadIdentity represents the infrastructure workload hosting the agent.
// This comes from SPIFFE/SPIRE.
type WorkloadIdentity struct {
	// SPIFFEID is the SPIFFE identifier (e.g., spiffe://domain/path)
	SPIFFEID string `json:"spiffe_id"`

	// TrustDomain is the SPIFFE trust domain
	TrustDomain string `json:"trust_domain,omitempty"`

	// ServiceName is the service name from the SPIFFE ID path
	ServiceName string `json:"service_name,omitempty"`

	// SVID is the X.509 SVID certificate (PEM encoded, optional)
	SVID string `json:"svid,omitempty"`

	// VerifiedAt is when the SPIFFE identity was verified
	VerifiedAt time.Time `json:"verified_at,omitempty"`
}

// IsValid checks if the composed identity has required components.
// At minimum, an agent identity is required.
func (c *ComposedIdentity) IsValid() bool {
	if c == nil || c.Agent == nil {
		return false
	}
	return c.Agent.AgentID != "" && c.BindingID != ""
}

// HasHuman returns true if human identity is present.
func (c *ComposedIdentity) HasHuman() bool {
	return c != nil && c.Human != nil && c.Human.Subject != ""
}

// HasWorkload returns true if workload identity is present.
func (c *ComposedIdentity) HasWorkload() bool {
	return c != nil && c.Workload != nil && c.Workload.SPIFFEID != ""
}

// IsExpired returns true if the binding has expired.
func (c *ComposedIdentity) IsExpired() bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(c.ExpiresAt)
}

// AuditString returns a string suitable for audit logs.
func (c *ComposedIdentity) AuditString() string {
	if c == nil || c.Agent == nil {
		return "invalid-identity"
	}

	s := "agent:" + c.Agent.AgentID
	if c.Human != nil && c.Human.Subject != "" {
		s += " for-human:" + c.Human.Subject
	}
	if c.Workload != nil && c.Workload.SPIFFEID != "" {
		s += " on-workload:" + c.Workload.SPIFFEID
	}
	s += " binding:" + c.BindingID
	return s
}

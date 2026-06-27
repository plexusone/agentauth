package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Errors for identity composition.
var (
	ErrAgentIdentityRequired   = errors.New("agent identity is required")
	ErrInvalidAAuthToken       = errors.New("invalid AAuth token")
	ErrInvalidIDJAGAssertion   = errors.New("invalid ID-JAG assertion")
	ErrInvalidWorkloadIdentity = errors.New("invalid workload identity")
	ErrCompositionFailed       = errors.New("identity composition failed")
)

// AAuthVerifier verifies AAuth tokens and extracts agent identity.
type AAuthVerifier interface {
	// VerifyAAuth verifies an AAuth token and returns the agent identity.
	VerifyAAuth(ctx context.Context, token string) (*AgentIdentity, error)
}

// IDJAGVerifier verifies ID-JAG assertions and extracts human identity.
type IDJAGVerifier interface {
	// VerifyIDJAG verifies an ID-JAG assertion and returns the human identity.
	VerifyIDJAG(ctx context.Context, assertion string) (*HumanIdentity, error)
}

// WorkloadVerifier extracts and verifies workload identity (e.g., from TLS).
type WorkloadVerifier interface {
	// VerifyWorkload extracts and verifies the workload identity.
	VerifyWorkload(ctx context.Context) (*WorkloadIdentity, error)
}

// Composer creates and validates composed identities from credentials.
type Composer struct {
	aauthVerifier    AAuthVerifier
	idjagVerifier    IDJAGVerifier
	workloadVerifier WorkloadVerifier
}

// ComposerOption configures the Composer.
type ComposerOption func(*Composer)

// WithAAuthVerifier sets the AAuth verifier.
func WithAAuthVerifier(v AAuthVerifier) ComposerOption {
	return func(c *Composer) {
		c.aauthVerifier = v
	}
}

// WithIDJAGVerifier sets the ID-JAG verifier.
func WithIDJAGVerifier(v IDJAGVerifier) ComposerOption {
	return func(c *Composer) {
		c.idjagVerifier = v
	}
}

// WithWorkloadVerifier sets the workload identity verifier.
func WithWorkloadVerifier(v WorkloadVerifier) ComposerOption {
	return func(c *Composer) {
		c.workloadVerifier = v
	}
}

// NewComposer creates a new identity composer.
func NewComposer(opts ...ComposerOption) *Composer {
	c := &Composer{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ComposeOptions specifies the credentials to compose.
type ComposeOptions struct {
	// AAuthToken is the AAuth access token (required)
	AAuthToken string

	// IDJAGAssertion is the ID-JAG assertion for human identity (optional)
	IDJAGAssertion string

	// IncludeWorkload indicates whether to extract workload identity
	IncludeWorkload bool

	// TraceID for distributed tracing
	TraceID string
}

// Compose creates a ComposedIdentity from available credentials.
// At minimum, an AAuth token is required for agent identity.
func (c *Composer) Compose(ctx context.Context, opts ComposeOptions) (*ComposedIdentity, error) {
	if opts.AAuthToken == "" {
		return nil, ErrAgentIdentityRequired
	}

	composed := &ComposedIdentity{
		BindingID: generateBindingID(),
		BoundAt:   time.Now(),
		TraceID:   opts.TraceID,
	}

	// Verify agent identity (required)
	if c.aauthVerifier != nil {
		agent, err := c.aauthVerifier.VerifyAAuth(ctx, opts.AAuthToken)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidAAuthToken, err)
		}
		composed.Agent = agent
	} else {
		// If no verifier, create minimal agent identity from token
		composed.Agent = &AgentIdentity{
			AAuthToken: opts.AAuthToken,
			VerifiedAt: time.Now(),
		}
	}

	// Verify human identity (optional)
	if opts.IDJAGAssertion != "" && c.idjagVerifier != nil {
		human, err := c.idjagVerifier.VerifyIDJAG(ctx, opts.IDJAGAssertion)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidIDJAGAssertion, err)
		}
		composed.Human = human
	}

	// Extract workload identity (optional)
	if opts.IncludeWorkload && c.workloadVerifier != nil {
		workload, err := c.workloadVerifier.VerifyWorkload(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidWorkloadIdentity, err)
		}
		composed.Workload = workload
	}

	// Calculate expiration (earliest of components)
	composed.ExpiresAt = c.calculateExpiration(composed)

	return composed, nil
}

// Verify validates all components of a ComposedIdentity.
func (c *Composer) Verify(ctx context.Context, identity *ComposedIdentity) error {
	if identity == nil {
		return ErrAgentIdentityRequired
	}

	if identity.IsExpired() {
		return fmt.Errorf("%w: binding expired", ErrCompositionFailed)
	}

	if !identity.IsValid() {
		return fmt.Errorf("%w: invalid identity structure", ErrCompositionFailed)
	}

	// Re-verify agent identity if we have the token
	if identity.Agent != nil && identity.Agent.AAuthToken != "" && c.aauthVerifier != nil {
		_, err := c.aauthVerifier.VerifyAAuth(ctx, identity.Agent.AAuthToken)
		if err != nil {
			return fmt.Errorf("%w: agent verification failed: %v", ErrInvalidAAuthToken, err)
		}
	}

	// Re-verify human identity if we have the token
	if identity.Human != nil && identity.Human.IDJAGToken != "" && c.idjagVerifier != nil {
		_, err := c.idjagVerifier.VerifyIDJAG(ctx, identity.Human.IDJAGToken)
		if err != nil {
			return fmt.Errorf("%w: human verification failed: %v", ErrInvalidIDJAGAssertion, err)
		}
	}

	return nil
}

// calculateExpiration finds the earliest expiration among components.
func (c *Composer) calculateExpiration(composed *ComposedIdentity) time.Time {
	// Default to 1 hour from now
	expiry := time.Now().Add(time.Hour)

	// In a real implementation, we would parse token expiration times
	// and use the earliest one. For now, use a reasonable default.

	return expiry
}

// generateBindingID creates a unique binding identifier.
func generateBindingID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("bind-%d", time.Now().UnixNano())
	}
	return "bind-" + hex.EncodeToString(b)
}

// FromContext extracts the ComposedIdentity from context, if present.
func FromContext(ctx context.Context) (*ComposedIdentity, bool) {
	identity, ok := ctx.Value(composedIdentityKey).(*ComposedIdentity)
	return identity, ok
}

// WithContext returns a new context with the ComposedIdentity attached.
func WithContext(ctx context.Context, identity *ComposedIdentity) context.Context {
	return context.WithValue(ctx, composedIdentityKey, identity)
}

type contextKey struct{}

var composedIdentityKey = contextKey{}

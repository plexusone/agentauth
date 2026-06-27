package agentauth

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/golang-jwt/jwt/v5"
)

// AAuthProvider implements Provider using AAuth protocol.
type AAuthProvider struct {
	config *AAuthConfig

	agent        *aauth.Agent
	consentMode  ConsentMode
	pollInterval time.Duration
	pollTimeout  time.Duration
}

// AAuthProviderOption configures the AAuthProvider.
type AAuthProviderOption func(*AAuthProvider)

// WithAAuthAgent sets the AAuth agent directly.
func WithAAuthAgent(agent *aauth.Agent) AAuthProviderOption {
	return func(p *AAuthProvider) {
		p.agent = agent
	}
}

// WithAAuthConsentMode sets the consent flow mode.
func WithAAuthConsentMode(mode ConsentMode) AAuthProviderOption {
	return func(p *AAuthProvider) {
		p.consentMode = mode
	}
}

// WithAAuthPollConfig sets polling configuration.
func WithAAuthPollConfig(interval, timeout time.Duration) AAuthProviderOption {
	return func(p *AAuthProvider) {
		p.pollInterval = interval
		p.pollTimeout = timeout
	}
}

// NewAAuthProvider creates a new AAuth provider.
func NewAAuthProvider(config *AAuthConfig, opts ...AAuthProviderOption) (*AAuthProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	p := &AAuthProvider{
		config:       config,
		consentMode:  ConsentModeDeferred,
		pollInterval: 2 * time.Second,
		pollTimeout:  5 * time.Minute,
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// Authorize submits a mission proposal and handles consent flow.
func (p *AAuthProvider) Authorize(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	if p.agent == nil {
		return nil, fmt.Errorf("aauth agent not configured")
	}

	// Build audience
	audience := req.Audience
	if len(audience) == 0 {
		audience = p.config.DefaultAudience
	}

	// Determine interaction type
	interactionType := req.InteractionType
	if interactionType == "" {
		interactionType = p.config.DefaultInteractionType
		if interactionType == "" {
			interactionType = string(aauth.InteractionSupervised)
		}
	}

	// Build mission proposal
	proposal := &aauth.MissionProposal{
		AgentID:         p.config.AgentID,
		Name:            req.MissionName,
		Description:     req.MissionDescription,
		InteractionType: aauth.InteractionType(interactionType),
		Permissions:     scopesToPermissions(req.Scopes),
	}

	if req.Duration > 0 {
		proposal.Duration = req.Duration
	} else if p.config.DefaultMissionDuration > 0 {
		proposal.Duration = p.config.DefaultMissionDuration
	} else {
		proposal.Duration = 24 * time.Hour
	}

	// Submit to Person Server
	result, err := p.submitMissionProposal(ctx, proposal, audience)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// submitMissionProposal submits the proposal to the Person Server.
func (p *AAuthProvider) submitMissionProposal(ctx context.Context, proposal *aauth.MissionProposal, audience []string) (*AuthResult, error) {
	// Get or create agent token
	agentToken, err := p.agent.GetOrCreateAgentToken(audience...)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent token: %w", err)
	}

	// Build scope from permissions
	var scopes []string
	for _, perm := range proposal.Permissions {
		if perm.Resource != "" && perm.Action != "" {
			scopes = append(scopes, perm.Resource+":"+perm.Action)
		} else if perm.Scope != "" {
			scopes = append(scopes, perm.Scope)
		}
	}

	// Create auth token request
	cnf, err := p.agent.KeyPair().ToCNF()
	if err != nil {
		return nil, fmt.Errorf("failed to create CNF: %w", err)
	}

	// Simulate Person Server response
	// In reality, this would be an HTTP request that might return:
	// - 200 OK with token (pre-approved)
	// - 202 Accepted with consent_uri (needs human approval)
	_ = agentToken // Used in real implementation
	_ = ctx        // Used in real implementation

	// Check if this is a "pre-approved" scope pattern
	// (In production, the Person Server would make this decision)
	if p.isPreApproved(scopes) {
		// Immediate approval - create auth token
		ttl := proposal.Duration
		if ttl == 0 {
			ttl = time.Hour
		}

		authToken := aauth.NewAuthToken(
			p.config.PersonServer,
			p.config.AgentID,
			audience,
			cnf,
			ttl,
		).WithScope(strings.Join(scopes, " "))

		// Sign the token (normally done by Person Server)
		signedToken, err := authToken.Sign(jwt.SigningMethodES256, p.agent.KeyPair().PrivateKey, p.agent.KeyPair().KeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to sign auth token: %w", err)
		}

		return &AuthResult{
			Status:    StatusApproved,
			Protocol:  ProtocolAAuth,
			Token:     signedToken,
			TokenType: "Bearer",
			ExpiresAt: authToken.ExpiresAt,
			Scopes:    scopes,
			Metadata: map[string]any{
				"mission_id":       proposal.ID,
				"interaction_type": proposal.InteractionType,
			},
		}, nil
	}

	// Human consent required - return pending result
	consentURI := fmt.Sprintf("%s/consent?mission_id=%s&scopes=%s",
		p.config.PersonServer,
		proposal.ID,
		strings.Join(scopes, ","),
	)
	statusURI := fmt.Sprintf("%s/consent/status/%s", p.config.PersonServer, proposal.ID)

	return &AuthResult{
		Status:       StatusPending,
		Protocol:     ProtocolAAuth,
		ConsentURI:   consentURI,
		StatusURI:    statusURI,
		PollInterval: p.pollInterval,
		Message:      fmt.Sprintf("Please approve the mission at: %s", consentURI),
		Metadata: map[string]any{
			"mission_id":       proposal.ID,
			"interaction_type": proposal.InteractionType,
		},
	}, nil
}

// isPreApproved checks if scopes are pre-approved (no human consent needed).
// In production, this would be determined by the Person Server.
func (p *AAuthProvider) isPreApproved(scopes []string) bool {
	// For demonstration: only read scopes are pre-approved
	for _, scope := range scopes {
		if !strings.HasSuffix(scope, ":read") && !strings.HasSuffix(scope, ":list") {
			return false
		}
	}
	return true
}

// CheckConsent checks the status of a pending consent request.
func (p *AAuthProvider) CheckConsent(ctx context.Context, statusURI string) (*AuthResult, error) {
	// Create consent poller for single check
	poller := aauth.NewConsentPoller(
		aauth.WithConsentHTTPClient(http.DefaultClient),
	)

	// Use Poll with zero interval for single check
	status, err := poller.Poll(ctx, statusURI, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to check consent status: %w", err)
	}

	return p.statusToResult(status, statusURI), nil
}

// statusToResult converts ConsentStatusResponse to AuthResult.
func (p *AAuthProvider) statusToResult(status *aauth.ConsentStatusResponse, statusURI string) *AuthResult {
	switch status.Status {
	case aauth.ConsentStatusApproved:
		expiresAt := time.Now().Add(time.Duration(status.ExpiresIn) * time.Second)
		return &AuthResult{
			Status:    StatusApproved,
			Protocol:  ProtocolAAuth,
			Token:     status.AccessToken,
			TokenType: status.TokenType,
			ExpiresAt: expiresAt,
		}
	case aauth.ConsentStatusDenied:
		return &AuthResult{
			Status:   StatusDenied,
			Protocol: ProtocolAAuth,
			Message:  "Consent denied by user",
		}
	case aauth.ConsentStatusExpired:
		return &AuthResult{
			Status:   StatusExpired,
			Protocol: ProtocolAAuth,
			Message:  "Consent request expired",
		}
	default:
		return &AuthResult{
			Status:       StatusPending,
			Protocol:     ProtocolAAuth,
			StatusURI:    statusURI,
			PollInterval: p.pollInterval,
		}
	}
}

// WaitForConsent polls for consent approval with timeout.
func (p *AAuthProvider) WaitForConsent(ctx context.Context, statusURI string, timeout time.Duration) (*AuthResult, error) {
	if timeout == 0 {
		timeout = p.pollTimeout
	}

	poller := aauth.NewConsentPoller(
		aauth.WithConsentHTTPClient(http.DefaultClient),
		aauth.WithMaxWaitTime(timeout),
		aauth.WithInitialBackoff(p.pollInterval),
	)

	status, err := poller.Poll(ctx, statusURI, int(p.pollInterval.Seconds()))
	if err != nil {
		if err == aauth.ErrConsentTimeout {
			return nil, ErrConsentTimeout
		}
		if err == aauth.ErrConsentDenied {
			return nil, ErrConsentDenied
		}
		return nil, fmt.Errorf("consent polling failed: %w", err)
	}

	return p.statusToResult(status, statusURI), nil
}

// Revoke revokes an AAuth authorization.
func (p *AAuthProvider) Revoke(ctx context.Context, token string) error {
	// AAuth doesn't define a standard revocation endpoint
	// This would be Person Server-specific
	return nil
}

// Protocol returns ProtocolAAuth.
func (p *AAuthProvider) Protocol() Protocol {
	return ProtocolAAuth
}

// HTTPClient returns an HTTP client with automatic AAuth authorization.
func (p *AAuthProvider) HTTPClient(ctx context.Context, req *AuthRequest) (*http.Client, error) {
	result, err := p.Authorize(ctx, req)
	if err != nil {
		return nil, err
	}

	if !result.IsApproved() {
		return nil, fmt.Errorf("%w: %s", ErrConsentRequired, result.ConsentURI)
	}

	// Use the agent's transport which adds HTTP signatures
	return p.agent.Client(), nil
}

// SetAgent sets the AAuth agent (for deferred initialization).
func (p *AAuthProvider) SetAgent(agent *aauth.Agent) {
	p.agent = agent
}

// scopesToPermissions converts OAuth scopes to AAuth permissions.
func scopesToPermissions(scopes []string) []aauth.Permission {
	var permissions []aauth.Permission
	for _, scope := range scopes {
		parts := strings.SplitN(scope, ":", 2)
		if len(parts) == 2 {
			permissions = append(permissions, aauth.Permission{
				Resource: parts[0],
				Action:   parts[1],
				Scope:    scope,
			})
		} else {
			// Scope without colon - treat as action only
			permissions = append(permissions, aauth.Permission{
				Action: scope,
				Scope:  scope,
			})
		}
	}
	return permissions
}

// InitializeAgent initializes the AAuth agent from config.
func (p *AAuthProvider) InitializeAgent(privateKey crypto.PrivateKey) error {
	agentID, err := aauth.ParseAAuthID(p.config.AgentID)
	if err != nil {
		return fmt.Errorf("invalid agent ID: %w", err)
	}

	agent, err := aauth.NewAgent(agentID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	p.agent = agent
	return nil
}

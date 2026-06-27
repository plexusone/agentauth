package agentauth

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// IDJAGProvider implements Provider using ID-JAG protocol.
type IDJAGProvider struct {
	config *IDJAGConfig

	privateKey crypto.PrivateKey
	client     *idjag.TokenExchangeClient
}

// IDJAGProviderOption configures the IDJAGProvider.
type IDJAGProviderOption func(*IDJAGProvider)

// WithIDJAGPrivateKey sets the private key directly.
func WithIDJAGPrivateKey(key crypto.PrivateKey) IDJAGProviderOption {
	return func(p *IDJAGProvider) {
		p.privateKey = key
	}
}

// WithIDJAGHTTPClient sets a custom HTTP client.
func WithIDJAGHTTPClient(client *http.Client) IDJAGProviderOption {
	return func(p *IDJAGProvider) {
		// Note: Would need to add HTTP client option to idjag.TokenExchangeClient
		// For now, we use the default client
		p.client = idjag.NewTokenExchangeClient(p.config.TokenEndpoint)
	}
}

// NewIDJAGProvider creates a new ID-JAG provider.
func NewIDJAGProvider(config *IDJAGConfig, opts ...IDJAGProviderOption) (*IDJAGProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	p := &IDJAGProvider{
		config: config,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Create token exchange client if not set
	if p.client == nil {
		p.client = idjag.NewTokenExchangeClient(config.TokenEndpoint)
	}

	return p, nil
}

// Authorize creates an assertion and exchanges it for an access token.
func (p *IDJAGProvider) Authorize(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	if p.privateKey == nil {
		return nil, fmt.Errorf("private key not configured")
	}

	// Build audience
	audience := req.Audience
	if len(audience) == 0 {
		audience = p.config.DefaultAudience
	}

	// Create assertion
	ttl := p.config.AssertionTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	var assertion *idjag.Assertion
	if req.Subject != "" {
		// Delegated assertion (acting on behalf of subject)
		assertion = idjag.NewDelegatedAssertion(
			p.config.Issuer,
			req.Subject,
			p.config.Issuer, // Agent is the actor
			audience,
			ttl,
		)
	} else {
		// Simple assertion (agent itself)
		assertion = idjag.NewAssertion(
			p.config.Issuer,
			p.config.Issuer, // Agent is the subject
			audience,
			ttl,
		)
	}

	// Sign the assertion
	signingMethod := p.signingMethod()
	signedAssertion, err := assertion.Sign(signingMethod, p.privateKey, p.config.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Exchange for access token
	scope := strings.Join(req.Scopes, " ")
	tokenResp, err := p.client.Exchange(ctx, &idjag.TokenExchangeRequest{
		SubjectToken:     signedAssertion,
		SubjectTokenType: idjag.TokenTypeIDJAG,
		Scope:            scope,
		Resource:         req.Resource,
	})
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	// Parse expiry
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return &AuthResult{
		Status:    StatusApproved,
		Protocol:  ProtocolIDJAG,
		Token:     tokenResp.AccessToken,
		TokenType: tokenResp.TokenType,
		ExpiresAt: expiresAt,
		Scopes:    strings.Fields(tokenResp.Scope),
	}, nil
}

// CheckConsent is not used by ID-JAG (no human consent flow).
func (p *IDJAGProvider) CheckConsent(ctx context.Context, statusURI string) (*AuthResult, error) {
	return nil, fmt.Errorf("ID-JAG does not use consent flow")
}

// WaitForConsent is not used by ID-JAG.
func (p *IDJAGProvider) WaitForConsent(ctx context.Context, statusURI string, timeout time.Duration) (*AuthResult, error) {
	return nil, fmt.Errorf("ID-JAG does not use consent flow")
}

// Revoke revokes a token (if supported by the authorization server).
func (p *IDJAGProvider) Revoke(ctx context.Context, token string) error {
	// ID-JAG doesn't define revocation; this would be server-specific
	return nil
}

// Protocol returns ProtocolIDJAG.
func (p *IDJAGProvider) Protocol() Protocol {
	return ProtocolIDJAG
}

// HTTPClient returns an HTTP client with automatic ID-JAG authorization.
func (p *IDJAGProvider) HTTPClient(ctx context.Context, req *AuthRequest) (*http.Client, error) {
	result, err := p.Authorize(ctx, req)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &authTransport{
			base:      http.DefaultTransport,
			token:     result.Token,
			tokenType: result.TokenType,
		},
	}, nil
}

// signingMethod returns the JWT signing method.
func (p *IDJAGProvider) signingMethod() jwt.SigningMethod {
	switch p.config.Algorithm {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodES256
	}
}

// SetPrivateKey sets the private key (for deferred initialization).
func (p *IDJAGProvider) SetPrivateKey(key crypto.PrivateKey) {
	p.privateKey = key
}

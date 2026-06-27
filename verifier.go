package agentauth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aistandardsio/agent-protocols/idjag"
)

// VerifierConfig configures the hybrid token verifier.
type VerifierConfig struct {
	// IDJAGEnabled enables ID-JAG token verification.
	IDJAGEnabled bool `json:"idjag_enabled" yaml:"idjag_enabled"`

	// IDJAGIssuers maps issuer URLs to JWKS URLs for ID-JAG verification.
	// If JWKS URL is empty, defaults to {issuer}/.well-known/jwks.json
	IDJAGIssuers map[string]string `json:"idjag_issuers" yaml:"idjag_issuers"`

	// IDJAGAudience is the expected audience for ID-JAG tokens.
	IDJAGAudience string `json:"idjag_audience" yaml:"idjag_audience"`

	// AAuthEnabled enables AAuth token verification.
	AAuthEnabled bool `json:"aauth_enabled" yaml:"aauth_enabled"`

	// AAuthIssuers maps issuer URLs to JWKS URLs for AAuth verification.
	// If JWKS URL is empty, defaults to {issuer}/.well-known/jwks.json
	AAuthIssuers map[string]string `json:"aauth_issuers" yaml:"aauth_issuers"`

	// AAuthAudience is the expected audience for AAuth tokens.
	AAuthAudience string `json:"aauth_audience" yaml:"aauth_audience"`

	// ActionPolicy routes actions to protocols.
	// Key is the action name (e.g., "chat", "write", "delete").
	// Value is the required protocol for that action.
	ActionPolicy map[string]Protocol `json:"action_policy" yaml:"action_policy"`

	// DefaultProtocol is used when no action policy matches.
	// Defaults to ProtocolIDJAG (automatic).
	DefaultProtocol Protocol `json:"default_protocol" yaml:"default_protocol"`

	// SensitiveActions require AAuth (human consent).
	// These override ActionPolicy.
	SensitiveActions []string `json:"sensitive_actions" yaml:"sensitive_actions"`

	// CacheTTL is how long to cache JWKS keys.
	CacheTTL time.Duration `json:"cache_ttl" yaml:"cache_ttl"`
}

// DefaultVerifierConfig returns a sensible default configuration.
func DefaultVerifierConfig() *VerifierConfig {
	return &VerifierConfig{
		IDJAGEnabled:    true,
		AAuthEnabled:    true,
		IDJAGIssuers:    make(map[string]string),
		AAuthIssuers:    make(map[string]string),
		DefaultProtocol: ProtocolIDJAG,
		SensitiveActions: []string{
			"write",
			"delete",
			"update",
			"create",
			"send",
			"upload",
			"admin",
		},
		CacheTTL: 5 * time.Minute,
	}
}

// TokenClaims represents verified token claims.
type TokenClaims struct {
	// Protocol indicates which protocol verified this token.
	Protocol Protocol `json:"protocol"`

	// Issuer is the token issuer.
	Issuer string `json:"iss"`

	// Subject is the token subject (agent ID).
	Subject string `json:"sub"`

	// Audience is the token audience.
	Audience []string `json:"aud"`

	// Scopes are the granted scopes (space-separated in token).
	Scopes []string `json:"scopes"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"exp"`

	// IssuedAt is when the token was issued.
	IssuedAt time.Time `json:"iat"`

	// Actor contains delegation information (who the agent acts for).
	Actor *ActorClaims `json:"act,omitempty"`

	// Raw contains the raw claims map for protocol-specific data.
	Raw map[string]any `json:"raw,omitempty"`
}

// ActorClaims represents the actor in a delegation token.
type ActorClaims struct {
	// Subject is the actor's identifier (e.g., user ID).
	Subject string `json:"sub"`

	// Issuer is the actor's identity provider.
	Issuer string `json:"iss,omitempty"`
}

// HasScope checks if the claims include a specific scope.
func (c *TokenClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the claims include any of the specified scopes.
func (c *TokenClaims) HasAnyScope(scopes ...string) bool {
	for _, scope := range scopes {
		if c.HasScope(scope) {
			return true
		}
	}
	return false
}

// TokenVerifier verifies tokens and enforces action-based policies.
type TokenVerifier struct {
	config *VerifierConfig

	mu             sync.RWMutex
	idjagVerifiers map[string]*idjag.JWKSVerifier
	aauthVerifiers map[string]*idjag.JWKSVerifier // AAuth uses same JWKS format
}

// NewTokenVerifier creates a new hybrid token verifier.
func NewTokenVerifier(config *VerifierConfig) *TokenVerifier {
	if config == nil {
		config = DefaultVerifierConfig()
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.DefaultProtocol == "" {
		config.DefaultProtocol = ProtocolIDJAG
	}

	return &TokenVerifier{
		config:         config,
		idjagVerifiers: make(map[string]*idjag.JWKSVerifier),
		aauthVerifiers: make(map[string]*idjag.JWKSVerifier),
	}
}

// AddIDJAGIssuer adds a trusted ID-JAG issuer.
func (v *TokenVerifier) AddIDJAGIssuer(issuerURL, jwksURL string) {
	if jwksURL == "" {
		jwksURL = strings.TrimRight(issuerURL, "/") + "/.well-known/jwks.json"
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	opts := idjag.VerifierOptions{
		ExpectedIssuer:   issuerURL,
		ExpectedAudience: v.config.IDJAGAudience,
	}
	verifier := idjag.NewJWKSVerifier(jwksURL, opts)
	verifier.WithCacheTTL(v.config.CacheTTL)
	v.idjagVerifiers[issuerURL] = verifier
}

// AddAAuthIssuer adds a trusted AAuth issuer.
func (v *TokenVerifier) AddAAuthIssuer(issuerURL, jwksURL string) {
	if jwksURL == "" {
		jwksURL = strings.TrimRight(issuerURL, "/") + "/.well-known/jwks.json"
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	opts := idjag.VerifierOptions{
		ExpectedIssuer:   issuerURL,
		ExpectedAudience: v.config.AAuthAudience,
	}
	verifier := idjag.NewJWKSVerifier(jwksURL, opts)
	verifier.WithCacheTTL(v.config.CacheTTL)
	v.aauthVerifiers[issuerURL] = verifier
}

// Verify verifies a token without action checking.
// Returns the claims if valid.
func (v *TokenVerifier) Verify(ctx context.Context, token string) (*TokenClaims, error) {
	// Try AAuth first if enabled (AAuth tokens have specific markers)
	if v.config.AAuthEnabled {
		claims, err := v.verifyAAuth(ctx, token)
		if err == nil {
			return claims, nil
		}
	}

	// Try ID-JAG if enabled
	if v.config.IDJAGEnabled {
		claims, err := v.verifyIDJAG(ctx, token)
		if err == nil {
			return claims, nil
		}
	}

	return nil, fmt.Errorf("token verification failed: no valid issuer found")
}

// VerifyForAction verifies a token and checks if it's valid for the given action.
// Returns an error if the token protocol doesn't match the action's required protocol.
func (v *TokenVerifier) VerifyForAction(ctx context.Context, token, action string) (*TokenClaims, error) {
	claims, err := v.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	requiredProtocol := v.GetRequiredProtocol(action)
	if requiredProtocol == ProtocolAAuth && claims.Protocol != ProtocolAAuth {
		return nil, fmt.Errorf("action %q requires AAuth (human consent), got %s token", action, claims.Protocol)
	}

	return claims, nil
}

// GetRequiredProtocol returns the required protocol for an action.
func (v *TokenVerifier) GetRequiredProtocol(action string) Protocol {
	// Check sensitive actions first (always require AAuth)
	actionLower := strings.ToLower(action)
	for _, sensitive := range v.config.SensitiveActions {
		if strings.Contains(actionLower, strings.ToLower(sensitive)) {
			return ProtocolAAuth
		}
	}

	// Check action policy
	if protocol, ok := v.config.ActionPolicy[action]; ok {
		return protocol
	}

	return v.config.DefaultProtocol
}

// IsSensitiveAction returns true if the action requires AAuth.
func (v *TokenVerifier) IsSensitiveAction(action string) bool {
	return v.GetRequiredProtocol(action) == ProtocolAAuth
}

// verifyIDJAG attempts to verify a token as ID-JAG.
func (v *TokenVerifier) verifyIDJAG(ctx context.Context, token string) (*TokenClaims, error) {
	// Extract issuer from token without verification
	issuer, err := extractIssuerFromJWT(token)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	verifier, ok := v.idjagVerifiers[issuer]
	v.mu.RUnlock()

	if !ok {
		// Try to auto-register issuer if issuers are configured
		if jwksURL, exists := v.config.IDJAGIssuers[issuer]; exists {
			v.AddIDJAGIssuer(issuer, jwksURL)
			v.mu.RLock()
			verifier = v.idjagVerifiers[issuer]
			v.mu.RUnlock()
		} else {
			return nil, fmt.Errorf("unknown ID-JAG issuer: %s", issuer)
		}
	}

	assertion, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("ID-JAG verification failed: %w", err)
	}

	return assertionToClaims(assertion, ProtocolIDJAG), nil
}

// verifyAAuth attempts to verify a token as AAuth.
func (v *TokenVerifier) verifyAAuth(ctx context.Context, token string) (*TokenClaims, error) {
	// Extract issuer from token without verification
	issuer, err := extractIssuerFromJWT(token)
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	verifier, ok := v.aauthVerifiers[issuer]
	v.mu.RUnlock()

	if !ok {
		// Try to auto-register issuer if issuers are configured
		if jwksURL, exists := v.config.AAuthIssuers[issuer]; exists {
			v.AddAAuthIssuer(issuer, jwksURL)
			v.mu.RLock()
			verifier = v.aauthVerifiers[issuer]
			v.mu.RUnlock()
		} else {
			return nil, fmt.Errorf("unknown AAuth issuer: %s", issuer)
		}
	}

	assertion, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("AAuth verification failed: %w", err)
	}

	return assertionToClaims(assertion, ProtocolAAuth), nil
}

// assertionToClaims converts an idjag.Assertion to TokenClaims.
func assertionToClaims(a *idjag.Assertion, protocol Protocol) *TokenClaims {
	claims := &TokenClaims{
		Protocol:  protocol,
		Issuer:    a.Issuer,
		Subject:   a.Subject,
		Audience:  a.Audience,
		ExpiresAt: a.ExpiresAt,
		IssuedAt:  a.IssuedAt,
		Raw:       make(map[string]any),
	}

	// Extract scopes from custom claims if present
	if a.Claims != nil {
		if scope, ok := a.Claims["scope"].(string); ok {
			claims.Scopes = strings.Split(scope, " ")
		}
		// Copy all claims to Raw
		for k, v := range a.Claims {
			claims.Raw[k] = v
		}
	}

	if a.Actor != nil {
		claims.Actor = &ActorClaims{
			Subject: a.Actor.Subject,
			Issuer:  a.Actor.Issuer,
		}
	}

	return claims
}

// extractIssuerFromJWT extracts the issuer claim from a JWT without verification.
func extractIssuerFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}

	// Parse JSON to extract issuer
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := jsonUnmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse claims: %w", err)
	}

	if claims.Issuer == "" {
		return "", fmt.Errorf("missing issuer claim")
	}

	return claims.Issuer, nil
}

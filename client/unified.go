package client

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/golang-jwt/jwt/v5"
)

// Protocol identifies the authentication protocol.
type Protocol string

const (
	// ProtocolAAuth uses the AAuth protocol (human consent).
	ProtocolAAuth Protocol = "aauth"
	// ProtocolIDJAG uses the ID-JAG protocol (automated).
	ProtocolIDJAG Protocol = "idjag"
)

// UnifiedClient provides a single interface for agent authentication across protocols.
// It automatically routes requests to the appropriate protocol based on policy configuration.
type UnifiedClient struct {
	config *UnifiedConfig

	// Protocol-specific clients
	aauth *aauth.Agent
	idjag *idjag.TokenExchangeClient

	// Key material
	privateKey crypto.PrivateKey
	keyID      string

	// Token cache
	mu    sync.RWMutex
	cache map[string]*cachedAuthResult

	// HTTP client for making authorized requests
	httpClient *http.Client
}

type cachedAuthResult struct {
	result    *AuthResult
	expiresAt time.Time
}

// UnifiedConfig configures the UnifiedClient.
type UnifiedConfig struct {
	// AgentID is the agent's AAuth identifier (e.g., "aauth:my-agent@example.com")
	AgentID string

	// PersonServer is the URL of the Person Server for AAuth flows
	PersonServer string

	// TokenEndpoint is the URL for ID-JAG token exchange
	TokenEndpoint string

	// Policy determines which protocol to use for which scopes
	Policy PolicyConfig

	// DefaultAudience is used when no audience is specified
	DefaultAudience []string

	// AssertionTTL is the lifetime for ID-JAG assertions
	AssertionTTL time.Duration

	// CacheEnabled enables token caching
	CacheEnabled bool

	// CacheMaxSize limits the number of cached tokens
	CacheMaxSize int
}

// PolicyConfig determines protocol routing based on scopes.
type PolicyConfig struct {
	// Default is the default protocol when no rules match
	Default Protocol

	// AAuthScopes are scope patterns that require AAuth (human consent)
	// Supports wildcards: "write:*", "admin:*", "delete:*"
	AAuthScopes []string

	// IDJAGScopes are scope patterns that use ID-JAG (automated)
	// If empty, all non-AAuth scopes use ID-JAG
	IDJAGScopes []string
}

// AuthRequest represents an authorization request.
type AuthRequest struct {
	// Scopes requested
	Scopes []string

	// Resource URL (audience)
	Resource string

	// Audience (if different from Resource)
	Audience []string

	// ForceProtocol overrides policy-based protocol selection
	ForceProtocol Protocol

	// MissionName for AAuth requests
	MissionName string

	// MissionDescription for AAuth requests
	MissionDescription string

	// Subject for delegated requests (ID-JAG)
	Subject string
}

// AuthResult contains the authorization result.
type AuthResult struct {
	// Status is "approved", "pending", "denied", or "error"
	Status string

	// Protocol used for this authorization
	Protocol Protocol

	// Token is the access token (if approved)
	Token string

	// TokenType is typically "Bearer"
	TokenType string

	// ExpiresAt is when the token expires
	ExpiresAt time.Time

	// Scopes granted
	Scopes []string

	// ConsentURI is where to send the user (if pending)
	ConsentURI string

	// StatusURI for polling consent status (if pending)
	StatusURI string

	// Error information
	Error string
}

// IsApproved returns true if authorization was granted.
func (r *AuthResult) IsApproved() bool {
	return r.Status == "approved"
}

// IsPending returns true if human consent is required.
func (r *AuthResult) IsPending() bool {
	return r.Status == "pending"
}

// UnifiedOption configures the UnifiedClient.
type UnifiedOption func(*UnifiedClient)

// WithAgentID sets the agent identifier.
func WithAgentID(agentID string) UnifiedOption {
	return func(c *UnifiedClient) {
		c.config.AgentID = agentID
	}
}

// WithPrivateKey sets the signing key.
func WithPrivateKey(key crypto.PrivateKey, keyID string) UnifiedOption {
	return func(c *UnifiedClient) {
		c.privateKey = key
		c.keyID = keyID
	}
}

// WithPersonServer sets the Person Server URL.
func WithPersonServer(url string) UnifiedOption {
	return func(c *UnifiedClient) {
		c.config.PersonServer = strings.TrimSuffix(url, "/")
	}
}

// WithTokenEndpoint sets the ID-JAG token endpoint.
func WithTokenEndpoint(url string) UnifiedOption {
	return func(c *UnifiedClient) {
		c.config.TokenEndpoint = url
	}
}

// WithPolicy sets the protocol routing policy.
func WithPolicy(policy PolicyConfig) UnifiedOption {
	return func(c *UnifiedClient) {
		c.config.Policy = policy
	}
}

// WithDefaultAudience sets the default audience.
func WithDefaultAudience(audience ...string) UnifiedOption {
	return func(c *UnifiedClient) {
		c.config.DefaultAudience = audience
	}
}

// WithCaching enables token caching.
func WithCaching(maxSize int) UnifiedOption {
	return func(c *UnifiedClient) {
		c.config.CacheEnabled = true
		c.config.CacheMaxSize = maxSize
	}
}

// WithUnifiedHTTPClient sets a custom HTTP client.
func WithUnifiedHTTPClient(client *http.Client) UnifiedOption {
	return func(c *UnifiedClient) {
		c.httpClient = client
	}
}

// NewUnified creates a new unified client for agent authentication.
func NewUnified(opts ...UnifiedOption) (*UnifiedClient, error) {
	c := &UnifiedClient{
		config: &UnifiedConfig{
			Policy: PolicyConfig{
				Default:     ProtocolIDJAG,
				AAuthScopes: []string{"write:*", "delete:*", "admin:*"},
			},
			AssertionTTL: 5 * time.Minute,
			CacheEnabled: true,
			CacheMaxSize: 100,
		},
		cache:      make(map[string]*cachedAuthResult),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	for _, opt := range opts {
		opt(c)
	}

	// Validate configuration
	if c.privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}

	// Initialize protocol clients
	if err := c.initClients(); err != nil {
		return nil, err
	}

	return c, nil
}

// initClients initializes the protocol-specific clients.
func (c *UnifiedClient) initClients() error {
	// Initialize AAuth agent if Person Server is configured
	if c.config.PersonServer != "" && c.config.AgentID != "" {
		agentID, err := aauth.ParseAAuthID(c.config.AgentID)
		if err != nil {
			return fmt.Errorf("invalid agent ID: %w", err)
		}

		agent, err := aauth.NewAgent(agentID, c.privateKey)
		if err != nil {
			return fmt.Errorf("failed to create AAuth agent: %w", err)
		}
		c.aauth = agent
	}

	// Initialize ID-JAG client if token endpoint is configured
	if c.config.TokenEndpoint != "" {
		c.idjag = idjag.NewTokenExchangeClient(c.config.TokenEndpoint)
	}

	return nil
}

// Authorize requests authorization for the given scopes.
// It automatically routes to the appropriate protocol based on policy.
func (c *UnifiedClient) Authorize(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	// Check cache
	if result := c.checkCache(req); result != nil {
		return result, nil
	}

	// Determine protocol
	protocol := c.selectProtocol(req)

	// Route to appropriate provider
	var result *AuthResult
	var err error

	switch protocol {
	case ProtocolAAuth:
		result, err = c.authorizeAAuth(ctx, req)
	case ProtocolIDJAG:
		result, err = c.authorizeIDJAG(ctx, req)
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocol)
	}

	if err != nil {
		return nil, err
	}

	// Cache successful results
	if result.IsApproved() && c.config.CacheEnabled {
		c.cacheResult(req, result)
	}

	return result, nil
}

// selectProtocol determines which protocol to use based on policy.
func (c *UnifiedClient) selectProtocol(req *AuthRequest) Protocol {
	// Check for forced protocol
	if req.ForceProtocol != "" {
		return req.ForceProtocol
	}

	// Check AAuth patterns
	for _, scope := range req.Scopes {
		for _, pattern := range c.config.Policy.AAuthScopes {
			if matchScopePattern(pattern, scope) {
				return ProtocolAAuth
			}
		}
	}

	// Check ID-JAG patterns (if specified)
	if len(c.config.Policy.IDJAGScopes) > 0 {
		for _, scope := range req.Scopes {
			for _, pattern := range c.config.Policy.IDJAGScopes {
				if matchScopePattern(pattern, scope) {
					return ProtocolIDJAG
				}
			}
		}
	}

	return c.config.Policy.Default
}

// matchScopePattern checks if a scope matches a pattern (supports * wildcards).
func matchScopePattern(pattern, scope string) bool {
	if pattern == scope {
		return true
	}

	// Handle wildcards
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(scope, prefix)
	}

	if strings.HasPrefix(pattern, "*:") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(scope, suffix)
	}

	if pattern == "**" || pattern == "*" {
		return true
	}

	return false
}

// authorizeAAuth handles AAuth protocol authorization.
func (c *UnifiedClient) authorizeAAuth(_ context.Context, req *AuthRequest) (*AuthResult, error) {
	// TODO: ctx will be used when implementing full Person Server interaction
	if c.aauth == nil {
		return nil, fmt.Errorf("AAuth not configured (missing Person Server or Agent ID)")
	}

	// Build audience
	audience := req.Audience
	if len(audience) == 0 {
		if req.Resource != "" {
			audience = []string{req.Resource}
		} else {
			audience = c.config.DefaultAudience
		}
	}

	// Get agent token
	agentToken, err := c.aauth.GetOrCreateAgentToken(audience...)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent token: %w", err)
	}

	// For now, return a result indicating AAuth flow is needed
	// In a full implementation, this would interact with the Person Server
	scope := strings.Join(req.Scopes, " ")

	return &AuthResult{
		Status:     "pending",
		Protocol:   ProtocolAAuth,
		ConsentURI: fmt.Sprintf("%s/consent?scope=%s", c.config.PersonServer, scope),
		StatusURI:  fmt.Sprintf("%s/consent/status", c.config.PersonServer),
		Token:      agentToken, // Agent token for the consent flow
		Scopes:     req.Scopes,
	}, nil
}

// authorizeIDJAG handles ID-JAG protocol authorization.
func (c *UnifiedClient) authorizeIDJAG(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	if c.idjag == nil {
		return nil, fmt.Errorf("ID-JAG not configured (missing Token Endpoint)")
	}

	// Build audience
	audience := req.Audience
	if len(audience) == 0 {
		if req.Resource != "" {
			audience = []string{req.Resource}
		} else {
			audience = c.config.DefaultAudience
		}
	}

	// Create ID-JAG assertion
	ttl := c.config.AssertionTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	var assertion *idjag.Assertion
	if req.Subject != "" {
		// Delegated assertion
		assertion = idjag.NewDelegatedAssertion(
			c.config.AgentID,
			req.Subject,
			c.config.AgentID,
			audience,
			ttl,
		)
	} else {
		// Simple assertion
		assertion = idjag.NewAssertion(
			c.config.AgentID,
			c.config.AgentID,
			audience,
			ttl,
		)
	}

	// Sign the assertion
	signedAssertion, err := assertion.Sign(jwt.SigningMethodES256, c.privateKey, c.keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Exchange for access token
	scope := strings.Join(req.Scopes, " ")
	tokenResp, err := c.idjag.Exchange(ctx, &idjag.TokenExchangeRequest{
		SubjectToken:     signedAssertion,
		SubjectTokenType: idjag.TokenTypeIDJAG,
		Scope:            scope,
		Resource:         req.Resource,
	})
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	return &AuthResult{
		Status:    "approved",
		Protocol:  ProtocolIDJAG,
		Token:     tokenResp.AccessToken,
		TokenType: tokenResp.TokenType,
		ExpiresAt: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scopes:    strings.Fields(tokenResp.Scope),
	}, nil
}

// HTTPClient returns an HTTP client that automatically adds authorization.
func (c *UnifiedClient) HTTPClient(req *AuthRequest) *http.Client {
	return &http.Client{
		Transport: &unifiedTransport{
			base:   c.httpClient.Transport,
			client: c,
			req:    req,
		},
		Timeout: c.httpClient.Timeout,
	}
}

// unifiedTransport adds authorization to HTTP requests.
type unifiedTransport struct {
	base   http.RoundTripper
	client *UnifiedClient
	req    *AuthRequest
}

func (t *unifiedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get authorization
	result, err := t.client.Authorize(req.Context(), t.req)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	if !result.IsApproved() {
		return nil, fmt.Errorf("authorization pending: %s", result.ConsentURI)
	}

	// Clone request and add authorization
	r2 := req.Clone(req.Context())
	tokenType := result.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	r2.Header.Set("Authorization", tokenType+" "+result.Token)

	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r2)
}

// cacheKey generates a cache key for a request.
func (c *UnifiedClient) cacheKey(req *AuthRequest) string {
	key := req.Resource
	for _, scope := range req.Scopes {
		key += ":" + scope
	}
	return key
}

// checkCache checks for a cached authorization result.
func (c *UnifiedClient) checkCache(req *AuthRequest) *AuthResult {
	if !c.config.CacheEnabled {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.cacheKey(req)
	cached, ok := c.cache[key]
	if !ok {
		return nil
	}

	// Check expiration (with 1 minute buffer)
	if time.Now().Add(time.Minute).After(cached.expiresAt) {
		return nil
	}

	return cached.result
}

// cacheResult caches a successful authorization result.
func (c *UnifiedClient) cacheResult(req *AuthRequest, result *AuthResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.cache) >= c.config.CacheMaxSize {
		c.evictOldest()
	}

	c.cache[c.cacheKey(req)] = &cachedAuthResult{
		result:    result,
		expiresAt: result.ExpiresAt,
	}
}

// evictOldest removes the oldest cache entry.
func (c *UnifiedClient) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range c.cache {
		if oldestKey == "" || cached.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.expiresAt
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// ClearCache removes all cached authorization results.
func (c *UnifiedClient) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*cachedAuthResult)
}

// GetProtocolForScopes returns which protocol would be used for the given scopes.
func (c *UnifiedClient) GetProtocolForScopes(scopes []string) Protocol {
	return c.selectProtocol(&AuthRequest{Scopes: scopes})
}

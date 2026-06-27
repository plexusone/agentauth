package agentauth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HybridProvider routes authorization requests to the appropriate provider
// based on policy configuration.
type HybridProvider struct {
	config  *Config
	matcher *PolicyMatcher

	idjag Provider
	aauth Provider

	// Token cache
	cacheMu sync.RWMutex
	cache   map[string]*cachedToken
}

type cachedToken struct {
	result    *AuthResult
	expiresAt time.Time
}

// HybridProviderOption configures the HybridProvider.
type HybridProviderOption func(*HybridProvider)

// WithIDJAGProvider sets the ID-JAG provider.
func WithIDJAGProvider(p Provider) HybridProviderOption {
	return func(h *HybridProvider) {
		h.idjag = p
	}
}

// WithAAuthProvider sets the AAuth provider.
func WithAAuthProvider(p Provider) HybridProviderOption {
	return func(h *HybridProvider) {
		h.aauth = p
	}
}

// NewHybridProvider creates a new hybrid provider.
func NewHybridProvider(config *Config, opts ...HybridProviderOption) (*HybridProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	h := &HybridProvider{
		config:  config,
		matcher: NewPolicyMatcher(config.Policy),
		cache:   make(map[string]*cachedToken),
	}

	for _, opt := range opts {
		opt(h)
	}

	return h, nil
}

// Authorize routes the request to the appropriate provider based on policy.
func (h *HybridProvider) Authorize(ctx context.Context, req *AuthRequest) (*AuthResult, error) {
	// Check cache first
	if result := h.checkCache(req); result != nil {
		return result, nil
	}

	// Determine protocol based on policy or override
	protocol := req.ForceProtocol
	if protocol == "" {
		protocol = h.matcher.Match(req.Scopes)
	}

	// Route to appropriate provider
	var provider Provider
	switch protocol {
	case ProtocolIDJAG:
		provider = h.idjag
		if provider == nil {
			return nil, fmt.Errorf("%w: idjag", ErrProviderNotConfigured)
		}
	case ProtocolAAuth:
		provider = h.aauth
		if provider == nil {
			return nil, fmt.Errorf("%w: aauth", ErrProviderNotConfigured)
		}
	default:
		return nil, fmt.Errorf("unknown protocol: %s", protocol)
	}

	// Execute authorization
	result, err := provider.Authorize(ctx, req)
	if err != nil {
		return nil, err
	}

	// Cache successful results
	if result.IsApproved() {
		h.cacheResult(req, result)
	}

	return result, nil
}

// CheckConsent delegates to the appropriate provider.
func (h *HybridProvider) CheckConsent(ctx context.Context, statusURI string) (*AuthResult, error) {
	// Consent is only used by AAuth
	if h.aauth == nil {
		return nil, fmt.Errorf("%w: aauth (required for consent)", ErrProviderNotConfigured)
	}
	return h.aauth.CheckConsent(ctx, statusURI)
}

// WaitForConsent polls for consent approval.
func (h *HybridProvider) WaitForConsent(ctx context.Context, statusURI string, timeout time.Duration) (*AuthResult, error) {
	if h.aauth == nil {
		return nil, fmt.Errorf("%w: aauth (required for consent)", ErrProviderNotConfigured)
	}
	return h.aauth.WaitForConsent(ctx, statusURI, timeout)
}

// Revoke revokes an authorization.
func (h *HybridProvider) Revoke(ctx context.Context, token string) error {
	// Try both providers
	var lastErr error
	if h.idjag != nil {
		if err := h.idjag.Revoke(ctx, token); err != nil {
			lastErr = err
		}
	}
	if h.aauth != nil {
		if err := h.aauth.Revoke(ctx, token); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// Protocol returns the hybrid protocol identifier.
func (h *HybridProvider) Protocol() Protocol {
	return "hybrid"
}

// HTTPClient returns an HTTP client with automatic authorization.
func (h *HybridProvider) HTTPClient(ctx context.Context, req *AuthRequest) (*http.Client, error) {
	// Get authorization first
	result, err := h.Authorize(ctx, req)
	if err != nil {
		return nil, err
	}

	if !result.IsApproved() {
		return nil, fmt.Errorf("%w: %s", ErrConsentRequired, result.ConsentURI)
	}

	// Create client with authorization transport
	return &http.Client{
		Transport: &authTransport{
			base:      http.DefaultTransport,
			token:     result.Token,
			tokenType: result.TokenType,
		},
	}, nil
}

// authTransport adds authorization headers to requests.
type authTransport struct {
	base      http.RoundTripper
	token     string
	tokenType string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request to avoid modifying the original
	r2 := req.Clone(req.Context())

	tokenType := t.tokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}
	r2.Header.Set("Authorization", tokenType+" "+t.token)

	return t.base.RoundTrip(r2)
}

// cacheKey generates a cache key for a request.
func (h *HybridProvider) cacheKey(req *AuthRequest) string {
	// Simple key based on scopes and resource
	key := req.Resource
	for _, scope := range req.Scopes {
		key += ":" + scope
	}
	return key
}

// checkCache checks for a cached token.
func (h *HybridProvider) checkCache(req *AuthRequest) *AuthResult {
	if h.config.Cache == nil || !h.config.Cache.Enabled {
		return nil
	}

	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()

	key := h.cacheKey(req)
	cached, ok := h.cache[key]
	if !ok {
		return nil
	}

	// Check if expired
	if time.Now().After(cached.expiresAt) {
		return nil
	}

	return cached.result
}

// cacheResult caches a successful authorization result.
func (h *HybridProvider) cacheResult(req *AuthRequest, result *AuthResult) {
	if h.config.Cache == nil || !h.config.Cache.Enabled {
		return
	}

	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()

	// Determine expiry
	expiresAt := result.ExpiresAt
	if expiresAt.IsZero() {
		// Default to 1 hour
		expiresAt = time.Now().Add(time.Hour)
	} else {
		// Expire 1 minute early to avoid edge cases
		expiresAt = expiresAt.Add(-time.Minute)
	}

	// Check cache size
	if len(h.cache) >= h.config.Cache.MaxSize {
		// Simple eviction: remove oldest
		h.evictOldest()
	}

	h.cache[h.cacheKey(req)] = &cachedToken{
		result:    result,
		expiresAt: expiresAt,
	}
}

// evictOldest removes the oldest cache entry.
func (h *HybridProvider) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range h.cache {
		if oldestKey == "" || cached.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.expiresAt
		}
	}

	if oldestKey != "" {
		delete(h.cache, oldestKey)
	}
}

// ClearCache clears the token cache.
func (h *HybridProvider) ClearCache() {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	h.cache = make(map[string]*cachedToken)
}

// PolicyMatcher returns the policy matcher for inspection.
func (h *HybridProvider) PolicyMatcher() *PolicyMatcher {
	return h.matcher
}

// GetProviderForScopes returns which provider would be used for the given scopes.
func (h *HybridProvider) GetProviderForScopes(scopes []string) (Protocol, Provider) {
	protocol := h.matcher.Match(scopes)
	switch protocol {
	case ProtocolIDJAG:
		return protocol, h.idjag
	case ProtocolAAuth:
		return protocol, h.aauth
	default:
		return protocol, nil
	}
}

// Package verifier provides unified token verification for multiple agent authentication protocols.
// It supports AAuth (aa-agent+jwt, aa-auth+jwt) and ID-JAG tokens with automatic protocol detection,
// JWKS caching, and issuer validation.
package verifier

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Protocol identifies the authentication protocol.
type Protocol string

const (
	// ProtocolAAuth is the AAuth protocol (agent tokens, auth tokens).
	ProtocolAAuth Protocol = "aauth"
	// ProtocolIDJAG is the ID-JAG protocol (identity assertion grant).
	ProtocolIDJAG Protocol = "idjag"
	// ProtocolUnknown indicates an unrecognized protocol.
	ProtocolUnknown Protocol = "unknown"
)

// TokenType identifies the specific token type within a protocol.
type TokenType string

const (
	// TokenTypeAgentToken is an AAuth agent token (aa-agent+jwt).
	TokenTypeAgentToken TokenType = "aa-agent+jwt" //nolint:gosec // Not a credential, this is a token type identifier
	// TokenTypeAuthToken is an AAuth auth token (aa-auth+jwt).
	TokenTypeAuthToken TokenType = "aa-auth+jwt" //nolint:gosec // Not a credential, this is a token type identifier
	// TokenTypeIDJAG is an ID-JAG assertion token.
	TokenTypeIDJAG TokenType = "id-jag"
	// TokenTypeAccessToken is a standard OAuth access token.
	TokenTypeAccessToken TokenType = "access_token"
)

// Claims represents verified token claims from any supported protocol.
type Claims struct {
	// Protocol identifies which protocol issued this token.
	Protocol Protocol `json:"protocol"`

	// TokenType identifies the specific token type.
	TokenType TokenType `json:"token_type"`

	// Standard JWT claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti,omitempty"`

	// Scope (space-separated or array)
	Scopes []string `json:"scopes,omitempty"`

	// AAuth-specific claims
	AgentID   string `json:"agent_id,omitempty"`   // For auth tokens: the agent this authorizes
	MissionID string `json:"mission_id,omitempty"` // Mission identifier

	// ID-JAG-specific claims
	Actor string `json:"act,omitempty"` // Actor claim for delegation

	// Confirmation claim (proof-of-possession)
	CNF *CNF `json:"cnf,omitempty"`

	// Raw claims for protocol-specific access
	Raw map[string]any `json:"raw,omitempty"`
}

// CNF represents the confirmation claim for proof-of-possession.
type CNF struct {
	JWK json.RawMessage `json:"jwk,omitempty"`
	JKT string          `json:"jkt,omitempty"` // JWK Thumbprint
}

// Verifier validates tokens from multiple agent authentication protocols.
type Verifier struct {
	trustedIssuers map[string]bool
	protocols      map[Protocol]bool
	httpClient     *http.Client
	cacheTTL       time.Duration

	// JWKS cache
	mu    sync.RWMutex
	cache map[string]*jwksCache
}

type jwksCache struct {
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithTrustedIssuers sets the list of trusted token issuers.
func WithTrustedIssuers(issuers ...string) Option {
	return func(v *Verifier) {
		for _, iss := range issuers {
			v.trustedIssuers[iss] = true
		}
	}
}

// WithProtocols sets which protocols to accept.
func WithProtocols(protocols ...Protocol) Option {
	return func(v *Verifier) {
		v.protocols = make(map[Protocol]bool)
		for _, p := range protocols {
			v.protocols[p] = true
		}
	}
}

// WithHTTPClient sets a custom HTTP client for JWKS fetching.
func WithHTTPClient(client *http.Client) Option {
	return func(v *Verifier) {
		v.httpClient = client
	}
}

// WithJWKSCache sets the JWKS cache TTL.
func WithJWKSCache(ttl time.Duration) Option {
	return func(v *Verifier) {
		v.cacheTTL = ttl
	}
}

// New creates a new multi-protocol token verifier.
func New(opts ...Option) (*Verifier, error) {
	v := &Verifier{
		trustedIssuers: make(map[string]bool),
		protocols:      map[Protocol]bool{ProtocolAAuth: true, ProtocolIDJAG: true},
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		cacheTTL:       time.Hour,
		cache:          make(map[string]*jwksCache),
	}

	for _, opt := range opts {
		opt(v)
	}

	return v, nil
}

// Verify validates a token and returns the claims.
// It automatically detects the protocol and token type.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, ErrEmptyToken
	}

	// Parse without verification first to extract header and claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Detect protocol and token type
	protocol, tokenType := v.detectProtocol(token)
	if !v.protocols[protocol] {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProtocol, protocol)
	}

	// Extract issuer
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, ErrMissingIssuer
	}

	// Check trusted issuers
	if len(v.trustedIssuers) > 0 && !v.trustedIssuers[issuer] {
		return nil, fmt.Errorf("%w: %s", ErrUntrustedIssuer, issuer)
	}

	// Get signing key
	keyID, _ := token.Header["kid"].(string)
	key, err := v.getSigningKey(ctx, issuer, keyID, protocol)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyNotFound, err)
	}

	// Verify signature with the key
	verifiedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "EdDSA"}))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	if !verifiedToken.Valid {
		return nil, ErrSignatureInvalid
	}

	// Build claims
	return v.buildClaims(claims, protocol, tokenType)
}

// detectProtocol determines the protocol and token type from the token.
func (v *Verifier) detectProtocol(token *jwt.Token) (Protocol, TokenType) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ProtocolUnknown, ""
	}

	// Check typ header
	if typ, ok := token.Header["typ"].(string); ok {
		switch typ {
		case "aa-agent+jwt":
			return ProtocolAAuth, TokenTypeAgentToken
		case "aa-auth+jwt":
			return ProtocolAAuth, TokenTypeAuthToken
		}
	}

	// Check for ID-JAG specific claims
	if _, hasAct := claims["act"]; hasAct {
		return ProtocolIDJAG, TokenTypeIDJAG
	}

	// Check for AAuth-specific claims
	if _, hasAgentID := claims["agent_id"]; hasAgentID {
		return ProtocolAAuth, TokenTypeAuthToken
	}

	// Check for CNF claim (common in AAuth)
	if _, hasCNF := claims["cnf"]; hasCNF {
		return ProtocolAAuth, TokenTypeAgentToken
	}

	// Default to ID-JAG for standard JWT
	return ProtocolIDJAG, TokenTypeAccessToken
}

// getSigningKey retrieves the public key for signature verification.
func (v *Verifier) getSigningKey(ctx context.Context, issuer, keyID string, protocol Protocol) (crypto.PublicKey, error) {
	// Check cache
	v.mu.RLock()
	cached, ok := v.cache[issuer]
	if ok && time.Since(cached.fetchedAt) < v.cacheTTL {
		if key, ok := cached.keys[keyID]; ok {
			v.mu.RUnlock()
			return key, nil
		}
		// Key ID not found, but cache is still valid - might be a new key
		if keyID == "" && len(cached.keys) == 1 {
			// Use the only key if no kid specified
			for _, key := range cached.keys {
				v.mu.RUnlock()
				return key, nil
			}
		}
	}
	v.mu.RUnlock()

	// Fetch JWKS
	jwksURL := v.jwksURL(issuer, protocol)
	keys, err := v.fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}

	// Update cache
	v.mu.Lock()
	v.cache[issuer] = &jwksCache{
		keys:      keys,
		fetchedAt: time.Now(),
	}
	v.mu.Unlock()

	// Return requested key
	if key, ok := keys[keyID]; ok {
		return key, nil
	}
	if keyID == "" && len(keys) == 1 {
		for _, key := range keys {
			return key, nil
		}
	}

	return nil, fmt.Errorf("key %q not found in JWKS", keyID)
}

// jwksURL constructs the JWKS URL for an issuer.
func (v *Verifier) jwksURL(issuer string, protocol Protocol) string {
	issuer = strings.TrimSuffix(issuer, "/")

	switch protocol {
	case ProtocolAAuth:
		// Try AAuth metadata first
		return issuer + "/.well-known/jwks.json"
	case ProtocolIDJAG:
		// OAuth/OIDC convention
		return issuer + "/.well-known/jwks.json"
	default:
		return issuer + "/.well-known/jwks.json"
	}
}

// fetchJWKS retrieves and parses a JWKS from a URL.
// The URL is derived from trusted issuer metadata, not user input.
func (v *Verifier) fetchJWKS(ctx context.Context, url string) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil) //nolint:gosec // URL is from trusted issuer
	if err != nil {
		return nil, err
	}

	resp, err := v.httpClient.Do(req) //nolint:gosec // URL is from trusted issuer
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed: %s", resp.Status)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	keys := make(map[string]crypto.PublicKey)
	for _, keyData := range jwks.Keys {
		key, kid, err := parseJWK(keyData)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[kid] = key
	}

	if len(keys) == 0 {
		return nil, errors.New("no valid keys in JWKS")
	}

	return keys, nil
}

// buildClaims constructs Claims from JWT map claims.
func (v *Verifier) buildClaims(claims jwt.MapClaims, protocol Protocol, tokenType TokenType) (*Claims, error) {
	c := &Claims{
		Protocol:  protocol,
		TokenType: tokenType,
		Raw:       claims,
	}

	// Standard claims
	c.Issuer, _ = claims["iss"].(string)
	c.Subject, _ = claims["sub"].(string)
	c.JWTID, _ = claims["jti"].(string)

	if exp, ok := claims["exp"].(float64); ok {
		c.ExpiresAt = int64(exp)
	}
	if iat, ok := claims["iat"].(float64); ok {
		c.IssuedAt = int64(iat)
	}

	// Audience (can be string or array)
	switch aud := claims["aud"].(type) {
	case string:
		c.Audience = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	}

	// Scope (can be string or array)
	switch scope := claims["scope"].(type) {
	case string:
		c.Scopes = strings.Fields(scope)
	case []any:
		for _, s := range scope {
			if str, ok := s.(string); ok {
				c.Scopes = append(c.Scopes, str)
			}
		}
	}

	// AAuth-specific
	c.AgentID, _ = claims["agent_id"].(string)
	c.MissionID, _ = claims["mission_id"].(string)

	// ID-JAG-specific
	if act, ok := claims["act"].(map[string]any); ok {
		if sub, ok := act["sub"].(string); ok {
			c.Actor = sub
		}
	}

	// CNF claim
	if cnfRaw, ok := claims["cnf"].(map[string]any); ok {
		c.CNF = &CNF{}
		if jkt, ok := cnfRaw["jkt"].(string); ok {
			c.CNF.JKT = jkt
		}
		if jwk, ok := cnfRaw["jwk"]; ok {
			if jwkBytes, err := json.Marshal(jwk); err == nil {
				c.CNF.JWK = jwkBytes
			}
		}
	}

	// Validate expiration
	if c.ExpiresAt > 0 && time.Now().Unix() > c.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return c, nil
}

// ClearCache clears the JWKS cache.
func (v *Verifier) ClearCache() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.cache = make(map[string]*jwksCache)
}

// AddTrustedIssuer adds an issuer to the trusted list.
func (v *Verifier) AddTrustedIssuer(issuer string) {
	v.trustedIssuers[issuer] = true
}

// RemoveTrustedIssuer removes an issuer from the trusted list.
func (v *Verifier) RemoveTrustedIssuer(issuer string) {
	delete(v.trustedIssuers, issuer)
}

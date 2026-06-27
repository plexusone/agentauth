// Package client provides a Go SDK for agents to interact with AgentAuth servers.
//
// The client supports both ID-JAG (automated) and AAuth (human consent) authorization flows.
//
// Example usage for ID-JAG flow:
//
//	client := client.New("https://authz.example.com")
//	token, err := client.ExchangeIDJAG(ctx, idJagAssertion, "read:email read:profile")
//
// Example usage for AAuth flow:
//
//	client := client.New("https://authz.example.com")
//	token, err := client.RequestAuthorization(ctx, &client.AuthorizationRequest{
//	    AgentToken:  agentToken,
//	    UserID:      "user-123",
//	    Scopes:      "write:profile",
//	    MissionName: "Update Profile",
//	})
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client provides methods to interact with AgentAuth servers.
type Client struct {
	// Base URL of the AgentAuth server
	baseURL string

	// HTTP client for making requests
	httpClient *http.Client

	// Token cache
	mu           sync.RWMutex
	cachedTokens map[string]*Token

	// Consent polling settings
	pollInterval time.Duration
	pollTimeout  time.Duration
}

// Token represents an access token with metadata.
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"-"`
}

// IsExpired returns true if the token has expired.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsExpiringSoon returns true if the token expires within the given duration.
func (t *Token) IsExpiringSoon(within time.Duration) bool {
	return time.Now().Add(within).After(t.ExpiresAt)
}

// AuthorizationRequest is a request for authorization via AAuth.
type AuthorizationRequest struct {
	AgentToken      string `json:"agent_token"`
	UserID          string `json:"user_id"`
	Scopes          string `json:"scope"`
	MissionName     string `json:"mission_name,omitempty"`
	MissionDesc     string `json:"mission_description,omitempty"`
	InteractionType string `json:"interaction_type,omitempty"`
	Duration        int64  `json:"duration,omitempty"`
	RedirectURI     string `json:"redirect_uri,omitempty"`
	State           string `json:"state,omitempty"`
}

// AuthorizationResult contains the result of an authorization request.
type AuthorizationResult struct {
	// Status is "approved", "denied", "pending", or "expired"
	Status string

	// Token is set if the authorization was approved
	Token *Token

	// ConsentURI is set if human consent is required
	ConsentURI string

	// StatusURI is set if human consent is required (for polling)
	StatusURI string

	// MissionID identifies the pending mission
	MissionID string

	// Error information if the request failed
	Error     string
	ErrorDesc string
}

// Option configures the Client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithPollInterval sets the interval for polling consent status.
func WithPollInterval(interval time.Duration) Option {
	return func(c *Client) {
		c.pollInterval = interval
	}
}

// WithPollTimeout sets the maximum time to wait for consent.
func WithPollTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.pollTimeout = timeout
	}
}

// New creates a new AgentAuth client.
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		cachedTokens: make(map[string]*Token),
		pollInterval: 2 * time.Second,
		pollTimeout:  5 * time.Minute,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ExchangeIDJAG exchanges an ID-JAG assertion for an access token.
// This uses the RFC 8693 token exchange protocol.
func (c *Client) ExchangeIDJAG(ctx context.Context, assertion, scope string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", assertion)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id-jag")
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.doTokenRequest(ctx, c.baseURL+"/oauth/token", form)
}

// ExchangeJWTBearer exchanges a JWT bearer assertion for an access token.
// This uses the RFC 7523 JWT bearer grant type.
func (c *Client) ExchangeJWTBearer(ctx context.Context, assertion, scope string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.doTokenRequest(ctx, c.baseURL+"/oauth/token", form)
}

// RequestAuthorization requests authorization via the AAuth flow.
// If pre-authorized, returns immediately with a token.
// If consent is required, returns a result with ConsentURI for the user to visit.
func (c *Client) RequestAuthorization(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/aauth/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Immediate approval (pre-authorized)
		var tokenResp struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}
		if err := json.Unmarshal(respBody, &tokenResp); err != nil {
			return nil, fmt.Errorf("decode token response: %w", err)
		}
		return &AuthorizationResult{
			Status: "approved",
			Token: &Token{
				AccessToken: tokenResp.AccessToken,
				TokenType:   tokenResp.TokenType,
				ExpiresIn:   tokenResp.ExpiresIn,
				Scope:       tokenResp.Scope,
				ExpiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
			},
		}, nil

	case http.StatusAccepted:
		// Consent required
		var consentResp struct {
			ConsentURI string `json:"consent_uri"`
			StatusURI  string `json:"status_uri"`
			MissionID  string `json:"mission_id"`
			Interval   int    `json:"interval"`
		}
		if err := json.Unmarshal(respBody, &consentResp); err != nil {
			return nil, fmt.Errorf("decode consent response: %w", err)
		}
		return &AuthorizationResult{
			Status:     "pending",
			ConsentURI: consentResp.ConsentURI,
			StatusURI:  consentResp.StatusURI,
			MissionID:  consentResp.MissionID,
		}, nil

	default:
		// Error
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return &AuthorizationResult{
			Status:    "error",
			Error:     errResp.Error,
			ErrorDesc: errResp.Description,
		}, nil
	}
}

// RequestAuthorizationAndWait requests authorization and waits for consent if needed.
// This is a convenience method that combines RequestAuthorization with PollConsentStatus.
// It blocks until the user approves/denies or the timeout is reached.
func (c *Client) RequestAuthorizationAndWait(ctx context.Context, req *AuthorizationRequest) (*Token, error) {
	result, err := c.RequestAuthorization(ctx, req)
	if err != nil {
		return nil, err
	}

	switch result.Status {
	case "approved":
		return result.Token, nil
	case "pending":
		return c.WaitForConsent(ctx, result.StatusURI)
	default:
		if result.Error != "" {
			return nil, fmt.Errorf("%s: %s", result.Error, result.ErrorDesc)
		}
		return nil, fmt.Errorf("unexpected status: %s", result.Status)
	}
}

// PollConsentStatus polls the status URI once and returns the current status.
func (c *Client) PollConsentStatus(ctx context.Context, statusURI string) (*AuthorizationResult, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURI, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var statusResp struct {
		Status      string `json:"status"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(respBody, &statusResp); err != nil {
		return nil, fmt.Errorf("decode status response: %w", err)
	}

	result := &AuthorizationResult{
		Status:    statusResp.Status,
		Error:     statusResp.Error,
		ErrorDesc: statusResp.ErrorDesc,
	}

	if statusResp.Status == "approved" && statusResp.AccessToken != "" {
		result.Token = &Token{
			AccessToken: statusResp.AccessToken,
			TokenType:   statusResp.TokenType,
			ExpiresIn:   statusResp.ExpiresIn,
			Scope:       statusResp.Scope,
			ExpiresAt:   time.Now().Add(time.Duration(statusResp.ExpiresIn) * time.Second),
		}
	}

	return result, nil
}

// WaitForConsent polls the status URI until consent is granted or denied.
// It respects the client's pollInterval and pollTimeout settings.
func (c *Client) WaitForConsent(ctx context.Context, statusURI string) (*Token, error) {
	deadline := time.Now().Add(c.pollTimeout)
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("consent timeout after %v", c.pollTimeout)
			}

			result, err := c.PollConsentStatus(ctx, statusURI)
			if err != nil {
				return nil, err
			}

			switch result.Status {
			case "approved":
				return result.Token, nil
			case "denied":
				return nil, fmt.Errorf("consent denied")
			case "expired":
				return nil, fmt.Errorf("consent request expired")
			case "pending":
				// Continue polling
			default:
				if result.Error != "" {
					return nil, fmt.Errorf("%s: %s", result.Error, result.ErrorDesc)
				}
			}
		}
	}
}

// RefreshToken refreshes an access token using a refresh token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken, scope string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	if scope != "" {
		form.Set("scope", scope)
	}

	return c.doTokenRequest(ctx, c.baseURL+"/oauth/token", form)
}

// Introspect checks if a token is valid and returns its metadata.
func (c *Client) Introspect(ctx context.Context, token string) (*IntrospectionResult, error) {
	form := url.Values{}
	form.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result IntrospectionResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, nil
}

// IntrospectionResult contains token introspection data.
type IntrospectionResult struct {
	Active    bool           `json:"active"`
	Scope     string         `json:"scope,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	Username  string         `json:"username,omitempty"`
	TokenType string         `json:"token_type,omitempty"`
	Exp       int64          `json:"exp,omitempty"`
	Iat       int64          `json:"iat,omitempty"`
	Sub       string         `json:"sub,omitempty"`
	Aud       string         `json:"aud,omitempty"`
	Iss       string         `json:"iss,omitempty"`
	Act       map[string]any `json:"act,omitempty"`
}

// Revoke invalidates an access or refresh token.
func (c *Client) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	form := url.Values{}
	form.Set("token", token)
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke failed: %d %s", resp.StatusCode, string(body))
	}

	return nil
}

// CacheToken stores a token in the client's cache.
func (c *Client) CacheToken(key string, token *Token) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cachedTokens[key] = token
}

// GetCachedToken retrieves a non-expired token from the cache.
// Returns nil if the token is not found or expired.
func (c *Client) GetCachedToken(key string) *Token {
	c.mu.RLock()
	defer c.mu.RUnlock()
	token, ok := c.cachedTokens[key]
	if !ok || token.IsExpired() {
		return nil
	}
	return token
}

// ClearCache removes all cached tokens.
func (c *Client) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cachedTokens = make(map[string]*Token)
}

func (c *Client) doTokenRequest(ctx context.Context, endpoint string, form url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("%s: %s", errResp.Error, errResp.Description)
		}
		return nil, fmt.Errorf("token request failed: %d %s", resp.StatusCode, string(body))
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	return &token, nil
}

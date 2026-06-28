// Package agentprovider implements the AAuth Agent Provider role.
// The Agent Provider is responsible for:
// - Agent registration and lifecycle management
// - Agent key management (public keys)
// - Agent token issuance (aa-agent+jwt)
// - Publishing metadata and JWKS
package agentprovider

import (
	"crypto"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/plexusone/agentauth/store"
)

// Provider implements the AAuth Agent Provider role.
type Provider struct {
	store  store.AgentProviderStorer
	issuer string
	logger *slog.Logger

	// Signing configuration
	signingKey crypto.PrivateKey
	keyID      string
	algorithm  string

	// Token configuration
	tokenTTL time.Duration
}

// Option configures the Provider.
type Option func(*Provider)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(p *Provider) {
		p.logger = logger
	}
}

// WithTokenTTL sets the default token TTL.
func WithTokenTTL(ttl time.Duration) Option {
	return func(p *Provider) {
		p.tokenTTL = ttl
	}
}

// WithAlgorithm sets the signing algorithm.
func WithAlgorithm(alg string) Option {
	return func(p *Provider) {
		p.algorithm = alg
	}
}

// New creates a new Agent Provider.
func New(
	store store.AgentProviderStorer,
	issuer string,
	signingKey crypto.PrivateKey,
	keyID string,
	opts ...Option,
) (*Provider, error) {
	p := &Provider{
		store:      store,
		issuer:     issuer,
		signingKey: signingKey,
		keyID:      keyID,
		algorithm:  "ES256",
		tokenTTL:   time.Hour,
		logger:     slog.Default(),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// RegisterHandlers registers HTTP handlers on the given mux.
// Endpoints:
//
//	GET  /.well-known/aauth-agent-provider  - Discovery metadata
//	GET  /.well-known/jwks.json             - Public keys
//	POST /agents                            - Register new agent
//	GET  /agents/{id}                       - Get agent info
//	DELETE /agents/{id}                     - Revoke agent
//	POST /agents/{id}/keys                  - Add key to agent
//	GET  /agents/{id}/keys                  - List agent keys
//	DELETE /agents/{id}/keys/{kid}          - Revoke key
//	POST /token                             - Issue agent token
func (p *Provider) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/aauth-agent-provider", p.HandleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", p.HandleJWKS)
	mux.HandleFunc("POST /agents", p.HandleRegisterAgent)
	mux.HandleFunc("GET /agents/{id}", p.HandleGetAgent)
	mux.HandleFunc("DELETE /agents/{id}", p.HandleRevokeAgent)
	mux.HandleFunc("POST /agents/{id}/keys", p.HandleAddKey)
	mux.HandleFunc("GET /agents/{id}/keys", p.HandleListKeys)
	mux.HandleFunc("DELETE /agents/{id}/keys/{kid}", p.HandleRevokeKey)
	mux.HandleFunc("POST /token", p.HandleToken)
}

// Metadata returns the Agent Provider metadata.
type Metadata struct {
	Issuer               string   `json:"issuer"`
	TokenEndpoint        string   `json:"token_endpoint"`
	RegistrationEndpoint string   `json:"registration_endpoint"`
	JWKSUri              string   `json:"jwks_uri"`
	TokenTypesSupported  []string `json:"token_types_supported"`
	SigningAlgsSupported []string `json:"signing_algs_supported"`
	GrantTypesSupported  []string `json:"grant_types_supported"`
}

// HandleMetadata returns the Agent Provider metadata.
func (p *Provider) HandleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := Metadata{
		Issuer:               p.issuer,
		TokenEndpoint:        p.issuer + "/token",
		RegistrationEndpoint: p.issuer + "/agents",
		JWKSUri:              p.issuer + "/.well-known/jwks.json",
		TokenTypesSupported:  []string{"aa-agent+jwt"},
		SigningAlgsSupported: []string{"ES256", "ES384", "ES512", "EdDSA"},
		GrantTypesSupported:  []string{"client_credentials"},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		p.logger.Error("failed to encode metadata", "error", err)
	}
}

// HandleJWKS returns the Agent Provider's public keys.
func (p *Provider) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := p.buildJWKS()
	if err != nil {
		p.logger.Error("failed to build JWKS", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		p.logger.Error("failed to encode JWKS", "error", err)
	}
}

// RegisterAgentRequest is the request body for agent registration.
type RegisterAgentRequest struct {
	ID          string            `json:"id"` // Requested agent ID
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	PublicKey   json.RawMessage   `json:"public_key"` // JWK format
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// RegisterAgentResponse is the response for agent registration.
type RegisterAgentResponse struct {
	ID       string `json:"id"`
	Issuer   string `json:"issuer"`
	KeyID    string `json:"key_id"`
	TokenURL string `json:"token_url"`
}

// HandleRegisterAgent handles agent registration.
func (p *Provider) HandleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	var req RegisterAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.ID == "" || req.Name == "" {
		http.Error(w, "id and name are required", http.StatusBadRequest)
		return
	}

	// Extract owner from auth context (simplified - would check auth token)
	ownerID := r.Header.Get("X-Owner-ID")
	if ownerID == "" {
		ownerID = "anonymous"
	}

	// Create registered agent
	now := time.Now()
	agent := &store.RegisteredAgent{
		ID:          req.ID,
		Name:        req.Name,
		Description: req.Description,
		OwnerID:     ownerID,
		Issuer:      p.issuer,
		Metadata:    req.Metadata,
		Status:      store.AgentStatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := p.store.RegisterAgent(r.Context(), agent); err != nil {
		if err == store.ErrAlreadyExists {
			http.Error(w, "agent already exists", http.StatusConflict)
			return
		}
		p.logger.Error("failed to register agent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Register the initial key
	keyID := generateKeyID()
	key := &store.AgentKey{
		ID:        keyID,
		AgentID:   req.ID,
		PublicKey: string(req.PublicKey),
		Algorithm: detectAlgorithm(req.PublicKey),
		Use:       "sig",
		CreatedAt: now,
	}

	if err := p.store.CreateAgentKey(r.Context(), key); err != nil {
		p.logger.Error("failed to create agent key", "error", err)
		// Don't fail the whole registration
	}

	resp := RegisterAgentResponse{
		ID:       agent.ID,
		Issuer:   p.issuer,
		KeyID:    keyID,
		TokenURL: p.issuer + "/token",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("failed to encode response", "error", err)
	}
}

// HandleGetAgent returns agent information.
func (p *Provider) HandleGetAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, "agent id required", http.StatusBadRequest)
		return
	}

	agent, err := p.store.GetRegisteredAgent(r.Context(), agentID)
	if err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}
		p.logger.Error("failed to get agent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Get agent's keys
	keys, _ := p.store.ListAgentKeys(r.Context(), agentID)

	resp := map[string]any{
		"id":          agent.ID,
		"name":        agent.Name,
		"description": agent.Description,
		"issuer":      agent.Issuer,
		"status":      agent.Status,
		"created_at":  agent.CreatedAt,
		"keys":        keys,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("failed to encode response", "error", err)
	}
}

// HandleRevokeAgent revokes an agent.
func (p *Provider) HandleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, "agent id required", http.StatusBadRequest)
		return
	}

	if err := p.store.RevokeRegisteredAgent(r.Context(), agentID); err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}
		p.logger.Error("failed to revoke agent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleAddKey adds a key to an agent.
func (p *Provider) HandleAddKey(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, "agent id required", http.StatusBadRequest)
		return
	}

	var req struct {
		PublicKey json.RawMessage `json:"public_key"`
		ExpiresIn int64           `json:"expires_in,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	now := time.Now()
	keyID := generateKeyID()
	key := &store.AgentKey{
		ID:        keyID,
		AgentID:   agentID,
		PublicKey: string(req.PublicKey),
		Algorithm: detectAlgorithm(req.PublicKey),
		Use:       "sig",
		CreatedAt: now,
	}

	if req.ExpiresIn > 0 {
		exp := now.Add(time.Duration(req.ExpiresIn) * time.Second)
		key.ExpiresAt = &exp
	}

	if err := p.store.CreateAgentKey(r.Context(), key); err != nil {
		p.logger.Error("failed to create key", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"key_id":     keyID,
		"created_at": now,
		"expires_at": key.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		p.logger.Error("failed to encode response", "error", err)
	}
}

// HandleListKeys lists an agent's keys.
func (p *Provider) HandleListKeys(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, "agent id required", http.StatusBadRequest)
		return
	}

	keys, err := p.store.ListAgentKeys(r.Context(), agentID)
	if err != nil {
		p.logger.Error("failed to list keys", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Filter out revoked keys and private information
	var publicKeys []map[string]any
	for _, k := range keys {
		if k.RevokedAt != nil {
			continue
		}
		publicKeys = append(publicKeys, map[string]any{
			"key_id":     k.ID,
			"algorithm":  k.Algorithm,
			"created_at": k.CreatedAt,
			"expires_at": k.ExpiresAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"keys": publicKeys}); err != nil {
		p.logger.Error("failed to encode response", "error", err)
	}
}

// HandleRevokeKey revokes an agent key.
func (p *Provider) HandleRevokeKey(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	keyID := r.PathValue("kid")
	if agentID == "" || keyID == "" {
		http.Error(w, "agent id and key id required", http.StatusBadRequest)
		return
	}

	if err := p.store.RevokeAgentKey(r.Context(), agentID, keyID); err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		p.logger.Error("failed to revoke key", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TokenRequest is the request for an agent token.
type TokenRequest struct {
	GrantType string `json:"grant_type"` // client_credentials
	AgentID   string `json:"agent_id"`
	Audience  string `json:"audience,omitempty"`
}

// TokenResponse is the response containing an agent token.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// HandleToken issues an agent token.
func (p *Provider) HandleToken(w http.ResponseWriter, r *http.Request) {
	// Parse form or JSON
	var agentID, audience string

	contentType := r.Header.Get("Content-Type")
	if contentType == "application/x-www-form-urlencoded" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		agentID = r.Form.Get("agent_id")
		audience = r.Form.Get("audience")
	} else {
		var req TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		agentID = req.AgentID
		audience = req.Audience
	}

	if agentID == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}

	// Verify agent exists and is active
	agent, err := p.store.GetRegisteredAgent(r.Context(), agentID)
	if err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}
		p.logger.Error("failed to get agent", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if !agent.IsActive() {
		http.Error(w, "agent is not active", http.StatusForbidden)
		return
	}

	// Issue token
	token, err := p.issueAgentToken(r.Context(), agent, audience)
	if err != nil {
		p.logger.Error("failed to issue token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := TokenResponse{ //nolint:gosec // TokenResponse is an OAuth token response, not hardcoded creds
		AccessToken: token,
		TokenType:   "aa-agent+jwt",
		ExpiresIn:   int64(p.tokenTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil { //nolint:gosec // Response contains token intentionally
		p.logger.Error("failed to encode response", "error", err)
	}
}

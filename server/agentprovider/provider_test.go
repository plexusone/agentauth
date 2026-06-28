package agentprovider

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/agentauth/store"
)

// mockAgentProviderStore implements store.AgentProviderStorer for testing.
type mockAgentProviderStore struct {
	store.Storer // Embed nil Storer for unimplemented methods

	agents map[string]*store.RegisteredAgent
	keys   map[string]map[string]*store.AgentKey
	tokens map[string]*store.IssuedAgentToken
}

func newMockAgentProviderStore() *mockAgentProviderStore {
	return &mockAgentProviderStore{
		agents: make(map[string]*store.RegisteredAgent),
		keys:   make(map[string]map[string]*store.AgentKey),
		tokens: make(map[string]*store.IssuedAgentToken),
	}
}

// Verify mockAgentProviderStore implements AgentProviderStorer.
var _ store.AgentProviderStorer = (*mockAgentProviderStore)(nil)

func (m *mockAgentProviderStore) RegisterAgent(_ context.Context, agent *store.RegisteredAgent) error {
	if agent.ID == "" {
		return store.ErrInvalidInput
	}
	if _, exists := m.agents[agent.ID]; exists {
		return store.ErrAlreadyExists
	}
	now := time.Now()
	agent.CreatedAt = now
	agent.UpdatedAt = now
	m.agents[agent.ID] = agent
	m.keys[agent.ID] = make(map[string]*store.AgentKey)
	return nil
}

func (m *mockAgentProviderStore) GetRegisteredAgent(_ context.Context, agentID string) (*store.RegisteredAgent, error) {
	agent, exists := m.agents[agentID]
	if !exists {
		return nil, store.ErrNotFound
	}
	return agent, nil
}

func (m *mockAgentProviderStore) UpdateRegisteredAgent(_ context.Context, agent *store.RegisteredAgent) error {
	if _, exists := m.agents[agent.ID]; !exists {
		return store.ErrNotFound
	}
	agent.UpdatedAt = time.Now()
	m.agents[agent.ID] = agent
	return nil
}

func (m *mockAgentProviderStore) RevokeRegisteredAgent(_ context.Context, agentID string) error {
	agent, exists := m.agents[agentID]
	if !exists || agent.Status == store.AgentStatusRevoked {
		return store.ErrNotFound
	}
	now := time.Now()
	agent.Status = store.AgentStatusRevoked
	agent.RevokedAt = &now
	agent.UpdatedAt = now
	return nil
}

func (m *mockAgentProviderStore) ListRegisteredAgents(_ context.Context, ownerID string) ([]*store.RegisteredAgent, error) {
	var result []*store.RegisteredAgent
	for _, agent := range m.agents {
		if agent.OwnerID == ownerID {
			result = append(result, agent)
		}
	}
	return result, nil
}

func (m *mockAgentProviderStore) ListAllRegisteredAgents(_ context.Context) ([]*store.RegisteredAgent, error) {
	var result []*store.RegisteredAgent
	for _, agent := range m.agents {
		result = append(result, agent)
	}
	return result, nil
}

func (m *mockAgentProviderStore) CreateAgentKey(_ context.Context, key *store.AgentKey) error {
	if key.ID == "" {
		key.ID = "generated-kid"
	}
	key.CreatedAt = time.Now()
	if m.keys[key.AgentID] == nil {
		m.keys[key.AgentID] = make(map[string]*store.AgentKey)
	}
	if _, exists := m.keys[key.AgentID][key.ID]; exists {
		return store.ErrAlreadyExists
	}
	m.keys[key.AgentID][key.ID] = key
	return nil
}

func (m *mockAgentProviderStore) GetAgentKey(_ context.Context, agentID, keyID string) (*store.AgentKey, error) {
	if m.keys[agentID] == nil {
		return nil, store.ErrNotFound
	}
	key, exists := m.keys[agentID][keyID]
	if !exists {
		return nil, store.ErrNotFound
	}
	return key, nil
}

func (m *mockAgentProviderStore) ListAgentKeys(_ context.Context, agentID string) ([]*store.AgentKey, error) {
	var result []*store.AgentKey
	if m.keys[agentID] != nil {
		for _, key := range m.keys[agentID] {
			result = append(result, key)
		}
	}
	return result, nil
}

func (m *mockAgentProviderStore) RevokeAgentKey(_ context.Context, agentID, keyID string) error {
	if m.keys[agentID] == nil {
		return store.ErrNotFound
	}
	key, exists := m.keys[agentID][keyID]
	if !exists || key.RevokedAt != nil {
		return store.ErrNotFound
	}
	now := time.Now()
	key.RevokedAt = &now
	return nil
}

func (m *mockAgentProviderStore) CreateIssuedAgentToken(_ context.Context, token *store.IssuedAgentToken) error {
	if token.JTI == "" {
		token.JTI = "generated-jti"
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now()
	}
	if _, exists := m.tokens[token.JTI]; exists {
		return store.ErrAlreadyExists
	}
	m.tokens[token.JTI] = token
	return nil
}

func (m *mockAgentProviderStore) GetIssuedAgentToken(_ context.Context, jti string) (*store.IssuedAgentToken, error) {
	token, exists := m.tokens[jti]
	if !exists {
		return nil, store.ErrNotFound
	}
	return token, nil
}

func (m *mockAgentProviderStore) RevokeIssuedAgentToken(_ context.Context, jti string) error {
	token, exists := m.tokens[jti]
	if !exists || token.RevokedAt != nil {
		return store.ErrNotFound
	}
	now := time.Now()
	token.RevokedAt = &now
	return nil
}

func (m *mockAgentProviderStore) ListIssuedAgentTokens(_ context.Context, agentID string) ([]*store.IssuedAgentToken, error) {
	var result []*store.IssuedAgentToken
	for _, token := range m.tokens {
		if token.AgentID == agentID {
			result = append(result, token)
		}
	}
	return result, nil
}

// generateTestKey creates a test ECDSA key.
func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

func TestNew(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, err := New(mockStore, "https://example.com", key, "test-key-id")
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if provider.issuer != "https://example.com" {
		t.Errorf("expected issuer https://example.com, got %s", provider.issuer)
	}
	if provider.keyID != "test-key-id" {
		t.Errorf("expected keyID test-key-id, got %s", provider.keyID)
	}
	if provider.algorithm != "ES256" {
		t.Errorf("expected default algorithm ES256, got %s", provider.algorithm)
	}
	if provider.tokenTTL != time.Hour {
		t.Errorf("expected default tokenTTL 1h, got %v", provider.tokenTTL)
	}
}

func TestNew_WithOptions(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, err := New(
		mockStore,
		"https://example.com",
		key,
		"test-key-id",
		WithTokenTTL(30*time.Minute),
		WithAlgorithm("ES384"),
	)
	if err != nil {
		t.Fatalf("New with options failed: %v", err)
	}

	if provider.tokenTTL != 30*time.Minute {
		t.Errorf("expected tokenTTL 30m, got %v", provider.tokenTTL)
	}
	if provider.algorithm != "ES384" {
		t.Errorf("expected algorithm ES384, got %s", provider.algorithm)
	}
}

func TestHandleMetadata(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/aauth-agent-provider", nil)
	rec := httptest.NewRecorder()

	provider.HandleMetadata(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	var metadata Metadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	if metadata.Issuer != "https://example.com" {
		t.Errorf("expected issuer https://example.com, got %s", metadata.Issuer)
	}
	if metadata.TokenEndpoint != "https://example.com/token" {
		t.Errorf("expected token_endpoint https://example.com/token, got %s", metadata.TokenEndpoint)
	}
	if metadata.RegistrationEndpoint != "https://example.com/agents" {
		t.Errorf("expected registration_endpoint https://example.com/agents, got %s", metadata.RegistrationEndpoint)
	}
	if metadata.JWKSUri != "https://example.com/.well-known/jwks.json" {
		t.Errorf("expected jwks_uri https://example.com/.well-known/jwks.json, got %s", metadata.JWKSUri)
	}
	if len(metadata.TokenTypesSupported) != 1 || metadata.TokenTypesSupported[0] != "aa-agent+jwt" {
		t.Errorf("expected token_types_supported [aa-agent+jwt], got %v", metadata.TokenTypesSupported)
	}
	if len(metadata.GrantTypesSupported) != 1 || metadata.GrantTypesSupported[0] != "client_credentials" {
		t.Errorf("expected grant_types_supported [client_credentials], got %v", metadata.GrantTypesSupported)
	}
}

func TestHandleJWKS(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	provider.HandleJWKS(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	cacheControl := rec.Header().Get("Cache-Control")
	if cacheControl != "public, max-age=3600" {
		t.Errorf("expected Cache-Control public, max-age=3600, got %s", cacheControl)
	}

	var jwks map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode JWKS: %v", err)
	}

	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %v", jwks)
	}

	jwk, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatalf("expected JWK to be map, got %T", keys[0])
	}

	if jwk["kid"] != "test-key-id" {
		t.Errorf("expected kid test-key-id, got %v", jwk["kid"])
	}
	if jwk["kty"] != "EC" {
		t.Errorf("expected kty EC, got %v", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("expected crv P-256, got %v", jwk["crv"])
	}
	if jwk["use"] != "sig" {
		t.Errorf("expected use sig, got %v", jwk["use"])
	}
	if jwk["alg"] != "ES256" {
		t.Errorf("expected alg ES256, got %v", jwk["alg"])
	}
}

func TestHandleRegisterAgent(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	body := `{
		"id": "test-agent",
		"name": "Test Agent",
		"description": "A test agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`

	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Owner-ID", "user-123")
	rec := httptest.NewRecorder()

	provider.HandleRegisterAgent(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp RegisterAgentResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.ID != "test-agent" {
		t.Errorf("expected ID test-agent, got %s", resp.ID)
	}
	if resp.Issuer != "https://example.com" {
		t.Errorf("expected Issuer https://example.com, got %s", resp.Issuer)
	}
	if resp.TokenURL != "https://example.com/token" {
		t.Errorf("expected TokenURL https://example.com/token, got %s", resp.TokenURL)
	}
	if resp.KeyID == "" {
		t.Error("expected KeyID to be set")
	}
}

func TestHandleRegisterAgent_InvalidBody(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	provider.HandleRegisterAgent(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestHandleRegisterAgent_MissingFields(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	body := `{"name": "Test Agent"}` // missing id

	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	provider.HandleRegisterAgent(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestHandleRegisterAgent_Duplicate(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	body := `{
		"id": "duplicate-agent",
		"name": "Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`

	// First registration
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("first registration failed: %d", rec.Code)
	}

	// Duplicate registration
	req = httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("expected status 409 for duplicate, got %d", rec.Code)
	}
}

func TestHandleGetAgent(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent
	body := `{
		"id": "get-test-agent",
		"name": "Get Test Agent",
		"description": "Agent for get testing",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Now get the agent
	req = httptest.NewRequest(http.MethodGet, "/agents/get-test-agent", nil)
	req.SetPathValue("id", "get-test-agent")
	rec = httptest.NewRecorder()

	provider.HandleGetAgent(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["id"] != "get-test-agent" {
		t.Errorf("expected id get-test-agent, got %v", resp["id"])
	}
	if resp["name"] != "Get Test Agent" {
		t.Errorf("expected name Get Test Agent, got %v", resp["name"])
	}
	if resp["status"] != "active" {
		t.Errorf("expected status active, got %v", resp["status"])
	}
}

func TestHandleGetAgent_NotFound(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	req := httptest.NewRequest(http.MethodGet, "/agents/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rec := httptest.NewRecorder()

	provider.HandleGetAgent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestHandleRevokeAgent(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent
	body := `{
		"id": "revoke-test-agent",
		"name": "Revoke Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Now revoke the agent
	req = httptest.NewRequest(http.MethodDelete, "/agents/revoke-test-agent", nil)
	req.SetPathValue("id", "revoke-test-agent")
	rec = httptest.NewRecorder()

	provider.HandleRevokeAgent(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRevokeAgent_NotFound(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	req := httptest.NewRequest(http.MethodDelete, "/agents/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	rec := httptest.NewRecorder()

	provider.HandleRevokeAgent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestHandleAddKey(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent
	body := `{
		"id": "addkey-test-agent",
		"name": "Add Key Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Now add another key
	keyBody := `{
		"public_key": {"kty":"EC","crv":"P-256","x":"ghi","y":"jkl"},
		"expires_in": 86400
	}`
	req = httptest.NewRequest(http.MethodPost, "/agents/addkey-test-agent/keys", strings.NewReader(keyBody))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "addkey-test-agent")
	rec = httptest.NewRecorder()

	provider.HandleAddKey(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["key_id"] == nil || resp["key_id"] == "" {
		t.Error("expected key_id to be set")
	}
}

func TestHandleListKeys(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent with a key
	body := `{
		"id": "listkeys-test-agent",
		"name": "List Keys Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// List keys
	req = httptest.NewRequest(http.MethodGet, "/agents/listkeys-test-agent/keys", nil)
	req.SetPathValue("id", "listkeys-test-agent")
	rec = httptest.NewRecorder()

	provider.HandleListKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	keys, ok := resp["keys"].([]any)
	if !ok {
		t.Fatalf("expected keys to be array, got %T", resp["keys"])
	}
	// Should have 1 key from registration
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestHandleRevokeKey(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent
	body := `{
		"id": "revokekey-test-agent",
		"name": "Revoke Key Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Get the key ID from the response
	var regResp RegisterAgentResponse
	if err := json.NewDecoder(rec.Body).Decode(&regResp); err != nil {
		t.Fatalf("failed to decode registration response: %v", err)
	}

	// Revoke the key
	req = httptest.NewRequest(http.MethodDelete, "/agents/revokekey-test-agent/keys/"+regResp.KeyID, nil)
	req.SetPathValue("id", "revokekey-test-agent")
	req.SetPathValue("kid", regResp.KeyID)
	rec = httptest.NewRecorder()

	provider.HandleRevokeKey(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected status 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRevokeKey_NotFound(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	req := httptest.NewRequest(http.MethodDelete, "/agents/nonexistent/keys/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	req.SetPathValue("kid", "nonexistent")
	rec := httptest.NewRecorder()

	provider.HandleRevokeKey(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestHandleToken(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent
	body := `{
		"id": "token-test-agent",
		"name": "Token Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Now request a token (JSON format)
	//nolint:gosec // G101 false positive - test data, not actual credentials
	tokenBody := `{
		"grant_type": "client_credentials",
		"agent_id": "token-test-agent",
		"audience": "https://api.example.com"
	}`
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	provider.HandleToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp TokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AccessToken == "" {
		t.Error("expected access_token to be set")
	}
	if resp.TokenType != "aa-agent+jwt" {
		t.Errorf("expected token_type aa-agent+jwt, got %s", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 { // 1 hour default
		t.Errorf("expected expires_in 3600, got %d", resp.ExpiresIn)
	}
}

func TestHandleToken_FormURLEncoded(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// First register an agent
	body := `{
		"id": "token-form-agent",
		"name": "Token Form Test Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Now request a token (form URL encoded)
	formData := "grant_type=client_credentials&agent_id=token-form-agent&audience=https://api.example.com"
	req = httptest.NewRequest(http.MethodPost, "/token", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()

	provider.HandleToken(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleToken_AgentNotFound(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	//nolint:gosec // G101 false positive - test data, not actual credentials
	tokenBody := `{
		"grant_type": "client_credentials",
		"agent_id": "nonexistent"
	}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	provider.HandleToken(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestHandleToken_AgentNotActive(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	// Register and then revoke an agent
	body := `{
		"id": "inactive-agent",
		"name": "Inactive Agent",
		"public_key": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/agents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	provider.HandleRegisterAgent(rec, req)

	// Revoke the agent
	req = httptest.NewRequest(http.MethodDelete, "/agents/inactive-agent", nil)
	req.SetPathValue("id", "inactive-agent")
	rec = httptest.NewRecorder()
	provider.HandleRevokeAgent(rec, req)

	// Now try to get a token
	//nolint:gosec // G101 false positive - test data, not actual credentials
	tokenBody := `{
		"grant_type": "client_credentials",
		"agent_id": "inactive-agent"
	}`
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()

	provider.HandleToken(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestHandleToken_MissingAgentID(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	//nolint:gosec // G101 false positive - test data, not actual credentials
	tokenBody := `{
		"grant_type": "client_credentials"
	}`
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	provider.HandleToken(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rec.Code)
	}
}

func TestRegisterHandlers(t *testing.T) {
	mockStore := newMockAgentProviderStore()
	key := generateTestKey(t)

	provider, _ := New(mockStore, "https://example.com", key, "test-key-id")

	mux := http.NewServeMux()
	provider.RegisterHandlers(mux)

	// Test that endpoints are registered by making requests
	testCases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/.well-known/aauth-agent-provider"},
		{http.MethodGet, "/.well-known/jwks.json"},
		{http.MethodPost, "/agents"},
		{http.MethodPost, "/token"},
	}

	for _, tc := range testCases {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()

		mux.ServeHTTP(rec, req)

		// Just check that we don't get 404 (handler was registered)
		// Other status codes are fine (400 for missing body, etc.)
		if rec.Code == http.StatusNotFound && rec.Body.String() == "404 page not found\n" {
			t.Errorf("handler not registered for %s %s", tc.method, tc.path)
		}
	}
}

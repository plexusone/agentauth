package store

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSQLiteStore_AgentProviderInterface verifies SQLiteStore implements AgentProviderStorer.
func TestSQLiteStore_AgentProviderInterface(t *testing.T) {
	// This is a compile-time check; if it compiles, the interface is satisfied
	var _ AgentProviderStorer = (*SQLiteStore)(nil)
}

// setupTestDB creates a temporary SQLite database for testing.
func setupTestDB(t *testing.T) (*SQLiteStore, func()) {
	t.Helper()

	tmpfile, err := os.CreateTemp("", "agentauth-test-*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpfile.Close()

	store, err := NewSQLite(tmpfile.Name())
	if err != nil {
		os.Remove(tmpfile.Name())
		t.Fatalf("failed to create SQLiteStore: %v", err)
	}

	// Ensure Agent Provider tables
	if err := store.EnsureAgentProviderTables(); err != nil {
		store.Close()
		os.Remove(tmpfile.Name())
		t.Fatalf("failed to ensure Agent Provider tables: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.Remove(tmpfile.Name())
	}

	return store, cleanup
}

func TestSQLiteStore_RegisterAgent(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test registering a new agent
	agent := &RegisteredAgent{
		ID:          "aauth:test-agent@example.com",
		Name:        "Test Agent",
		Description: "A test agent for unit testing",
		OwnerID:     "user-123",
		Issuer:      "https://example.com",
		Metadata:    map[string]string{"version": "1.0", "env": "test"},
		Status:      AgentStatusActive,
	}

	err := store.RegisterAgent(ctx, agent)
	if err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	if agent.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if agent.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}

	// Test duplicate registration
	agent2 := &RegisteredAgent{
		ID:      "aauth:test-agent@example.com",
		Name:    "Duplicate Agent",
		OwnerID: "user-456",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	err = store.RegisterAgent(ctx, agent2)
	if err != ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}

	// Test empty ID
	agent3 := &RegisteredAgent{
		Name:    "No ID Agent",
		OwnerID: "user-789",
		Issuer:  "https://example.com",
	}
	err = store.RegisterAgent(ctx, agent3)
	if err != ErrInvalidInput {
		t.Errorf("expected ErrInvalidInput for empty ID, got %v", err)
	}
}

func TestSQLiteStore_GetRegisteredAgent(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent first
	agent := &RegisteredAgent{
		ID:          "aauth:get-test@example.com",
		Name:        "Get Test Agent",
		Description: "Agent for get testing",
		OwnerID:     "user-123",
		Issuer:      "https://example.com",
		Metadata:    map[string]string{"key": "value"},
		Status:      AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Test getting the agent
	retrieved, err := store.GetRegisteredAgent(ctx, "aauth:get-test@example.com")
	if err != nil {
		t.Fatalf("GetRegisteredAgent failed: %v", err)
	}

	if retrieved.ID != agent.ID {
		t.Errorf("expected ID %s, got %s", agent.ID, retrieved.ID)
	}
	if retrieved.Name != agent.Name {
		t.Errorf("expected Name %s, got %s", agent.Name, retrieved.Name)
	}
	if retrieved.Description != agent.Description {
		t.Errorf("expected Description %s, got %s", agent.Description, retrieved.Description)
	}
	if retrieved.OwnerID != agent.OwnerID {
		t.Errorf("expected OwnerID %s, got %s", agent.OwnerID, retrieved.OwnerID)
	}
	if retrieved.Issuer != agent.Issuer {
		t.Errorf("expected Issuer %s, got %s", agent.Issuer, retrieved.Issuer)
	}
	if retrieved.Status != AgentStatusActive {
		t.Errorf("expected status active, got %s", retrieved.Status)
	}
	if retrieved.Metadata["key"] != "value" {
		t.Errorf("expected metadata key=value, got %v", retrieved.Metadata)
	}

	// Test getting non-existent agent
	_, err = store.GetRegisteredAgent(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_UpdateRegisteredAgent(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent first
	agent := &RegisteredAgent{
		ID:          "aauth:update-test@example.com",
		Name:        "Original Name",
		Description: "Original description",
		OwnerID:     "user-123",
		Issuer:      "https://example.com",
		Status:      AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Update the agent
	agent.Name = "Updated Name"
	agent.Description = "Updated description"
	agent.Metadata = map[string]string{"new": "metadata"}
	agent.Status = AgentStatusSuspended

	err := store.UpdateRegisteredAgent(ctx, agent)
	if err != nil {
		t.Fatalf("UpdateRegisteredAgent failed: %v", err)
	}

	// Verify the update
	retrieved, err := store.GetRegisteredAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetRegisteredAgent failed: %v", err)
	}

	if retrieved.Name != "Updated Name" {
		t.Errorf("expected Name 'Updated Name', got %s", retrieved.Name)
	}
	if retrieved.Description != "Updated description" {
		t.Errorf("expected Description 'Updated description', got %s", retrieved.Description)
	}
	if retrieved.Metadata["new"] != "metadata" {
		t.Errorf("expected metadata new=metadata, got %v", retrieved.Metadata)
	}
	if retrieved.Status != AgentStatusSuspended {
		t.Errorf("expected status suspended, got %s", retrieved.Status)
	}

	// Test updating non-existent agent
	nonexistent := &RegisteredAgent{
		ID:   "nonexistent",
		Name: "Test",
	}
	err = store.UpdateRegisteredAgent(ctx, nonexistent)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_RevokeRegisteredAgent(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent first
	agent := &RegisteredAgent{
		ID:      "aauth:revoke-test@example.com",
		Name:    "Revoke Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Revoke the agent
	err := store.RevokeRegisteredAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("RevokeRegisteredAgent failed: %v", err)
	}

	// Verify the revocation
	retrieved, err := store.GetRegisteredAgent(ctx, agent.ID)
	if err != nil {
		t.Fatalf("GetRegisteredAgent failed: %v", err)
	}

	if retrieved.Status != AgentStatusRevoked {
		t.Errorf("expected status revoked, got %s", retrieved.Status)
	}
	if retrieved.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if !retrieved.IsActive() {
		// This is expected
	} else {
		t.Error("expected IsActive() to return false for revoked agent")
	}

	// Test revoking already revoked agent (should return ErrNotFound)
	err = store.RevokeRegisteredAgent(ctx, agent.ID)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for already revoked agent, got %v", err)
	}

	// Test revoking non-existent agent
	err = store.RevokeRegisteredAgent(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_ListRegisteredAgents(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create agents for two different owners
	agents := []*RegisteredAgent{
		{ID: "agent-1", Name: "Agent 1", OwnerID: "owner-1", Issuer: "https://example.com", Status: AgentStatusActive},
		{ID: "agent-2", Name: "Agent 2", OwnerID: "owner-1", Issuer: "https://example.com", Status: AgentStatusActive},
		{ID: "agent-3", Name: "Agent 3", OwnerID: "owner-2", Issuer: "https://example.com", Status: AgentStatusActive},
	}

	for _, a := range agents {
		if err := store.RegisterAgent(ctx, a); err != nil {
			t.Fatalf("RegisterAgent failed: %v", err)
		}
	}

	// List agents for owner-1
	owner1Agents, err := store.ListRegisteredAgents(ctx, "owner-1")
	if err != nil {
		t.Fatalf("ListRegisteredAgents failed: %v", err)
	}
	if len(owner1Agents) != 2 {
		t.Errorf("expected 2 agents for owner-1, got %d", len(owner1Agents))
	}

	// List agents for owner-2
	owner2Agents, err := store.ListRegisteredAgents(ctx, "owner-2")
	if err != nil {
		t.Fatalf("ListRegisteredAgents failed: %v", err)
	}
	if len(owner2Agents) != 1 {
		t.Errorf("expected 1 agent for owner-2, got %d", len(owner2Agents))
	}

	// List agents for non-existent owner
	noAgents, err := store.ListRegisteredAgents(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ListRegisteredAgents failed: %v", err)
	}
	if len(noAgents) != 0 {
		t.Errorf("expected 0 agents for nonexistent owner, got %d", len(noAgents))
	}
}

func TestSQLiteStore_ListAllRegisteredAgents(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create agents
	agents := []*RegisteredAgent{
		{ID: "all-1", Name: "Agent 1", OwnerID: "owner-1", Issuer: "https://example.com", Status: AgentStatusActive},
		{ID: "all-2", Name: "Agent 2", OwnerID: "owner-2", Issuer: "https://example.com", Status: AgentStatusActive},
		{ID: "all-3", Name: "Agent 3", OwnerID: "owner-3", Issuer: "https://example.com", Status: AgentStatusActive},
	}

	for _, a := range agents {
		if err := store.RegisterAgent(ctx, a); err != nil {
			t.Fatalf("RegisterAgent failed: %v", err)
		}
	}

	// List all agents
	allAgents, err := store.ListAllRegisteredAgents(ctx)
	if err != nil {
		t.Fatalf("ListAllRegisteredAgents failed: %v", err)
	}
	if len(allAgents) != 3 {
		t.Errorf("expected 3 agents, got %d", len(allAgents))
	}
}

func TestSQLiteStore_CreateAgentKey(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent first
	agent := &RegisteredAgent{
		ID:      "aauth:key-test@example.com",
		Name:    "Key Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create a key
	key := &AgentKey{
		AgentID:   agent.ID,
		PublicKey: `{"kty":"EC","crv":"P-256","x":"WbbXwA","y":"NbQkPv"}`,
		Algorithm: "ES256",
		Use:       "sig",
	}

	err := store.CreateAgentKey(ctx, key)
	if err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}

	if key.ID == "" {
		t.Error("expected key ID to be generated")
	}
	if key.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	// Create another key with expiration
	expiration := time.Now().Add(time.Hour * 24)
	key2 := &AgentKey{
		AgentID:   agent.ID,
		PublicKey: `{"kty":"EC","crv":"P-256","x":"AnotherKey","y":"Value"}`,
		Algorithm: "ES256",
		Use:       "sig",
		ExpiresAt: &expiration,
	}

	err = store.CreateAgentKey(ctx, key2)
	if err != nil {
		t.Fatalf("CreateAgentKey with expiration failed: %v", err)
	}
}

func TestSQLiteStore_GetAgentKey(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent and key
	agent := &RegisteredAgent{
		ID:      "aauth:getkey-test@example.com",
		Name:    "Get Key Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	key := &AgentKey{
		ID:        "test-key-id",
		AgentID:   agent.ID,
		PublicKey: `{"kty":"EC","crv":"P-256","x":"TestKey","y":"Value"}`,
		Algorithm: "ES256",
		Use:       "sig",
	}
	if err := store.CreateAgentKey(ctx, key); err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}

	// Get the key
	retrieved, err := store.GetAgentKey(ctx, agent.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}

	if retrieved.ID != key.ID {
		t.Errorf("expected ID %s, got %s", key.ID, retrieved.ID)
	}
	if retrieved.AgentID != agent.ID {
		t.Errorf("expected AgentID %s, got %s", agent.ID, retrieved.AgentID)
	}
	if retrieved.Algorithm != "ES256" {
		t.Errorf("expected Algorithm ES256, got %s", retrieved.Algorithm)
	}
	if retrieved.Use != "sig" {
		t.Errorf("expected Use sig, got %s", retrieved.Use)
	}

	// Test getting non-existent key
	_, err = store.GetAgentKey(ctx, agent.ID, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_ListAgentKeys(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent
	agent := &RegisteredAgent{
		ID:      "aauth:listkeys-test@example.com",
		Name:    "List Keys Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create multiple keys
	for i := 0; i < 3; i++ {
		key := &AgentKey{
			AgentID:   agent.ID,
			PublicKey: `{"kty":"EC","crv":"P-256"}`,
			Algorithm: "ES256",
			Use:       "sig",
		}
		if err := store.CreateAgentKey(ctx, key); err != nil {
			t.Fatalf("CreateAgentKey failed: %v", err)
		}
	}

	// List keys
	keys, err := store.ListAgentKeys(ctx, agent.ID)
	if err != nil {
		t.Fatalf("ListAgentKeys failed: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}

	// List keys for non-existent agent
	noKeys, err := store.ListAgentKeys(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ListAgentKeys failed: %v", err)
	}
	if len(noKeys) != 0 {
		t.Errorf("expected 0 keys for nonexistent agent, got %d", len(noKeys))
	}
}

func TestSQLiteStore_RevokeAgentKey(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent and key
	agent := &RegisteredAgent{
		ID:      "aauth:revokekey-test@example.com",
		Name:    "Revoke Key Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	key := &AgentKey{
		ID:        "revoke-test-key",
		AgentID:   agent.ID,
		PublicKey: `{"kty":"EC"}`,
		Algorithm: "ES256",
		Use:       "sig",
	}
	if err := store.CreateAgentKey(ctx, key); err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}

	// Revoke the key
	err := store.RevokeAgentKey(ctx, agent.ID, key.ID)
	if err != nil {
		t.Fatalf("RevokeAgentKey failed: %v", err)
	}

	// Verify revocation
	retrieved, err := store.GetAgentKey(ctx, agent.ID, key.ID)
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}
	if retrieved.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if retrieved.IsValid() {
		t.Error("expected IsValid() to return false for revoked key")
	}

	// Test revoking already revoked key
	err = store.RevokeAgentKey(ctx, agent.ID, key.ID)
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for already revoked key, got %v", err)
	}

	// Test revoking non-existent key
	err = store.RevokeAgentKey(ctx, agent.ID, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_CreateIssuedAgentToken(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent
	agent := &RegisteredAgent{
		ID:      "aauth:token-test@example.com",
		Name:    "Token Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create a token
	token := &IssuedAgentToken{
		AgentID:   agent.ID,
		KeyID:     "test-key",
		Audience:  "https://api.example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := store.CreateIssuedAgentToken(ctx, token)
	if err != nil {
		t.Fatalf("CreateIssuedAgentToken failed: %v", err)
	}

	if token.JTI == "" {
		t.Error("expected JTI to be generated")
	}
	if token.IssuedAt.IsZero() {
		t.Error("expected IssuedAt to be set")
	}

	// Test creating token with explicit JTI
	token2 := &IssuedAgentToken{
		JTI:       "explicit-jti-123",
		AgentID:   agent.ID,
		KeyID:     "test-key",
		Audience:  "https://api.example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err = store.CreateIssuedAgentToken(ctx, token2)
	if err != nil {
		t.Fatalf("CreateIssuedAgentToken with explicit JTI failed: %v", err)
	}
	if token2.JTI != "explicit-jti-123" {
		t.Errorf("expected JTI explicit-jti-123, got %s", token2.JTI)
	}

	// Test duplicate JTI
	token3 := &IssuedAgentToken{
		JTI:       "explicit-jti-123",
		AgentID:   agent.ID,
		KeyID:     "test-key",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	err = store.CreateIssuedAgentToken(ctx, token3)
	if err != ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestSQLiteStore_GetIssuedAgentToken(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent and token
	agent := &RegisteredAgent{
		ID:      "aauth:gettoken-test@example.com",
		Name:    "Get Token Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	token := &IssuedAgentToken{
		JTI:       "get-test-jti",
		AgentID:   agent.ID,
		KeyID:     "test-key",
		Audience:  "https://api.example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateIssuedAgentToken(ctx, token); err != nil {
		t.Fatalf("CreateIssuedAgentToken failed: %v", err)
	}

	// Get the token
	retrieved, err := store.GetIssuedAgentToken(ctx, "get-test-jti")
	if err != nil {
		t.Fatalf("GetIssuedAgentToken failed: %v", err)
	}

	if retrieved.JTI != "get-test-jti" {
		t.Errorf("expected JTI get-test-jti, got %s", retrieved.JTI)
	}
	if retrieved.AgentID != agent.ID {
		t.Errorf("expected AgentID %s, got %s", agent.ID, retrieved.AgentID)
	}
	if retrieved.Audience != "https://api.example.com" {
		t.Errorf("expected Audience https://api.example.com, got %s", retrieved.Audience)
	}

	// Test getting non-existent token
	_, err = store.GetIssuedAgentToken(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_RevokeIssuedAgentToken(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent and token
	agent := &RegisteredAgent{
		ID:      "aauth:revoketoken-test@example.com",
		Name:    "Revoke Token Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	token := &IssuedAgentToken{
		JTI:       "revoke-test-jti",
		AgentID:   agent.ID,
		KeyID:     "test-key",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateIssuedAgentToken(ctx, token); err != nil {
		t.Fatalf("CreateIssuedAgentToken failed: %v", err)
	}

	// Revoke the token
	err := store.RevokeIssuedAgentToken(ctx, "revoke-test-jti")
	if err != nil {
		t.Fatalf("RevokeIssuedAgentToken failed: %v", err)
	}

	// Verify revocation
	retrieved, err := store.GetIssuedAgentToken(ctx, "revoke-test-jti")
	if err != nil {
		t.Fatalf("GetIssuedAgentToken failed: %v", err)
	}
	if retrieved.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if retrieved.IsValid() {
		t.Error("expected IsValid() to return false for revoked token")
	}

	// Test revoking already revoked token
	err = store.RevokeIssuedAgentToken(ctx, "revoke-test-jti")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound for already revoked token, got %v", err)
	}

	// Test revoking non-existent token
	err = store.RevokeIssuedAgentToken(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSQLiteStore_ListIssuedAgentTokens(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create an agent
	agent := &RegisteredAgent{
		ID:      "aauth:listtokens-test@example.com",
		Name:    "List Tokens Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create multiple tokens
	for i := 0; i < 3; i++ {
		token := &IssuedAgentToken{
			AgentID:   agent.ID,
			KeyID:     "test-key",
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := store.CreateIssuedAgentToken(ctx, token); err != nil {
			t.Fatalf("CreateIssuedAgentToken failed: %v", err)
		}
	}

	// List tokens
	tokens, err := store.ListIssuedAgentTokens(ctx, agent.ID)
	if err != nil {
		t.Fatalf("ListIssuedAgentTokens failed: %v", err)
	}
	if len(tokens) != 3 {
		t.Errorf("expected 3 tokens, got %d", len(tokens))
	}

	// List tokens for non-existent agent
	noTokens, err := store.ListIssuedAgentTokens(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("ListIssuedAgentTokens failed: %v", err)
	}
	if len(noTokens) != 0 {
		t.Errorf("expected 0 tokens for nonexistent agent, got %d", len(noTokens))
	}
}

func TestSQLiteStore_AgentKeyValidity(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	agent := &RegisteredAgent{
		ID:      "aauth:validity-test@example.com",
		Name:    "Validity Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create a key that's already expired
	past := time.Now().Add(-time.Hour)
	expiredKey := &AgentKey{
		ID:        "expired-key",
		AgentID:   agent.ID,
		PublicKey: `{"kty":"EC"}`,
		Algorithm: "ES256",
		Use:       "sig",
		ExpiresAt: &past,
	}
	if err := store.CreateAgentKey(ctx, expiredKey); err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}

	retrieved, err := store.GetAgentKey(ctx, agent.ID, "expired-key")
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}
	if retrieved.IsValid() {
		t.Error("expected IsValid() to return false for expired key")
	}

	// Create a valid key
	future := time.Now().Add(time.Hour)
	validKey := &AgentKey{
		ID:        "valid-key",
		AgentID:   agent.ID,
		PublicKey: `{"kty":"EC"}`,
		Algorithm: "ES256",
		Use:       "sig",
		ExpiresAt: &future,
	}
	if err := store.CreateAgentKey(ctx, validKey); err != nil {
		t.Fatalf("CreateAgentKey failed: %v", err)
	}

	retrieved, err = store.GetAgentKey(ctx, agent.ID, "valid-key")
	if err != nil {
		t.Fatalf("GetAgentKey failed: %v", err)
	}
	if !retrieved.IsValid() {
		t.Error("expected IsValid() to return true for valid key")
	}
}

func TestSQLiteStore_IssuedAgentTokenValidity(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	agent := &RegisteredAgent{
		ID:      "aauth:tokenvalidity-test@example.com",
		Name:    "Token Validity Test Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, agent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	// Create an expired token
	expiredToken := &IssuedAgentToken{
		JTI:       "expired-token",
		AgentID:   agent.ID,
		KeyID:     "test-key",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if err := store.CreateIssuedAgentToken(ctx, expiredToken); err != nil {
		t.Fatalf("CreateIssuedAgentToken failed: %v", err)
	}

	retrieved, err := store.GetIssuedAgentToken(ctx, "expired-token")
	if err != nil {
		t.Fatalf("GetIssuedAgentToken failed: %v", err)
	}
	if retrieved.IsValid() {
		t.Error("expected IsValid() to return false for expired token")
	}

	// Create a valid token
	validToken := &IssuedAgentToken{
		JTI:       "valid-token",
		AgentID:   agent.ID,
		KeyID:     "test-key",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateIssuedAgentToken(ctx, validToken); err != nil {
		t.Fatalf("CreateIssuedAgentToken failed: %v", err)
	}

	retrieved, err = store.GetIssuedAgentToken(ctx, "valid-token")
	if err != nil {
		t.Fatalf("GetIssuedAgentToken failed: %v", err)
	}
	if !retrieved.IsValid() {
		t.Error("expected IsValid() to return true for valid token")
	}
}

func TestSQLiteStore_RegisteredAgentIsActive(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Active agent
	activeAgent := &RegisteredAgent{
		ID:      "aauth:active@example.com",
		Name:    "Active Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusActive,
	}
	if err := store.RegisterAgent(ctx, activeAgent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	retrieved, err := store.GetRegisteredAgent(ctx, "aauth:active@example.com")
	if err != nil {
		t.Fatalf("GetRegisteredAgent failed: %v", err)
	}
	if !retrieved.IsActive() {
		t.Error("expected IsActive() to return true for active agent")
	}

	// Suspended agent
	suspendedAgent := &RegisteredAgent{
		ID:      "aauth:suspended@example.com",
		Name:    "Suspended Agent",
		OwnerID: "user-123",
		Issuer:  "https://example.com",
		Status:  AgentStatusSuspended,
	}
	if err := store.RegisterAgent(ctx, suspendedAgent); err != nil {
		t.Fatalf("RegisterAgent failed: %v", err)
	}

	retrieved, err = store.GetRegisteredAgent(ctx, "aauth:suspended@example.com")
	if err != nil {
		t.Fatalf("GetRegisteredAgent failed: %v", err)
	}
	if retrieved.IsActive() {
		t.Error("expected IsActive() to return false for suspended agent")
	}
}

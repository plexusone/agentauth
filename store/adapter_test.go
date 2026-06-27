package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth/personserver"
	"github.com/aistandardsio/agent-protocols/idjag/authzserver"
)

// ============================================================================
// Mock Storer Implementation
// ============================================================================

type mockStorer struct {
	mu                sync.RWMutex
	users             map[string]*User
	usersByEmail      map[string]*User
	agents            map[string]*Agent
	missions          map[string]*Mission
	tokens            map[string]*Token
	preAuthorizations map[string]*PreAuthorization
	scopePolicies     map[string]*ScopePolicy
	idCounter         int
}

func newMockStorer() *mockStorer {
	return &mockStorer{
		users:             make(map[string]*User),
		usersByEmail:      make(map[string]*User),
		agents:            make(map[string]*Agent),
		missions:          make(map[string]*Mission),
		tokens:            make(map[string]*Token),
		preAuthorizations: make(map[string]*PreAuthorization),
		scopePolicies:     make(map[string]*ScopePolicy),
	}
}

// Verify mockStorer implements Storer.
var _ Storer = (*mockStorer)(nil)

func (m *mockStorer) Close() error { return nil }

func (m *mockStorer) generateID() string {
	m.idCounter++
	return time.Now().Format("20060102150405") + string(rune('0'+m.idCounter%10))
}

// User operations

func (m *mockStorer) CreateUser(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if user.ID == "" {
		user.ID = m.generateID()
	}
	if _, exists := m.users[user.ID]; exists {
		return ErrAlreadyExists
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	m.users[user.ID] = user
	if user.Email != "" {
		m.usersByEmail[user.Email] = user
	}
	return nil
}

func (m *mockStorer) GetUser(ctx context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[id]
	if !exists {
		return nil, ErrNotFound
	}
	return user, nil
}

func (m *mockStorer) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByEmail[email]
	if !exists {
		return nil, ErrNotFound
	}
	return user, nil
}

func (m *mockStorer) ListUsers(ctx context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, nil
}

// Agent operations

func (m *mockStorer) CreateAgent(ctx context.Context, agent *Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if agent.ID == "" {
		agent.ID = m.generateID()
	}
	if _, exists := m.agents[agent.ID]; exists {
		return ErrAlreadyExists
	}

	now := time.Now()
	agent.CreatedAt = now
	agent.UpdatedAt = now
	m.agents[agent.ID] = agent
	return nil
}

func (m *mockStorer) GetAgent(ctx context.Context, id string) (*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agent, exists := m.agents[id]
	if !exists {
		return nil, ErrNotFound
	}
	return agent, nil
}

func (m *mockStorer) ListAgents(ctx context.Context) ([]*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	agents := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		agents = append(agents, a)
	}
	return agents, nil
}

// Mission operations

func (m *mockStorer) CreateMission(ctx context.Context, mission *Mission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if mission.ID == "" {
		mission.ID = m.generateID()
	}
	if _, exists := m.missions[mission.ID]; exists {
		return ErrAlreadyExists
	}

	now := time.Now()
	mission.CreatedAt = now
	mission.UpdatedAt = now
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockStorer) GetMission(ctx context.Context, id string) (*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	mission, exists := m.missions[id]
	if !exists {
		return nil, ErrNotFound
	}
	return mission, nil
}

func (m *mockStorer) ApproveMission(ctx context.Context, id string, duration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mission, exists := m.missions[id]
	if !exists {
		return ErrNotFound
	}

	now := time.Now()
	expiresAt := now.Add(duration)
	mission.Status = MissionStatusApproved
	mission.ApprovedAt = &now
	mission.ExpiresAt = &expiresAt
	mission.UpdatedAt = now
	return nil
}

func (m *mockStorer) DenyMission(ctx context.Context, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	mission, exists := m.missions[id]
	if !exists {
		return ErrNotFound
	}

	now := time.Now()
	mission.Status = MissionStatusDenied
	mission.DeniedAt = &now
	mission.DenialReason = reason
	mission.UpdatedAt = now
	return nil
}

func (m *mockStorer) ListPendingMissions(ctx context.Context) ([]*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	missions := make([]*Mission, 0)
	for _, mission := range m.missions {
		if mission.Status == MissionStatusPending {
			missions = append(missions, mission)
		}
	}
	return missions, nil
}

func (m *mockStorer) ListMissionsByUser(ctx context.Context, userID string) ([]*Mission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	missions := make([]*Mission, 0)
	for _, mission := range m.missions {
		if mission.UserID == userID {
			missions = append(missions, mission)
		}
	}
	return missions, nil
}

// Token operations

func (m *mockStorer) CreateToken(ctx context.Context, token *Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if token.ID == "" {
		token.ID = m.generateID()
	}
	if _, exists := m.tokens[token.ID]; exists {
		return ErrAlreadyExists
	}

	token.IssuedAt = time.Now()
	m.tokens[token.ID] = token
	return nil
}

func (m *mockStorer) GetToken(ctx context.Context, id string) (*Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[id]
	if !exists {
		return nil, ErrNotFound
	}
	return token, nil
}

func (m *mockStorer) RevokeToken(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[id]
	if !exists {
		return ErrNotFound
	}

	now := time.Now()
	token.RevokedAt = &now
	return nil
}

func (m *mockStorer) ListTokens(ctx context.Context) ([]*Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tokens := make([]*Token, 0, len(m.tokens))
	for _, t := range m.tokens {
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// Pre-authorization operations

func (m *mockStorer) CreatePreAuthorization(ctx context.Context, preAuth *PreAuthorization) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := preAuth.UserID + ":" + preAuth.AgentID
	if preAuth.ID == "" {
		preAuth.ID = m.generateID()
	}

	preAuth.CreatedAt = time.Now()
	m.preAuthorizations[key] = preAuth
	return nil
}

func (m *mockStorer) GetPreAuthorization(ctx context.Context, userID, agentID string) (*PreAuthorization, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := userID + ":" + agentID
	preAuth, exists := m.preAuthorizations[key]
	if !exists {
		return nil, ErrNotFound
	}
	return preAuth, nil
}

func (m *mockStorer) DeletePreAuthorization(ctx context.Context, userID, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := userID + ":" + agentID
	if _, exists := m.preAuthorizations[key]; !exists {
		return ErrNotFound
	}
	delete(m.preAuthorizations, key)
	return nil
}

// Scope policy operations

func (m *mockStorer) CreateScopePolicy(ctx context.Context, policy *ScopePolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if policy.ID == "" {
		policy.ID = m.generateID()
	}
	if _, exists := m.scopePolicies[policy.ID]; exists {
		return ErrAlreadyExists
	}

	policy.CreatedAt = time.Now()
	m.scopePolicies[policy.ID] = policy
	return nil
}

func (m *mockStorer) GetScopePolicy(ctx context.Context, id string) (*ScopePolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, exists := m.scopePolicies[id]
	if !exists {
		return nil, ErrNotFound
	}
	return policy, nil
}

func (m *mockStorer) ListScopePolicies(ctx context.Context) ([]*ScopePolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policies := make([]*ScopePolicy, 0, len(m.scopePolicies))
	for _, p := range m.scopePolicies {
		policies = append(policies, p)
	}
	return policies, nil
}

func (m *mockStorer) DeleteScopePolicy(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.scopePolicies[id]; !exists {
		return ErrNotFound
	}
	delete(m.scopePolicies, id)
	return nil
}

// ============================================================================
// PersonServerAdapter Tests
// ============================================================================

func TestPersonServerAdapter_UserOperations(t *testing.T) {
	store := newMockStorer()
	adapter := NewPersonServerAdapter(store)
	ctx := context.Background()

	// Test CreateUser
	user := &personserver.User{
		ID:    "user-1",
		Email: "test@example.com",
		Name:  "Test User",
	}

	err := adapter.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	if user.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}

	// Test GetUser
	retrieved, err := adapter.GetUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}

	if retrieved.ID != user.ID {
		t.Errorf("expected ID %s, got %s", user.ID, retrieved.ID)
	}
	if retrieved.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, retrieved.Email)
	}

	// Test GetUser not found
	_, err = adapter.GetUser(ctx, "nonexistent")
	if err != personserver.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Test GetUserByEmail
	byEmail, err := adapter.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}
	if byEmail.ID != user.ID {
		t.Errorf("expected ID %s, got %s", user.ID, byEmail.ID)
	}

	// Test ListUsers
	users, err := adapter.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	// Test duplicate user
	err = adapter.CreateUser(ctx, &personserver.User{ID: "user-1"})
	if err != personserver.ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists, got %v", err)
	}
}

func TestPersonServerAdapter_AgentOperations(t *testing.T) {
	store := newMockStorer()
	adapter := NewPersonServerAdapter(store)
	ctx := context.Background()

	// Test CreateAgent
	agent := &personserver.Agent{
		ID:          "agent-1",
		Name:        "Test Agent",
		Description: "A test agent",
		PublicKey:   "test-key",
		Trusted:     true,
	}

	err := adapter.CreateAgent(ctx, agent)
	if err != nil {
		t.Fatalf("CreateAgent failed: %v", err)
	}

	// Test GetAgent
	retrieved, err := adapter.GetAgent(ctx, "agent-1")
	if err != nil {
		t.Fatalf("GetAgent failed: %v", err)
	}

	if retrieved.ID != agent.ID {
		t.Errorf("expected ID %s, got %s", agent.ID, retrieved.ID)
	}
	if retrieved.Name != agent.Name {
		t.Errorf("expected name %s, got %s", agent.Name, retrieved.Name)
	}
	if !retrieved.Trusted {
		t.Error("expected Trusted to be true")
	}

	// Test GetAgent not found
	_, err = adapter.GetAgent(ctx, "nonexistent")
	if err != personserver.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Test ListAgents
	agents, err := adapter.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents failed: %v", err)
	}
	if len(agents) != 1 {
		t.Errorf("expected 1 agent, got %d", len(agents))
	}
}

func TestPersonServerAdapter_MissionOperations(t *testing.T) {
	store := newMockStorer()
	adapter := NewPersonServerAdapter(store)
	ctx := context.Background()

	// Test CreateMission
	mission := &personserver.Mission{
		AgentID:         "agent-1",
		UserID:          "user-1",
		Name:            "Test Mission",
		Scopes:          "read:email",
		InteractionType: "supervised",
		Status:          personserver.MissionStatusPending,
		Duration:        3600,
	}

	err := adapter.CreateMission(ctx, mission)
	if err != nil {
		t.Fatalf("CreateMission failed: %v", err)
	}

	if mission.ID == "" {
		t.Error("expected ID to be set")
	}

	missionID := mission.ID

	// Test GetMission
	retrieved, err := adapter.GetMission(ctx, missionID)
	if err != nil {
		t.Fatalf("GetMission failed: %v", err)
	}

	if retrieved.AgentID != mission.AgentID {
		t.Errorf("expected AgentID %s, got %s", mission.AgentID, retrieved.AgentID)
	}
	if retrieved.Status != personserver.MissionStatusPending {
		t.Errorf("expected status pending, got %s", retrieved.Status)
	}

	// Test ListPendingMissions
	pending, err := adapter.ListPendingMissions(ctx)
	if err != nil {
		t.Fatalf("ListPendingMissions failed: %v", err)
	}
	if len(pending) != 1 {
		t.Errorf("expected 1 pending mission, got %d", len(pending))
	}

	// Test ApproveMission
	err = adapter.ApproveMission(ctx, missionID, time.Hour)
	if err != nil {
		t.Fatalf("ApproveMission failed: %v", err)
	}

	retrieved, _ = adapter.GetMission(ctx, missionID)
	if retrieved.Status != personserver.MissionStatusApproved {
		t.Errorf("expected status approved, got %s", retrieved.Status)
	}
	if retrieved.ApprovedAt == nil {
		t.Error("expected ApprovedAt to be set")
	}
	if retrieved.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}

	// Test ListPendingMissions after approval
	pending, _ = adapter.ListPendingMissions(ctx)
	if len(pending) != 0 {
		t.Errorf("expected 0 pending missions after approval, got %d", len(pending))
	}

	// Test DenyMission
	mission2 := &personserver.Mission{
		AgentID: "agent-1",
		UserID:  "user-2",
		Name:    "Test Mission 2",
		Scopes:  "write:profile",
		Status:  personserver.MissionStatusPending,
	}
	if err := adapter.CreateMission(ctx, mission2); err != nil {
		t.Fatalf("CreateMission failed: %v", err)
	}

	err = adapter.DenyMission(ctx, mission2.ID, "Not authorized")
	if err != nil {
		t.Fatalf("DenyMission failed: %v", err)
	}

	retrieved, _ = adapter.GetMission(ctx, mission2.ID)
	if retrieved.Status != personserver.MissionStatusDenied {
		t.Errorf("expected status denied, got %s", retrieved.Status)
	}
	if retrieved.DenialReason != "Not authorized" {
		t.Errorf("expected denial reason, got %s", retrieved.DenialReason)
	}

	// Test ListMissionsByUser
	missions, err := adapter.ListMissionsByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListMissionsByUser failed: %v", err)
	}
	if len(missions) != 1 {
		t.Errorf("expected 1 mission for user-1, got %d", len(missions))
	}
}

func TestPersonServerAdapter_TokenOperations(t *testing.T) {
	store := newMockStorer()
	adapter := NewPersonServerAdapter(store)
	ctx := context.Background()

	// Test CreateToken
	token := &personserver.Token{
		MissionID: "mission-1",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:email",
		TokenType: "Bearer",
		Protocol:  "aauth",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := adapter.CreateToken(ctx, token)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	if token.ID == "" {
		t.Error("expected ID to be set")
	}

	tokenID := token.ID

	// Test GetToken
	retrieved, err := adapter.GetToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	if retrieved.AgentID != token.AgentID {
		t.Errorf("expected AgentID %s, got %s", token.AgentID, retrieved.AgentID)
	}
	if retrieved.Protocol != "aauth" {
		t.Errorf("expected protocol aauth, got %s", retrieved.Protocol)
	}

	// Test GetToken not found
	_, err = adapter.GetToken(ctx, "nonexistent")
	if err != personserver.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Test RevokeToken
	err = adapter.RevokeToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	retrieved, _ = adapter.GetToken(ctx, tokenID)
	if retrieved.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
}

func TestPersonServerAdapter_Close(t *testing.T) {
	store := newMockStorer()
	adapter := NewPersonServerAdapter(store)

	err := adapter.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// ============================================================================
// AuthzServerAdapter Tests
// ============================================================================

func TestAuthzServerAdapter_TokenOperations(t *testing.T) {
	store := newMockStorer()
	adapter := NewAuthzServerAdapter(store)
	ctx := context.Background()

	// Test CreateToken
	token := &authzserver.Token{
		MissionID: "mission-1",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:email write:profile",
		TokenType: "Bearer",
		Protocol:  "idjag",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := adapter.CreateToken(ctx, token)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}

	if token.ID == "" {
		t.Error("expected ID to be set")
	}

	tokenID := token.ID

	// Test GetToken
	retrieved, err := adapter.GetToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}

	if retrieved.AgentID != token.AgentID {
		t.Errorf("expected AgentID %s, got %s", token.AgentID, retrieved.AgentID)
	}
	if retrieved.Protocol != "idjag" {
		t.Errorf("expected protocol idjag, got %s", retrieved.Protocol)
	}
	if retrieved.Scopes != "read:email write:profile" {
		t.Errorf("expected scopes, got %s", retrieved.Scopes)
	}

	// Test GetToken not found
	_, err = adapter.GetToken(ctx, "nonexistent")
	if err != authzserver.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Test ListTokens
	tokens, err := adapter.ListTokens(ctx)
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if len(tokens) != 1 {
		t.Errorf("expected 1 token, got %d", len(tokens))
	}

	// Test RevokeToken
	err = adapter.RevokeToken(ctx, tokenID)
	if err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	retrieved, _ = adapter.GetToken(ctx, tokenID)
	if retrieved.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
}

func TestAuthzServerAdapter_ScopePolicyOperations(t *testing.T) {
	store := newMockStorer()
	adapter := NewAuthzServerAdapter(store)
	ctx := context.Background()

	// Test CreateScopePolicy
	policy := &authzserver.ScopePolicy{
		Pattern:         "read:*",
		Protocol:        "idjag",
		InteractionType: "supervised",
		Description:     "Read operations",
		Priority:        100,
	}

	err := adapter.CreateScopePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreateScopePolicy failed: %v", err)
	}

	if policy.ID == "" {
		t.Error("expected ID to be set")
	}

	policyID := policy.ID

	// Test GetScopePolicy
	retrieved, err := adapter.GetScopePolicy(ctx, policyID)
	if err != nil {
		t.Fatalf("GetScopePolicy failed: %v", err)
	}

	if retrieved.Pattern != "read:*" {
		t.Errorf("expected pattern read:*, got %s", retrieved.Pattern)
	}
	if retrieved.Protocol != "idjag" {
		t.Errorf("expected protocol idjag, got %s", retrieved.Protocol)
	}
	if retrieved.Priority != 100 {
		t.Errorf("expected priority 100, got %d", retrieved.Priority)
	}

	// Test GetScopePolicy not found
	_, err = adapter.GetScopePolicy(ctx, "nonexistent")
	if err != authzserver.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}

	// Create another policy
	policy2 := &authzserver.ScopePolicy{
		Pattern:  "write:*",
		Protocol: "aauth",
		Priority: 200,
	}
	if err := adapter.CreateScopePolicy(ctx, policy2); err != nil {
		t.Fatalf("CreateScopePolicy failed: %v", err)
	}

	// Test ListScopePolicies
	policies, err := adapter.ListScopePolicies(ctx)
	if err != nil {
		t.Fatalf("ListScopePolicies failed: %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	// Test DeleteScopePolicy
	err = adapter.DeleteScopePolicy(ctx, policyID)
	if err != nil {
		t.Fatalf("DeleteScopePolicy failed: %v", err)
	}

	// Verify deleted
	_, err = adapter.GetScopePolicy(ctx, policyID)
	if err != authzserver.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}

	// Test DeleteScopePolicy not found
	err = adapter.DeleteScopePolicy(ctx, "nonexistent")
	if err != authzserver.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAuthzServerAdapter_Close(t *testing.T) {
	store := newMockStorer()
	adapter := NewAuthzServerAdapter(store)

	err := adapter.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

// ============================================================================
// Error Conversion Tests
// ============================================================================

func TestConvertError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{"nil", nil, nil},
		{"ErrNotFound", ErrNotFound, personserver.ErrNotFound},
		{"ErrAlreadyExists", ErrAlreadyExists, personserver.ErrAlreadyExists},
		{"ErrInvalidInput", ErrInvalidInput, personserver.ErrInvalidInput},
		{"other error", errors.New("other"), errors.New("other")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertError(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else if result == nil {
				t.Errorf("expected %v, got nil", tt.expected)
			} else if result.Error() != tt.expected.Error() {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestConvertAuthzError(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{"nil", nil, nil},
		{"ErrNotFound", ErrNotFound, authzserver.ErrNotFound},
		{"ErrAlreadyExists", ErrAlreadyExists, authzserver.ErrAlreadyExists},
		{"ErrInvalidInput", ErrInvalidInput, authzserver.ErrInvalidInput},
		{"other error", errors.New("other"), errors.New("other")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertAuthzError(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else if result == nil {
				t.Errorf("expected %v, got nil", tt.expected)
			} else if result.Error() != tt.expected.Error() {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// ============================================================================
// Type Conversion Tests
// ============================================================================

func TestToPersonServerUser(t *testing.T) {
	now := time.Now()
	internal := &User{
		ID:        "user-1",
		Email:     "test@example.com",
		Name:      "Test User",
		CreatedAt: now,
		UpdatedAt: now,
	}

	result := toPersonServerUser(internal)

	if result.ID != internal.ID {
		t.Errorf("expected ID %s, got %s", internal.ID, result.ID)
	}
	if result.Email != internal.Email {
		t.Errorf("expected Email %s, got %s", internal.Email, result.Email)
	}
	if result.Name != internal.Name {
		t.Errorf("expected Name %s, got %s", internal.Name, result.Name)
	}
	if !result.CreatedAt.Equal(internal.CreatedAt) {
		t.Errorf("expected CreatedAt %v, got %v", internal.CreatedAt, result.CreatedAt)
	}
}

func TestToPersonServerAgent(t *testing.T) {
	now := time.Now()
	internal := &Agent{
		ID:          "agent-1",
		Name:        "Test Agent",
		Description: "A test agent",
		PublicKey:   "key-data",
		RedirectURI: "https://example.com/callback",
		Trusted:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	result := toPersonServerAgent(internal)

	if result.ID != internal.ID {
		t.Errorf("expected ID %s, got %s", internal.ID, result.ID)
	}
	if result.Name != internal.Name {
		t.Errorf("expected Name %s, got %s", internal.Name, result.Name)
	}
	if result.Description != internal.Description {
		t.Errorf("expected Description %s, got %s", internal.Description, result.Description)
	}
	if result.PublicKey != internal.PublicKey {
		t.Errorf("expected PublicKey %s, got %s", internal.PublicKey, result.PublicKey)
	}
	if result.RedirectURI != internal.RedirectURI {
		t.Errorf("expected RedirectURI %s, got %s", internal.RedirectURI, result.RedirectURI)
	}
	if result.Trusted != internal.Trusted {
		t.Errorf("expected Trusted %v, got %v", internal.Trusted, result.Trusted)
	}
}

func TestToPersonServerMission(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	internal := &Mission{
		ID:              "mission-1",
		AgentID:         "agent-1",
		UserID:          "user-1",
		Name:            "Test Mission",
		Description:     "A test mission",
		Scopes:          "read:email write:profile",
		InteractionType: "supervised",
		Status:          MissionStatusApproved,
		Duration:        3600,
		ExpiresAt:       &expiresAt,
		ApprovedAt:      &now,
		DeniedAt:        nil,
		DenialReason:    "",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	result := toPersonServerMission(internal)

	if result.ID != internal.ID {
		t.Errorf("expected ID %s, got %s", internal.ID, result.ID)
	}
	if result.AgentID != internal.AgentID {
		t.Errorf("expected AgentID %s, got %s", internal.AgentID, result.AgentID)
	}
	if result.Status != personserver.MissionStatusApproved {
		t.Errorf("expected status approved, got %s", result.Status)
	}
	if result.Scopes != internal.Scopes {
		t.Errorf("expected Scopes %s, got %s", internal.Scopes, result.Scopes)
	}
}

func TestToPersonServerToken(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	internal := &Token{
		ID:        "token-1",
		MissionID: "mission-1",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:email",
		TokenType: "Bearer",
		Protocol:  "aauth",
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		RevokedAt: nil,
	}

	result := toPersonServerToken(internal)

	if result.ID != internal.ID {
		t.Errorf("expected ID %s, got %s", internal.ID, result.ID)
	}
	if result.MissionID != internal.MissionID {
		t.Errorf("expected MissionID %s, got %s", internal.MissionID, result.MissionID)
	}
	if result.Protocol != internal.Protocol {
		t.Errorf("expected Protocol %s, got %s", internal.Protocol, result.Protocol)
	}
}

func TestToAuthzServerToken(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	internal := &Token{
		ID:        "token-1",
		MissionID: "mission-1",
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:email",
		TokenType: "Bearer",
		Protocol:  "idjag",
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		RevokedAt: nil,
	}

	result := toAuthzServerToken(internal)

	if result.ID != internal.ID {
		t.Errorf("expected ID %s, got %s", internal.ID, result.ID)
	}
	if result.Protocol != "idjag" {
		t.Errorf("expected Protocol idjag, got %s", result.Protocol)
	}
}

func TestToAuthzServerScopePolicy(t *testing.T) {
	now := time.Now()
	internal := &ScopePolicy{
		ID:              "policy-1",
		Pattern:         "read:*",
		Protocol:        "idjag",
		InteractionType: "supervised",
		Description:     "Read operations",
		Priority:        100,
		CreatedAt:       now,
	}

	result := toAuthzServerScopePolicy(internal)

	if result.ID != internal.ID {
		t.Errorf("expected ID %s, got %s", internal.ID, result.ID)
	}
	if result.Pattern != internal.Pattern {
		t.Errorf("expected Pattern %s, got %s", internal.Pattern, result.Pattern)
	}
	if result.Protocol != internal.Protocol {
		t.Errorf("expected Protocol %s, got %s", internal.Protocol, result.Protocol)
	}
	if result.Priority != internal.Priority {
		t.Errorf("expected Priority %d, got %d", internal.Priority, result.Priority)
	}
}

// ============================================================================
// Integration Tests - Using Adapters Together
// ============================================================================

func TestAdaptersShareUnderlyingStore(t *testing.T) {
	store := newMockStorer()
	psAdapter := NewPersonServerAdapter(store)
	asAdapter := NewAuthzServerAdapter(store)
	ctx := context.Background()

	// Create a token via PersonServerAdapter
	psToken := &personserver.Token{
		AgentID:   "agent-1",
		UserID:    "user-1",
		Scopes:    "read:email",
		Protocol:  "shared",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := psAdapter.CreateToken(ctx, psToken)
	if err != nil {
		t.Fatalf("CreateToken via PersonServerAdapter failed: %v", err)
	}

	// Retrieve the same token via AuthzServerAdapter
	asToken, err := asAdapter.GetToken(ctx, psToken.ID)
	if err != nil {
		t.Fatalf("GetToken via AuthzServerAdapter failed: %v", err)
	}

	if asToken.ID != psToken.ID {
		t.Errorf("expected same ID, got %s vs %s", psToken.ID, asToken.ID)
	}
	if asToken.Protocol != "shared" {
		t.Errorf("expected protocol shared, got %s", asToken.Protocol)
	}

	// Revoke via AuthzServerAdapter
	err = asAdapter.RevokeToken(ctx, psToken.ID)
	if err != nil {
		t.Fatalf("RevokeToken via AuthzServerAdapter failed: %v", err)
	}

	// Verify revocation is visible via PersonServerAdapter
	retrievedPS, _ := psAdapter.GetToken(ctx, psToken.ID)
	if retrievedPS.RevokedAt == nil {
		t.Error("expected token to be revoked")
	}
}

// ============================================================================
// Store Types Tests
// ============================================================================

func TestMissionIsActive(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	tests := []struct {
		name     string
		mission  Mission
		expected bool
	}{
		{
			name:     "pending mission",
			mission:  Mission{Status: MissionStatusPending},
			expected: false,
		},
		{
			name:     "approved, not expired",
			mission:  Mission{Status: MissionStatusApproved, ExpiresAt: &future},
			expected: true,
		},
		{
			name:     "approved, expired",
			mission:  Mission{Status: MissionStatusApproved, ExpiresAt: &past},
			expected: false,
		},
		{
			name:     "approved, no expiry",
			mission:  Mission{Status: MissionStatusApproved},
			expected: true,
		},
		{
			name:     "denied mission",
			mission:  Mission{Status: MissionStatusDenied},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mission.IsActive(); got != tt.expected {
				t.Errorf("IsActive() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestTokenIsValid(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	tests := []struct {
		name     string
		token    Token
		expected bool
	}{
		{
			name:     "valid token",
			token:    Token{ExpiresAt: future},
			expected: true,
		},
		{
			name:     "expired token",
			token:    Token{ExpiresAt: past},
			expected: false,
		},
		{
			name:     "revoked token",
			token:    Token{ExpiresAt: future, RevokedAt: &now},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestPreAuthorizationCovers(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	tests := []struct {
		name     string
		preAuth  PreAuthorization
		scopes   []string
		expected bool
	}{
		{
			name:     "covers all requested",
			preAuth:  PreAuthorization{Scopes: "read:email read:profile write:email"},
			scopes:   []string{"read:email", "write:email"},
			expected: true,
		},
		{
			name:     "missing scope",
			preAuth:  PreAuthorization{Scopes: "read:email"},
			scopes:   []string{"read:email", "write:email"},
			expected: false,
		},
		{
			name:     "expired",
			preAuth:  PreAuthorization{Scopes: "read:email", ExpiresAt: &past},
			scopes:   []string{"read:email"},
			expected: false,
		},
		{
			name:     "not expired",
			preAuth:  PreAuthorization{Scopes: "read:email", ExpiresAt: &future},
			scopes:   []string{"read:email"},
			expected: true,
		},
		{
			name:     "empty requested",
			preAuth:  PreAuthorization{Scopes: "read:email"},
			scopes:   []string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.preAuth.Covers(tt.scopes); got != tt.expected {
				t.Errorf("Covers(%v) = %v, expected %v", tt.scopes, got, tt.expected)
			}
		})
	}
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", nil},
		{"read:email", []string{"read:email"}},
		{"read:email read:profile", []string{"read:email", "read:profile"}},
		{"read:email  read:profile", []string{"read:email", "read:profile"}},
		{" read:email ", []string{"read:email"}},
	}

	for _, tt := range tests {
		result := SplitScopes(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("SplitScopes(%q) = %v, expected %v", tt.input, result, tt.expected)
			continue
		}
		for i, v := range result {
			if v != tt.expected[i] {
				t.Errorf("SplitScopes(%q)[%d] = %q, expected %q", tt.input, i, v, tt.expected[i])
			}
		}
	}
}

func TestJoinScopes(t *testing.T) {
	tests := []struct {
		input    []string
		expected string
	}{
		{nil, ""},
		{[]string{}, ""},
		{[]string{"read:email"}, "read:email"},
		{[]string{"read:email", "read:profile"}, "read:email read:profile"},
	}

	for _, tt := range tests {
		result := JoinScopes(tt.input)
		if result != tt.expected {
			t.Errorf("JoinScopes(%v) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

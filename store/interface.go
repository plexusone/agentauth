// Package store provides storage abstractions for agent authorization.
package store

import (
	"context"
	"errors"
	"time"
)

// Store errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrInvalidInput  = errors.New("invalid input")
)

// Storer defines the interface for authorization storage backends.
// Both SQLite and DynamoDB implementations satisfy this interface.
type Storer interface {
	// Close closes the store connection.
	Close() error

	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)

	// Agent operations
	CreateAgent(ctx context.Context, agent *Agent) error
	GetAgent(ctx context.Context, id string) (*Agent, error)
	ListAgents(ctx context.Context) ([]*Agent, error)

	// Mission operations
	CreateMission(ctx context.Context, mission *Mission) error
	GetMission(ctx context.Context, id string) (*Mission, error)
	ApproveMission(ctx context.Context, id string, duration time.Duration) error
	DenyMission(ctx context.Context, id, reason string) error
	ListPendingMissions(ctx context.Context) ([]*Mission, error)
	ListMissionsByUser(ctx context.Context, userID string) ([]*Mission, error)

	// Token operations
	CreateToken(ctx context.Context, token *Token) error
	GetToken(ctx context.Context, id string) (*Token, error)
	RevokeToken(ctx context.Context, id string) error
	ListTokens(ctx context.Context) ([]*Token, error)

	// Pre-authorization operations
	CreatePreAuthorization(ctx context.Context, preAuth *PreAuthorization) error
	GetPreAuthorization(ctx context.Context, userID, agentID string) (*PreAuthorization, error)
	DeletePreAuthorization(ctx context.Context, userID, agentID string) error

	// Scope policy operations
	CreateScopePolicy(ctx context.Context, policy *ScopePolicy) error
	GetScopePolicy(ctx context.Context, id string) (*ScopePolicy, error)
	ListScopePolicies(ctx context.Context) ([]*ScopePolicy, error)
	DeleteScopePolicy(ctx context.Context, id string) error
}

// AgentProviderStorer extends Storer with Agent Provider operations.
// Implementations should embed Storer and add these methods.
type AgentProviderStorer interface {
	Storer

	// Registered agent operations
	RegisterAgent(ctx context.Context, agent *RegisteredAgent) error
	GetRegisteredAgent(ctx context.Context, agentID string) (*RegisteredAgent, error)
	UpdateRegisteredAgent(ctx context.Context, agent *RegisteredAgent) error
	RevokeRegisteredAgent(ctx context.Context, agentID string) error
	ListRegisteredAgents(ctx context.Context, ownerID string) ([]*RegisteredAgent, error)
	ListAllRegisteredAgents(ctx context.Context) ([]*RegisteredAgent, error)

	// Agent key operations
	CreateAgentKey(ctx context.Context, key *AgentKey) error
	GetAgentKey(ctx context.Context, agentID, keyID string) (*AgentKey, error)
	ListAgentKeys(ctx context.Context, agentID string) ([]*AgentKey, error)
	RevokeAgentKey(ctx context.Context, agentID, keyID string) error

	// Issued agent token operations (for tracking/revocation)
	CreateIssuedAgentToken(ctx context.Context, token *IssuedAgentToken) error
	GetIssuedAgentToken(ctx context.Context, jti string) (*IssuedAgentToken, error)
	RevokeIssuedAgentToken(ctx context.Context, jti string) error
	ListIssuedAgentTokens(ctx context.Context, agentID string) ([]*IssuedAgentToken, error)
}

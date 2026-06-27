package store

import (
	"context"

	"github.com/aistandardsio/agent-protocols/idjag/authzserver"
)

// AuthzServerAdapter adapts a Storer implementation to the authzserver.Store interface.
// This allows using SQLiteStore, DynamoDBStore, or any other Storer with the authzserver package.
type AuthzServerAdapter struct {
	store Storer
}

// Verify AuthzServerAdapter implements authzserver.Store at compile time.
var _ authzserver.Store = (*AuthzServerAdapter)(nil)

// NewAuthzServerAdapter creates a new adapter for the given store.
func NewAuthzServerAdapter(store Storer) *AuthzServerAdapter {
	return &AuthzServerAdapter{store: store}
}

// Close closes the underlying store.
func (a *AuthzServerAdapter) Close() error {
	return a.store.Close()
}

// Token operations

func (a *AuthzServerAdapter) CreateToken(ctx context.Context, token *authzserver.Token) error {
	internalToken := &Token{
		ID:        token.ID,
		MissionID: token.MissionID,
		AgentID:   token.AgentID,
		UserID:    token.UserID,
		Scopes:    token.Scopes,
		TokenType: token.TokenType,
		Protocol:  token.Protocol,
		IssuedAt:  token.IssuedAt,
		ExpiresAt: token.ExpiresAt,
		RevokedAt: token.RevokedAt,
	}
	err := a.store.CreateToken(ctx, internalToken)
	if err != nil {
		return convertAuthzError(err)
	}
	token.ID = internalToken.ID
	token.IssuedAt = internalToken.IssuedAt
	return nil
}

func (a *AuthzServerAdapter) GetToken(ctx context.Context, id string) (*authzserver.Token, error) {
	token, err := a.store.GetToken(ctx, id)
	if err != nil {
		return nil, convertAuthzError(err)
	}
	return toAuthzServerToken(token), nil
}

func (a *AuthzServerAdapter) RevokeToken(ctx context.Context, id string) error {
	return convertAuthzError(a.store.RevokeToken(ctx, id))
}

func (a *AuthzServerAdapter) ListTokens(ctx context.Context) ([]*authzserver.Token, error) {
	tokens, err := a.store.ListTokens(ctx)
	if err != nil {
		return nil, convertAuthzError(err)
	}
	result := make([]*authzserver.Token, len(tokens))
	for i, t := range tokens {
		result[i] = toAuthzServerToken(t)
	}
	return result, nil
}

// ScopePolicy operations

func (a *AuthzServerAdapter) CreateScopePolicy(ctx context.Context, policy *authzserver.ScopePolicy) error {
	internalPolicy := &ScopePolicy{
		ID:              policy.ID,
		Pattern:         policy.Pattern,
		Protocol:        policy.Protocol,
		InteractionType: policy.InteractionType,
		Description:     policy.Description,
		Priority:        policy.Priority,
		CreatedAt:       policy.CreatedAt,
	}
	err := a.store.CreateScopePolicy(ctx, internalPolicy)
	if err != nil {
		return convertAuthzError(err)
	}
	policy.ID = internalPolicy.ID
	policy.CreatedAt = internalPolicy.CreatedAt
	return nil
}

func (a *AuthzServerAdapter) GetScopePolicy(ctx context.Context, id string) (*authzserver.ScopePolicy, error) {
	policy, err := a.store.GetScopePolicy(ctx, id)
	if err != nil {
		return nil, convertAuthzError(err)
	}
	return toAuthzServerScopePolicy(policy), nil
}

func (a *AuthzServerAdapter) ListScopePolicies(ctx context.Context) ([]*authzserver.ScopePolicy, error) {
	policies, err := a.store.ListScopePolicies(ctx)
	if err != nil {
		return nil, convertAuthzError(err)
	}
	result := make([]*authzserver.ScopePolicy, len(policies))
	for i, p := range policies {
		result[i] = toAuthzServerScopePolicy(p)
	}
	return result, nil
}

func (a *AuthzServerAdapter) DeleteScopePolicy(ctx context.Context, id string) error {
	return convertAuthzError(a.store.DeleteScopePolicy(ctx, id))
}

// Conversion helpers

func convertAuthzError(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case ErrNotFound:
		return authzserver.ErrNotFound
	case ErrAlreadyExists:
		return authzserver.ErrAlreadyExists
	case ErrInvalidInput:
		return authzserver.ErrInvalidInput
	default:
		return err
	}
}

func toAuthzServerToken(t *Token) *authzserver.Token {
	return &authzserver.Token{
		ID:        t.ID,
		MissionID: t.MissionID,
		AgentID:   t.AgentID,
		UserID:    t.UserID,
		Scopes:    t.Scopes,
		TokenType: t.TokenType,
		Protocol:  t.Protocol,
		IssuedAt:  t.IssuedAt,
		ExpiresAt: t.ExpiresAt,
		RevokedAt: t.RevokedAt,
	}
}

func toAuthzServerScopePolicy(p *ScopePolicy) *authzserver.ScopePolicy {
	return &authzserver.ScopePolicy{
		ID:              p.ID,
		Pattern:         p.Pattern,
		Protocol:        p.Protocol,
		InteractionType: p.InteractionType,
		Description:     p.Description,
		Priority:        p.Priority,
		CreatedAt:       p.CreatedAt,
	}
}

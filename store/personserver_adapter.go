package store

import (
	"context"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth/personserver"
)

// PersonServerAdapter adapts a Storer implementation to the personserver.Store interface.
// This allows using SQLiteStore, DynamoDBStore, or any other Storer with the personserver package.
type PersonServerAdapter struct {
	store Storer
}

// Verify PersonServerAdapter implements personserver.Store at compile time.
var _ personserver.Store = (*PersonServerAdapter)(nil)

// NewPersonServerAdapter creates a new adapter for the given store.
func NewPersonServerAdapter(store Storer) *PersonServerAdapter {
	return &PersonServerAdapter{store: store}
}

// Close closes the underlying store.
func (a *PersonServerAdapter) Close() error {
	return a.store.Close()
}

// User operations

func (a *PersonServerAdapter) CreateUser(ctx context.Context, user *personserver.User) error {
	internalUser := &User{
		ID:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
	err := a.store.CreateUser(ctx, internalUser)
	if err != nil {
		return convertError(err)
	}
	user.ID = internalUser.ID
	user.CreatedAt = internalUser.CreatedAt
	user.UpdatedAt = internalUser.UpdatedAt
	return nil
}

func (a *PersonServerAdapter) GetUser(ctx context.Context, id string) (*personserver.User, error) {
	user, err := a.store.GetUser(ctx, id)
	if err != nil {
		return nil, convertError(err)
	}
	return toPersonServerUser(user), nil
}

func (a *PersonServerAdapter) GetUserByEmail(ctx context.Context, email string) (*personserver.User, error) {
	user, err := a.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, convertError(err)
	}
	return toPersonServerUser(user), nil
}

func (a *PersonServerAdapter) ListUsers(ctx context.Context) ([]*personserver.User, error) {
	users, err := a.store.ListUsers(ctx)
	if err != nil {
		return nil, convertError(err)
	}
	result := make([]*personserver.User, len(users))
	for i, u := range users {
		result[i] = toPersonServerUser(u)
	}
	return result, nil
}

// Agent operations

func (a *PersonServerAdapter) CreateAgent(ctx context.Context, agent *personserver.Agent) error {
	internalAgent := &Agent{
		ID:          agent.ID,
		Name:        agent.Name,
		Description: agent.Description,
		PublicKey:   agent.PublicKey,
		RedirectURI: agent.RedirectURI,
		Trusted:     agent.Trusted,
		CreatedAt:   agent.CreatedAt,
		UpdatedAt:   agent.UpdatedAt,
	}
	err := a.store.CreateAgent(ctx, internalAgent)
	if err != nil {
		return convertError(err)
	}
	agent.ID = internalAgent.ID
	agent.CreatedAt = internalAgent.CreatedAt
	agent.UpdatedAt = internalAgent.UpdatedAt
	return nil
}

func (a *PersonServerAdapter) GetAgent(ctx context.Context, id string) (*personserver.Agent, error) {
	agent, err := a.store.GetAgent(ctx, id)
	if err != nil {
		return nil, convertError(err)
	}
	return toPersonServerAgent(agent), nil
}

func (a *PersonServerAdapter) ListAgents(ctx context.Context) ([]*personserver.Agent, error) {
	agents, err := a.store.ListAgents(ctx)
	if err != nil {
		return nil, convertError(err)
	}
	result := make([]*personserver.Agent, len(agents))
	for i, a := range agents {
		result[i] = toPersonServerAgent(a)
	}
	return result, nil
}

// Mission operations

func (a *PersonServerAdapter) CreateMission(ctx context.Context, mission *personserver.Mission) error {
	internalMission := &Mission{
		ID:              mission.ID,
		AgentID:         mission.AgentID,
		UserID:          mission.UserID,
		Name:            mission.Name,
		Description:     mission.Description,
		Scopes:          mission.Scopes,
		InteractionType: mission.InteractionType,
		Status:          MissionStatus(mission.Status),
		Duration:        mission.Duration,
		ExpiresAt:       mission.ExpiresAt,
		ApprovedAt:      mission.ApprovedAt,
		DeniedAt:        mission.DeniedAt,
		DenialReason:    mission.DenialReason,
		CreatedAt:       mission.CreatedAt,
		UpdatedAt:       mission.UpdatedAt,
	}
	err := a.store.CreateMission(ctx, internalMission)
	if err != nil {
		return convertError(err)
	}
	mission.ID = internalMission.ID
	mission.CreatedAt = internalMission.CreatedAt
	mission.UpdatedAt = internalMission.UpdatedAt
	return nil
}

func (a *PersonServerAdapter) GetMission(ctx context.Context, id string) (*personserver.Mission, error) {
	mission, err := a.store.GetMission(ctx, id)
	if err != nil {
		return nil, convertError(err)
	}
	return toPersonServerMission(mission), nil
}

func (a *PersonServerAdapter) ApproveMission(ctx context.Context, id string, duration time.Duration) error {
	return convertError(a.store.ApproveMission(ctx, id, duration))
}

func (a *PersonServerAdapter) DenyMission(ctx context.Context, id, reason string) error {
	return convertError(a.store.DenyMission(ctx, id, reason))
}

func (a *PersonServerAdapter) ListPendingMissions(ctx context.Context) ([]*personserver.Mission, error) {
	missions, err := a.store.ListPendingMissions(ctx)
	if err != nil {
		return nil, convertError(err)
	}
	result := make([]*personserver.Mission, len(missions))
	for i, m := range missions {
		result[i] = toPersonServerMission(m)
	}
	return result, nil
}

func (a *PersonServerAdapter) ListMissionsByUser(ctx context.Context, userID string) ([]*personserver.Mission, error) {
	missions, err := a.store.ListMissionsByUser(ctx, userID)
	if err != nil {
		return nil, convertError(err)
	}
	result := make([]*personserver.Mission, len(missions))
	for i, m := range missions {
		result[i] = toPersonServerMission(m)
	}
	return result, nil
}

// Token operations

func (a *PersonServerAdapter) CreateToken(ctx context.Context, token *personserver.Token) error {
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
		return convertError(err)
	}
	token.ID = internalToken.ID
	token.IssuedAt = internalToken.IssuedAt
	return nil
}

func (a *PersonServerAdapter) GetToken(ctx context.Context, id string) (*personserver.Token, error) {
	token, err := a.store.GetToken(ctx, id)
	if err != nil {
		return nil, convertError(err)
	}
	return toPersonServerToken(token), nil
}

func (a *PersonServerAdapter) RevokeToken(ctx context.Context, id string) error {
	return convertError(a.store.RevokeToken(ctx, id))
}

// Conversion helpers

func convertError(err error) error {
	if err == nil {
		return nil
	}
	switch err {
	case ErrNotFound:
		return personserver.ErrNotFound
	case ErrAlreadyExists:
		return personserver.ErrAlreadyExists
	case ErrInvalidInput:
		return personserver.ErrInvalidInput
	default:
		return err
	}
}

func toPersonServerUser(u *User) *personserver.User {
	return &personserver.User{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

func toPersonServerAgent(a *Agent) *personserver.Agent {
	return &personserver.Agent{
		ID:          a.ID,
		Name:        a.Name,
		Description: a.Description,
		PublicKey:   a.PublicKey,
		RedirectURI: a.RedirectURI,
		Trusted:     a.Trusted,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
}

func toPersonServerMission(m *Mission) *personserver.Mission {
	return &personserver.Mission{
		ID:              m.ID,
		AgentID:         m.AgentID,
		UserID:          m.UserID,
		Name:            m.Name,
		Description:     m.Description,
		Scopes:          m.Scopes,
		InteractionType: m.InteractionType,
		Status:          personserver.MissionStatus(m.Status),
		Duration:        m.Duration,
		ExpiresAt:       m.ExpiresAt,
		ApprovedAt:      m.ApprovedAt,
		DeniedAt:        m.DeniedAt,
		DenialReason:    m.DenialReason,
		CreatedAt:       m.CreatedAt,
		UpdatedAt:       m.UpdatedAt,
	}
}

func toPersonServerToken(t *Token) *personserver.Token {
	return &personserver.Token{
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

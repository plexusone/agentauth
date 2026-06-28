package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Verify SQLiteStore implements AgentProviderStorer at compile time.
var _ AgentProviderStorer = (*SQLiteStore)(nil)

// migrateAgentProvider adds Agent Provider tables to the database.
func (s *SQLiteStore) migrateAgentProvider() error {
	schema := `
	-- Registered agents (Agent Provider)
	CREATE TABLE IF NOT EXISTS registered_agents (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		owner_id TEXT NOT NULL,
		issuer TEXT NOT NULL,
		metadata TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		revoked_at DATETIME
	);

	-- Agent keys
	CREATE TABLE IF NOT EXISTS agent_keys (
		id TEXT NOT NULL,
		agent_id TEXT NOT NULL REFERENCES registered_agents(id),
		public_key TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		use TEXT DEFAULT 'sig',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		revoked_at DATETIME,
		PRIMARY KEY (agent_id, id)
	);

	-- Issued agent tokens (for tracking/revocation)
	CREATE TABLE IF NOT EXISTS issued_agent_tokens (
		jti TEXT PRIMARY KEY,
		agent_id TEXT NOT NULL REFERENCES registered_agents(id),
		key_id TEXT NOT NULL,
		audience TEXT,
		issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		revoked_at DATETIME
	);

	-- Indexes for Agent Provider
	CREATE INDEX IF NOT EXISTS idx_registered_agents_owner ON registered_agents(owner_id);
	CREATE INDEX IF NOT EXISTS idx_registered_agents_status ON registered_agents(status);
	CREATE INDEX IF NOT EXISTS idx_agent_keys_agent ON agent_keys(agent_id);
	CREATE INDEX IF NOT EXISTS idx_issued_tokens_agent ON issued_agent_tokens(agent_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// EnsureAgentProviderTables ensures Agent Provider tables exist.
// Call this after NewSQLite if you need Agent Provider functionality.
func (s *SQLiteStore) EnsureAgentProviderTables() error {
	return s.migrateAgentProvider()
}

// RegisterAgent registers a new agent.
func (s *SQLiteStore) RegisterAgent(ctx context.Context, agent *RegisteredAgent) error {
	if agent.ID == "" {
		return ErrInvalidInput
	}

	now := time.Now()
	agent.CreatedAt = now
	agent.UpdatedAt = now
	if agent.Status == "" {
		agent.Status = AgentStatusActive
	}

	// Serialize metadata to JSON
	var metadataJSON string
	if agent.Metadata != nil {
		data, err := json.Marshal(agent.Metadata)
		if err != nil {
			return err
		}
		metadataJSON = string(data)
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO registered_agents (id, name, description, owner_id, issuer, metadata, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, agent.ID, agent.Name, agent.Description, agent.OwnerID, agent.Issuer, metadataJSON,
		agent.Status, agent.CreatedAt, agent.UpdatedAt)

	if err != nil {
		if isUniqueConstraintError(err) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

// GetRegisteredAgent retrieves a registered agent by ID.
func (s *SQLiteStore) GetRegisteredAgent(ctx context.Context, agentID string) (*RegisteredAgent, error) {
	var agent RegisteredAgent
	var description, metadataJSON sql.NullString
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, owner_id, issuer, metadata, status, created_at, updated_at, revoked_at
		FROM registered_agents WHERE id = ?
	`, agentID).Scan(&agent.ID, &agent.Name, &description, &agent.OwnerID, &agent.Issuer,
		&metadataJSON, &agent.Status, &agent.CreatedAt, &agent.UpdatedAt, &revokedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if description.Valid {
		agent.Description = description.String
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		if err := json.Unmarshal([]byte(metadataJSON.String), &agent.Metadata); err != nil {
			// Ignore JSON parse errors for metadata
			agent.Metadata = nil
		}
	}
	if revokedAt.Valid {
		agent.RevokedAt = &revokedAt.Time
	}

	return &agent, nil
}

// UpdateRegisteredAgent updates a registered agent.
func (s *SQLiteStore) UpdateRegisteredAgent(ctx context.Context, agent *RegisteredAgent) error {
	agent.UpdatedAt = time.Now()

	var metadataJSON string
	if agent.Metadata != nil {
		data, err := json.Marshal(agent.Metadata)
		if err != nil {
			return err
		}
		metadataJSON = string(data)
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE registered_agents
		SET name = ?, description = ?, metadata = ?, status = ?, updated_at = ?
		WHERE id = ?
	`, agent.Name, agent.Description, metadataJSON, agent.Status, agent.UpdatedAt, agent.ID)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// RevokeRegisteredAgent revokes a registered agent.
func (s *SQLiteStore) RevokeRegisteredAgent(ctx context.Context, agentID string) error {
	now := time.Now()

	result, err := s.db.ExecContext(ctx, `
		UPDATE registered_agents
		SET status = ?, revoked_at = ?, updated_at = ?
		WHERE id = ? AND status != ?
	`, AgentStatusRevoked, now, now, agentID, AgentStatusRevoked)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListRegisteredAgents lists agents owned by a user.
func (s *SQLiteStore) ListRegisteredAgents(ctx context.Context, ownerID string) ([]*RegisteredAgent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, owner_id, issuer, metadata, status, created_at, updated_at, revoked_at
		FROM registered_agents WHERE owner_id = ? ORDER BY created_at DESC
	`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	return scanRegisteredAgents(rows)
}

// ListAllRegisteredAgents lists all registered agents.
func (s *SQLiteStore) ListAllRegisteredAgents(ctx context.Context) ([]*RegisteredAgent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, description, owner_id, issuer, metadata, status, created_at, updated_at, revoked_at
		FROM registered_agents ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	return scanRegisteredAgents(rows)
}

func scanRegisteredAgents(rows *sql.Rows) ([]*RegisteredAgent, error) {
	var agents []*RegisteredAgent
	for rows.Next() {
		var agent RegisteredAgent
		var description, metadataJSON sql.NullString
		var revokedAt sql.NullTime

		if err := rows.Scan(&agent.ID, &agent.Name, &description, &agent.OwnerID, &agent.Issuer,
			&metadataJSON, &agent.Status, &agent.CreatedAt, &agent.UpdatedAt, &revokedAt); err != nil {
			return nil, err
		}

		if description.Valid {
			agent.Description = description.String
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			_ = json.Unmarshal([]byte(metadataJSON.String), &agent.Metadata)
		}
		if revokedAt.Valid {
			agent.RevokedAt = &revokedAt.Time
		}

		agents = append(agents, &agent)
	}
	return agents, rows.Err()
}

// CreateAgentKey creates a new key for an agent.
func (s *SQLiteStore) CreateAgentKey(ctx context.Context, key *AgentKey) error {
	if key.ID == "" {
		key.ID = uuid.New().String()[:8]
	}
	key.CreatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agent_keys (id, agent_id, public_key, algorithm, use, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, key.ID, key.AgentID, key.PublicKey, key.Algorithm, key.Use, key.CreatedAt, key.ExpiresAt)

	if err != nil {
		if isUniqueConstraintError(err) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

// GetAgentKey retrieves a specific key for an agent.
func (s *SQLiteStore) GetAgentKey(ctx context.Context, agentID, keyID string) (*AgentKey, error) {
	var key AgentKey
	var expiresAt, revokedAt sql.NullTime
	var use sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, agent_id, public_key, algorithm, use, created_at, expires_at, revoked_at
		FROM agent_keys WHERE agent_id = ? AND id = ?
	`, agentID, keyID).Scan(&key.ID, &key.AgentID, &key.PublicKey, &key.Algorithm, &use,
		&key.CreatedAt, &expiresAt, &revokedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if use.Valid {
		key.Use = use.String
	}
	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		key.RevokedAt = &revokedAt.Time
	}

	return &key, nil
}

// ListAgentKeys lists all keys for an agent.
func (s *SQLiteStore) ListAgentKeys(ctx context.Context, agentID string) ([]*AgentKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, agent_id, public_key, algorithm, use, created_at, expires_at, revoked_at
		FROM agent_keys WHERE agent_id = ? ORDER BY created_at DESC
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var keys []*AgentKey
	for rows.Next() {
		var key AgentKey
		var expiresAt, revokedAt sql.NullTime
		var use sql.NullString

		if err := rows.Scan(&key.ID, &key.AgentID, &key.PublicKey, &key.Algorithm, &use,
			&key.CreatedAt, &expiresAt, &revokedAt); err != nil {
			return nil, err
		}

		if use.Valid {
			key.Use = use.String
		}
		if expiresAt.Valid {
			key.ExpiresAt = &expiresAt.Time
		}
		if revokedAt.Valid {
			key.RevokedAt = &revokedAt.Time
		}

		keys = append(keys, &key)
	}
	return keys, rows.Err()
}

// RevokeAgentKey revokes a key for an agent.
func (s *SQLiteStore) RevokeAgentKey(ctx context.Context, agentID, keyID string) error {
	now := time.Now()

	result, err := s.db.ExecContext(ctx, `
		UPDATE agent_keys SET revoked_at = ? WHERE agent_id = ? AND id = ? AND revoked_at IS NULL
	`, now, agentID, keyID)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// CreateIssuedAgentToken records an issued agent token.
func (s *SQLiteStore) CreateIssuedAgentToken(ctx context.Context, token *IssuedAgentToken) error {
	if token.JTI == "" {
		token.JTI = uuid.New().String()
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO issued_agent_tokens (jti, agent_id, key_id, audience, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, token.JTI, token.AgentID, token.KeyID, token.Audience, token.IssuedAt, token.ExpiresAt)

	if err != nil {
		if isUniqueConstraintError(err) {
			return ErrAlreadyExists
		}
		return err
	}
	return nil
}

// GetIssuedAgentToken retrieves an issued agent token by JTI.
func (s *SQLiteStore) GetIssuedAgentToken(ctx context.Context, jti string) (*IssuedAgentToken, error) {
	var token IssuedAgentToken
	var audience sql.NullString
	var revokedAt sql.NullTime

	err := s.db.QueryRowContext(ctx, `
		SELECT jti, agent_id, key_id, audience, issued_at, expires_at, revoked_at
		FROM issued_agent_tokens WHERE jti = ?
	`, jti).Scan(&token.JTI, &token.AgentID, &token.KeyID, &audience,
		&token.IssuedAt, &token.ExpiresAt, &revokedAt)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if audience.Valid {
		token.Audience = audience.String
	}
	if revokedAt.Valid {
		token.RevokedAt = &revokedAt.Time
	}

	return &token, nil
}

// RevokeIssuedAgentToken revokes an issued agent token.
func (s *SQLiteStore) RevokeIssuedAgentToken(ctx context.Context, jti string) error {
	now := time.Now()

	result, err := s.db.ExecContext(ctx, `
		UPDATE issued_agent_tokens SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL
	`, now, jti)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// ListIssuedAgentTokens lists issued tokens for an agent.
func (s *SQLiteStore) ListIssuedAgentTokens(ctx context.Context, agentID string) ([]*IssuedAgentToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT jti, agent_id, key_id, audience, issued_at, expires_at, revoked_at
		FROM issued_agent_tokens WHERE agent_id = ? ORDER BY issued_at DESC
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var tokens []*IssuedAgentToken
	for rows.Next() {
		var token IssuedAgentToken
		var audience sql.NullString
		var revokedAt sql.NullTime

		if err := rows.Scan(&token.JTI, &token.AgentID, &token.KeyID, &audience,
			&token.IssuedAt, &token.ExpiresAt, &revokedAt); err != nil {
			return nil, err
		}

		if audience.Valid {
			token.Audience = audience.String
		}
		if revokedAt.Valid {
			token.RevokedAt = &revokedAt.Time
		}

		tokens = append(tokens, &token)
	}
	return tokens, rows.Err()
}

package store

import (
	"time"
)

// User represents a person who can authorize agents.
type User struct {
	ID        string    `json:"id" db:"id"`
	Email     string    `json:"email" db:"email"`
	Name      string    `json:"name" db:"name"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Agent represents a registered agent that can request authorization.
type Agent struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	PublicKey   string    `json:"public_key" db:"public_key"`
	RedirectURI string    `json:"redirect_uri,omitempty" db:"redirect_uri"`
	Trusted     bool      `json:"trusted" db:"trusted"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// MissionStatus represents the status of a mission request.
type MissionStatus string

// Mission statuses.
const (
	MissionStatusPending  MissionStatus = "pending"
	MissionStatusApproved MissionStatus = "approved"
	MissionStatusDenied   MissionStatus = "denied"
	MissionStatusExpired  MissionStatus = "expired"
	MissionStatusRevoked  MissionStatus = "revoked"
)

// Mission represents an agent's request to act on behalf of a user.
type Mission struct {
	ID              string        `json:"id" db:"id"`
	AgentID         string        `json:"agent_id" db:"agent_id"`
	UserID          string        `json:"user_id" db:"user_id"`
	Name            string        `json:"name" db:"name"`
	Description     string        `json:"description,omitempty" db:"description"`
	Scopes          string        `json:"scopes" db:"scopes"`
	InteractionType string        `json:"interaction_type" db:"interaction_type"`
	Status          MissionStatus `json:"status" db:"status"`
	Duration        int64         `json:"duration" db:"duration"`
	ExpiresAt       *time.Time    `json:"expires_at,omitempty" db:"expires_at"`
	ApprovedAt      *time.Time    `json:"approved_at,omitempty" db:"approved_at"`
	DeniedAt        *time.Time    `json:"denied_at,omitempty" db:"denied_at"`
	DenialReason    string        `json:"denial_reason,omitempty" db:"denial_reason"`
	CreatedAt       time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at" db:"updated_at"`
}

// IsActive returns true if the mission is currently active.
func (m *Mission) IsActive() bool {
	if m.Status != MissionStatusApproved {
		return false
	}
	if m.ExpiresAt != nil && time.Now().After(*m.ExpiresAt) {
		return false
	}
	return true
}

// Token represents an issued auth token.
type Token struct {
	ID        string     `json:"id" db:"id"`
	MissionID string     `json:"mission_id,omitempty" db:"mission_id"`
	AgentID   string     `json:"agent_id" db:"agent_id"`
	UserID    string     `json:"user_id" db:"user_id"`
	Scopes    string     `json:"scopes" db:"scopes"`
	TokenType string     `json:"token_type" db:"token_type"`
	Protocol  string     `json:"protocol" db:"protocol"`
	IssuedAt  time.Time  `json:"issued_at" db:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// IsValid returns true if the token is still valid.
func (t *Token) IsValid() bool {
	if t.RevokedAt != nil {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

// PreAuthorization allows users to pre-approve certain scopes for agents.
type PreAuthorization struct {
	ID        string     `json:"id" db:"id"`
	UserID    string     `json:"user_id" db:"user_id"`
	AgentID   string     `json:"agent_id" db:"agent_id"`
	Scopes    string     `json:"scopes" db:"scopes"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
}

// Covers returns true if this pre-authorization covers the requested scopes.
func (p *PreAuthorization) Covers(requestedScopes []string) bool {
	if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		return false
	}

	authorized := make(map[string]bool)
	for _, s := range SplitScopes(p.Scopes) {
		authorized[s] = true
	}

	for _, s := range requestedScopes {
		if !authorized[s] {
			return false
		}
	}
	return true
}

// ScopePolicy represents a scope policy stored in the database.
type ScopePolicy struct {
	ID              string    `json:"id" db:"id"`
	Pattern         string    `json:"pattern" db:"pattern"`
	Protocol        string    `json:"protocol" db:"protocol"`
	InteractionType string    `json:"interaction_type,omitempty" db:"interaction_type"`
	Description     string    `json:"description,omitempty" db:"description"`
	Priority        int       `json:"priority" db:"priority"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
}

// SplitScopes splits a space-separated scope string.
func SplitScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}
	var result []string
	current := ""
	for _, c := range scopes {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// JoinScopes joins scopes into a space-separated string.
func JoinScopes(scopes []string) string {
	if len(scopes) == 0 {
		return ""
	}
	result := scopes[0]
	for _, s := range scopes[1:] {
		result += " " + s
	}
	return result
}

// ============================================================================
// Agent Provider Types (AAuth Agent Identity)
// ============================================================================

// RegisteredAgent represents a fully registered agent with the Agent Provider.
// This extends the basic Agent type with ownership and lifecycle information.
type RegisteredAgent struct {
	ID          string            `json:"id" db:"id"`     // AAuth ID (e.g., "aauth:name@domain")
	Name        string            `json:"name" db:"name"` // Human-readable name
	Description string            `json:"description,omitempty" db:"description"`
	OwnerID     string            `json:"owner_id" db:"owner_id"`    // User who owns this agent
	Issuer      string            `json:"issuer" db:"issuer"`        // Agent Provider issuer URL
	Metadata    map[string]string `json:"metadata,omitempty" db:"-"` // Arbitrary metadata (JSON in DB)
	MetadataRaw string            `json:"-" db:"metadata"`           // JSON serialized metadata
	Status      AgentStatus       `json:"status" db:"status"`        // active, suspended, revoked
	CreatedAt   time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at" db:"updated_at"`
	RevokedAt   *time.Time        `json:"revoked_at,omitempty" db:"revoked_at"`
}

// AgentStatus represents the status of a registered agent.
type AgentStatus string

// Agent statuses.
const (
	AgentStatusActive    AgentStatus = "active"
	AgentStatusSuspended AgentStatus = "suspended"
	AgentStatusRevoked   AgentStatus = "revoked"
)

// IsActive returns true if the agent is active.
func (a *RegisteredAgent) IsActive() bool {
	return a.Status == AgentStatusActive && a.RevokedAt == nil
}

// AgentKey represents a public key registered for an agent.
type AgentKey struct {
	ID        string     `json:"id" db:"id"` // Key ID (kid)
	AgentID   string     `json:"agent_id" db:"agent_id"`
	PublicKey string     `json:"public_key" db:"public_key"` // JWK format
	Algorithm string     `json:"algorithm" db:"algorithm"`   // ES256, EdDSA, RS256, etc.
	Use       string     `json:"use,omitempty" db:"use"`     // sig or enc
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// IsValid returns true if the key is valid (not expired or revoked).
func (k *AgentKey) IsValid() bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// IssuedAgentToken represents an agent token issued by the Agent Provider.
// This tracks issued tokens for auditing and revocation.
type IssuedAgentToken struct {
	JTI       string     `json:"jti" db:"jti"` // JWT ID
	AgentID   string     `json:"agent_id" db:"agent_id"`
	KeyID     string     `json:"key_id" db:"key_id"`     // Which key was used to sign
	Audience  string     `json:"audience" db:"audience"` // Space-separated audience
	IssuedAt  time.Time  `json:"issued_at" db:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// IsValid returns true if the token is valid.
func (t *IssuedAgentToken) IsValid() bool {
	if t.RevokedAt != nil {
		return false
	}
	return time.Now().Before(t.ExpiresAt)
}

// Package agentauth provides a unified authorization layer for AI agents.
// It abstracts the underlying protocols (ID-JAG, AAuth) and provides
// policy-based routing to determine which protocol to use for each request.
package agentauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Provider errors.
var (
	// ErrConsentRequired indicates human consent is needed.
	ErrConsentRequired = errors.New("human consent required")

	// ErrConsentDenied indicates consent was denied.
	ErrConsentDenied = errors.New("consent denied")

	// ErrConsentTimeout indicates consent polling timed out.
	ErrConsentTimeout = errors.New("consent timeout")

	// ErrUnauthorized indicates authorization failed.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrProviderNotConfigured indicates the required provider is not configured.
	ErrProviderNotConfigured = errors.New("provider not configured")
)

// Protocol identifies the authorization protocol.
type Protocol string

// Supported protocols.
const (
	// ProtocolIDJAG uses ID-JAG for policy-based automatic authorization.
	ProtocolIDJAG Protocol = "idjag"

	// ProtocolAAuth uses AAuth for human consent-based authorization.
	ProtocolAAuth Protocol = "aauth"
)

// AuthStatus represents the status of an authorization request.
type AuthStatus string

// Authorization statuses.
const (
	StatusApproved AuthStatus = "approved"
	StatusPending  AuthStatus = "pending"
	StatusDenied   AuthStatus = "denied"
	StatusExpired  AuthStatus = "expired"
)

// AuthResult contains the result of an authorization request.
type AuthResult struct {
	// Status is the authorization status.
	Status AuthStatus `json:"status"`

	// Protocol indicates which protocol was used.
	Protocol Protocol `json:"protocol"`

	// Token is the access token (if approved).
	Token string `json:"token,omitempty"`

	// TokenType is the token type (e.g., "Bearer", "DPoP").
	TokenType string `json:"token_type,omitempty"`

	// ExpiresAt is when the token expires.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Scopes are the granted scopes.
	Scopes []string `json:"scopes,omitempty"`

	// ConsentURI is the URI for human consent (if pending).
	ConsentURI string `json:"consent_uri,omitempty"`

	// StatusURI is the URI to poll for consent status.
	StatusURI string `json:"status_uri,omitempty"`

	// PollInterval is the recommended polling interval.
	PollInterval time.Duration `json:"poll_interval,omitempty"`

	// Message is a human-readable message.
	Message string `json:"message,omitempty"`

	// Metadata contains protocol-specific metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// IsApproved returns true if authorization was granted.
func (r *AuthResult) IsApproved() bool {
	return r.Status == StatusApproved && r.Token != ""
}

// IsPending returns true if human consent is pending.
func (r *AuthResult) IsPending() bool {
	return r.Status == StatusPending
}

// AuthRequest contains the parameters for an authorization request.
type AuthRequest struct {
	// Scopes are the requested scopes.
	Scopes []string `json:"scopes"`

	// Resource is the target resource (optional).
	Resource string `json:"resource,omitempty"`

	// Audience is the intended audience (optional).
	Audience []string `json:"audience,omitempty"`

	// Subject is the subject being represented (for delegation).
	Subject string `json:"subject,omitempty"`

	// MissionName is a human-readable name for the mission (AAuth).
	MissionName string `json:"mission_name,omitempty"`

	// MissionDescription describes what the agent will do (AAuth).
	MissionDescription string `json:"mission_description,omitempty"`

	// Duration is the requested authorization duration.
	Duration time.Duration `json:"duration,omitempty"`

	// InteractionType is the AAuth interaction type.
	InteractionType string `json:"interaction_type,omitempty"`

	// RedirectURI is the callback URI for consent flow.
	RedirectURI string `json:"redirect_uri,omitempty"`

	// State is an opaque value for CSRF protection.
	State string `json:"state,omitempty"`

	// ForceProtocol overrides policy-based protocol selection.
	ForceProtocol Protocol `json:"force_protocol,omitempty"`

	// Metadata contains additional request metadata.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Provider is the interface for authorization providers.
type Provider interface {
	// Authorize requests authorization for the given scopes.
	// Returns AuthResult with token if approved, or consent info if pending.
	Authorize(ctx context.Context, req *AuthRequest) (*AuthResult, error)

	// CheckConsent checks the status of a pending consent request.
	CheckConsent(ctx context.Context, statusURI string) (*AuthResult, error)

	// WaitForConsent polls for consent approval with timeout.
	WaitForConsent(ctx context.Context, statusURI string, timeout time.Duration) (*AuthResult, error)

	// Revoke revokes an existing authorization.
	Revoke(ctx context.Context, token string) error

	// Protocol returns the protocol this provider implements.
	Protocol() Protocol

	// HTTPClient returns an HTTP client that automatically adds authorization.
	HTTPClient(ctx context.Context, req *AuthRequest) (*http.Client, error)
}

// ConsentHandler handles interactive consent flows.
type ConsentHandler interface {
	// StartConsent initiates a consent flow.
	// Returns the consent URI for the user to visit.
	StartConsent(ctx context.Context, req *AuthRequest) (consentURI string, state string, err error)

	// HandleCallback handles the consent callback.
	HandleCallback(ctx context.Context, code, state string) (*AuthResult, error)

	// ServeHTTP handles HTTP callbacks (implements http.Handler).
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// TokenRefresher handles token refresh.
type TokenRefresher interface {
	// Refresh refreshes an expired or expiring token.
	Refresh(ctx context.Context, token string) (*AuthResult, error)

	// NeedsRefresh returns true if the token should be refreshed.
	NeedsRefresh(expiresAt time.Time) bool
}

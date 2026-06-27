package agentauth

import (
	"fmt"
	"time"
)

// Config is the main configuration for the agentauth package.
type Config struct {
	// AgentID is the agent's identifier.
	AgentID string `json:"agent_id" yaml:"agent_id"`

	// Policy defines authorization routing rules.
	Policy *Policy `json:"policy" yaml:"policy"`

	// IDJAG is the ID-JAG provider configuration.
	IDJAG *IDJAGConfig `json:"idjag,omitempty" yaml:"idjag,omitempty"`

	// AAuth is the AAuth provider configuration.
	AAuth *AAuthConfig `json:"aauth,omitempty" yaml:"aauth,omitempty"`

	// Consent configures the consent flow.
	Consent *ConsentConfig `json:"consent,omitempty" yaml:"consent,omitempty"`

	// Cache configures token caching.
	Cache *CacheConfig `json:"cache,omitempty" yaml:"cache,omitempty"`
}

// IDJAGConfig configures the ID-JAG provider.
type IDJAGConfig struct {
	// Enabled enables ID-JAG authorization.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Issuer is the assertion issuer (agent's identity).
	Issuer string `json:"issuer" yaml:"issuer"`

	// TokenEndpoint is the authorization server's token endpoint.
	TokenEndpoint string `json:"token_endpoint" yaml:"token_endpoint"`

	// PrivateKey is the path/URI to the private key for signing.
	// Supports: file path, vault URI (op://, bw://), env:// prefix.
	PrivateKey string `json:"private_key" yaml:"private_key"`

	// KeyID is the key identifier.
	KeyID string `json:"key_id,omitempty" yaml:"key_id,omitempty"`

	// Algorithm is the signing algorithm (default: ES256).
	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`

	// DefaultAudience is the default audience for assertions.
	DefaultAudience []string `json:"default_audience,omitempty" yaml:"default_audience,omitempty"`

	// AssertionTTL is the assertion lifetime (default: 5m).
	AssertionTTL time.Duration `json:"assertion_ttl,omitempty" yaml:"assertion_ttl,omitempty"`
}

// AAuthConfig configures the AAuth provider.
type AAuthConfig struct {
	// Enabled enables AAuth authorization.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// AgentID is the AAuth agent identifier (e.g., "aauth:agent@example.com").
	AgentID string `json:"agent_id" yaml:"agent_id"`

	// PersonServer is the Person Server URL.
	PersonServer string `json:"person_server" yaml:"person_server"`

	// PrivateKey is the path/URI to the private key.
	PrivateKey string `json:"private_key" yaml:"private_key"`

	// KeyID is the key identifier.
	KeyID string `json:"key_id,omitempty" yaml:"key_id,omitempty"`

	// Algorithm is the signing algorithm (default: ES256).
	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`

	// DefaultAudience is the default audience for tokens.
	DefaultAudience []string `json:"default_audience,omitempty" yaml:"default_audience,omitempty"`

	// DefaultInteractionType is the default interaction type.
	DefaultInteractionType string `json:"default_interaction_type,omitempty" yaml:"default_interaction_type,omitempty"`

	// DefaultMissionDuration is the default mission duration.
	DefaultMissionDuration time.Duration `json:"default_mission_duration,omitempty" yaml:"default_mission_duration,omitempty"`
}

// ConsentConfig configures the consent flow.
type ConsentConfig struct {
	// Mode is the consent flow mode.
	Mode ConsentMode `json:"mode" yaml:"mode"`

	// RedirectURI is the callback URI for redirect flow.
	RedirectURI string `json:"redirect_uri,omitempty" yaml:"redirect_uri,omitempty"`

	// ListenAddr is the address for the callback server (redirect flow).
	ListenAddr string `json:"listen_addr,omitempty" yaml:"listen_addr,omitempty"`

	// PollInterval is the polling interval for deferred flow.
	PollInterval time.Duration `json:"poll_interval,omitempty" yaml:"poll_interval,omitempty"`

	// PollTimeout is the maximum time to wait for consent.
	PollTimeout time.Duration `json:"poll_timeout,omitempty" yaml:"poll_timeout,omitempty"`

	// ShowQRCode shows a QR code for the consent URI (CLI).
	ShowQRCode bool `json:"show_qr_code,omitempty" yaml:"show_qr_code,omitempty"`

	// OpenBrowser automatically opens the consent URI in a browser.
	OpenBrowser bool `json:"open_browser,omitempty" yaml:"open_browser,omitempty"`

	// OnConsentRequired is called when consent is required.
	// Allows custom UI handling.
	OnConsentRequired func(consentURI string) `json:"-" yaml:"-"`
}

// ConsentMode defines how consent is handled.
type ConsentMode string

// Consent modes.
const (
	// ConsentModeRedirect uses OAuth-style redirect flow.
	ConsentModeRedirect ConsentMode = "redirect"

	// ConsentModeDeferred uses polling-based deferred consent.
	ConsentModeDeferred ConsentMode = "deferred"

	// ConsentModeDevice uses device authorization flow.
	ConsentModeDevice ConsentMode = "device"
)

// CacheConfig configures token caching.
type CacheConfig struct {
	// Enabled enables token caching.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// TTL is the cache TTL (default: token expiry - 1 minute).
	TTL time.Duration `json:"ttl,omitempty" yaml:"ttl,omitempty"`

	// MaxSize is the maximum cache size.
	MaxSize int `json:"max_size,omitempty" yaml:"max_size,omitempty"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}

	if c.Policy == nil {
		c.Policy = DefaultPolicy()
	}

	// Validate that required providers are configured based on policy
	switch c.Policy.Mode {
	case PolicyModeAuto:
		if c.IDJAG == nil || !c.IDJAG.Enabled {
			return fmt.Errorf("idjag must be enabled for auto mode")
		}
	case PolicyModeHuman:
		if c.AAuth == nil || !c.AAuth.Enabled {
			return fmt.Errorf("aauth must be enabled for human mode")
		}
	case PolicyModeHybrid:
		// At least one provider must be configured
		hasProvider := (c.IDJAG != nil && c.IDJAG.Enabled) ||
			(c.AAuth != nil && c.AAuth.Enabled)
		if !hasProvider {
			return fmt.Errorf("at least one provider must be enabled for hybrid mode")
		}
	}

	if c.IDJAG != nil && c.IDJAG.Enabled {
		if err := c.IDJAG.Validate(); err != nil {
			return fmt.Errorf("idjag: %w", err)
		}
	}

	if c.AAuth != nil && c.AAuth.Enabled {
		if err := c.AAuth.Validate(); err != nil {
			return fmt.Errorf("aauth: %w", err)
		}
	}

	return nil
}

// Validate validates the ID-JAG configuration.
func (c *IDJAGConfig) Validate() error {
	if c.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if c.TokenEndpoint == "" {
		return fmt.Errorf("token_endpoint is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("private_key is required")
	}
	return nil
}

// Validate validates the AAuth configuration.
func (c *AAuthConfig) Validate() error {
	if c.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if c.PersonServer == "" {
		return fmt.Errorf("person_server is required")
	}
	if c.PrivateKey == "" {
		return fmt.Errorf("private_key is required")
	}
	return nil
}

// DefaultConfig returns a default configuration.
func DefaultConfig(agentID string) *Config {
	return &Config{
		AgentID: agentID,
		Policy:  DefaultPolicy(),
		Consent: &ConsentConfig{
			Mode:         ConsentModeDeferred,
			PollInterval: 2 * time.Second,
			PollTimeout:  5 * time.Minute,
		},
		Cache: &CacheConfig{
			Enabled: true,
			MaxSize: 100,
		},
	}
}

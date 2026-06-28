package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestNewUnified_RequiresPrivateKey(t *testing.T) {
	_, err := NewUnified()
	if err == nil {
		t.Error("expected error without private key")
	}
}

func TestNewUnified_WithOptions(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	c, err := NewUnified(
		WithPrivateKey(key, "key-1"),
		WithAgentID("aauth:test@example.com"),
		WithPersonServer("https://ps.example.com"),
		WithTokenEndpoint("https://as.example.com/oauth/token"),
		WithPolicy(PolicyConfig{
			Default:     ProtocolIDJAG,
			AAuthScopes: []string{"write:*", "admin:*"},
		}),
		WithDefaultAudience("https://api.example.com"),
		WithCaching(50),
	)
	if err != nil {
		t.Fatalf("NewUnified() error = %v", err)
	}

	if c.config.AgentID != "aauth:test@example.com" {
		t.Errorf("AgentID = %v, want aauth:test@example.com", c.config.AgentID)
	}
	if c.config.PersonServer != "https://ps.example.com" {
		t.Errorf("PersonServer = %v, want https://ps.example.com", c.config.PersonServer)
	}
	if c.config.CacheMaxSize != 50 {
		t.Errorf("CacheMaxSize = %v, want 50", c.config.CacheMaxSize)
	}
}

func TestMatchScopePattern(t *testing.T) {
	tests := []struct {
		pattern string
		scope   string
		want    bool
	}{
		// Exact match
		{"read:data", "read:data", true},
		{"read:data", "write:data", false},

		// Suffix wildcard
		{"write:*", "write:data", true},
		{"write:*", "write:anything", true},
		{"write:*", "read:data", false},

		// Prefix wildcard
		{"*:read", "data:read", true},
		{"*:read", "anything:read", true},
		{"*:read", "data:write", false},

		// Full wildcard
		{"*", "anything", true},
		{"**", "anything:here", true},

		// No match
		{"admin:users", "admin:settings", false},
	}

	for _, tt := range tests {
		got := matchScopePattern(tt.pattern, tt.scope)
		if got != tt.want {
			t.Errorf("matchScopePattern(%q, %q) = %v, want %v", tt.pattern, tt.scope, got, tt.want)
		}
	}
}

func TestUnifiedClient_SelectProtocol(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	c, err := NewUnified(
		WithPrivateKey(key, "key-1"),
		WithPolicy(PolicyConfig{
			Default:     ProtocolIDJAG,
			AAuthScopes: []string{"write:*", "delete:*", "admin:*"},
		}),
	)
	if err != nil {
		t.Fatalf("NewUnified() error = %v", err)
	}

	tests := []struct {
		name   string
		scopes []string
		want   Protocol
	}{
		{"read scope uses ID-JAG", []string{"read:data"}, ProtocolIDJAG},
		{"write scope uses AAuth", []string{"write:data"}, ProtocolAAuth},
		{"delete scope uses AAuth", []string{"delete:user"}, ProtocolAAuth},
		{"admin scope uses AAuth", []string{"admin:settings"}, ProtocolAAuth},
		{"mixed scopes - AAuth wins", []string{"read:data", "write:data"}, ProtocolAAuth},
		{"empty scopes uses default", []string{}, ProtocolIDJAG},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c.GetProtocolForScopes(tt.scopes)
			if got != tt.want {
				t.Errorf("GetProtocolForScopes(%v) = %v, want %v", tt.scopes, got, tt.want)
			}
		})
	}
}

func TestUnifiedClient_SelectProtocol_ForceProtocol(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	c, err := NewUnified(
		WithPrivateKey(key, "key-1"),
		WithPolicy(PolicyConfig{
			Default:     ProtocolIDJAG,
			AAuthScopes: []string{"write:*"},
		}),
	)
	if err != nil {
		t.Fatalf("NewUnified() error = %v", err)
	}

	// write:data would normally use AAuth, but we force ID-JAG
	req := &AuthRequest{
		Scopes:        []string{"write:data"},
		ForceProtocol: ProtocolIDJAG,
	}

	got := c.selectProtocol(req)
	if got != ProtocolIDJAG {
		t.Errorf("selectProtocol with ForceProtocol = %v, want %v", got, ProtocolIDJAG)
	}
}

func TestAuthResult_IsApproved(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"approved", true},
		{"pending", false},
		{"denied", false},
		{"error", false},
	}

	for _, tt := range tests {
		r := &AuthResult{Status: tt.status}
		if got := r.IsApproved(); got != tt.want {
			t.Errorf("AuthResult{Status: %q}.IsApproved() = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestAuthResult_IsPending(t *testing.T) {
	tests := []struct {
		status string
		want   bool
	}{
		{"approved", false},
		{"pending", true},
		{"denied", false},
		{"error", false},
	}

	for _, tt := range tests {
		r := &AuthResult{Status: tt.status}
		if got := r.IsPending(); got != tt.want {
			t.Errorf("AuthResult{Status: %q}.IsPending() = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestUnifiedClient_CacheOperations(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	c, err := NewUnified(
		WithPrivateKey(key, "key-1"),
		WithCaching(10),
	)
	if err != nil {
		t.Fatalf("NewUnified() error = %v", err)
	}

	// Test cacheKey
	req := &AuthRequest{
		Resource: "https://api.example.com",
		Scopes:   []string{"read:data", "write:data"},
	}
	key1 := c.cacheKey(req)
	key2 := c.cacheKey(req)
	if key1 != key2 {
		t.Error("cacheKey should be deterministic")
	}

	// Test cache is empty initially
	if result := c.checkCache(req); result != nil {
		t.Error("cache should be empty initially")
	}

	// Test ClearCache
	c.ClearCache()
	if len(c.cache) != 0 {
		t.Error("cache should be empty after ClearCache")
	}
}

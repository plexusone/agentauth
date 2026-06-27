package agentauth

import (
	"testing"
)

func TestDefaultVerifierConfig(t *testing.T) {
	cfg := DefaultVerifierConfig()

	if !cfg.IDJAGEnabled {
		t.Error("ID-JAG should be enabled by default")
	}
	if !cfg.AAuthEnabled {
		t.Error("AAuth should be enabled by default")
	}
	if cfg.DefaultProtocol != ProtocolIDJAG {
		t.Errorf("expected default protocol %s, got %s", ProtocolIDJAG, cfg.DefaultProtocol)
	}
	if len(cfg.SensitiveActions) == 0 {
		t.Error("sensitive actions should not be empty")
	}
}

func TestNewTokenVerifier(t *testing.T) {
	v := NewTokenVerifier(nil)
	if v == nil {
		t.Fatal("verifier should not be nil")
	}
	if v.config == nil {
		t.Fatal("config should not be nil")
	}
}

func TestTokenVerifier_GetRequiredProtocol(t *testing.T) {
	cfg := DefaultVerifierConfig()
	v := NewTokenVerifier(cfg)

	tests := []struct {
		action   string
		expected Protocol
	}{
		{"read", ProtocolIDJAG},        // default
		{"write", ProtocolAAuth},       // sensitive
		{"delete", ProtocolAAuth},      // sensitive
		{"update", ProtocolAAuth},      // sensitive
		{"create", ProtocolAAuth},      // sensitive
		{"send", ProtocolAAuth},        // sensitive
		{"upload", ProtocolAAuth},      // sensitive
		{"admin", ProtocolAAuth},       // sensitive
		{"chat", ProtocolIDJAG},        // default
		{"list", ProtocolIDJAG},        // default
		{"view", ProtocolIDJAG},        // default
		{"WriteData", ProtocolAAuth},   // case-insensitive match
		{"DELETE_USER", ProtocolAAuth}, // case-insensitive match
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			got := v.GetRequiredProtocol(tt.action)
			if got != tt.expected {
				t.Errorf("action %q: expected protocol %s, got %s", tt.action, tt.expected, got)
			}
		})
	}
}

func TestTokenVerifier_IsSensitiveAction(t *testing.T) {
	cfg := DefaultVerifierConfig()
	v := NewTokenVerifier(cfg)

	if !v.IsSensitiveAction("write") {
		t.Error("write should be sensitive")
	}
	if !v.IsSensitiveAction("delete") {
		t.Error("delete should be sensitive")
	}
	if v.IsSensitiveAction("read") {
		t.Error("read should not be sensitive")
	}
	if v.IsSensitiveAction("chat") {
		t.Error("chat should not be sensitive")
	}
}

func TestTokenVerifier_CustomActionPolicy(t *testing.T) {
	cfg := DefaultVerifierConfig()
	cfg.ActionPolicy = map[string]Protocol{
		"special-read": ProtocolAAuth, // Override: require AAuth for this read
		"safe-write":   ProtocolIDJAG, // Override: allow ID-JAG for this write
	}
	v := NewTokenVerifier(cfg)

	// Custom policy should override
	if v.GetRequiredProtocol("special-read") != ProtocolAAuth {
		t.Error("special-read should require AAuth per custom policy")
	}

	// Note: safe-write still matches "write" in sensitive actions, so it requires AAuth
	// Custom action policy is checked second, after sensitive actions check
	// This is intentional: sensitive actions take precedence
	if v.GetRequiredProtocol("safe-write") != ProtocolAAuth {
		t.Error("safe-write contains 'write' so it's still sensitive")
	}
}

func TestTokenClaims_HasScope(t *testing.T) {
	claims := &TokenClaims{
		Scopes: []string{"read:calendar", "write:profile", "admin"},
	}

	if !claims.HasScope("read:calendar") {
		t.Error("should have read:calendar scope")
	}
	if !claims.HasScope("admin") {
		t.Error("should have admin scope")
	}
	if claims.HasScope("delete:users") {
		t.Error("should not have delete:users scope")
	}
}

func TestTokenClaims_HasAnyScope(t *testing.T) {
	claims := &TokenClaims{
		Scopes: []string{"read:calendar", "write:profile"},
	}

	if !claims.HasAnyScope("read:calendar", "read:email") {
		t.Error("should match read:calendar")
	}
	if !claims.HasAnyScope("write:profile") {
		t.Error("should match write:profile")
	}
	if claims.HasAnyScope("admin", "delete:users") {
		t.Error("should not match any")
	}
}

func TestIsJWT(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.sig", true},
		{"header.payload.signature", true},
		{"a.b.c", true},
		{"not-a-jwt", false},
		{"only.two.parts", true}, // three parts
		{"one.two", false},       // only two parts
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := IsJWT(tt.input)
			if got != tt.expected {
				t.Errorf("IsJWT(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractIssuerFromJWT(t *testing.T) {
	// Valid JWT with issuer claim
	// Header: {"alg":"none"}
	// Payload: {"iss":"https://example.com"}
	validJWT := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIn0.signature"

	issuer, err := extractIssuerFromJWT(validJWT)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if issuer != "https://example.com" {
		t.Errorf("expected issuer 'https://example.com', got %q", issuer)
	}

	// Invalid JWT
	_, err = extractIssuerFromJWT("not-a-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

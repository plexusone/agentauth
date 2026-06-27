package agentauth

import (
	"testing"
)

func TestPolicyMatcher_Match(t *testing.T) {
	tests := []struct {
		name     string
		policy   *Policy
		scopes   []string
		expected Protocol
	}{
		{
			name: "auto mode always returns IDJAG",
			policy: &Policy{
				Mode: PolicyModeAuto,
			},
			scopes:   []string{"calendar:write", "admin:delete"},
			expected: ProtocolIDJAG,
		},
		{
			name: "human mode always returns AAuth",
			policy: &Policy{
				Mode: PolicyModeHuman,
			},
			scopes:   []string{"profile:read"},
			expected: ProtocolAAuth,
		},
		{
			name: "hybrid mode with sensitive scope",
			policy: &Policy{
				Mode:            PolicyModeHybrid,
				DefaultProtocol: ProtocolIDJAG,
				SensitiveScopes: []string{"admin:*"},
			},
			scopes:   []string{"admin:delete"},
			expected: ProtocolAAuth,
		},
		{
			name: "hybrid mode with auto scope",
			policy: &Policy{
				Mode:            PolicyModeHybrid,
				DefaultProtocol: ProtocolAAuth,
				AutoScopes:      []string{"*:read"},
			},
			scopes:   []string{"calendar:read"},
			expected: ProtocolIDJAG,
		},
		{
			name: "hybrid mode mixed scopes - sensitive wins",
			policy: &Policy{
				Mode:            PolicyModeHybrid,
				DefaultProtocol: ProtocolIDJAG,
				SensitiveScopes: []string{"payments:*"},
				AutoScopes:      []string{"*:read"},
			},
			scopes:   []string{"calendar:read", "payments:charge"},
			expected: ProtocolAAuth,
		},
		{
			name:     "default policy sensitive scope",
			policy:   DefaultPolicy(),
			scopes:   []string{"email:send"},
			expected: ProtocolAAuth,
		},
		{
			name:     "default policy read scope",
			policy:   DefaultPolicy(),
			scopes:   []string{"calendar:read"},
			expected: ProtocolIDJAG,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewPolicyMatcher(tt.policy)
			result := matcher.Match(tt.scopes)
			if result != tt.expected {
				t.Errorf("Match(%v) = %v, want %v", tt.scopes, result, tt.expected)
			}
		})
	}
}

func TestPolicyMatcher_MatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		scope   string
		match   bool
	}{
		{"calendar:read", "calendar:read", true},
		{"calendar:read", "calendar:write", false},
		{"calendar:*", "calendar:read", true},
		{"calendar:*", "calendar:write", true},
		{"calendar:*", "email:read", false},
		{"*:read", "calendar:read", true},
		{"*:read", "email:read", true},
		{"*:read", "calendar:write", false},
		{"admin:**", "admin:users:delete", true},
		{"admin:**", "admin:settings", true},
		{"**", "anything:here", true},
	}

	policy := &Policy{
		Mode:            PolicyModeHybrid,
		DefaultProtocol: ProtocolIDJAG,
	}
	matcher := NewPolicyMatcher(policy)

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.scope, func(t *testing.T) {
			patternParts := splitScope(tt.pattern)
			scopeParts := splitScope(tt.scope)
			result := matcher.matchPattern(patternParts, scopeParts)
			if result != tt.match {
				t.Errorf("matchPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.scope, result, tt.match)
			}
		})
	}
}

func TestPolicyMatcher_SplitByProtocol(t *testing.T) {
	policy := &Policy{
		Mode:            PolicyModeHybrid,
		DefaultProtocol: ProtocolIDJAG,
		SensitiveScopes: []string{"payments:*", "admin:*"},
		AutoScopes:      []string{"*:read"},
	}
	matcher := NewPolicyMatcher(policy)

	scopes := []string{"calendar:read", "payments:charge", "profile:read", "admin:delete"}
	auto, human := matcher.SplitByProtocol(scopes)

	expectedAuto := []string{"calendar:read", "profile:read"}
	expectedHuman := []string{"payments:charge", "admin:delete"}

	if len(auto) != len(expectedAuto) {
		t.Errorf("auto scopes: got %v, want %v", auto, expectedAuto)
	}

	if len(human) != len(expectedHuman) {
		t.Errorf("human scopes: got %v, want %v", human, expectedHuman)
	}
}

func TestPolicyMatcher_RequiresConsent(t *testing.T) {
	policy := DefaultPolicy()
	matcher := NewPolicyMatcher(policy)

	tests := []struct {
		scopes   []string
		requires bool
	}{
		{[]string{"profile:read"}, false},
		{[]string{"email:send"}, true},
		{[]string{"profile:read", "email:send"}, true},
		{[]string{"calendar:read", "files:read"}, false},
	}

	for _, tt := range tests {
		result := matcher.RequiresConsent(tt.scopes)
		if result != tt.requires {
			t.Errorf("RequiresConsent(%v) = %v, want %v",
				tt.scopes, result, tt.requires)
		}
	}
}

func TestPolicyMatcher_GetScopePolicy(t *testing.T) {
	policy := &Policy{
		Mode:            PolicyModeHybrid,
		DefaultProtocol: ProtocolIDJAG,
		ScopePolicies: []ScopePolicy{
			{
				Pattern:         "payments:*",
				Protocol:        ProtocolAAuth,
				InteractionType: "human_in_loop",
				Description:     "Payment operations require approval",
				Priority:        100,
			},
		},
	}
	matcher := NewPolicyMatcher(policy)

	sp := matcher.GetScopePolicy("payments:charge")
	if sp == nil {
		t.Fatal("expected scope policy, got nil")
	}

	if sp.InteractionType != "human_in_loop" {
		t.Errorf("InteractionType = %v, want human_in_loop", sp.InteractionType)
	}

	if sp.Description != "Payment operations require approval" {
		t.Errorf("Description mismatch")
	}
}

func TestDefaultPolicy(t *testing.T) {
	policy := DefaultPolicy()

	if policy.Mode != PolicyModeHybrid {
		t.Errorf("Mode = %v, want hybrid", policy.Mode)
	}

	if policy.DefaultProtocol != ProtocolIDJAG {
		t.Errorf("DefaultProtocol = %v, want idjag", policy.DefaultProtocol)
	}

	if len(policy.SensitiveScopes) == 0 {
		t.Error("expected sensitive scopes")
	}

	if len(policy.AutoScopes) == 0 {
		t.Error("expected auto scopes")
	}
}

func splitScope(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ':' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

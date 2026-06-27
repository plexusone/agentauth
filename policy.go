package agentauth

import (
	"strings"
)

// PolicyMode determines how authorization requests are routed.
type PolicyMode string

// Policy modes.
const (
	// PolicyModeAuto uses ID-JAG for all requests (no human interaction).
	PolicyModeAuto PolicyMode = "auto"

	// PolicyModeHuman uses AAuth for all requests (always human consent).
	PolicyModeHuman PolicyMode = "human"

	// PolicyModeHybrid routes based on scope policies.
	PolicyModeHybrid PolicyMode = "hybrid"
)

// ScopePolicy defines how a scope pattern should be authorized.
type ScopePolicy struct {
	// Pattern is the scope pattern to match.
	// Supports wildcards: "calendar:*", "admin:**", "email:read"
	Pattern string `json:"pattern" yaml:"pattern"`

	// Protocol is the protocol to use for matching scopes.
	Protocol Protocol `json:"protocol" yaml:"protocol"`

	// RequireConsent forces human consent even for ID-JAG.
	RequireConsent bool `json:"require_consent,omitempty" yaml:"require_consent,omitempty"`

	// InteractionType is the AAuth interaction type for this scope.
	InteractionType string `json:"interaction_type,omitempty" yaml:"interaction_type,omitempty"`

	// MaxDuration is the maximum authorization duration for this scope.
	MaxDuration string `json:"max_duration,omitempty" yaml:"max_duration,omitempty"`

	// Description describes what this scope allows.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Priority determines matching order (higher = checked first).
	Priority int `json:"priority,omitempty" yaml:"priority,omitempty"`
}

// Policy defines authorization policies for scope routing.
type Policy struct {
	// Mode is the overall policy mode.
	Mode PolicyMode `json:"mode" yaml:"mode"`

	// DefaultProtocol is used when no scope policy matches (hybrid mode).
	DefaultProtocol Protocol `json:"default_protocol" yaml:"default_protocol"`

	// ScopePolicies define per-scope authorization rules.
	ScopePolicies []ScopePolicy `json:"scope_policies,omitempty" yaml:"scope_policies,omitempty"`

	// SensitiveScopes always require AAuth/human consent.
	// Shorthand for adding AAuth policies for each scope.
	SensitiveScopes []string `json:"sensitive_scopes,omitempty" yaml:"sensitive_scopes,omitempty"`

	// AutoScopes always use ID-JAG/automatic authorization.
	// Shorthand for adding ID-JAG policies for each scope.
	AutoScopes []string `json:"auto_scopes,omitempty" yaml:"auto_scopes,omitempty"`
}

// DefaultPolicy returns a sensible default policy.
func DefaultPolicy() *Policy {
	return &Policy{
		Mode:            PolicyModeHybrid,
		DefaultProtocol: ProtocolIDJAG,
		SensitiveScopes: []string{
			"admin:*",
			"*:write",
			"*:delete",
			"payments:*",
			"email:send",
			"files:upload",
		},
		AutoScopes: []string{
			"*:read",
			"profile:*",
			"openid",
		},
	}
}

// PolicyMatcher matches scopes to policies.
type PolicyMatcher struct {
	policy *Policy

	// Compiled policies sorted by priority
	compiled []compiledPolicy
}

type compiledPolicy struct {
	ScopePolicy
	parts []string
}

// NewPolicyMatcher creates a new policy matcher.
func NewPolicyMatcher(policy *Policy) *PolicyMatcher {
	if policy == nil {
		policy = DefaultPolicy()
	}

	m := &PolicyMatcher{
		policy:   policy,
		compiled: make([]compiledPolicy, 0),
	}

	// Add explicit scope policies
	for _, sp := range policy.ScopePolicies {
		m.compiled = append(m.compiled, compiledPolicy{
			ScopePolicy: sp,
			parts:       strings.Split(sp.Pattern, ":"),
		})
	}

	// Add sensitive scopes as AAuth policies
	for _, scope := range policy.SensitiveScopes {
		m.compiled = append(m.compiled, compiledPolicy{
			ScopePolicy: ScopePolicy{
				Pattern:  scope,
				Protocol: ProtocolAAuth,
				Priority: 10, // Lower priority than explicit policies
			},
			parts: strings.Split(scope, ":"),
		})
	}

	// Add auto scopes as ID-JAG policies
	for _, scope := range policy.AutoScopes {
		m.compiled = append(m.compiled, compiledPolicy{
			ScopePolicy: ScopePolicy{
				Pattern:  scope,
				Protocol: ProtocolIDJAG,
				Priority: 5, // Lowest priority
			},
			parts: strings.Split(scope, ":"),
		})
	}

	// Sort by priority (highest first)
	m.sortByPriority()

	return m
}

func (m *PolicyMatcher) sortByPriority() {
	// Simple bubble sort (policies are typically small)
	for i := 0; i < len(m.compiled); i++ {
		for j := i + 1; j < len(m.compiled); j++ {
			if m.compiled[j].Priority > m.compiled[i].Priority {
				m.compiled[i], m.compiled[j] = m.compiled[j], m.compiled[i]
			}
		}
	}
}

// Match returns the protocol for a set of scopes.
// If any scope requires AAuth, AAuth is returned.
// If all scopes match auto policies, IDJAG is returned.
func (m *PolicyMatcher) Match(scopes []string) Protocol {
	// Short circuit for non-hybrid modes
	switch m.policy.Mode {
	case PolicyModeAuto:
		return ProtocolIDJAG
	case PolicyModeHuman:
		return ProtocolAAuth
	}

	// Hybrid mode: check each scope
	hasAAuth := false
	hasIDJAG := false
	allMatched := true

	for _, scope := range scopes {
		protocol, matched := m.matchScopeWithResult(scope)
		if !matched {
			allMatched = false
			continue
		}
		if protocol == ProtocolAAuth {
			hasAAuth = true
		} else if protocol == ProtocolIDJAG {
			hasIDJAG = true
		}
	}

	// AAuth takes precedence (any sensitive scope requires human consent)
	if hasAAuth {
		return ProtocolAAuth
	}

	// If any scope matched IDJAG policy, use IDJAG
	if hasIDJAG {
		return ProtocolIDJAG
	}

	// If all scopes matched policies, use the most restrictive matched protocol
	if allMatched && len(scopes) > 0 {
		return ProtocolIDJAG
	}

	return m.policy.DefaultProtocol
}

// matchScope matches a single scope to a policy.
func (m *PolicyMatcher) matchScope(scope string) Protocol {
	protocol, _ := m.matchScopeWithResult(scope)
	return protocol
}

// matchScopeWithResult matches a single scope to a policy and reports if matched.
func (m *PolicyMatcher) matchScopeWithResult(scope string) (Protocol, bool) {
	scopeParts := strings.Split(scope, ":")

	for _, cp := range m.compiled {
		if m.matchPattern(cp.parts, scopeParts) {
			return cp.Protocol, true
		}
	}

	return m.policy.DefaultProtocol, false
}

// matchPattern matches scope parts against pattern parts.
func (m *PolicyMatcher) matchPattern(pattern, scope []string) bool {
	pi, si := 0, 0

	for pi < len(pattern) && si < len(scope) {
		switch pattern[pi] {
		case "**":
			// ** matches everything remaining
			return true
		case "*":
			// * matches one segment
			pi++
			si++
		default:
			// Exact match required
			if pattern[pi] != scope[si] {
				return false
			}
			pi++
			si++
		}
	}

	// Check if we consumed both
	return pi == len(pattern) && si == len(scope)
}

// GetScopePolicy returns the policy for a specific scope.
func (m *PolicyMatcher) GetScopePolicy(scope string) *ScopePolicy {
	scopeParts := strings.Split(scope, ":")

	for _, cp := range m.compiled {
		if m.matchPattern(cp.parts, scopeParts) {
			return &cp.ScopePolicy
		}
	}

	return nil
}

// RequiresConsent returns true if any scope requires human consent.
func (m *PolicyMatcher) RequiresConsent(scopes []string) bool {
	return m.Match(scopes) == ProtocolAAuth
}

// SplitByProtocol splits scopes into auto and human-required groups.
func (m *PolicyMatcher) SplitByProtocol(scopes []string) (auto, human []string) {
	for _, scope := range scopes {
		if m.matchScope(scope) == ProtocolAAuth {
			human = append(human, scope)
		} else {
			auto = append(auto, scope)
		}
	}
	return
}

# Policy Matching

The `PolicyMatcher` determines which protocol (ID-JAG or AAuth) should be used based on requested scopes.

## Overview

PolicyMatcher uses a rules-based approach to route authorization requests:

1. **Specific rules** - Exact scope or pattern matches
2. **Sensitive scopes** - Wildcards that always require AAuth
3. **Default protocol** - Fallback when no rules match

## Configuration

```go
import "github.com/plexusone/agentauth"

policy := &agentauth.PolicyConfig{
    // Default protocol when no rules match
    Default: agentauth.ProtocolIDJAG,

    // Protocol for sensitive operations (overrides rules)
    Sensitive: agentauth.ProtocolAAuth,

    // Specific scope-to-protocol mappings
    Rules: map[string]agentauth.Protocol{
        // Exact matches
        "admin":         agentauth.ProtocolAAuth,
        "read:email":    agentauth.ProtocolIDJAG,

        // Wildcard patterns
        "write:*":       agentauth.ProtocolAAuth,
        "delete:*":      agentauth.ProtocolAAuth,
        "read:*":        agentauth.ProtocolIDJAG,
        "list:*":        agentauth.ProtocolIDJAG,
    },

    // Scopes that always require AAuth (human consent)
    SensitiveScopes: []string{
        "admin:*",
        "*.admin",
        "billing:*",
        "payment:*",
    },
}

matcher := agentauth.NewPolicyMatcher(policy)
```

## Matching Scopes

The `Match` method returns the required protocol for a set of scopes:

```go
// Single read scope -> ID-JAG
protocol := matcher.Match([]string{"read:email"})
// Returns: ProtocolIDJAG

// Write scope -> AAuth
protocol := matcher.Match([]string{"write:profile"})
// Returns: ProtocolAAuth

// Mixed scopes -> highest privilege required (AAuth wins)
protocol := matcher.Match([]string{"read:email", "write:profile"})
// Returns: ProtocolAAuth
```

## Rule Priority

Rules are evaluated in priority order:

1. **Sensitive scopes** (always AAuth)
2. **Exact match rules**
3. **Wildcard pattern rules**
4. **Default protocol**

```go
// Sensitive scope always wins
protocol := matcher.Match([]string{"admin:users"})
// Returns: ProtocolAAuth (from SensitiveScopes)

// Exact match over wildcard
// If Rules has "read:sensitive": ProtocolAAuth
// And "read:*": ProtocolIDJAG
protocol := matcher.Match([]string{"read:sensitive"})
// Returns: ProtocolAAuth (exact match)
```

## Wildcard Patterns

Supported wildcard patterns:

| Pattern | Matches |
|---------|---------|
| `admin` | Exact "admin" scope |
| `read:*` | "read:email", "read:profile", etc. |
| `*.admin` | "users.admin", "data.admin", etc. |
| `*:sensitive` | "read:sensitive", "write:sensitive", etc. |

## Multiple Scopes

When multiple scopes are requested, the matcher returns the most restrictive protocol:

```go
// Scenario: Agent requests multiple scopes
scopes := []string{
    "read:email",      // -> ProtocolIDJAG
    "read:profile",    // -> ProtocolIDJAG
    "write:profile",   // -> ProtocolAAuth
}

protocol := matcher.Match(scopes)
// Returns: ProtocolAAuth (most restrictive wins)
```

## Custom Matcher Logic

Extend the matcher with custom logic:

```go
type CustomMatcher struct {
    base *agentauth.PolicyMatcher
}

func (m *CustomMatcher) Match(scopes []string) agentauth.Protocol {
    // Check time-based restrictions
    if isOutsideBusinessHours() {
        return agentauth.ProtocolAAuth  // Require consent outside hours
    }

    // Fall back to base matcher
    return m.base.Match(scopes)
}
```

## Best Practices

### Principle of Least Privilege

Configure the default to require the minimum necessary protocol:

```go
policy := &agentauth.PolicyConfig{
    Default: agentauth.ProtocolIDJAG,  // Automated for most operations
    Rules: map[string]agentauth.Protocol{
        // Explicitly require consent for sensitive operations
        "payment:*":  agentauth.ProtocolAAuth,
        "admin:*":    agentauth.ProtocolAAuth,
    },
}
```

### Audit Trail

Log protocol decisions for security auditing:

```go
protocol := matcher.Match(scopes)
logger.Info("protocol selected",
    "scopes", scopes,
    "protocol", protocol,
    "requires_consent", protocol == agentauth.ProtocolAAuth,
)
```

### Testing Policies

Verify policy behavior in tests:

```go
func TestPolicyMatcher(t *testing.T) {
    matcher := agentauth.NewPolicyMatcher(policy)

    tests := []struct {
        scopes   []string
        expected agentauth.Protocol
    }{
        {[]string{"read:email"}, agentauth.ProtocolIDJAG},
        {[]string{"write:profile"}, agentauth.ProtocolAAuth},
        {[]string{"admin:users"}, agentauth.ProtocolAAuth},
    }

    for _, tt := range tests {
        got := matcher.Match(tt.scopes)
        if got != tt.expected {
            t.Errorf("Match(%v) = %v, want %v", tt.scopes, got, tt.expected)
        }
    }
}
```

## Related

- [Token Verification](verifier.md) - Server-side token verification
- [Hybrid Provider](hybrid.md) - Protocol routing with PolicyMatcher

# Token Verification

AgentAuth provides two token verification options:

1. **Unified Verifier (v0.3.0)** - The `verifier` package with automatic protocol detection and JWKS caching
2. **TokenVerifier** - Action-based verification with sensitive operation policies

## Unified Verifier (v0.3.0)

The `verifier` package provides multi-protocol token verification with automatic protocol detection:

```go
import "github.com/plexusone/agentauth/verifier"

v, _ := verifier.New(
    verifier.WithTrustedIssuers(
        "https://auth.example.com",
        "https://consent.example.com",
    ),
    verifier.WithProtocols(verifier.ProtocolAAuth, verifier.ProtocolIDJAG),
    verifier.WithJWKSCache(time.Hour),
)

// Verify any token (auto-detects protocol)
claims, err := v.Verify(ctx, tokenString)
if err != nil {
    return err
}

fmt.Printf("Protocol: %s\n", claims.Protocol)    // "aauth" or "idjag"
fmt.Printf("Token Type: %s\n", claims.TokenType) // "aa-agent+jwt", "aa-auth+jwt", "id-jag"
fmt.Printf("Subject: %s\n", claims.Subject)
fmt.Printf("Scopes: %v\n", claims.Scopes)
fmt.Printf("Agent ID: %s\n", claims.AgentID)     // AAuth-specific
fmt.Printf("Actor: %s\n", claims.Actor)          // ID-JAG delegation
```

### Unified Verifier Options

| Option | Description |
|--------|-------------|
| `WithTrustedIssuers(...)` | Issuers whose tokens are accepted |
| `WithProtocols(...)` | Protocols to accept (AAuth, ID-JAG) |
| `WithJWKSCache(ttl)` | JWKS cache duration |
| `WithHTTPClient(client)` | Custom HTTP client for JWKS fetching |

### HTTP Middleware

```go
// Protect all routes under /api/
mux.Handle("/api/", v.Middleware(apiHandler))

// Require specific scopes
mux.Handle("/api/admin/", v.RequireScopes("admin:*")(adminHandler))

// Access claims in handler
func apiHandler(w http.ResponseWriter, r *http.Request) {
    claims := verifier.ClaimsFromContext(r.Context())
    fmt.Printf("Request from: %s\n", claims.Subject)
}
```

---

## TokenVerifier (Action-Based)

The `TokenVerifier` provides multi-protocol token verification with action-based routing for server-side validation.

### Overview

TokenVerifier can verify both ID-JAG and AAuth tokens automatically, determining the protocol from the token's issuer claim. It also enforces action-based policies, requiring AAuth (human consent) for sensitive operations.

## Configuration

```go
import "github.com/plexusone/agentauth"

config := &agentauth.VerifierConfig{
    // Enable protocols
    IDJAGEnabled: true,
    AAuthEnabled: true,

    // Map issuer URLs to JWKS URLs (empty string auto-discovers)
    IDJAGIssuers: map[string]string{
        "https://issuer.example.com": "",
        "https://custom.example.com": "https://custom.example.com/keys.json",
    },
    AAuthIssuers: map[string]string{
        "https://consent.example.com": "",
    },

    // Expected audience for tokens
    IDJAGAudience: "https://api.example.com",
    AAuthAudience: "https://api.example.com",

    // Actions that require AAuth (human consent)
    SensitiveActions: []string{
        "write",
        "delete",
        "update",
        "create",
        "send",
        "admin",
    },

    // Override protocol for specific actions
    ActionPolicy: map[string]agentauth.Protocol{
        "read":   agentauth.ProtocolIDJAG,
        "export": agentauth.ProtocolAAuth,
    },

    // Default protocol when no policy matches
    DefaultProtocol: agentauth.ProtocolIDJAG,

    // JWKS cache TTL
    CacheTTL: 5 * time.Minute,
}

verifier := agentauth.NewTokenVerifier(config)
```

## Basic Verification

Verify any token (tries both protocols):

```go
claims, err := verifier.Verify(ctx, token)
if err != nil {
    // Token invalid or issuer unknown
    return err
}

fmt.Printf("Protocol: %s\n", claims.Protocol)  // "idjag" or "aauth"
fmt.Printf("Subject: %s\n", claims.Subject)    // Agent ID
fmt.Printf("Scopes: %v\n", claims.Scopes)
```

## Action-Based Verification

Verify with action checking (enforces sensitive action policies):

```go
// Reading is allowed with ID-JAG
claims, err := verifier.VerifyForAction(ctx, token, "read:email")
// OK if token is valid

// Deleting requires AAuth (human consent)
claims, err := verifier.VerifyForAction(ctx, token, "delete:account")
if err != nil {
    // Returns error if token is ID-JAG (no human consent)
    // Error: "action 'delete:account' requires AAuth (human consent), got idjag token"
}
```

## TokenClaims

The `TokenClaims` struct contains the verified token data:

```go
type TokenClaims struct {
    Protocol  Protocol      // "idjag" or "aauth"
    Issuer    string        // Token issuer
    Subject   string        // Agent ID
    Audience  []string      // Token audience
    Scopes    []string      // Granted scopes
    ExpiresAt time.Time     // Expiration time
    IssuedAt  time.Time     // Issue time
    Actor     *ActorClaims  // Delegation info (who agent acts for)
    Raw       map[string]any // Raw claims for protocol-specific data
}

// Check if a scope is granted
if claims.HasScope("read:email") {
    // Allowed
}

// Check if any of several scopes is granted
if claims.HasAnyScope("admin", "write:*") {
    // Has elevated permissions
}
```

## Dynamic Issuer Registration

Add trusted issuers at runtime:

```go
// Add ID-JAG issuer (auto-discovers JWKS at .well-known/jwks.json)
verifier.AddIDJAGIssuer("https://new-issuer.example.com", "")

// Add AAuth issuer with explicit JWKS URL
verifier.AddAAuthIssuer("https://consent.example.com", "https://consent.example.com/jwks")
```

## HTTP Middleware

Use the verifier in HTTP middleware:

```go
func AuthMiddleware(verifier *agentauth.TokenVerifier) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract token from Authorization header
            token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
            if token == "" {
                http.Error(w, "missing authorization", http.StatusUnauthorized)
                return
            }

            // Determine action from request
            action := determineAction(r.Method, r.URL.Path)

            // Verify with action checking
            claims, err := verifier.VerifyForAction(r.Context(), token, action)
            if err != nil {
                http.Error(w, err.Error(), http.StatusForbidden)
                return
            }

            // Add claims to context
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

## Related

- [Hybrid Provider](hybrid.md) - Route to ID-JAG or AAuth based on policy
- [Policy Matching](policy.md) - Scope-based protocol routing

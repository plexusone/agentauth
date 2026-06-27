# Hybrid Provider

The `HybridProvider` routes authorization requests to the appropriate protocol (ID-JAG or AAuth) based on policy configuration.

## Overview

HybridProvider acts as a single entry point for authorization that automatically routes to:

- **ID-JAG** for automated, machine-to-machine flows
- **AAuth** for sensitive operations requiring human consent

## Configuration

```go
import "github.com/plexusone/agentauth"

config := &agentauth.Config{
    // ID-JAG provider settings
    IDJAG: &agentauth.IDJAGConfig{
        TokenEndpoint: "https://auth.example.com/token",
        Issuer:        "https://issuer.example.com",
    },

    // AAuth provider settings
    AAuth: &agentauth.AAuthConfig{
        PersonServerURL: "https://consent.example.com",
        Issuer:          "https://consent.example.com",
    },

    // Policy for protocol routing
    Policy: &agentauth.PolicyConfig{
        Default:   agentauth.ProtocolIDJAG,  // Use ID-JAG by default
        Sensitive: agentauth.ProtocolAAuth,  // Use AAuth for sensitive scopes
        Rules: map[string]agentauth.Protocol{
            "admin:*":        agentauth.ProtocolAAuth,
            "write:*":        agentauth.ProtocolAAuth,
            "delete:*":       agentauth.ProtocolAAuth,
            "read:*":         agentauth.ProtocolIDJAG,
            "list:*":         agentauth.ProtocolIDJAG,
        },
    },

    // Token cache settings
    Cache: &agentauth.CacheConfig{
        Enabled: true,
        MaxSize: 1000,
    },
}
```

## Creating the Provider

```go
provider, err := agentauth.NewHybridProvider(config,
    agentauth.WithIDJAGProvider(idjagProvider),
    agentauth.WithAAuthProvider(aauthProvider),
)
if err != nil {
    return fmt.Errorf("create hybrid provider: %w", err)
}
```

## Authorization

The `Authorize` method routes to the appropriate protocol based on requested scopes:

```go
// Read scopes route to ID-JAG (automated)
result, err := provider.Authorize(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"read:email", "read:profile"},
})
// result.Token is immediately available

// Write scopes route to AAuth (requires consent)
result, err := provider.Authorize(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"write:profile"},
})
// result may have ConsentURI if consent required
```

## Consent Flow

When AAuth is selected, handle the consent flow:

```go
result, err := provider.Authorize(ctx, &agentauth.AuthRequest{
    Scopes: []string{"delete:account"},
})

if result.ConsentRequired() {
    // Display consent URI to user
    fmt.Printf("Please approve at: %s\n", result.ConsentURI)

    // Wait for consent (blocks until approved/denied/timeout)
    finalResult, err := provider.WaitForConsent(ctx, result.StatusURI, 5*time.Minute)
    if err != nil {
        return err
    }

    // Use the token
    token := finalResult.Token
}
```

## HTTP Client

Get an authenticated HTTP client:

```go
client, err := provider.HTTPClient(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"read:data"},
})
if err != nil {
    // May require consent for sensitive scopes
    return err
}

// Client automatically adds Authorization header
resp, err := client.Get("https://api.example.com/data")
```

## Force Protocol

Override policy and force a specific protocol:

```go
// Force AAuth even for read-only scopes
result, err := provider.Authorize(ctx, &agentauth.AuthRequest{
    Scopes:        []string{"read:sensitive"},
    ForceProtocol: agentauth.ProtocolAAuth,
})
```

## Token Caching

HybridProvider caches successful authorizations:

```go
// First call fetches token
result1, _ := provider.Authorize(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"read:email"},
})

// Second call returns cached token
result2, _ := provider.Authorize(ctx, &agentauth.AuthRequest{
    Resource: "https://api.example.com",
    Scopes:   []string{"read:email"},
})

// Clear cache when needed
provider.ClearCache()
```

## Introspection

Query which provider would be used for given scopes:

```go
protocol, prov := provider.GetProviderForScopes([]string{"admin:users"})
fmt.Printf("Would use: %s\n", protocol)  // "aauth"
```

## Related

- [Token Verification](verifier.md) - Server-side token verification
- [Policy Matching](policy.md) - Scope-based protocol routing

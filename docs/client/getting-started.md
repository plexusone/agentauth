# Client SDK - Getting Started

The AgentAuth client SDK provides agents with methods to authenticate and obtain access tokens.

## Installation

```bash
go get github.com/plexusone/agentauth
```

## Creating a Client

```go
import "github.com/plexusone/agentauth/client"

// Create client with defaults
c := client.New("https://authz.example.com")

// Create client with options
c := client.New("https://authz.example.com",
    client.WithHTTPClient(customHTTPClient),
    client.WithPollInterval(2 * time.Second),
    client.WithPollTimeout(5 * time.Minute),
)
```

## Quick Start: ID-JAG Flow

For automated, machine-to-machine authorization:

```go
// Create ID-JAG assertion (signed JWT)
assertion := createIDJAGAssertion(agentPrivateKey)

// Exchange for access token
token, err := c.ExchangeIDJAG(ctx, assertion, "read:email read:profile")
if err != nil {
    return err
}

// Use the token
fmt.Printf("Access Token: %s\n", token.AccessToken)
fmt.Printf("Expires At: %s\n", token.ExpiresAt)
```

## Quick Start: AAuth Flow

For operations requiring human consent:

```go
// Request authorization
result, err := c.RequestAuthorization(ctx, &client.AuthorizationRequest{
    AgentToken:  agentToken,
    UserID:      "user-123",
    Scopes:      "write:profile",
    MissionName: "Update User Profile",
})
if err != nil {
    return err
}

switch result.Status {
case "approved":
    // Pre-authorized, use token immediately
    fmt.Printf("Token: %s\n", result.Token.AccessToken)

case "pending":
    // Human consent required
    fmt.Printf("Please approve at: %s\n", result.ConsentURI)

    // Wait for approval
    token, err := c.WaitForConsent(ctx, result.StatusURI)
    if err != nil {
        return err  // Denied, expired, or timeout
    }
    fmt.Printf("Approved! Token: %s\n", token.AccessToken)
}
```

## Token Caching

The client includes built-in token caching:

```go
// Store a token with a key
c.CacheToken("api.example.com:read", token)

// Retrieve cached token (returns nil if expired)
if cached := c.GetCachedToken("api.example.com:read"); cached != nil {
    // Use cached token
}

// Clear all cached tokens
c.ClearCache()
```

## Token Introspection

Check if a token is valid:

```go
result, err := c.Introspect(ctx, token.AccessToken)
if err != nil {
    return err
}

if result.Active {
    fmt.Printf("Token is valid for: %s\n", result.Sub)
    fmt.Printf("Scopes: %s\n", result.Scope)
} else {
    fmt.Println("Token is invalid or expired")
}
```

## Token Revocation

Invalidate a token:

```go
err := c.Revoke(ctx, token.AccessToken, "access_token")
if err != nil {
    return err
}
```

## Next Steps

- [Token Exchange](token-exchange.md) - ID-JAG and JWT bearer flows
- [Consent Flow](consent-flow.md) - AAuth consent handling

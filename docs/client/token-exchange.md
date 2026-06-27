# Token Exchange

The client SDK supports OAuth 2.0 token exchange flows for automated authorization.

## ID-JAG Token Exchange (RFC 8693)

Exchange an ID-JAG assertion for an access token:

```go
import "github.com/plexusone/agentauth/client"

c := client.New("https://authz.example.com")

// Create ID-JAG assertion
// (typically done using github.com/aistandardsio/agent-protocols/idjag)
assertion := createIDJAGAssertion()

// Exchange for access token
token, err := c.ExchangeIDJAG(ctx, assertion, "read:email read:profile")
if err != nil {
    return fmt.Errorf("token exchange failed: %w", err)
}

fmt.Printf("Access Token: %s\n", token.AccessToken)
fmt.Printf("Token Type: %s\n", token.TokenType)
fmt.Printf("Expires In: %d seconds\n", token.ExpiresIn)
fmt.Printf("Scopes: %s\n", token.Scope)
```

### Creating an ID-JAG Assertion

Use the agent-protocols library to create assertions:

```go
import "github.com/aistandardsio/agent-protocols/idjag"

// Create assertion
assertion := idjag.NewAssertion(
    "https://issuer.example.com",       // Issuer
    "agent:calendar-bot",                // Subject (agent ID)
    []string{"https://authz.example.com"}, // Audience
    5 * time.Minute,                     // Validity
)

// Add custom claims
assertion.WithClaims(map[string]any{
    "act": map[string]any{
        "sub": "user-123",  // Acting on behalf of user
    },
})

// Sign the assertion
signedAssertion, err := assertion.Sign(privateKey, "key-1")
if err != nil {
    return err
}
```

## JWT Bearer Grant (RFC 7523)

Exchange a JWT bearer assertion for an access token:

```go
// Exchange JWT bearer assertion
token, err := c.ExchangeJWTBearer(ctx, jwtAssertion, "read:data")
if err != nil {
    return err
}
```

### Creating a JWT Bearer Assertion

```go
import "github.com/golang-jwt/jwt/v5"

claims := jwt.MapClaims{
    "iss": "https://agent.example.com",
    "sub": "agent-123",
    "aud": "https://authz.example.com",
    "exp": time.Now().Add(5 * time.Minute).Unix(),
    "iat": time.Now().Unix(),
    "jti": uuid.NewString(),  // Unique ID to prevent replay
}

token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
token.Header["kid"] = "key-1"

signedToken, err := token.SignedString(privateKey)
```

## Token Structure

The returned `Token` struct:

```go
type Token struct {
    AccessToken  string    // The access token
    TokenType    string    // Usually "Bearer"
    ExpiresIn    int       // Seconds until expiration
    Scope        string    // Granted scopes
    RefreshToken string    // Optional refresh token
    ExpiresAt    time.Time // Computed expiration time
}

// Check if token is expired
if token.IsExpired() {
    // Need to refresh or get new token
}

// Check if token expires soon (within 5 minutes)
if token.IsExpiringSoon(5 * time.Minute) {
    // Proactively refresh
}
```

## Refreshing Tokens

If a refresh token is provided:

```go
newToken, err := c.RefreshToken(ctx, token.RefreshToken, "read:email")
if err != nil {
    // Refresh failed, need to re-authenticate
    return err
}
```

## Error Handling

Token exchange may fail for various reasons:

```go
token, err := c.ExchangeIDJAG(ctx, assertion, scope)
if err != nil {
    // Common errors:
    // - "invalid_grant: assertion expired"
    // - "invalid_grant: unknown issuer"
    // - "invalid_scope: requested scope not allowed"
    // - "server_error: ..."
    return err
}
```

## Best Practices

### Cache Tokens

Avoid unnecessary token exchanges by caching:

```go
cacheKey := fmt.Sprintf("%s:%s", resource, scope)

if token := c.GetCachedToken(cacheKey); token != nil {
    if !token.IsExpiringSoon(1 * time.Minute) {
        return token, nil  // Use cached
    }
}

// Exchange for new token
token, err := c.ExchangeIDJAG(ctx, assertion, scope)
if err != nil {
    return nil, err
}

c.CacheToken(cacheKey, token)
return token, nil
```

### Proactive Refresh

Refresh tokens before they expire:

```go
if token.IsExpiringSoon(5 * time.Minute) && token.RefreshToken != "" {
    newToken, err := c.RefreshToken(ctx, token.RefreshToken, "")
    if err == nil {
        c.CacheToken(cacheKey, newToken)
        return newToken, nil
    }
    // Fall through to re-authenticate if refresh fails
}
```

## Related

- [Getting Started](getting-started.md) - Client setup
- [Consent Flow](consent-flow.md) - AAuth human consent

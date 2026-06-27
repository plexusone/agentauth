# Consent Flow

The AAuth consent flow enables agents to request authorization for operations that require human approval.

## Overview

The consent flow:

1. Agent requests authorization for sensitive operation
2. Server returns consent URI if not pre-authorized
3. Human visits consent URI and approves/denies
4. Agent polls or waits for approval
5. On approval, agent receives access token

## Requesting Authorization

```go
import "github.com/plexusone/agentauth/client"

c := client.New("https://authz.example.com")

result, err := c.RequestAuthorization(ctx, &client.AuthorizationRequest{
    AgentToken:      agentToken,           // Agent's identity token
    UserID:          "user-123",           // User the agent acts for
    Scopes:          "write:profile",      // Requested scopes
    MissionName:     "Update Profile",     // Human-readable mission name
    MissionDesc:     "Change display name", // Optional description
    InteractionType: "supervised",         // supervised, autonomous, etc.
    Duration:        3600,                 // Requested duration in seconds
    RedirectURI:     "https://app.example.com/callback", // Optional
    State:           "abc123",             // Optional state parameter
})
```

## Handling the Response

The response status indicates the authorization state:

```go
switch result.Status {
case "approved":
    // Pre-authorized - token available immediately
    token := result.Token
    fmt.Printf("Token: %s\n", token.AccessToken)

case "pending":
    // Consent required - direct user to approval page
    fmt.Printf("Mission ID: %s\n", result.MissionID)
    fmt.Printf("Consent URI: %s\n", result.ConsentURI)
    fmt.Printf("Status URI: %s\n", result.StatusURI)

case "denied":
    // Authorization denied
    fmt.Println("User denied the request")

case "expired":
    // Consent request expired before user responded
    fmt.Println("Request expired")

case "error":
    // Error occurred
    fmt.Printf("Error: %s - %s\n", result.Error, result.ErrorDesc)
}
```

## Waiting for Consent

### Blocking Wait

Wait until the user approves or denies:

```go
result, err := c.RequestAuthorization(ctx, req)
if err != nil {
    return err
}

if result.Status == "pending" {
    // Display consent URL to user
    fmt.Printf("Please approve at: %s\n", result.ConsentURI)

    // Block until approved, denied, or timeout (uses client's pollTimeout)
    token, err := c.WaitForConsent(ctx, result.StatusURI)
    if err != nil {
        // "consent denied", "consent request expired", or context cancelled
        return err
    }

    fmt.Printf("Approved! Token: %s\n", token.AccessToken)
}
```

### One-Shot Convenience

Request and wait in one call:

```go
// Blocks until approved/denied/timeout
token, err := c.RequestAuthorizationAndWait(ctx, req)
if err != nil {
    return err
}

fmt.Printf("Token: %s\n", token.AccessToken)
```

### Manual Polling

Poll for status manually:

```go
if result.Status == "pending" {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            status, err := c.PollConsentStatus(ctx, result.StatusURI)
            if err != nil {
                return err
            }

            switch status.Status {
            case "approved":
                return status.Token, nil
            case "denied":
                return nil, fmt.Errorf("denied")
            case "expired":
                return nil, fmt.Errorf("expired")
            case "pending":
                // Continue polling
            }
        }
    }
}
```

## Poll Settings

Configure polling behavior:

```go
c := client.New("https://authz.example.com",
    // How often to poll (default: 2s)
    client.WithPollInterval(2 * time.Second),

    // Max time to wait for consent (default: 5m)
    client.WithPollTimeout(10 * time.Minute),
)
```

## Mission Types

The `InteractionType` field indicates the nature of the mission:

| Type | Description |
|------|-------------|
| `supervised` | Agent operates with human oversight |
| `autonomous` | Agent operates independently |
| `collaborative` | Agent works alongside human |
| `one-time` | Single action, consent expires after use |

```go
req := &client.AuthorizationRequest{
    InteractionType: "autonomous",
    Duration:        86400, // 24 hours for autonomous operation
}
```

## User Experience

### Displaying Consent Information

Show the user what they're approving:

```go
if result.Status == "pending" {
    fmt.Println("=== Authorization Required ===")
    fmt.Printf("Agent: %s\n", agentName)
    fmt.Printf("Mission: %s\n", req.MissionName)
    fmt.Printf("Description: %s\n", req.MissionDesc)
    fmt.Printf("Scopes: %s\n", req.Scopes)
    fmt.Printf("Duration: %d seconds\n", req.Duration)
    fmt.Println()
    fmt.Printf("Approve at: %s\n", result.ConsentURI)
}
```

### QR Code for Mobile

Display QR code for mobile approval:

```go
import "github.com/mdp/qrterminal/v3"

if result.Status == "pending" {
    fmt.Println("Scan to approve:")
    qrterminal.Generate(result.ConsentURI, qrterminal.L, os.Stdout)
}
```

## Error Handling

Common consent flow errors:

```go
token, err := c.WaitForConsent(ctx, statusURI)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "consent denied"):
        // User explicitly denied
        return nil, ErrUserDenied

    case strings.Contains(err.Error(), "expired"):
        // Consent request timed out
        return nil, ErrConsentExpired

    case errors.Is(err, context.DeadlineExceeded):
        // Client-side timeout
        return nil, ErrPollTimeout

    default:
        return nil, err
    }
}
```

## Related

- [Getting Started](getting-started.md) - Client setup
- [Token Exchange](token-exchange.md) - Automated flows

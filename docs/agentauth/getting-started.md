# Getting Started with AgentAuth

This guide covers installation and basic usage of the AgentAuth package.

## Package Options

AgentAuth provides two approaches:

| Package | Storage | Use Case |
|---------|---------|----------|
| `agentauth/*` | Built-in SQLite | Quick start, development, simple deployments |
| `aauth/personserver` + `idjag/authzserver` | Interface-based | Custom storage (DynamoDB, PostgreSQL, etc.) |

For interface-based packages, see:

- [aauth/personserver](../../aauth/personserver/) - AAuth Person Server with `Store` interface
- [idjag/authzserver](../../idjag/authzserver/) - ID-JAG Authorization Server with `Store` interface
- [plexusone/agentauth/store](https://github.com/plexusone/agentauth) - Storage implementations (SQLite, DynamoDB)

## Installation

```bash
go get github.com/aistandardsio/agent-protocols/agentauth
```

For interface-based packages with storage:

```bash
go get github.com/aistandardsio/agent-protocols/aauth/personserver
go get github.com/aistandardsio/agent-protocols/idjag/authzserver
go get github.com/plexusone/agentauth/store
```

## Quick Start (SQLite)

### Running the Server

The fastest way to get started is using the CLI server:

```bash
# Run with in-memory database (development)
go run ./cmd/agentauth-server

# Run with persistent SQLite storage
go run ./cmd/agentauth-server --db ./agentauth.db

# Run with custom port
go run ./cmd/agentauth-server --port 9000 --db ./agentauth.db
```

### Server Endpoints

Once running, the server exposes:

| Endpoint | Description |
|----------|-------------|
| `http://localhost:8080/.well-known/aauth-configuration` | AAuth discovery |
| `http://localhost:8080/.well-known/jwks.json` | Public keys |
| `http://localhost:8080/aauth/authorize` | Authorization request |
| `http://localhost:8080/aauth/consent/{id}` | Consent page |
| `http://localhost:8080/oauth/token` | Token exchange |

### Testing the Server

```bash
# Check discovery endpoint
curl http://localhost:8080/.well-known/aauth-configuration | jq

# Check JWKS endpoint
curl http://localhost:8080/.well-known/jwks.json | jq
```

## Using the Client SDK

### ID-JAG Token Exchange

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/aistandardsio/agent-protocols/agentauth/client"
)

func main() {
    ctx := context.Background()
    c := client.New("http://localhost:8080")

    // Exchange an ID-JAG assertion for an access token
    token, err := c.ExchangeIDJAG(ctx, idJagAssertion, "read:email read:profile")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Access token:", token.AccessToken)
    fmt.Println("Expires in:", token.ExpiresIn, "seconds")
}
```

### AAuth Authorization (Human Consent)

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/aistandardsio/agent-protocols/agentauth/client"
)

func main() {
    ctx := context.Background()
    c := client.New("http://localhost:8080/aauth")

    // Request authorization that may require human consent
    result, err := c.RequestAuthorization(ctx, &client.AuthorizationRequest{
        AgentToken:  agentToken,
        UserID:      "user-123",
        Scopes:      "write:profile",
        MissionName: "Update Profile",
    })
    if err != nil {
        log.Fatal(err)
    }

    switch result.Status {
    case "approved":
        // Immediate approval (pre-authorized)
        fmt.Println("Token:", result.Token.AccessToken)

    case "pending":
        // User needs to approve
        fmt.Println("Please approve at:", result.ConsentURI)

        // Wait for approval (with timeout)
        token, err := c.WaitForConsent(ctx, result.StatusURI)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("Token:", token.AccessToken)
    }
}
```

### Combined Request and Wait

For simpler code, use `RequestAuthorizationAndWait`:

```go
// Request authorization and automatically wait for consent if needed
token, err := c.RequestAuthorizationAndWait(ctx, &client.AuthorizationRequest{
    AgentToken:  agentToken,
    UserID:      "user-123",
    Scopes:      "write:profile",
    MissionName: "Update Profile",
})
if err != nil {
    log.Fatal(err)
}
fmt.Println("Token:", token.AccessToken)
```

## Embedding with Interface-Based Packages

For production deployments with custom storage, use the interface-based packages:

### Basic Server Setup

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "log"
    "net/http"
    "time"

    "github.com/aistandardsio/agent-protocols/aauth/personserver"
    "github.com/aistandardsio/agent-protocols/idjag/authzserver"
    "github.com/plexusone/agentauth/store"
)

func main() {
    // Create SQLite store
    sqliteStore, err := store.NewSQLite("agentauth.db")
    if err != nil {
        log.Fatal(err)
    }
    defer sqliteStore.Close()

    // Create adapters for both server types
    psStore := store.NewPersonServerAdapter(sqliteStore)
    asStore := store.NewAuthzServerAdapter(sqliteStore)

    // Generate signing key
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    keyID := "key-1"
    issuer := "http://localhost:8080"

    // Create Person Server (AAuth)
    ps, err := personserver.New(psStore, issuer, privateKey, keyID,
        personserver.WithTokenTTL(2*time.Hour),
        personserver.WithMissionTimeout(15*time.Minute),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create Authorization Server (ID-JAG)
    as, err := authzserver.New(asStore, issuer, privateKey, keyID,
        authzserver.WithTokenTTL(time.Hour),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Register handlers
    mux := http.NewServeMux()

    // AAuth endpoints under /aauth
    psMux := http.NewServeMux()
    ps.RegisterHandlers(psMux)
    mux.Handle("/aauth/", http.StripPrefix("/aauth", psMux))

    // ID-JAG endpoints under /oauth
    asMux := http.NewServeMux()
    as.RegisterHandlers(asMux)
    mux.Handle("/oauth/", http.StripPrefix("/oauth", asMux))

    // Shared discovery and JWKS
    mux.HandleFunc("/.well-known/aauth-configuration", ps.HandleMetadata)
    mux.HandleFunc("/.well-known/jwks.json", as.HandleJWKS)

    log.Println("Server running at http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Seeding Demo Data

For development, you can seed demo users and agents:

```go
import "github.com/plexusone/agentauth/store"

func seedDemoData(s *store.SQLiteStore) error {
    ctx := context.Background()

    // Create demo user
    user := &store.User{
        ID:    "demo-user",
        Email: "demo@example.com",
        Name:  "Demo User",
    }
    if err := s.CreateUser(ctx, user); err != nil {
        return err
    }

    // Create demo agent
    agent := &store.Agent{
        ID:          "demo-agent",
        Name:        "Demo Agent",
        Description: "A demo AI agent",
    }
    if err := s.CreateAgent(ctx, agent); err != nil {
        return err
    }

    // Pre-authorize agent for certain scopes (skips consent flow)
    preAuth := &store.PreAuthorization{
        UserID:  "demo-user",
        AgentID: "demo-agent",
        Scopes:  "read:* chat:*",
    }
    if err := s.CreatePreAuthorization(ctx, preAuth); err != nil {
        return err
    }

    return nil
}
```

## Next Steps

- [Deployment](deployment.md) - Deploy to AWS Lambda
- [Integration](integration.md) - Integrate with OmniAgent
- [API Reference](api-reference.md) - Full endpoint documentation

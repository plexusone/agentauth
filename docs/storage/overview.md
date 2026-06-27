# Storage Overview

AgentAuth provides pluggable storage backends for persisting users, agents, missions, tokens, and audit logs.

## Storage Interface

The `Storer` interface defines the storage contract:

```go
type Storer interface {
    // User management
    CreateUser(ctx context.Context, user *User) error
    GetUser(ctx context.Context, id string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    UpdateUser(ctx context.Context, user *User) error
    DeleteUser(ctx context.Context, id string) error

    // Agent management
    CreateAgent(ctx context.Context, agent *Agent) error
    GetAgent(ctx context.Context, id string) (*Agent, error)
    ListAgents(ctx context.Context, opts ListOptions) ([]*Agent, error)
    UpdateAgent(ctx context.Context, agent *Agent) error
    DeleteAgent(ctx context.Context, id string) error

    // Mission management (AAuth)
    CreateMission(ctx context.Context, mission *Mission) error
    GetMission(ctx context.Context, id string) (*Mission, error)
    UpdateMission(ctx context.Context, mission *Mission) error

    // Token management
    StoreToken(ctx context.Context, token *Token) error
    GetToken(ctx context.Context, id string) (*Token, error)
    RevokeToken(ctx context.Context, id string) error

    // Pre-authorization
    CreatePreAuthorization(ctx context.Context, preAuth *PreAuthorization) error
    GetPreAuthorization(ctx context.Context, userID, agentID string) (*PreAuthorization, error)

    // Audit logging
    LogAudit(ctx context.Context, entry *AuditLog) error

    // Lifecycle
    Close() error
}
```

## Storage Backends

### SQLite

Best for development and single-instance deployments:

```go
import "github.com/plexusone/agentauth/store"

// Create SQLite store
db, err := store.NewSQLite("agentauth.db")
if err != nil {
    log.Fatal(err)
}
defer db.Close()

// Use in-memory for testing
db, err := store.NewSQLite(":memory:")
```

### DynamoDB

Best for production serverless deployments:

```go
import "github.com/plexusone/agentauth/store"

// Create DynamoDB store
db, err := store.NewDynamoDB(ctx, store.DynamoDBConfig{
    TableName: "agentauth",
    Region:    "us-west-2",
})
if err != nil {
    log.Fatal(err)
}
```

DynamoDB table schema:

| Attribute | Type | Description |
|-----------|------|-------------|
| `PK` | String | Partition key (e.g., `USER#123`) |
| `SK` | String | Sort key (e.g., `METADATA`) |
| `GSI1PK` | String | Global secondary index PK |
| `GSI1SK` | String | Global secondary index SK |
| `Data` | Map | Entity data |
| `TTL` | Number | Expiration timestamp |

## Server Adapters

Adapters connect storage to agent-protocols interface packages:

### PersonServer Adapter

```go
import (
    "github.com/aistandardsio/agent-protocols/aauth/personserver"
    "github.com/plexusone/agentauth/store"
)

// Create adapter
sqliteStore, _ := store.NewSQLite("agentauth.db")
psStore := store.NewPersonServerAdapter(sqliteStore)

// Use with PersonServer
ps, err := personserver.New(psStore, issuer, privateKey, keyID)
```

### AuthzServer Adapter

```go
import (
    "github.com/aistandardsio/agent-protocols/idjag/authzserver"
    "github.com/plexusone/agentauth/store"
)

// Create adapter
sqliteStore, _ := store.NewSQLite("agentauth.db")
asStore := store.NewAuthzServerAdapter(sqliteStore)

// Use with AuthzServer
as, err := authzserver.New(asStore, issuer, privateKey, keyID)
```

## Data Types

### User

```go
type User struct {
    ID        string    `json:"id"`
    Email     string    `json:"email"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### Agent

```go
type Agent struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    PublicKey   string    `json:"public_key,omitempty"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

### Mission

```go
type Mission struct {
    ID              string    `json:"id"`
    AgentID         string    `json:"agent_id"`
    UserID          string    `json:"user_id"`
    Name            string    `json:"name"`
    Description     string    `json:"description"`
    Scopes          string    `json:"scopes"`
    Status          string    `json:"status"` // pending, approved, denied
    InteractionType string    `json:"interaction_type"`
    CreatedAt       time.Time `json:"created_at"`
    ExpiresAt       time.Time `json:"expires_at"`
}
```

### Token

```go
type Token struct {
    ID        string    `json:"id"`
    UserID    string    `json:"user_id"`
    AgentID   string    `json:"agent_id"`
    MissionID string    `json:"mission_id,omitempty"`
    Scopes    string    `json:"scopes"`
    IssuedAt  time.Time `json:"issued_at"`
    ExpiresAt time.Time `json:"expires_at"`
    Revoked   bool      `json:"revoked"`
}
```

### PreAuthorization

```go
type PreAuthorization struct {
    UserID    string    `json:"user_id"`
    AgentID   string    `json:"agent_id"`
    Scopes    string    `json:"scopes"` // Wildcard patterns: "read:*"
    CreatedAt time.Time `json:"created_at"`
    ExpiresAt time.Time `json:"expires_at,omitempty"`
}
```

## Usage Example

```go
package main

import (
    "context"
    "log"

    "github.com/plexusone/agentauth/store"
)

func main() {
    ctx := context.Background()

    // Create store
    db, err := store.NewSQLite("agentauth.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create user
    user := &store.User{
        ID:    "user-123",
        Email: "alice@example.com",
        Name:  "Alice",
    }
    if err := db.CreateUser(ctx, user); err != nil {
        log.Fatal(err)
    }

    // Create agent
    agent := &store.Agent{
        ID:          "research-agent",
        Name:        "Research Assistant",
        Description: "Helps with research tasks",
    }
    if err := db.CreateAgent(ctx, agent); err != nil {
        log.Fatal(err)
    }

    // Pre-authorize agent for read scopes
    preAuth := &store.PreAuthorization{
        UserID:  "user-123",
        AgentID: "research-agent",
        Scopes:  "read:*",
    }
    if err := db.CreatePreAuthorization(ctx, preAuth); err != nil {
        log.Fatal(err)
    }
}
```

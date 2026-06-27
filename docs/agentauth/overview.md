# AgentAuth Overview

AgentAuth is a unified authorization layer for AI agents that combines two complementary protocols:

- **ID-JAG** (Identity Assertion Authorization Grant) - Automated, policy-based authorization via RFC 8693 token exchange
- **AAuth** (Agent Authorization) - Human-in-the-loop consent for sensitive operations

## Package Structure

| Package | Description |
|---------|-------------|
| `agentauth/` | Self-contained with SQLite storage (quick start) |
| `aauth/personserver/` | Interface-based AAuth Person Server |
| `idjag/authzserver/` | Interface-based ID-JAG Authorization Server |

For custom storage backends (DynamoDB, PostgreSQL, etc.), use the interface-based packages. See [Getting Started](getting-started.md) for details.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           AgentAuth Server              │
                    │                                         │
┌─────────┐        │  ┌─────────────┐   ┌─────────────┐      │        ┌─────────────┐
│  Agent  │───────>│  │ PersonServer│   │ AuthzServer │      │───────>│  Resource   │
│         │        │  │  (AAuth)    │   │  (ID-JAG)   │      │        │   Server    │
└─────────┘        │  └─────────────┘   └─────────────┘      │        └─────────────┘
     │             │          │                 │             │
     │             │          └────────┬────────┘             │
     │             │                   │                      │
     │             │         ┌─────────┴─────────┐            │
     │             │         │   Shared Store    │            │
     │             │         │ (SQLite/DynamoDB) │            │
     │             │         └───────────────────┘            │
     │             └─────────────────────────────────────────┘
     │
     │ Consent
     v
┌─────────┐
│  Human  │
└─────────┘
```

## Key Concepts

### Person Server (AAuth Protocol)

The Person Server handles human consent for agent operations:

1. **Agent requests authorization** - Agent submits scope request with user ID
2. **Consent flow** - User is presented with consent page
3. **Token issuance** - Upon approval, access token is issued

```
POST /aauth/authorize
{
  "agent_token": "eyJ...",
  "user_id": "user-123",
  "scope": "write:profile read:email",
  "mission_name": "Update User Profile"
}
```

### Authorization Server (ID-JAG Protocol)

The Authorization Server handles automated token exchange:

1. **Agent presents ID-JAG assertion** - JWT from identity provider
2. **Policy evaluation** - Server checks scope policies
3. **Token exchange** - Access token issued per RFC 8693

```
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<id-jag-assertion>
&scope=read:data
```

### Policy-Based Routing

Scope policies determine which protocol handles each request:

| Pattern | Protocol | Use Case |
|---------|----------|----------|
| `read:*` | ID-JAG | Read-only operations (auto-approved) |
| `write:*` | AAuth | Write operations (human consent) |
| `admin:*` | AAuth | Admin operations (human consent) |

## Components

| Component | Description |
|-----------|-------------|
| **PersonServer** | AAuth Person Server with consent UI |
| **AuthzServer** | ID-JAG Authorization Server with policy routing |
| **Store** | Shared SQLite/DynamoDB storage |
| **Client SDK** | Go client for agents |

## Deployment Options

| Option | Use Case |
|--------|----------|
| **Local Development** | Single binary with SQLite |
| **AWS Lambda** | Serverless with DynamoDB |
| **Kubernetes** | Container deployment |

## Token Types

### Access Token

Issued after successful authorization:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": ["https://api.example.com"],
  "scope": "read:profile write:profile",
  "exp": 1234567890,
  "iat": 1234564290,
  "jti": "token-uuid"
}
```

### Mission (AAuth)

A mission represents a pending authorization request:

```json
{
  "id": "mission-uuid",
  "agent_id": "agent-123",
  "user_id": "user-123",
  "name": "Update Profile",
  "description": "Agent requests permission to update your profile",
  "scopes": "write:profile",
  "status": "pending",
  "interaction_type": "supervised"
}
```

## Next Steps

- [Getting Started](getting-started.md) - Quick start guide
- [Deployment](deployment.md) - Deployment options
- [Integration](integration.md) - OmniAgent integration
- [API Reference](api-reference.md) - Endpoint documentation

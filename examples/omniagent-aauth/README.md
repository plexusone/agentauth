# OmniAgent + AAuth End-to-End Demo

This demo shows how to integrate OmniAgent with the AIStandardsIO PeopleServer for AAuth-based authorization.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           User/Client                                │
│                                                                     │
│  1. Request chat completion with AAuth token                        │
│     Authorization: Bearer <aauth-jwt>                               │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         OmniAgent                                   │
│                      localhost:8080                                  │
│                                                                     │
│  • Validates AAuth JWT via JWKS                                     │
│  • Extracts user/agent claims                                       │
│  • Processes chat request                                           │
└─────────────────────────────────────────────────────────────────────┘
                                │
          Token validation via JWKS fetch
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│               AIStandardsIO PeopleServer                            │
│                      localhost:8888                                  │
│                                                                     │
│  Endpoints:                                                         │
│  • /.well-known/aauth-configuration  (discovery)                    │
│  • /.well-known/jwks.json            (public keys)                  │
│  • /aauth/authorize                   (request authorization)       │
│  • /aauth/consent/{id}                (user consent page)           │
│  • /aauth/consent/status/{id}         (poll for approval)           │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. Go 1.21+
2. OmniAgent installed: `go install github.com/plexusone/omniagent/cmd/omniagent@latest`
3. An LLM API key (OpenAI, Anthropic, etc.)

## Running the Demo

### Step 1: Start the PeopleServer

```bash
# From the agent-protocols directory
go run ./examples/omniagent-aauth/peopleserver/main.go
```

This starts the PeopleServer at `http://localhost:8888` with:
- Demo user: `demo@example.com`
- Demo agent: `omniagent`
- Scope policies:
  - `read:*` → auto-approved via ID-JAG
  - `write:*` → requires human consent via AAuth

### Step 2: Get an AAuth Token

The demo PeopleServer exposes an endpoint to get a test token:

```bash
# Get a pre-authorized token for read scopes
# Note: Pre-authorization uses exact scope matching, so request "read:*" not "read:chat"
curl -X POST http://localhost:8888/aauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "agent_token": "omniagent",
    "user_id": "demo-user",
    "scope": "read:*"
  }'
```

This returns an immediate token because `read:*` is pre-authorized for the demo agent.

For write scopes, you'll need to approve via the consent page:

```bash
# Request authorization for write scope
curl -X POST http://localhost:8888/aauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "agent_token": "omniagent",
    "user_id": "demo-user",
    "scope": "write:profile",
    "mission_name": "Update Profile"
  }'

# Response includes consent_uri - open in browser to approve
# Then poll status_uri for the token
```

### Step 3: Start OmniAgent with AAuth

```bash
# Set environment variables for AAuth
export AUTH_AAUTH_ENABLED=true
export AUTH_AAUTH_ISSUER=http://localhost:8888
export AUTH_AAUTH_AUDIENCE=http://localhost:8080

# Set your LLM provider
export OPENAI_API_KEY=your-api-key  # or other provider

# Start OmniAgent
omniagent openai serve --address :8080 --web-ui
```

### Step 4: Make Authenticated Requests

```bash
# Use the AAuth token from Step 2
TOKEN="<your-aauth-jwt>"

# Make a chat completion request
curl http://localhost:8080/openai/v1/chat/completions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Environment Variables

### PeopleServer (this demo)

| Variable | Description | Default |
|----------|-------------|---------|
| `PEOPLESERVER_ADDRESS` | Server listen address | `:8888` |
| `PEOPLESERVER_DB` | SQLite database path | `:memory:` |

### OmniAgent

| Variable | Description | Required |
|----------|-------------|----------|
| `AUTH_AAUTH_ENABLED` | Enable AAuth validation | Yes |
| `AUTH_AAUTH_ISSUER` | PeopleServer URL | Yes |
| `AUTH_AAUTH_AUDIENCE` | Expected audience (this server) | Recommended |
| `AUTH_AAUTH_JWKS_URL` | Custom JWKS URL | No (defaults to issuer) |

## Flow Diagram

```
┌──────────┐     ┌──────────────┐     ┌─────────────┐
│  Agent   │     │ PeopleServer │     │    User     │
└────┬─────┘     └──────┬───────┘     └──────┬──────┘
     │                  │                    │
     │ POST /authorize  │                    │
     │─────────────────>│                    │
     │                  │                    │
     │ 202 Accepted     │                    │
     │ consent_uri      │                    │
     │<─────────────────│                    │
     │                  │                    │
     │                  │  Visit consent_uri │
     │                  │<───────────────────│
     │                  │                    │
     │                  │  Show consent page │
     │                  │───────────────────>│
     │                  │                    │
     │                  │  Approve           │
     │                  │<───────────────────│
     │                  │                    │
     │ Poll status_uri  │                    │
     │─────────────────>│                    │
     │                  │                    │
     │ Access Token     │                    │
     │<─────────────────│                    │
     │                  │                    │
     │ Use token with OmniAgent             │
     │──────────────────────────────────────>│
```

## Security Considerations

1. **Token Validation**: OmniAgent validates tokens via JWKS - no shared secrets needed
2. **Audience Claim**: Set `AUTH_AAUTH_AUDIENCE` to prevent token reuse across services
3. **Scope-Based Access**: Use scopes to control what operations the token allows
4. **Token Expiry**: AAuth tokens have short expiry (default 1 hour)

## Next Steps

- Add Lambda deployment for PeopleServer (see `lambda/` directory)
- Configure additional scope policies
- Integrate with real identity providers (Zitadel, Okta, etc.)

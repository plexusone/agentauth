# AgentAuth API Reference

This document describes the HTTP endpoints exposed by AgentAuth servers.

## Person Server Endpoints (AAuth)

### Discovery

#### GET /.well-known/aauth-configuration

Returns AAuth server metadata.

**Response:**

```json
{
  "issuer": "http://localhost:8080",
  "authorization_endpoint": "http://localhost:8080/aauth/authorize",
  "token_endpoint": "http://localhost:8080/aauth/token",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "consent_endpoint": "http://localhost:8080/aauth/consent",
  "scopes_supported": ["read:*", "write:*"],
  "response_types_supported": ["token"],
  "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"]
}
```

#### GET /.well-known/jwks.json

Returns the JSON Web Key Set for token verification.

**Response:**

```json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "kid": "key-1",
      "use": "sig",
      "alg": "ES256"
    }
  ]
}
```

### Authorization

#### POST /aauth/authorize

Request authorization for an agent to act on behalf of a user.

**Request:**

```json
{
  "agent_token": "agent-identifier",
  "user_id": "user-123",
  "scope": "read:profile write:profile",
  "mission_name": "Update Profile",
  "mission_description": "Agent requests permission to update your profile",
  "interaction_type": "supervised"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_token` | string | Yes | Agent identifier or JWT |
| `user_id` | string | Yes | User to request authorization from |
| `scope` | string | Yes | Space-separated scopes |
| `mission_name` | string | No | Human-readable mission name |
| `mission_description` | string | No | Detailed description |
| `interaction_type` | string | No | `autonomous`, `supervised`, `collaborative` |

**Response (pending consent):**

```json
{
  "status": "pending",
  "mission_id": "mission-uuid",
  "consent_uri": "http://localhost:8080/aauth/consent/mission-uuid",
  "status_uri": "http://localhost:8080/aauth/consent/status/mission-uuid"
}
```

**Response (pre-authorized):**

```json
{
  "status": "approved",
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "read:profile write:profile"
}
```

### Consent

#### GET /aauth/consent/{mission_id}

Returns the consent page HTML for human approval.

**Response:** HTML page with approve/deny buttons.

#### POST /aauth/consent/{mission_id}

Submit consent decision.

**Request (form data):**

```
decision=approve
```

Or:

```
decision=deny&reason=Not authorized for this action
```

**Response:** Redirect to status page or JSON confirmation.

#### GET /aauth/consent/status/{mission_id}

Poll for consent status.

**Response (pending):**

```json
{
  "status": "pending"
}
```

**Response (approved):**

```json
{
  "status": "approved",
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "read:profile"
}
```

**Response (denied):**

```json
{
  "status": "denied",
  "reason": "User declined the request"
}
```

### Token Management

#### POST /aauth/token

Token endpoint (RFC 8693 token exchange).

**Request (form data):**

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<id-jag-assertion>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=read:profile
```

**Response:**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "read:profile"
}
```

#### POST /aauth/revoke

Revoke a token.

**Request (form data):**

```
token=<access_token>
&token_type_hint=access_token
```

**Response:** 200 OK (empty body)

## Authorization Server Endpoints (ID-JAG)

### Discovery

#### GET /.well-known/oauth-authorization-server

Returns OAuth 2.0 authorization server metadata.

**Response:**

```json
{
  "issuer": "http://localhost:8080",
  "token_endpoint": "http://localhost:8080/oauth/token",
  "introspection_endpoint": "http://localhost:8080/oauth/introspect",
  "revocation_endpoint": "http://localhost:8080/oauth/revoke",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"]
}
```

### Token Exchange

#### POST /oauth/token

Exchange an ID-JAG assertion for an access token (RFC 8693).

**Request (form data):**

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<id-jag-assertion>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&scope=read:data
&audience=https://api.example.com
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | Must be `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Yes | ID-JAG assertion JWT |
| `subject_token_type` | Yes | Must be `urn:ietf:params:oauth:token-type:jwt` |
| `scope` | No | Requested scopes |
| `audience` | No | Target audience |

**Response:**

```json
{
  "access_token": "eyJ...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read:data"
}
```

### Token Introspection

#### POST /oauth/introspect

Introspect a token (RFC 7662).

**Request (form data):**

```
token=<access_token>
&token_type_hint=access_token
```

**Response (active):**

```json
{
  "active": true,
  "sub": "user-123",
  "iss": "http://localhost:8080",
  "scope": "read:data",
  "exp": 1234567890,
  "iat": 1234564290,
  "client_id": "agent-456"
}
```

**Response (inactive):**

```json
{
  "active": false
}
```

### Token Revocation

#### POST /oauth/revoke

Revoke a token (RFC 7009).

**Request (form data):**

```
token=<access_token>
&token_type_hint=access_token
```

**Response:** 200 OK (empty body)

### Policy Evaluation

#### POST /oauth/policy/evaluate

Evaluate scope policy to determine which protocol to use.

**Request:**

```json
{
  "agent_id": "agent-123",
  "scopes": ["read:profile", "write:profile"]
}
```

**Response:**

```json
{
  "protocol": "aauth",
  "allowed_scopes": ["read:profile", "write:profile"],
  "interaction_type": "supervised",
  "requires_consent": true
}
```

## Error Responses

All endpoints return errors in this format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable description"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `invalid_token` | 401 | Token is invalid or expired |
| `invalid_grant` | 400 | Invalid authorization grant |
| `unauthorized_client` | 401 | Client not authorized |
| `access_denied` | 403 | User denied consent |
| `unsupported_grant_type` | 400 | Grant type not supported |
| `invalid_scope` | 400 | Requested scope is invalid |
| `server_error` | 500 | Internal server error |

## Token Claims

### Access Token

```json
{
  "iss": "http://localhost:8080",
  "sub": "user-123",
  "aud": ["https://api.example.com"],
  "exp": 1234567890,
  "iat": 1234564290,
  "nbf": 1234564290,
  "jti": "token-uuid",
  "scope": "read:profile write:profile",
  "client_id": "agent-456",
  "agent_id": "agent-456",
  "mission_id": "mission-uuid",
  "act": {
    "sub": "agent-456"
  }
}
```

| Claim | Description |
|-------|-------------|
| `iss` | Token issuer |
| `sub` | Subject (user ID) |
| `aud` | Intended audience |
| `exp` | Expiration time |
| `iat` | Issued at time |
| `jti` | Unique token ID |
| `scope` | Granted scopes |
| `client_id` | Agent/client ID |
| `agent_id` | Agent ID (AAuth) |
| `mission_id` | Mission ID (AAuth) |
| `act` | Actor claim (delegation) |

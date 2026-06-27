# AgentAuth Deployment

This guide covers deployment options for AgentAuth servers.

## Deployment Options

| Option | Storage | Use Case |
|--------|---------|----------|
| **Local Binary** | SQLite | Development, testing |
| **AWS Lambda** | DynamoDB | Production serverless |
| **Container** | SQLite/DynamoDB | Kubernetes, ECS |

## Local Development

### Using the CLI

```bash
# Run with default settings
go run ./cmd/agentauth-server

# Run with persistent storage
go run ./cmd/agentauth-server --db ./agentauth.db --seed-demo

# Custom configuration
go run ./cmd/agentauth-server \
  --port 9000 \
  --db ./agentauth.db \
  --issuer https://auth.example.com
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PEOPLESERVER_ISSUER` | Token issuer URL | `http://localhost:8080` |
| `PEOPLESERVER_PORT` | Server port | `8080` |
| `PEOPLESERVER_DB` | SQLite database path | `:memory:` |
| `SEED_DEMO_DATA` | Seed demo user/agent | `false` |

## AWS Lambda Deployment

The Lambda deployment uses:

- **API Gateway** (HTTP API) - Request routing
- **Lambda** (ARM64) - Serverless compute
- **DynamoDB** - Persistent storage

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AWS Cloud                                  │
│                                                                     │
│  ┌──────────────────┐     ┌─────────────────────────────────────┐  │
│  │  API Gateway     │     │       Lambda Function               │  │
│  │  (HTTP API)      │────>│       PeopleServer                  │  │
│  │                  │     │                                     │  │
│  │  /aauth/*        │     │  - AAuth authorization              │  │
│  │  /oauth/*        │     │  - Consent flow                     │  │
│  │  /.well-known/*  │     │  - Token issuance                   │  │
│  └──────────────────┘     └──────────────┬──────────────────────┘  │
│                                          │                          │
│  ┌───────────────────────────────────────┴──────────────────────┐  │
│  │                      DynamoDB Tables                          │  │
│  │  users | agents | missions | tokens | policies               │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Prerequisites

- AWS CLI configured
- AWS SAM CLI installed
- Go 1.21+
- Make

### Quick Deployment

```bash
cd lambda/peopleserver

# Build
make build

# Deploy to dev environment
make deploy

# Deploy to production
ENVIRONMENT=prod make deploy
```

### Custom Domain Deployment

```bash
# Deploy with custom domain
ENVIRONMENT=prod \
DOMAIN_NAME=auth.example.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/xxx \
make deploy-domain
```

After deployment, create a Route 53 alias record pointing to the API Gateway domain.

### SAM Template Configuration

The `template.yaml` defines:

```yaml
Parameters:
  Environment:
    Type: String
    Default: dev
  DomainName:
    Type: String
    Default: ""
  CertificateArn:
    Type: String
    Default: ""

Resources:
  PeopleServerFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: bootstrap
      Runtime: provided.al2023
      Architectures: [arm64]
      MemorySize: 256
      Timeout: 30
      Environment:
        Variables:
          PEOPLESERVER_ISSUER: !Sub "https://${ServerlessHttpApi}.execute-api.${AWS::Region}.amazonaws.com"
          USE_DYNAMODB: "true"

  # DynamoDB Tables
  UsersTable:
    Type: AWS::DynamoDB::Table
  AgentsTable:
    Type: AWS::DynamoDB::Table
  MissionsTable:
    Type: AWS::DynamoDB::Table
  TokensTable:
    Type: AWS::DynamoDB::Table
  PoliciesTable:
    Type: AWS::DynamoDB::Table
```

### Environment Variables (Lambda)

| Variable | Description | Required |
|----------|-------------|----------|
| `PEOPLESERVER_ISSUER` | Token issuer URL | Yes |
| `PEOPLESERVER_TABLE_PREFIX` | DynamoDB table prefix | No |
| `PEOPLESERVER_SIGNING_KEY_ARN` | KMS key ARN for signing | No |
| `SEED_DEMO_DATA` | Seed demo user/agent | No |
| `USE_DYNAMODB` | Use DynamoDB store | Yes |

### Local Testing with SAM

```bash
cd lambda/peopleserver

# Start local API Gateway
make local

# In another terminal, test the API
curl http://localhost:8888/health
curl http://localhost:8888/.well-known/aauth-configuration
```

### Viewing Logs

```bash
make logs
```

### Cleanup

```bash
make delete
```

## DynamoDB Storage

### Build with DynamoDB Support

```bash
# Build with DynamoDB store
go build -tags dynamodb ./...
```

### DynamoDB Table Schema

**Users Table:**

| Attribute | Type | Key |
|-----------|------|-----|
| `id` | String | Partition Key |
| `email` | String | GSI |
| `name` | String | |
| `created_at` | Number | |

**Missions Table:**

| Attribute | Type | Key |
|-----------|------|-----|
| `id` | String | Partition Key |
| `status` | String | GSI |
| `user_id` | String | GSI |
| `agent_id` | String | |
| `scopes` | String | |
| `expires_at` | Number | |

### Using DynamoDB Store Programmatically

```go
//go:build dynamodb

import "github.com/aistandardsio/agent-protocols/agentauth"

func main() {
    store, err := agentauth.NewDynamoDBStore(ctx,
        agentauth.WithTablePrefix("myapp"),
        agentauth.WithRegion("us-east-1"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    // Use store with Person Server
    ps, _ := personserver.New(store, issuer, privateKey, keyID)
}
```

## Container Deployment

### Dockerfile

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o agentauth-server ./cmd/agentauth-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/agentauth-server .
EXPOSE 8080
CMD ["./agentauth-server"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  agentauth:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PEOPLESERVER_ISSUER=http://localhost:8080
      - PEOPLESERVER_DB=/data/agentauth.db
      - SEED_DEMO_DATA=true
    volumes:
      - ./data:/data
```

## Production Considerations

### Signing Keys

For production, use AWS KMS:

```bash
# Create KMS key
aws kms create-key --description "AgentAuth signing key"

# Set environment variable
export PEOPLESERVER_SIGNING_KEY_ARN=arn:aws:kms:us-east-1:123456789012:key/xxx
```

### Security

1. **TLS** - Always use HTTPS in production
2. **CORS** - Configure allowed origins
3. **WAF** - Consider AWS WAF for API Gateway
4. **IAM** - Use least-privilege policies

### Monitoring

1. **CloudWatch Logs** - Lambda logs automatically
2. **CloudWatch Metrics** - Track invocations, errors, latency
3. **X-Ray** - Enable tracing for debugging

## Cost Estimation

With pay-per-request DynamoDB and Lambda:

| Component | Pricing |
|-----------|---------|
| Lambda | $0.20 per 1M requests + compute |
| API Gateway | $1.00 per 1M requests |
| DynamoDB | Pay per request |

For 10K requests/day: ~$10-15/month

## Next Steps

- [Integration](integration.md) - Integrate with OmniAgent
- [API Reference](api-reference.md) - Endpoint documentation

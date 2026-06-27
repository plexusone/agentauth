# PeopleServer Lambda

AWS Lambda deployment for the AIStandardsIO PeopleServer - an AAuth Person Server for agent authorization.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AWS Cloud                                  │
│                                                                     │
│  ┌──────────────────┐     ┌─────────────────────────────────────┐  │
│  │  API Gateway     │     │       Lambda Function               │  │
│  │  (HTTP API)      │────>│       PeopleServer                  │  │
│  │                  │     │                                     │  │
│  │  /aauth/*        │     │  • AAuth authorization              │  │
│  │  /oauth/*        │     │  • Consent flow                     │  │
│  │  /.well-known/*  │     │  • Token issuance                   │  │
│  └──────────────────┘     └──────────────┬──────────────────────┘  │
│                                          │                          │
│  ┌───────────────────────────────────────┴──────────────────────┐  │
│  │                      DynamoDB Tables                          │  │
│  │  users | agents | missions | tokens | policies               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐                         │
│  │  Route 53       │  │  ACM            │                         │
│  │  (optional)     │  │  Certificate    │                         │
│  └─────────────────┘  └─────────────────┘                         │
└─────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- AWS CLI configured with appropriate credentials
- AWS SAM CLI installed (`brew install aws-sam-cli` or `pip install aws-sam-cli`)
- Go 1.21+
- Make

## Quick Start

### 1. Build

```bash
cd lambda/peopleserver
make build
```

### 2. Deploy to AWS

```bash
# Deploy to dev environment
make deploy

# Deploy to production
ENVIRONMENT=prod make deploy
```

### 3. Get Endpoint URL

```bash
make outputs
```

## Deployment Options

### Standard Deployment

```bash
# Default deployment (dev environment, us-east-1)
make deploy

# Custom environment and region
ENVIRONMENT=prod REGION=eu-west-1 make deploy
```

### Custom Domain Deployment

```bash
# First, create an ACM certificate for your domain
# Then deploy with custom domain
ENVIRONMENT=prod \
DOMAIN_NAME=auth.example.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/xxx \
make deploy-domain
```

After deployment, create a Route 53 alias record pointing to the API Gateway domain.

## Local Development

### Run Locally with SAM

```bash
# Start local API Gateway
make local

# In another terminal, test the API
curl http://localhost:8888/health
curl http://localhost:8888/.well-known/jwks.json
```

### Test with Sample Event

```bash
make invoke
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PEOPLESERVER_ISSUER` | Token issuer URL | Yes | API Gateway URL |
| `PEOPLESERVER_TABLE_PREFIX` | DynamoDB table prefix | No | `peopleserver` |
| `PEOPLESERVER_SIGNING_KEY_ARN` | KMS key ARN for signing | No | Ephemeral key |
| `SEED_DEMO_DATA` | Seed demo user/agent | No | `false` |
| `USE_DYNAMODB` | Use DynamoDB store | No | `false` |

### SAM Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `Environment` | Deployment environment | `dev` |
| `DomainName` | Custom domain name | (none) |
| `CertificateArn` | ACM certificate ARN | (none) |

## API Endpoints

Once deployed, the following endpoints are available:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/aauth-configuration` | GET | Discovery metadata |
| `/.well-known/jwks.json` | GET | Public key set |
| `/aauth/authorize` | POST | Request authorization |
| `/aauth/consent/{id}` | GET | Consent page |
| `/aauth/consent/{id}` | POST | Submit consent |
| `/aauth/consent/status/{id}` | GET | Poll consent status |
| `/oauth/token` | POST | Token exchange |
| `/health` | GET | Health check |

## Usage with OmniAgent

After deploying, configure OmniAgent to use the Lambda endpoint:

```bash
# Get the API endpoint
API_URL=$(aws cloudformation describe-stacks \
  --stack-name peopleserver-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ApiEndpoint`].OutputValue' \
  --output text)

# Configure OmniAgent
export AUTH_AAUTH_ENABLED=true
export AUTH_AAUTH_ISSUER=$API_URL
export AUTH_AAUTH_AUDIENCE=http://localhost:8080

# Start OmniAgent
omniagent openai serve
```

## Monitoring

### View Logs

```bash
make logs
```

### CloudWatch Metrics

The Lambda function emits standard CloudWatch metrics:
- Invocations
- Duration
- Errors
- Throttles

## Cost Estimation

With pay-per-request DynamoDB and Lambda:

| Component | Pricing |
|-----------|---------|
| Lambda | $0.20 per 1M requests + compute time |
| API Gateway | $1.00 per 1M requests |
| DynamoDB | Pay per request (minimal for auth workloads) |

For a typical auth workload (10K requests/day):
- ~$10-15/month estimated

## Security Considerations

1. **Signing Keys**: Use AWS KMS for production signing keys
2. **DynamoDB**: Enable encryption at rest (default)
3. **API Gateway**: Consider adding WAF rules
4. **IAM**: Use least-privilege policies

## Cleanup

```bash
make delete
```

This removes:
- Lambda function
- API Gateway
- DynamoDB tables
- All associated resources

## Troubleshooting

### Lambda Cold Starts

The function is configured with 256MB memory. Increase if cold starts are slow:

```yaml
# In template.yaml
MemorySize: 512  # or 1024
```

### CORS Issues

CORS is configured to allow all origins by default. For production, restrict to specific origins in `template.yaml`.

### Token Validation Fails

Check that:
1. `PEOPLESERVER_ISSUER` matches the URL clients use
2. JWKS endpoint is accessible
3. Token hasn't expired

## Next Steps

- [ ] Implement DynamoDB store for persistent state
- [ ] Add KMS signing key support
- [ ] Add CloudWatch alarms
- [ ] Add X-Ray tracing
- [ ] Create Terraform alternative to SAM

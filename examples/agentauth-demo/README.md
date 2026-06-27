# AgentAuth Demo

This demo demonstrates the agentauth server with both ID-JAG (automated) and AAuth (human consent) authorization flows.

## Overview

The agentauth server combines two authorization protocols:

1. **ID-JAG (Automated)**: For low-risk scopes like `read:*`, tokens are issued automatically via token exchange
2. **AAuth (Human Consent)**: For sensitive scopes like `write:*`, human approval is required

## Running the Demo

```bash
go run ./examples/agentauth-demo
```

## What the Demo Shows

### Demo 1: ID-JAG Flow (Automated)

- Agent requests `read:email read:profile` scopes
- Server evaluates policy and determines these can be auto-approved
- Access token is issued immediately via RFC 8693 token exchange

### Demo 2: AAuth Flow (Human Consent)

- Agent requests `write:profile` scope
- Server evaluates policy and determines human consent is required
- Server returns 202 Accepted with consent URI
- Agent polls status URI while waiting for user decision
- User approves the request (simulated)
- Access token is issued after approval

## Server Endpoints

Once running, the server exposes:

| Endpoint | Description |
|----------|-------------|
| `/.well-known/aauth-configuration` | AAuth discovery metadata |
| `/.well-known/jwks.json` | Public key set |
| `/oauth/token` | ID-JAG token exchange |
| `/aauth/authorize` | AAuth authorization request |
| `/aauth/consent/{id}` | Consent page for user |
| `/aauth/consent/status/{id}` | Poll consent status |

## Policy Configuration

The demo seeds the following scope policies:

| Pattern | Protocol | Description |
|---------|----------|-------------|
| `read:*` | ID-JAG | Auto-approved |
| `write:*` | AAuth | Requires human consent |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    agentauth-server                          │
│                                                              │
│  ┌─────────────────────┐    ┌─────────────────────┐         │
│  │   Person Server     │    │   AuthZ Server      │         │
│  │   (AAuth Protocol)  │    │   (ID-JAG Protocol) │         │
│  │                     │    │                     │         │
│  │  - Consent UI       │    │  - Token Exchange   │         │
│  │  - Mission Tracking │    │  - Policy Eval      │         │
│  │  - Token Issuance   │    │  - Introspection    │         │
│  └─────────────────────┘    └─────────────────────┘         │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  Shared Store (SQLite)                │   │
│  │  Users | Agents | Missions | Tokens | Policies        │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## Related Documentation

- [AAuth Protocol](../../docs/aauth/overview.md)
- [ID-JAG Protocol](../../docs/idjag/protocol-overview.md)
- [Roadmap](../../docs/specs/ROADMAP.md)

#!/bin/bash
# OmniAgent + AAuth End-to-End Demo Script
#
# This script demonstrates the full AAuth flow:
# 1. Start PeopleServer
# 2. Request authorization (auto-approved for read scopes)
# 3. Use the token with OmniAgent

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== OmniAgent + AAuth Demo ===${NC}"
echo ""

# Check if PeopleServer is running
if ! curl -s http://localhost:8888/health > /dev/null 2>&1; then
    echo -e "${YELLOW}Starting PeopleServer...${NC}"
    echo "Run in another terminal: go run ./examples/omniagent-aauth/peopleserver"
    echo ""
    echo "Then re-run this script."
    exit 1
fi

echo -e "${GREEN}PeopleServer is running at http://localhost:8888${NC}"
echo ""

# Step 1: Fetch JWKS to verify server is working
echo -e "${YELLOW}Step 1: Fetching JWKS...${NC}"
curl -s http://localhost:8888/.well-known/jwks.json | jq .
echo ""

# Step 2: Request authorization for read:* scope (auto-approved via pre-authorization)
# Note: Pre-authorization uses exact scope matching, so we request "read:*" exactly
echo -e "${YELLOW}Step 2: Requesting authorization for read:* scope (pre-authorized)...${NC}"
RESPONSE=$(curl -s -X POST http://localhost:8888/aauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "agent_token": "omniagent",
    "user_id": "demo-user",
    "scope": "read:*"
  }')

echo "$RESPONSE" | jq .

# Extract access token
ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token // empty')

if [ -n "$ACCESS_TOKEN" ]; then
    echo ""
    echo -e "${GREEN}Got access token (auto-approved):${NC}"
    echo "${ACCESS_TOKEN:0:50}..."
    echo ""

    # Decode JWT payload (without verification)
    echo -e "${YELLOW}Token payload:${NC}"
    echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "(could not decode)"
    echo ""
else
    echo -e "${RED}No immediate token - consent required${NC}"
    CONSENT_URI=$(echo "$RESPONSE" | jq -r '.consent_uri // empty')
    STATUS_URI=$(echo "$RESPONSE" | jq -r '.status_uri // empty')

    if [ -n "$CONSENT_URI" ]; then
        echo "Visit to approve: $CONSENT_URI"
        echo "Poll for status: $STATUS_URI"
    fi
fi

# Step 3: Request authorization for write:profile scope (requires consent)
echo -e "${YELLOW}Step 3: Requesting authorization for write:profile scope...${NC}"
RESPONSE=$(curl -s -X POST http://localhost:8888/aauth/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "agent_token": "omniagent",
    "user_id": "demo-user",
    "scope": "write:profile",
    "mission_name": "Update Profile",
    "mission_description": "Allow OmniAgent to update your profile"
  }')

echo "$RESPONSE" | jq .

# Check if consent is required
STATUS=$(echo "$RESPONSE" | jq -r '.consent_uri // empty')
if [ -n "$STATUS" ]; then
    CONSENT_URI=$(echo "$RESPONSE" | jq -r '.consent_uri')
    STATUS_URI=$(echo "$RESPONSE" | jq -r '.status_uri')
    MISSION_ID=$(echo "$RESPONSE" | jq -r '.mission_id')

    echo ""
    echo -e "${YELLOW}Human consent required!${NC}"
    echo "  Mission ID: $MISSION_ID"
    echo "  Consent URI: $CONSENT_URI"
    echo "  Status URI: $STATUS_URI"
    echo ""
    echo "Open in browser to approve: $CONSENT_URI"
fi

echo ""
echo -e "${GREEN}=== Demo Complete ===${NC}"
echo ""
echo "To use with OmniAgent, set these environment variables:"
echo ""
echo "  export AUTH_AAUTH_ENABLED=true"
echo "  export AUTH_AAUTH_ISSUER=http://localhost:8888"
echo "  export AUTH_AAUTH_AUDIENCE=http://localhost:8080"
echo ""
echo "Then start OmniAgent:"
echo "  omniagent openai serve --address :8080"
echo ""
echo "And make requests with the token:"
echo "  curl http://localhost:8080/openai/v1/chat/completions \\"
echo "    -H \"Authorization: Bearer \$TOKEN\" \\"
echo "    -H \"Content-Type: application/json\" \\"
echo "    -d '{\"model\":\"gpt-4\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'"

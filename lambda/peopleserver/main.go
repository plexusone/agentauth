// Package main provides an AWS Lambda handler for the AIStandardsIO PeopleServer.
//
// This Lambda function implements the AAuth Person Server, providing:
// - Authorization requests from agents
// - Human consent flow for sensitive operations
// - Token issuance after approval
//
// Deploy with API Gateway (HTTP API or REST API) for full functionality.
//
// Environment Variables:
//   - PEOPLESERVER_ISSUER: Token issuer URL (required, e.g., https://auth.example.com)
//   - PEOPLESERVER_TABLE_PREFIX: DynamoDB table prefix (default: "peopleserver")
//   - PEOPLESERVER_SIGNING_KEY_ARN: AWS KMS key ARN for signing (optional, generates ephemeral if not set)
//   - AWS_REGION: AWS region for DynamoDB
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"os"

	"github.com/aistandardsio/agent-protocols/aauth/personserver"
	"github.com/aistandardsio/agent-protocols/idjag/authzserver"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/aws-lambda-go-api-proxy/httpadapter"
	"github.com/google/uuid"
	"github.com/plexusone/agentauth/store"
)

var (
	httpAdapter *httpadapter.HandlerAdapterV2
)

func init() {
	// Get configuration from environment
	issuer := os.Getenv("PEOPLESERVER_ISSUER")
	if issuer == "" {
		log.Fatal("PEOPLESERVER_ISSUER environment variable is required")
	}

	tablePrefix := os.Getenv("PEOPLESERVER_TABLE_PREFIX")
	if tablePrefix == "" {
		tablePrefix = "peopleserver"
	}

	log.Printf("Initializing PeopleServer Lambda")
	log.Printf("  Issuer: %s", issuer)            //nolint:gosec // Lambda startup logging
	log.Printf("  Table Prefix: %s", tablePrefix) //nolint:gosec // Lambda startup logging

	// Create store
	// For Lambda, we use DynamoDB instead of SQLite
	// For now, fall back to in-memory for development
	var sqliteStore *store.SQLiteStore
	var err error

	// Check if we should use DynamoDB
	if os.Getenv("USE_DYNAMODB") == "true" {
		// DynamoDB store would be initialized here
		// dynamoStore, err := store.NewDynamoDB(context.Background(), tablePrefix)
		log.Printf("DynamoDB support not yet implemented, using in-memory store")
		sqliteStore, err = store.NewSQLite(":memory:")
	} else {
		sqliteStore, err = store.NewSQLite(":memory:")
	}
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}

	// Create adapters for both server types
	psStore := store.NewPersonServerAdapter(sqliteStore)
	asStore := store.NewAuthzServerAdapter(sqliteStore)

	// Generate or load signing key
	// In production, use AWS KMS for key management
	var privateKey *ecdsa.PrivateKey
	keyID := uuid.New().String()[:8]

	if kmsKeyARN := os.Getenv("PEOPLESERVER_SIGNING_KEY_ARN"); kmsKeyARN != "" {
		// KMS signing would be implemented here
		log.Printf("KMS signing not yet implemented, using ephemeral key")
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		// Generate ephemeral key (not recommended for production)
		log.Printf("WARNING: Using ephemeral signing key. Set PEOPLESERVER_SIGNING_KEY_ARN for production.")
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Seed demo data for testing
	if os.Getenv("SEED_DEMO_DATA") == "true" {
		seedDemoData(context.Background(), sqliteStore)
	}

	// Create servers
	ps, err := personserver.New(psStore, issuer, privateKey, keyID)
	if err != nil {
		log.Fatalf("Failed to create person server: %v", err)
	}

	as, err := authzserver.New(
		asStore,
		issuer,
		privateKey,
		keyID,
		authzserver.WithPersonServerURL(issuer+"/aauth"),
	)
	if err != nil {
		log.Fatalf("Failed to create auth server: %v", err)
	}

	// Create HTTP handler
	mux := http.NewServeMux()

	// AAuth endpoints under /aauth
	psMux := http.NewServeMux()
	ps.RegisterHandlers(psMux)
	mux.Handle("/aauth/", http.StripPrefix("/aauth", psMux))

	// ID-JAG endpoints under /oauth
	asMux := http.NewServeMux()
	as.RegisterHandlers(asMux)
	mux.Handle("/oauth/", http.StripPrefix("/oauth", asMux))

	// Root discovery endpoints
	mux.HandleFunc("GET /.well-known/aauth-configuration", ps.HandleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", as.HandleJWKS)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Create Lambda adapter
	httpAdapter = httpadapter.NewV2(mux)

	log.Printf("PeopleServer Lambda initialized successfully")
}

func handler(ctx context.Context, req events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return httpAdapter.ProxyWithContext(ctx, req)
}

func main() {
	lambda.Start(handler)
}

func seedDemoData(ctx context.Context, s *store.SQLiteStore) {
	log.Printf("Seeding demo data...")

	// Create demo user
	user := &store.User{
		ID:    "demo-user",
		Email: "demo@example.com",
		Name:  "Demo User",
	}
	_ = s.CreateUser(ctx, user)

	// Create demo agent
	agent := &store.Agent{
		ID:          "demo-agent",
		Name:        "Demo Agent",
		Description: "Demo AI Agent",
		PublicKey:   "demo-key",
	}
	_ = s.CreateAgent(ctx, agent)

	// Create scope policies
	policies := []*store.ScopePolicy{
		{Pattern: "read:*", Protocol: "idjag", Description: "Read scopes auto-approved", Priority: 100},
		{Pattern: "chat:*", Protocol: "idjag", Description: "Chat scopes auto-approved", Priority: 100},
		{Pattern: "write:*", Protocol: "aauth", InteractionType: "supervised", Description: "Write scopes require consent", Priority: 100},
	}
	for _, p := range policies {
		_ = s.CreateScopePolicy(ctx, p)
	}

	log.Printf("Demo data seeded: user=%s, agent=%s", user.Email, agent.ID)
}

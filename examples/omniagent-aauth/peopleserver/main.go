// Command peopleserver runs the AIStandardsIO PeopleServer for the OmniAgent demo.
//
// This server provides AAuth authorization for OmniAgent, allowing agents to
// request tokens with human consent for sensitive operations.
//
// Run: go run ./examples/omniagent-aauth/peopleserver
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
	"github.com/google/uuid"
	"github.com/plexusone/agentauth/store"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// Configuration
	address := os.Getenv("PEOPLESERVER_ADDRESS")
	if address == "" {
		address = ":8888"
	}
	dbPath := os.Getenv("PEOPLESERVER_DB")
	if dbPath == "" {
		dbPath = ":memory:"
	}
	issuer := os.Getenv("PEOPLESERVER_ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8888"
	}

	log.Println("=== AIStandardsIO PeopleServer ===")
	log.Printf("Address: %s", address) //nolint:gosec // Demo logging
	log.Printf("Database: %s", dbPath) //nolint:gosec // Demo logging
	log.Printf("Issuer: %s", issuer)   //nolint:gosec // Demo logging
	log.Println()

	// Create store
	sqliteStore, err := store.NewSQLite(dbPath)
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}
	defer sqliteStore.Close()

	// Generate signing key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	keyID := uuid.New().String()[:8]

	// Seed demo data
	ctx := context.Background()
	seedDemoData(ctx, sqliteStore)

	// Create adapters for both server types
	psStore := store.NewPersonServerAdapter(sqliteStore)
	asStore := store.NewAuthzServerAdapter(sqliteStore)

	// Create Person Server (AAuth)
	ps, err := personserver.New(psStore, issuer, privateKey, keyID)
	if err != nil {
		log.Fatalf("Failed to create person server: %v", err)
	}

	// Create Authorization Server (ID-JAG)
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

	// Create router
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
		_, _ = w.Write([]byte("ok"))
	})

	log.Println("Endpoints:")
	log.Printf("  Discovery:  %s/.well-known/aauth-configuration", issuer) //nolint:gosec // Demo logging
	log.Printf("  JWKS:       %s/.well-known/jwks.json", issuer)           //nolint:gosec // Demo logging
	log.Printf("  Authorize:  %s/aauth/authorize", issuer)                 //nolint:gosec // Demo logging
	log.Printf("  Token:      %s/oauth/token", issuer)                     //nolint:gosec // Demo logging
	log.Println()
	log.Printf("Starting server at %s", address) //nolint:gosec // Demo logging

	if err := http.ListenAndServe(address, mux); err != nil { //nolint:gosec // Demo server
		log.Fatalf("Server error: %v", err)
	}
}

func seedDemoData(ctx context.Context, s *store.SQLiteStore) {
	// Create demo user
	user := &store.User{
		ID:    "demo-user",
		Email: "demo@example.com",
		Name:  "Demo User",
	}
	if err := s.CreateUser(ctx, user); err != nil {
		log.Printf("User may already exist: %v", err)
	}

	// Create OmniAgent as a registered agent
	agent := &store.Agent{
		ID:          "omniagent",
		Name:        "OmniAgent",
		Description: "OmniAgent AI Assistant",
		PublicKey:   "omniagent-key",
	}
	if err := s.CreateAgent(ctx, agent); err != nil {
		log.Printf("Agent may already exist: %v", err)
	}

	// Create scope policies
	policies := []*store.ScopePolicy{
		{
			Pattern:     "read:*",
			Protocol:    "idjag",
			Description: "Read scopes are auto-approved",
			Priority:    100,
		},
		{
			Pattern:         "write:*",
			Protocol:        "aauth",
			InteractionType: "supervised",
			Description:     "Write scopes require human consent",
			Priority:        100,
		},
		{
			Pattern:     "chat:*",
			Protocol:    "idjag",
			Description: "Chat scopes are auto-approved",
			Priority:    100,
		},
	}
	for _, p := range policies {
		if err := s.CreateScopePolicy(ctx, p); err != nil {
			log.Printf("Policy may already exist: %v", err)
		}
	}

	// Pre-authorize OmniAgent for read and chat scopes
	preAuth := &store.PreAuthorization{
		UserID:  "demo-user",
		AgentID: "omniagent",
		Scopes:  "read:* chat:*",
	}
	if err := s.CreatePreAuthorization(ctx, preAuth); err != nil {
		log.Printf("Pre-auth may already exist: %v", err)
	}

	log.Println("Demo data seeded:")
	log.Printf("  User: %s (%s)", user.Name, user.Email)
	log.Printf("  Agent: %s", agent.Name)
	log.Println("  Policies:")
	log.Println("    - read:* -> ID-JAG (auto)")
	log.Println("    - chat:* -> ID-JAG (auto)")
	log.Println("    - write:* -> AAuth (human consent)")
	log.Println("  Pre-authorized: read:* chat:* for omniagent")
	log.Println()
}

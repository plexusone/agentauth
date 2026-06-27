// Command agentauth-demo demonstrates the agentauth server with both
// ID-JAG (automated) and AAuth (human consent) authorization flows.
//
// This demo:
//  1. Starts an agentauth server
//  2. Creates a demo user and agent
//  3. Demonstrates ID-JAG flow for read scopes (auto-approved)
//  4. Demonstrates AAuth flow for write scopes (requires human consent)
//  5. Shows how to poll for consent status
//
// Run: go run ./examples/agentauth-demo
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth/personserver"
	"github.com/aistandardsio/agent-protocols/idjag"
	"github.com/aistandardsio/agent-protocols/idjag/authzserver"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/plexusone/agentauth/store"
)

const (
	serverAddr = "localhost:8888"
	serverURL  = "http://localhost:8888"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Println("=== AgentAuth Demo ===")
	log.Println()

	// Create store and signing key
	sqliteStore, err := store.NewSQLite(":memory:")
	if err != nil {
		log.Fatalf("Failed to create store: %v", err)
	}
	defer sqliteStore.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	keyID := uuid.New().String()[:8]

	// Seed demo data
	ctx := context.Background()
	seedData(ctx, sqliteStore)

	// Create and start server
	mux := createServer(sqliteStore, privateKey, keyID)
	server := &http.Server{Addr: serverAddr, Handler: mux} //nolint:gosec // Demo server

	go func() {
		log.Printf("Starting server at %s", serverURL)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	log.Println()
	log.Println("=== Demo 1: ID-JAG Flow (Automated Authorization) ===")
	log.Println("Requesting 'read:email' scope - should be auto-approved via ID-JAG")
	log.Println()

	demoIDJAGFlow(privateKey)

	log.Println()
	log.Println("=== Demo 2: AAuth Flow (Human Consent Required) ===")
	log.Println("Requesting 'write:profile' scope - requires human consent via AAuth")
	log.Println()

	demoAAuthFlow()

	log.Println()
	log.Println("=== Demo Complete ===")
	log.Println()
	log.Printf("Server is still running at %s", serverURL)
	log.Println("Endpoints:")
	log.Printf("  Discovery:  %s/.well-known/aauth-configuration", serverURL)
	log.Printf("  JWKS:       %s/.well-known/jwks.json", serverURL)
	log.Printf("  OAuth:      %s/oauth/token", serverURL)
	log.Printf("  AAuth:      %s/aauth/authorize", serverURL)
	log.Println()
	log.Println("Press Ctrl+C to exit")

	// Keep running
	select {}
}

func seedData(ctx context.Context, s *store.SQLiteStore) {
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
		Name:        "Demo AI Agent",
		Description: "A demo AI agent for testing",
		PublicKey:   "demo-key",
	}
	_ = s.CreateAgent(ctx, agent)

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
	}
	for _, p := range policies {
		_ = s.CreateScopePolicy(ctx, p)
	}

	log.Println("Seeded demo data:")
	log.Printf("  User: %s (%s)", user.Name, user.Email)
	log.Printf("  Agent: %s", agent.Name)
	log.Println("  Policies:")
	log.Println("    - read:* -> ID-JAG (auto)")
	log.Println("    - write:* -> AAuth (human consent)")
}

func createServer(sqliteStore *store.SQLiteStore, privateKey *ecdsa.PrivateKey, keyID string) *http.ServeMux {
	mux := http.NewServeMux()

	// Create adapters for both server types
	psStore := store.NewPersonServerAdapter(sqliteStore)
	asStore := store.NewAuthzServerAdapter(sqliteStore)

	// Create Person Server
	ps, err := personserver.New(psStore, serverURL, privateKey, keyID)
	if err != nil {
		log.Fatalf("Failed to create person server: %v", err)
	}

	// Create Authorization Server
	as, err := authzserver.New(
		asStore,
		serverURL,
		privateKey,
		keyID,
		authzserver.WithPersonServerURL(serverURL+"/aauth"),
	)
	if err != nil {
		log.Fatalf("Failed to create auth server: %v", err)
	}

	// Register handlers
	psMux := http.NewServeMux()
	ps.RegisterHandlers(psMux)
	mux.Handle("/aauth/", http.StripPrefix("/aauth", psMux))

	asMux := http.NewServeMux()
	as.RegisterHandlers(asMux)
	mux.Handle("/oauth/", http.StripPrefix("/oauth", asMux))

	// Root discovery endpoints
	mux.HandleFunc("GET /.well-known/aauth-configuration", ps.HandleMetadata)
	mux.HandleFunc("GET /.well-known/jwks.json", as.HandleJWKS)

	return mux
}

func demoIDJAGFlow(privateKey *ecdsa.PrivateKey) {
	// Create an ID-JAG assertion (simulating what an IdP would issue)
	assertion := createIDJAGAssertion(privateKey, "demo-user", "demo-agent")
	log.Printf("1. Created ID-JAG assertion for user 'demo-user', agent 'demo-agent'")

	// Exchange assertion for access token
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", assertion)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id-jag")
	form.Set("scope", "read:email read:profile")

	log.Printf("2. Sending token exchange request to %s/oauth/token", serverURL)

	resp, err := http.Post(serverURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		log.Printf("   Error: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		var tokenResp map[string]any
		_ = json.Unmarshal(body, &tokenResp)
		log.Printf("3. SUCCESS! Received access token:")
		log.Printf("   Token Type: %s", tokenResp["token_type"])
		log.Printf("   Expires In: %v seconds", tokenResp["expires_in"])
		log.Printf("   Scope: %s", tokenResp["scope"])
		accessToken := tokenResp["access_token"].(string)
		log.Printf("   Access Token: %s...%s", accessToken[:20], accessToken[len(accessToken)-10:])
	} else {
		log.Printf("3. Failed with status %d: %s", resp.StatusCode, string(body))
	}
}

func demoAAuthFlow() {
	// Request authorization for write scope (requires human consent)
	authReq := map[string]any{
		"agent_token":         "demo-agent",
		"user_id":             "demo-user",
		"scope":               "write:profile",
		"mission_name":        "Profile Update",
		"mission_description": "Allow the agent to update your profile information",
	}
	body, _ := json.Marshal(authReq)

	log.Printf("1. Sending authorization request to %s/aauth/authorize", serverURL)
	log.Printf("   Scope: write:profile (requires human consent)")

	resp, err := http.Post(serverURL+"/aauth/authorize", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("   Error: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusAccepted {
		var authResp map[string]any
		_ = json.Unmarshal(respBody, &authResp)

		missionID := authResp["mission_id"].(string)
		// The consent URIs are returned without the /aauth prefix, add it
		consentURI := serverURL + "/aauth/consent/" + missionID
		statusURI := serverURL + "/aauth/consent/status/" + missionID

		log.Printf("2. Received 202 Accepted - Human consent required")
		log.Printf("   Mission ID: %s", missionID)
		log.Printf("   Consent URI: %s", consentURI)
		log.Printf("   Status URI: %s", statusURI)
		log.Println()
		log.Println("   In a real scenario, the user would visit the consent URI")
		log.Println("   to approve or deny the request. The agent polls the status URI.")
		log.Println()

		// Simulate polling for consent status
		log.Printf("3. Polling status URI...")
		statusResp, _ := http.Get(statusURI) //nolint:gosec // Demo code
		statusBody, _ := io.ReadAll(statusResp.Body)
		statusResp.Body.Close()

		var status map[string]any
		_ = json.Unmarshal(statusBody, &status)
		log.Printf("   Status: %s", status["status"])

		// Simulate user approval by calling the approval endpoint
		log.Println()
		log.Printf("4. Simulating user approval via POST to consent endpoint...")

		form := url.Values{}
		form.Set("decision", "approve")
		form.Set("remember", "on")

		approvalResp, _ := http.Post(consentURI, "application/x-www-form-urlencoded", strings.NewReader(form.Encode())) //nolint:gosec // Demo code
		approvalResp.Body.Close()
		log.Printf("   Approval submitted (status %d)", approvalResp.StatusCode)

		// Poll again for the token
		log.Println()
		log.Printf("5. Polling status URI again for token...")
		statusResp2, _ := http.Get(statusURI) //nolint:gosec // Demo code
		statusBody2, _ := io.ReadAll(statusResp2.Body)
		statusResp2.Body.Close()

		var finalStatus map[string]any
		_ = json.Unmarshal(statusBody2, &finalStatus)

		if finalStatus["status"] == "approved" {
			log.Printf("   Status: approved")
			log.Printf("   Token Type: %s", finalStatus["token_type"])
			log.Printf("   Expires In: %v seconds", finalStatus["expires_in"])
			log.Printf("   Scope: %s", finalStatus["scope"])
			accessToken := finalStatus["access_token"].(string)
			log.Printf("   Access Token: %s...%s", accessToken[:20], accessToken[len(accessToken)-10:])
		} else {
			log.Printf("   Status: %v", finalStatus)
		}
	} else if resp.StatusCode == http.StatusOK {
		// Pre-authorized
		log.Printf("2. Received immediate approval (pre-authorized)")
	} else {
		log.Printf("2. Failed with status %d: %s", resp.StatusCode, string(respBody))
	}
}

func createIDJAGAssertion(privateKey *ecdsa.PrivateKey, userID, agentID string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": serverURL,
		"sub": userID,
		"aud": serverURL,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
		"act": map[string]string{
			"sub": agentID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = idjag.TokenTypeIDJAG

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("Failed to sign assertion: %v", err)
	}

	return signedToken
}

func init() {
	// Disable log prefix for cleaner output
	log.SetOutput(os.Stdout)
}

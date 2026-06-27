// Command agentauth-server runs a unified authorization server that combines
// the AAuth Person Server (human consent) and the ID-JAG Authorization Server
// (automated token exchange) into a single deployable binary.
//
// Usage:
//
//	agentauth-server [flags]
//
// The server exposes endpoints for both protocols:
//
//	AAuth Person Server endpoints (human consent):
//	  GET  /.well-known/aauth-configuration  - Discovery metadata
//	  POST /aauth/authorize                  - Request authorization
//	  GET  /aauth/consent/{id}               - Consent page
//	  POST /aauth/consent/{id}               - Submit consent
//	  GET  /aauth/consent/status/{id}        - Poll consent status
//	  POST /aauth/token                      - Token endpoint
//
//	ID-JAG Authorization Server endpoints (automated):
//	  GET  /.well-known/oauth-authorization-server  - Discovery metadata
//	  POST /oauth/token                              - Token exchange
//	  POST /oauth/introspect                         - Token introspection
//	  POST /oauth/revoke                             - Token revocation
//
//	Shared endpoints:
//	  GET  /.well-known/jwks.json  - Public key set
//
// Example:
//
//	# Start server with default settings (in-memory database)
//	agentauth-server
//
//	# Start with persistent SQLite database
//	agentauth-server --db ./agentauth.db
//
//	# Start with custom port and issuer
//	agentauth-server --port 9000 --issuer https://auth.example.com
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aistandardsio/agent-protocols/aauth/personserver"
	"github.com/aistandardsio/agent-protocols/idjag/authzserver"
	"github.com/google/uuid"
	"github.com/plexusone/agentauth/store"
)

func main() {
	// Parse command line flags
	var (
		port      = flag.Int("port", 8080, "Server port")
		dbPath    = flag.String("db", ":memory:", "SQLite database path (use :memory: for in-memory)")
		issuer    = flag.String("issuer", "", "Issuer URL (default: http://localhost:<port>)")
		verbose   = flag.Bool("verbose", false, "Enable verbose logging")
		seedData  = flag.Bool("seed", true, "Seed database with demo data")
		aauthOnly = flag.Bool("aauth-only", false, "Only run AAuth Person Server")
		idjagOnly = flag.Bool("idjag-only", false, "Only run ID-JAG Authorization Server")
	)
	flag.Parse()

	// Setup logging
	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Determine issuer URL
	issuerURL := *issuer
	if issuerURL == "" {
		issuerURL = fmt.Sprintf("http://localhost:%d", *port)
	}

	// Initialize store
	sqliteStore, err := store.NewSQLite(*dbPath)
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer sqliteStore.Close()

	// Create adapters for both server types
	psStore := store.NewPersonServerAdapter(sqliteStore)
	asStore := store.NewAuthzServerAdapter(sqliteStore)

	// Seed demo data if requested
	if *seedData {
		if err := seedDemoData(sqliteStore); err != nil {
			logger.Warn("failed to seed demo data", "error", err)
		}
	}

	// Generate signing key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("failed to generate signing key", "error", err)
		os.Exit(1)
	}
	keyID := uuid.New().String()[:8]

	// Create HTTP mux
	mux := http.NewServeMux()

	// Add health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Register Person Server (AAuth) handlers
	if !*idjagOnly {
		ps, err := personserver.New(
			psStore,
			issuerURL,
			privateKey,
			keyID,
			personserver.WithLogger(logger.With("server", "personserver")),
		)
		if err != nil {
			logger.Error("failed to create person server", "error", err)
			os.Exit(1)
		}

		// Register with /aauth prefix
		psHandler := http.NewServeMux()
		ps.RegisterHandlers(psHandler)
		mux.Handle("/aauth/", http.StripPrefix("/aauth", psHandler))

		// Also register discovery at root
		mux.HandleFunc("GET /.well-known/aauth-configuration", ps.HandleMetadata)

		logger.Info("AAuth Person Server enabled",
			"authorize", issuerURL+"/aauth/authorize",
			"consent", issuerURL+"/aauth/consent/{id}")
	}

	// Register Authorization Server (ID-JAG) handlers
	if !*aauthOnly {
		as, err := authzserver.New(
			asStore,
			issuerURL,
			privateKey,
			keyID,
			authzserver.WithLogger(logger.With("server", "authzserver")),
			authzserver.WithPersonServerURL(issuerURL+"/aauth"),
		)
		if err != nil {
			logger.Error("failed to create authorization server", "error", err)
			os.Exit(1)
		}

		// Register with /oauth prefix
		asHandler := http.NewServeMux()
		as.RegisterHandlers(asHandler)
		mux.Handle("/oauth/", http.StripPrefix("/oauth", asHandler))

		// Also register discovery at root
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", as.HandleMetadata)

		// Shared JWKS endpoint
		mux.HandleFunc("GET /.well-known/jwks.json", as.HandleJWKS)

		logger.Info("ID-JAG Authorization Server enabled",
			"token", issuerURL+"/oauth/token",
			"introspect", issuerURL+"/oauth/introspect")
	}

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      loggingMiddleware(logger)(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("starting server",
			"addr", server.Addr,
			"issuer", issuerURL,
			"db", *dbPath)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server shutdown error", "error", err)
	}

	logger.Info("server stopped")
}

// loggingMiddleware logs HTTP requests.
func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Debug("request",
				"method", r.Method,
				"path", r.URL.Path,
				"duration", time.Since(start))
		})
	}
}

// seedDemoData adds demo users and agents to the database.
func seedDemoData(s *store.SQLiteStore) error {
	ctx := context.Background()

	// Create demo user
	user := &store.User{
		ID:    "demo-user",
		Email: "demo@example.com",
		Name:  "Demo User",
	}
	if err := s.CreateUser(ctx, user); err != nil {
		// Ignore already exists error
		if err != store.ErrAlreadyExists {
			return err
		}
	}

	// Create demo agent
	agent := &store.Agent{
		ID:          "demo-agent",
		Name:        "Demo Agent",
		Description: "A demo AI agent for testing",
		PublicKey:   "demo-public-key",
	}
	if err := s.CreateAgent(ctx, agent); err != nil {
		// Ignore error (might already exist)
	}

	// Create some default scope policies
	policies := []*store.ScopePolicy{
		{
			Pattern:     "read:*",
			Protocol:    "idjag",
			Description: "Read-only scopes can be auto-approved",
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
			Pattern:         "admin:*",
			Protocol:        "aauth",
			InteractionType: "supervised",
			Description:     "Admin scopes require human consent",
			Priority:        200,
		},
		{
			Pattern:         "delete:*",
			Protocol:        "aauth",
			InteractionType: "supervised",
			Description:     "Delete scopes require human consent",
			Priority:        200,
		},
	}
	for _, policy := range policies {
		_ = s.CreateScopePolicy(ctx, policy)
	}

	return nil
}

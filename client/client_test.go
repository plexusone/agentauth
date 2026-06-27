package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExchangeIDJAG(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("Expected path /oauth/token, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
			t.Errorf("Expected token-exchange grant type")
		}
		if r.Form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:id-jag" {
			t.Errorf("Expected id-jag token type")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read:email",
		})
	}))
	defer server.Close()

	client := New(server.URL)
	token, err := client.ExchangeIDJAG(context.Background(), "test-assertion", "read:email")
	if err != nil {
		t.Fatalf("ExchangeIDJAG failed: %v", err)
	}

	if token.AccessToken != "test-access-token" {
		t.Errorf("Expected access token 'test-access-token', got %s", token.AccessToken)
	}
	if token.TokenType != "Bearer" {
		t.Errorf("Expected token type 'Bearer', got %s", token.TokenType)
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("Expected expires_in 3600, got %d", token.ExpiresIn)
	}
}

func TestExchangeJWTBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("Expected jwt-bearer grant type")
		}
		if r.Form.Get("assertion") != "test-jwt" {
			t.Errorf("Expected assertion 'test-jwt'")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "bearer-token",
			"token_type":   "Bearer",
			"expires_in":   7200,
		})
	}))
	defer server.Close()

	client := New(server.URL)
	token, err := client.ExchangeJWTBearer(context.Background(), "test-jwt", "")
	if err != nil {
		t.Fatalf("ExchangeJWTBearer failed: %v", err)
	}

	if token.AccessToken != "bearer-token" {
		t.Errorf("Expected access token 'bearer-token', got %s", token.AccessToken)
	}
}

func TestRequestAuthorization_PreAuthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/aauth/authorize" {
			t.Errorf("Expected path /aauth/authorize, got %s", r.URL.Path)
		}

		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req["agent_token"] != "agent-1" {
			t.Errorf("Expected agent_token 'agent-1'")
		}

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // Test data, not real credentials
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "pre-auth-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read:profile",
		})
	}))
	defer server.Close()

	client := New(server.URL)
	result, err := client.RequestAuthorization(context.Background(), &AuthorizationRequest{
		AgentToken: "agent-1",
		UserID:     "user-1",
		Scopes:     "read:profile",
	})
	if err != nil {
		t.Fatalf("RequestAuthorization failed: %v", err)
	}

	if result.Status != "approved" {
		t.Errorf("Expected status 'approved', got %s", result.Status)
	}
	if result.Token == nil {
		t.Fatal("Expected token to be set")
	}
	if result.Token.AccessToken != "pre-auth-token" {
		t.Errorf("Expected token 'pre-auth-token', got %s", result.Token.AccessToken)
	}
}

func TestRequestAuthorization_ConsentRequired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"consent_uri": "https://auth.example.com/consent/mission-1",
			"status_uri":  "https://auth.example.com/consent/status/mission-1",
			"mission_id":  "mission-1",
			"interval":    5,
		})
	}))
	defer server.Close()

	client := New(server.URL)
	result, err := client.RequestAuthorization(context.Background(), &AuthorizationRequest{
		AgentToken: "agent-1",
		UserID:     "user-1",
		Scopes:     "write:profile",
	})
	if err != nil {
		t.Fatalf("RequestAuthorization failed: %v", err)
	}

	if result.Status != "pending" {
		t.Errorf("Expected status 'pending', got %s", result.Status)
	}
	if result.ConsentURI != "https://auth.example.com/consent/mission-1" {
		t.Errorf("Expected consent_uri")
	}
	if result.StatusURI != "https://auth.example.com/consent/status/mission-1" {
		t.Errorf("Expected status_uri")
	}
	if result.MissionID != "mission-1" {
		t.Errorf("Expected mission_id 'mission-1'")
	}
}

func TestPollConsentStatus(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")

		if count < 3 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "pending",
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "approved",
				"access_token": "approved-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}
	}))
	defer server.Close()

	client := New(server.URL, WithPollInterval(10*time.Millisecond))

	// First poll - pending
	result, err := client.PollConsentStatus(context.Background(), server.URL+"/consent/status/mission-1")
	if err != nil {
		t.Fatalf("PollConsentStatus failed: %v", err)
	}
	if result.Status != "pending" {
		t.Errorf("Expected status 'pending', got %s", result.Status)
	}

	// Second poll - still pending
	result, err = client.PollConsentStatus(context.Background(), server.URL+"/consent/status/mission-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "pending" {
		t.Errorf("Expected status 'pending', got %s", result.Status)
	}

	// Third poll - approved
	result, err = client.PollConsentStatus(context.Background(), server.URL+"/consent/status/mission-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "approved" {
		t.Errorf("Expected status 'approved', got %s", result.Status)
	}
	if result.Token == nil || result.Token.AccessToken != "approved-token" {
		t.Error("Expected approved-token")
	}
}

func TestWaitForConsent(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")

		if count < 3 {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "pending",
			})
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":       "approved",
				"access_token": "waited-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}
	}))
	defer server.Close()

	client := New(server.URL,
		WithPollInterval(10*time.Millisecond),
		WithPollTimeout(time.Second),
	)

	token, err := client.WaitForConsent(context.Background(), server.URL+"/consent/status/mission-1")
	if err != nil {
		t.Fatalf("WaitForConsent failed: %v", err)
	}

	if token.AccessToken != "waited-token" {
		t.Errorf("Expected token 'waited-token', got %s", token.AccessToken)
	}
}

func TestWaitForConsent_Denied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "denied",
		})
	}))
	defer server.Close()

	client := New(server.URL, WithPollInterval(10*time.Millisecond))

	_, err := client.WaitForConsent(context.Background(), server.URL+"/consent/status/mission-1")
	if err == nil {
		t.Error("Expected error for denied consent")
	}
}

func TestWaitForConsent_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "pending",
		})
	}))
	defer server.Close()

	client := New(server.URL,
		WithPollInterval(10*time.Millisecond),
		WithPollTimeout(50*time.Millisecond),
	)

	_, err := client.WaitForConsent(context.Background(), server.URL+"/consent/status/mission-1")
	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestIntrospect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/introspect" {
			t.Errorf("Expected path /oauth/introspect")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("token") != "test-token" {
			t.Errorf("Expected token 'test-token'")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active":     true,
			"scope":      "read:email",
			"sub":        "user-1",
			"exp":        time.Now().Add(time.Hour).Unix(),
			"token_type": "Bearer",
		})
	}))
	defer server.Close()

	client := New(server.URL)
	result, err := client.Introspect(context.Background(), "test-token")
	if err != nil {
		t.Fatalf("Introspect failed: %v", err)
	}

	if !result.Active {
		t.Error("Expected token to be active")
	}
	if result.Scope != "read:email" {
		t.Errorf("Expected scope 'read:email', got %s", result.Scope)
	}
	if result.Sub != "user-1" {
		t.Errorf("Expected sub 'user-1', got %s", result.Sub)
	}
}

func TestRevoke(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/revoke" {
			t.Errorf("Expected path /oauth/revoke")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("token") != "token-to-revoke" {
			t.Errorf("Expected token 'token-to-revoke'")
		}
		if r.Form.Get("token_type_hint") != "access_token" {
			t.Errorf("Expected token_type_hint 'access_token'")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(server.URL)
	err := client.Revoke(context.Background(), "token-to-revoke", "access_token")
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
}

func TestTokenCache(t *testing.T) {
	client := New("https://example.com")

	// Cache a token
	token := &Token{
		AccessToken: "cached-token",
		ExpiresIn:   3600,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	client.CacheToken("user-1:read", token)

	// Retrieve it
	cached := client.GetCachedToken("user-1:read")
	if cached == nil {
		t.Fatal("Expected cached token")
	}
	if cached.AccessToken != "cached-token" {
		t.Errorf("Expected 'cached-token', got %s", cached.AccessToken)
	}

	// Non-existent key
	if client.GetCachedToken("unknown") != nil {
		t.Error("Expected nil for unknown key")
	}

	// Expired token
	expiredToken := &Token{
		AccessToken: "expired-token",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}
	client.CacheToken("user-2:read", expiredToken)
	if client.GetCachedToken("user-2:read") != nil {
		t.Error("Expected nil for expired token")
	}

	// Clear cache
	client.ClearCache()
	if client.GetCachedToken("user-1:read") != nil {
		t.Error("Expected nil after cache clear")
	}
}

func TestToken_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		token := &Token{ExpiresAt: time.Now().Add(time.Hour)}
		if token.IsExpired() {
			t.Error("Token should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		token := &Token{ExpiresAt: time.Now().Add(-time.Hour)}
		if !token.IsExpired() {
			t.Error("Token should be expired")
		}
	})
}

func TestToken_IsExpiringSoon(t *testing.T) {
	t.Run("not expiring soon", func(t *testing.T) {
		token := &Token{ExpiresAt: time.Now().Add(time.Hour)}
		if token.IsExpiringSoon(5 * time.Minute) {
			t.Error("Token should not be expiring soon")
		}
	})

	t.Run("expiring soon", func(t *testing.T) {
		token := &Token{ExpiresAt: time.Now().Add(2 * time.Minute)}
		if !token.IsExpiringSoon(5 * time.Minute) {
			t.Error("Token should be expiring soon")
		}
	})
}

func TestErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "The assertion is invalid",
		})
	}))
	defer server.Close()

	client := New(server.URL)
	_, err := client.ExchangeIDJAG(context.Background(), "invalid", "")
	if err == nil {
		t.Fatal("Expected error")
	}
	if err.Error() != "invalid_grant: The assertion is invalid" {
		t.Errorf("Unexpected error: %v", err)
	}
}

// Unused but kept for potential future use
var _ = func() *ecdsa.PrivateKey {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestNew(t *testing.T) {
	v, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if v == nil {
		t.Fatal("New() returned nil")
	}

	// Check defaults
	if !v.protocols[ProtocolAAuth] {
		t.Error("AAuth protocol not enabled by default")
	}
	if !v.protocols[ProtocolIDJAG] {
		t.Error("IDJAG protocol not enabled by default")
	}
}

func TestNewWithOptions(t *testing.T) {
	v, err := New(
		WithTrustedIssuers("https://issuer1.example.com", "https://issuer2.example.com"),
		WithProtocols(ProtocolAAuth),
		WithJWKSCache(30*time.Minute),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if !v.trustedIssuers["https://issuer1.example.com"] {
		t.Error("issuer1 not in trusted issuers")
	}
	if !v.trustedIssuers["https://issuer2.example.com"] {
		t.Error("issuer2 not in trusted issuers")
	}
	if !v.protocols[ProtocolAAuth] {
		t.Error("AAuth protocol not enabled")
	}
	if v.protocols[ProtocolIDJAG] {
		t.Error("IDJAG protocol should not be enabled")
	}
	if v.cacheTTL != 30*time.Minute {
		t.Errorf("cacheTTL = %v, want 30m", v.cacheTTL)
	}
}

func TestVerify_EmptyToken(t *testing.T) {
	v, _ := New()
	_, err := v.Verify(context.Background(), "")
	if err != ErrEmptyToken {
		t.Errorf("Verify() error = %v, want ErrEmptyToken", err)
	}
}

func TestVerify_InvalidToken(t *testing.T) {
	v, _ := New()
	_, err := v.Verify(context.Background(), "not.a.jwt")
	if err == nil {
		t.Error("Verify() expected error for invalid token")
	}
}

func TestVerify_WithMockJWKS(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "EC",
					"crv": "P-256",
					"kid": "test-key-1",
					"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// Create token
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   jwksServer.URL,
		"sub":   "test-subject",
		"aud":   "test-audience",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"scope": "read:data write:data",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-1"
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	// Verify token
	v, _ := New(WithTrustedIssuers(jwksServer.URL))
	result, err := v.Verify(context.Background(), tokenString)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Issuer != jwksServer.URL {
		t.Errorf("Issuer = %v, want %v", result.Issuer, jwksServer.URL)
	}
	if result.Subject != "test-subject" {
		t.Errorf("Subject = %v, want test-subject", result.Subject)
	}
	if len(result.Scopes) != 2 {
		t.Errorf("Scopes = %v, want 2 scopes", result.Scopes)
	}
}

func TestVerify_UntrustedIssuer(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "EC",
					"crv": "P-256",
					"kid": "test-key",
					"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	claims := jwt.MapClaims{
		"iss": jwksServer.URL,
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key"
	tokenString, _ := token.SignedString(privateKey)

	// Verifier with different trusted issuer
	v, _ := New(WithTrustedIssuers("https://other.example.com"))
	_, err := v.Verify(context.Background(), tokenString)
	if err == nil {
		t.Error("expected ErrUntrustedIssuer")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "EC",
					"crv": "P-256",
					"kid": "test-key",
					"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// Create expired token
	claims := jwt.MapClaims{
		"iss": jwksServer.URL,
		"sub": "test",
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key"
	tokenString, _ := token.SignedString(privateKey)

	v, _ := New(WithTrustedIssuers(jwksServer.URL))
	_, err := v.Verify(context.Background(), tokenString)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		name         string
		header       map[string]any
		claims       jwt.MapClaims
		wantProtocol Protocol
		wantType     TokenType
	}{
		{
			name:         "AAuth agent token by typ header",
			header:       map[string]any{"typ": "aa-agent+jwt"},
			claims:       jwt.MapClaims{},
			wantProtocol: ProtocolAAuth,
			wantType:     TokenTypeAgentToken,
		},
		{
			name:         "AAuth auth token by typ header",
			header:       map[string]any{"typ": "aa-auth+jwt"},
			claims:       jwt.MapClaims{},
			wantProtocol: ProtocolAAuth,
			wantType:     TokenTypeAuthToken,
		},
		{
			name:         "ID-JAG by act claim",
			header:       map[string]any{},
			claims:       jwt.MapClaims{"act": map[string]any{"sub": "actor"}},
			wantProtocol: ProtocolIDJAG,
			wantType:     TokenTypeIDJAG,
		},
		{
			name:         "AAuth by agent_id claim",
			header:       map[string]any{},
			claims:       jwt.MapClaims{"agent_id": "agent-123"},
			wantProtocol: ProtocolAAuth,
			wantType:     TokenTypeAuthToken,
		},
		{
			name:         "AAuth by cnf claim",
			header:       map[string]any{},
			claims:       jwt.MapClaims{"cnf": map[string]any{"jkt": "thumbprint"}},
			wantProtocol: ProtocolAAuth,
			wantType:     TokenTypeAgentToken,
		},
		{
			name:         "Default to ID-JAG",
			header:       map[string]any{},
			claims:       jwt.MapClaims{"sub": "user"},
			wantProtocol: ProtocolIDJAG,
			wantType:     TokenTypeAccessToken,
		},
	}

	v, _ := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &jwt.Token{
				Header: tt.header,
				Claims: tt.claims,
			}
			protocol, tokenType := v.detectProtocol(token)
			if protocol != tt.wantProtocol {
				t.Errorf("detectProtocol() protocol = %v, want %v", protocol, tt.wantProtocol)
			}
			if tokenType != tt.wantType {
				t.Errorf("detectProtocol() tokenType = %v, want %v", tokenType, tt.wantType)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		scopes   []string
		required string
		want     bool
	}{
		{[]string{"read:data"}, "read:data", true},
		{[]string{"read:data"}, "write:data", false},
		{[]string{"read:*"}, "read:anything", true},
		{[]string{"read:*"}, "write:anything", false},
		{[]string{}, "read:data", false},
	}

	for _, tt := range tests {
		got := hasScope(tt.scopes, tt.required)
		if got != tt.want {
			t.Errorf("hasScope(%v, %q) = %v, want %v", tt.scopes, tt.required, got, tt.want)
		}
	}
}

func TestMiddleware(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "EC",
					"crv": "P-256",
					"kid": "test-key",
					"x":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes()),
					"y":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.Y.Bytes()),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	// Create valid token
	claims := jwt.MapClaims{
		"iss":   jwksServer.URL,
		"sub":   "test-user",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"scope": "read:data",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key"
	tokenString, _ := token.SignedString(privateKey)

	v, _ := New(WithTrustedIssuers(jwksServer.URL))

	// Create test handler that checks claims
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := ClaimsFromContext(r.Context())
		if c == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if c.Subject != "test-user" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Test with valid token
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("middleware with valid token: status = %d, want 200", rec.Code)
	}

	// Test without token
	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("middleware without token: status = %d, want 401", rec.Code)
	}
}

func TestClearCache(t *testing.T) {
	v, _ := New()

	// Add something to cache
	v.cache["test"] = &jwksCache{}

	v.ClearCache()

	if len(v.cache) != 0 {
		t.Error("cache not cleared")
	}
}

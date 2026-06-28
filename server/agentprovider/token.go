package agentprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/plexusone/agentauth/store"
)

// issueAgentToken creates and signs an agent token.
func (p *Provider) issueAgentToken(ctx context.Context, agent *store.RegisteredAgent, audience string) (string, error) {
	now := time.Now()
	jti := uuid.New().String()

	// Build claims
	claims := jwt.MapClaims{
		"iss": p.issuer,
		"sub": agent.ID,
		"iat": now.Unix(),
		"exp": now.Add(p.tokenTTL).Unix(),
		"jti": jti,
	}

	if audience != "" {
		claims["aud"] = strings.Fields(audience)
	}

	// Create token
	token := jwt.NewWithClaims(p.signingMethod(), claims)
	token.Header["typ"] = "aa-agent+jwt"
	token.Header["kid"] = p.keyID

	// Sign token
	signedToken, err := token.SignedString(p.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Record issued token for tracking
	issuedToken := &store.IssuedAgentToken{
		JTI:       jti,
		AgentID:   agent.ID,
		KeyID:     p.keyID,
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: now.Add(p.tokenTTL),
	}
	if err := p.store.CreateIssuedAgentToken(ctx, issuedToken); err != nil {
		p.logger.Warn("failed to record issued token", "error", err, "jti", jti)
		// Don't fail token issuance for this
	}

	return signedToken, nil
}

// signingMethod returns the JWT signing method based on the configured algorithm.
func (p *Provider) signingMethod() jwt.SigningMethod {
	switch p.algorithm {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodES256
	}
}

// buildJWKS constructs a JWKS from the provider's signing key.
func (p *Provider) buildJWKS() (map[string]any, error) {
	jwk, err := publicKeyToJWK(p.signingKey, p.keyID, p.algorithm)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"keys": []map[string]any{jwk},
	}, nil
}

// publicKeyToJWK converts a public key to JWK format.
func publicKeyToJWK(privateKey any, keyID, alg string) (map[string]any, error) {
	jwk := map[string]any{
		"kid": keyID,
		"use": "sig",
		"alg": alg,
	}

	switch k := privateKey.(type) {
	case *ecdsa.PrivateKey:
		jwk["kty"] = "EC"
		jwk["crv"] = curveName(k.Curve.Params().Name)
		jwk["x"] = base64.RawURLEncoding.EncodeToString(k.PublicKey.X.Bytes())
		jwk["y"] = base64.RawURLEncoding.EncodeToString(k.PublicKey.Y.Bytes())

	case *rsa.PrivateKey:
		jwk["kty"] = "RSA"
		jwk["n"] = base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes())
		// Convert E to bytes
		e := k.PublicKey.E
		eBytes := make([]byte, 0)
		for e > 0 {
			eBytes = append([]byte{byte(e & 0xff)}, eBytes...)
			e >>= 8
		}
		jwk["e"] = base64.RawURLEncoding.EncodeToString(eBytes)

	case ed25519.PrivateKey:
		pub := k.Public().(ed25519.PublicKey)
		jwk["kty"] = "OKP"
		jwk["crv"] = "Ed25519"
		jwk["x"] = base64.RawURLEncoding.EncodeToString(pub)

	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}

	return jwk, nil
}

// curveName normalizes EC curve names to JWK format.
func curveName(name string) string {
	switch name {
	case "P-256", "prime256v1":
		return "P-256"
	case "P-384", "secp384r1":
		return "P-384"
	case "P-521", "secp521r1":
		return "P-521"
	default:
		return name
	}
}

// generateKeyID creates a unique key ID.
func generateKeyID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// detectAlgorithm detects the algorithm from a JWK.
func detectAlgorithm(jwkData json.RawMessage) string {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(jwkData, &jwk); err != nil {
		return "ES256" // Default
	}

	// If algorithm is explicitly specified
	if jwk.Alg != "" {
		return jwk.Alg
	}

	// Infer from key type and curve
	switch jwk.Kty {
	case "EC":
		switch jwk.Crv {
		case "P-256":
			return "ES256"
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		}
	case "RSA":
		return "RS256"
	case "OKP":
		if jwk.Crv == "Ed25519" {
			return "EdDSA"
		}
	}

	return "ES256"
}

// ComputeKeyThumbprint computes the JWK thumbprint (RFC 7638).
func ComputeKeyThumbprint(jwkData json.RawMessage) (string, error) {
	var jwk map[string]any
	if err := json.Unmarshal(jwkData, &jwk); err != nil {
		return "", err
	}

	// Build canonical representation
	kty, _ := jwk["kty"].(string)
	var canonical map[string]any

	switch kty {
	case "EC":
		canonical = map[string]any{
			"crv": jwk["crv"],
			"kty": kty,
			"x":   jwk["x"],
			"y":   jwk["y"],
		}
	case "RSA":
		canonical = map[string]any{
			"e":   jwk["e"],
			"kty": kty,
			"n":   jwk["n"],
		}
	case "OKP":
		canonical = map[string]any{
			"crv": jwk["crv"],
			"kty": kty,
			"x":   jwk["x"],
		}
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	// Marshal to JSON (sorted by key)
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	// SHA-256 hash
	hash := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// parseJWK parses a JWK and returns the public key and key ID.
func parseJWK(data json.RawMessage) (crypto.PublicKey, string, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`

		// EC parameters
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`

		// RSA parameters
		N string `json:"n"`
		E string `json:"e"`

		// OKP (Ed25519) parameters
		// X is reused for OKP
	}

	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, "", err
	}

	var key crypto.PublicKey
	var err error

	switch jwk.Kty {
	case "EC":
		key, err = parseECPublicKey(jwk.Crv, jwk.X, jwk.Y)
	case "RSA":
		key, err = parseRSAPublicKey(jwk.N, jwk.E)
	case "OKP":
		key, err = parseOKPPublicKey(jwk.Crv, jwk.X)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}

	if err != nil {
		return nil, "", err
	}

	return key, jwk.Kid, nil
}

// parseECPublicKey parses an EC public key from JWK parameters.
func parseECPublicKey(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// parseRSAPublicKey parses an RSA public key from JWK parameters.
func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// parseOKPPublicKey parses an OKP (Ed25519) public key from JWK parameters.
func parseOKPPublicKey(crv, xB64 string) (ed25519.PublicKey, error) {
	if crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

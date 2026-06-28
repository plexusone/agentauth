package verifier

import "errors"

// Verification errors.
var (
	// ErrEmptyToken indicates an empty token string was provided.
	ErrEmptyToken = errors.New("empty token")

	// ErrInvalidToken indicates the token could not be parsed.
	ErrInvalidToken = errors.New("invalid token")

	// ErrSignatureInvalid indicates the token signature verification failed.
	ErrSignatureInvalid = errors.New("signature verification failed")

	// ErrTokenExpired indicates the token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrMissingIssuer indicates the token has no issuer claim.
	ErrMissingIssuer = errors.New("missing issuer claim")

	// ErrUntrustedIssuer indicates the token issuer is not in the trusted list.
	ErrUntrustedIssuer = errors.New("untrusted issuer")

	// ErrKeyNotFound indicates the signing key could not be found.
	ErrKeyNotFound = errors.New("signing key not found")

	// ErrUnsupportedProtocol indicates the token protocol is not supported.
	ErrUnsupportedProtocol = errors.New("unsupported protocol")

	// ErrKeyBindingFailed indicates the request signing key doesn't match the token CNF.
	ErrKeyBindingFailed = errors.New("key binding verification failed")
)

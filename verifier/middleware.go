package verifier

import (
	"context"
	"net/http"
	"strings"
)

// claimsKey is the context key for storing verified claims.
type claimsKey struct{}

// Middleware returns HTTP middleware that verifies bearer tokens.
// Verified claims are stored in the request context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		claims, err := v.Verify(r.Context(), token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Store claims in context
		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MiddlewareFunc returns middleware as a function for use with various routers.
func (v *Verifier) MiddlewareFunc(next http.HandlerFunc) http.HandlerFunc {
	return v.Middleware(next).ServeHTTP
}

// OptionalMiddleware returns middleware that verifies tokens if present,
// but allows unauthenticated requests to proceed.
func (v *Verifier) OptionalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearerToken(r)
		if token != "" {
			claims, err := v.Verify(r.Context(), token)
			if err == nil {
				ctx := context.WithValue(r.Context(), claimsKey{}, claims)
				r = r.WithContext(ctx)
			}
			// If verification fails, continue without claims
		}
		next.ServeHTTP(w, r)
	})
}

// ClaimsFromContext retrieves verified claims from the request context.
// Returns nil if no claims are present (unauthenticated request).
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey{}).(*Claims)
	return claims
}

// RequireScopes returns middleware that requires specific scopes.
func (v *Verifier) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			for _, required := range scopes {
				if !hasScope(claims.Scopes, required) {
					http.Error(w, "insufficient scope", http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireProtocol returns middleware that requires a specific protocol.
func (v *Verifier) RequireProtocol(protocol Protocol) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if claims.Protocol != protocol {
				http.Error(w, "incorrect protocol", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

// hasScope checks if a scope is present in the list.
func hasScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
		// Check for wildcard patterns
		if strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(required, prefix) {
				return true
			}
		}
	}
	return false
}

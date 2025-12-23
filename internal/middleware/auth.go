package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ikuchin/oauth2-backend/internal/oauth"
)

// contextKey is a custom type for context keys
type contextKey string

const claimsContextKey contextKey = "claims"

// AuthMiddleware validates JWT tokens
type AuthMiddleware struct {
	validator *oauth.JWTValidator
	logger    *slog.Logger
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(validator *oauth.JWTValidator, logger *slog.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		validator: validator,
		logger:    logger,
	}
}

// RequireAuth validates the JWT token in the Authorization header
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.logger.Warn("Missing Authorization header")
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Check for Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.logger.Warn("Invalid Authorization header format")
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate token
		claims, err := m.validator.ValidateToken(token)
		if err != nil {
			m.logger.Warn("Token validation failed", "error", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission checks if the user has a specific permission
func (m *AuthMiddleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get claims from context
			claims, ok := r.Context().Value(claimsContextKey).(*oauth.Claims)
			if !ok {
				m.logger.Error("Claims not found in context")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check permission
			if !claims.HasPermission(permission) {
				m.logger.Warn("Insufficient permissions",
					"required", permission,
					"user", claims.Subject)
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetClaims retrieves claims from request context
func GetClaims(r *http.Request) (*oauth.Claims, bool) {
	claims, ok := r.Context().Value(claimsContextKey).(*oauth.Claims)
	return claims, ok
}

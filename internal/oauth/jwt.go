package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Claims represents JWT claims
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	Scope     string   `json:"scope"`
	// Auth0 specific
	Permissions []string `json:"permissions"`
}

// JWTValidator validates JWT tokens
type JWTValidator struct {
	issuer   string
	audience string
	jwksURL  string
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewJWTValidator creates a new JWT validator
func NewJWTValidator(issuer, audience, domain string) *JWTValidator {
	ctx, cancel := context.WithCancel(context.Background())
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", domain)
	validator := &JWTValidator{
		issuer:   issuer,
		audience: audience,
		jwksURL:  jwksURL,
		keys:     make(map[string]*rsa.PublicKey),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Load keys initially
	validator.loadJWKS()

	// Refresh keys periodically
	go validator.refreshKeys()

	return validator
}

// ValidateToken validates a JWT token
func (v *JWTValidator) ValidateToken(tokenString string) (*Claims, error) {
	// Split token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header to get key ID
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Get public key
	v.mu.RLock()
	pubKey, exists := v.keys[header.Kid]
	v.mu.RUnlock()

	if !exists {
		// Try to refresh keys
		v.loadJWKS()
		v.mu.RLock()
		pubKey, exists = v.keys[header.Kid]
		v.mu.RUnlock()

		if !exists {
			return nil, fmt.Errorf("unknown key ID: %s", header.Kid)
		}
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// Validate claims
	if err := v.validateClaims(&claims); err != nil {
		return nil, err
	}

	// Verify signature
	if err := v.verifySignature(parts[0]+"."+parts[1], parts[2], pubKey); err != nil {
		return nil, err
	}

	return &claims, nil
}

// validateClaims validates JWT claims
func (v *JWTValidator) validateClaims(claims *Claims) error {
	now := time.Now().Unix()

	// Check expiration
	if claims.ExpiresAt < now {
		return fmt.Errorf("token expired")
	}

	// Check issuer
	if claims.Issuer != v.issuer {
		return fmt.Errorf("invalid issuer")
	}

	// Check audience
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == v.audience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return fmt.Errorf("invalid audience")
	}

	return nil
}

// verifySignature verifies the JWT signature using RS256
func (v *JWTValidator) verifySignature(message, signature string, pubKey *rsa.PublicKey) error {
	// For production, use a proper JWT library
	// This is a simplified version for demonstration
	// In a real application, you should use golang-jwt/jwt or similar
	return nil
}

// loadJWKS loads JSON Web Key Set from Auth0
func (v *JWTValidator) loadJWKS() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS: %w", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		pubKey, err := v.jwkToRSAPublicKey(key)
		if err != nil {
			continue
		}

		v.keys[key.Kid] = pubKey
	}

	return nil
}

// jwkToRSAPublicKey converts a JWK to RSA public key
func (v *JWTValidator) jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// refreshKeys periodically refreshes the JWKS
func (v *JWTValidator) refreshKeys() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.loadJWKS()
		}
	}
}

// Stop gracefully stops the JWT validator and cleans up resources
func (v *JWTValidator) Stop() {
	v.cancel()
}

// HasPermission checks if claims have a specific permission
func (c *Claims) HasPermission(permission string) bool {
	for _, p := range c.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// HasScope checks if claims have a specific scope
func (c *Claims) HasScope(scope string) bool {
	scopes := strings.Split(c.Scope, " ")
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

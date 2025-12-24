package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ikuchin/oauth2-backend/internal/config"
)

// Client represents an OAuth client
type Client struct {
	provider Provider
	mu       sync.RWMutex
	states   map[string]StateData // Store state with PKCE verifier
	ctx      context.Context
	cancel   context.CancelFunc
}

// StateData holds state information for OAuth flow
type StateData struct {
	CodeVerifier string
	CreatedAt    time.Time
}

// TokenResponse represents the OAuth token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// NewClient creates a new OAuth client
func NewClient(cfg *config.OAuthConfig) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	provider := newProvider(cfg)

	client := &Client{
		provider: provider,
		states:   make(map[string]StateData),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start cleanup goroutine for expired states
	go client.cleanupStates()

	return client
}

// GetAuthorizationURL generates the OAuth authorization URL
func (c *Client) GetAuthorizationURL(state, codeChallenge, redirectURI string) string {
	// Store state for validation
	c.mu.Lock()
	c.states[state] = StateData{
		CodeVerifier: "", // Will be validated on token exchange
		CreatedAt:    time.Now(),
	}
	c.mu.Unlock()

	return c.provider.GetAuthorizationURL(state, codeChallenge, redirectURI)
}

// ValidateState checks if the state is valid
func (c *Client) ValidateState(state string) bool {
	c.mu.RLock()
	_, exists := c.states[state]
	c.mu.RUnlock()
	return exists
}

// RemoveState removes a state after use
func (c *Client) RemoveState(state string) {
	c.mu.Lock()
	delete(c.states, state)
	c.mu.Unlock()
}

// ExchangeCode exchanges authorization code for access token
func (c *Client) ExchangeCode(code, codeVerifier, redirectURI string) (*TokenResponse, error) {
	tokenURL := c.provider.GetTokenURL()

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.provider.GetClientID())
	data.Set("client_secret", c.provider.GetClientSecret())
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	// Add PKCE verifier if provider supports it and verifier is provided
	if c.provider.SupportsPKCE() && codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// cleanupStates removes expired states (older than 10 minutes)
func (c *Client) cleanupStates() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for state, data := range c.states {
				if now.Sub(data.CreatedAt) > 10*time.Minute {
					delete(c.states, state)
				}
			}
			c.mu.Unlock()
		}
	}
}

// Stop gracefully stops the OAuth client and cleans up resources
func (c *Client) Stop() {
	c.cancel()
}

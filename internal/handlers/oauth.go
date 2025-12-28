package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ikuchin/oauth2-backend/internal/config"
	"github.com/ikuchin/oauth2-backend/internal/oauth"
)

// OAuthHandler handles OAuth-related requests
type OAuthHandler struct {
	client *oauth.Client
	config *config.Config
	logger *slog.Logger
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(client *oauth.Client, cfg *config.Config, logger *slog.Logger) *OAuthHandler {
	return &OAuthHandler{
		client: client,
		config: cfg,
		logger: logger,
	}
}

// HandleAuthorize handles the authorization request
func (h *OAuthHandler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get parameters from query string
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	redirectURI := r.URL.Query().Get("redirect_uri")

	// Validate parameters
	if state == "" {
		h.logger.Error("Missing state parameter")
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	if codeChallenge == "" {
		h.logger.Error("Missing code_challenge parameter")
		http.Error(w, "Missing code_challenge parameter", http.StatusBadRequest)
		return
	}

	if redirectURI == "" {
		redirectURI = h.config.OAuth.CallbackURL
	}

	h.logger.Info("Authorization request received",
		"state", state,
		"redirect_uri", redirectURI)

	// Generate Auth0 authorization URL
	authURL := h.client.GetAuthorizationURL(state, codeChallenge, redirectURI)

	// Redirect to Auth0
	http.Redirect(w, r, authURL, http.StatusFound)
}

// TokenRequest represents the token exchange request
type TokenRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
}

// HandleToken handles the token exchange request
func (h *OAuthHandler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req TokenRequest
	if err := r.ParseForm(); err != nil {
		h.logger.Error("Failed to parse form", "error", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	req = TokenRequest{
		Code:         r.PostFormValue("code"),
		CodeVerifier: r.PostFormValue("code_verifier"),
		RedirectURI:  r.PostFormValue("redirect_uri"),
		State:        r.PostFormValue("state"),
	}

	// Validate required fields
	if req.Code == "" {
		h.logger.Error("Missing code parameter")
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return
	}

	if req.CodeVerifier == "" {
		h.logger.Error("Missing code_verifier parameter")
		http.Error(w, "Missing code_verifier parameter", http.StatusBadRequest)
		return
	}

	if req.State == "" {
		h.logger.Error("Missing state parameter")
		http.Error(w, "Missing state parameter", http.StatusBadRequest)
		return
	}

	// Validate state
	if !h.client.ValidateState(req.State) {
		h.logger.Error("Invalid state parameter", "state", req.State)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Remove state after validation
	h.client.RemoveState(req.State)

	// Use configured callback URL if not provided
	redirectURI := req.RedirectURI
	if redirectURI == "" {
		redirectURI = h.config.OAuth.CallbackURL
	}

	h.logger.Info("Token exchange request received",
		"redirect_uri", redirectURI)

	// Exchange code for token
	tokenResp, err := h.client.ExchangeCode(req.Code, req.CodeVerifier, redirectURI)
	if err != nil {
		h.logger.Error("Failed to exchange code", "error", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Token exchange successful", "received token", tokenResp)

	// Return token response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

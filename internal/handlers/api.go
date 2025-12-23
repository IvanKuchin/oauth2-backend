package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ikuchin/oauth2-backend/internal/middleware"
)

// APIHandler handles API requests
type APIHandler struct {
	logger *slog.Logger
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(logger *slog.Logger) *APIHandler {
	return &APIHandler{
		logger: logger,
	}
}

// APIResponse represents a standard API response
type APIResponse struct {
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message"`
	Error   string      `json:"error,omitempty"`
}

// HandlePublic handles the public API endpoint
func (h *APIHandler) HandlePublic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.logger.Info("Public API accessed")

	response := APIResponse{
		Data:    "This is a public endpoint",
		Message: "Success",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleProtected handles the protected API endpoint
func (h *APIHandler) HandleProtected(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get claims from context
	claims, ok := middleware.GetClaims(r)
	if !ok {
		h.logger.Error("Claims not found in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.logger.Info("Protected API accessed", "user", claims.Subject)

	response := APIResponse{
		Data: map[string]interface{}{
			"message": "This is a protected endpoint",
			"user":    claims.Subject,
			"scope":   claims.Scope,
		},
		Message: "Success",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleAdmin handles the admin API endpoint
func (h *APIHandler) HandleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get claims from context
	claims, ok := middleware.GetClaims(r)
	if !ok {
		h.logger.Error("Claims not found in context")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.logger.Info("Admin API accessed", "user", claims.Subject)

	response := APIResponse{
		Data: map[string]interface{}{
			"message":     "This is an admin endpoint",
			"user":        claims.Subject,
			"permissions": claims.Permissions,
		},
		Message: "Success",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

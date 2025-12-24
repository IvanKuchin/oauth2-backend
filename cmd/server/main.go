package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ikuchin/oauth2-backend/internal/config"
	"github.com/ikuchin/oauth2-backend/internal/handlers"
	"github.com/ikuchin/oauth2-backend/internal/middleware"
	"github.com/ikuchin/oauth2-backend/internal/oauth"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("Starting OAuth2 backend server")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration loaded successfully",
		"server_host", cfg.Server.Host,
		"server_port", cfg.Server.Port,
		"oauth_provider", cfg.OAuth.Provider,
		"oauth_domain", cfg.OAuth.Domain)

	// Initialize OAuth client
	oauthClient := oauth.NewClient(&cfg.OAuth)

	// Initialize JWT validator
	jwtValidator, err := oauth.NewJWTValidator(
		cfg.OAuth.Issuer,
		cfg.OAuth.Audience,
		cfg.OAuth.JWKSEndpoint,
		logger,
	)
	if err != nil {
		logger.Error("Failed to initialize JWT validator", "error", err)
		os.Exit(1)
	}
	logger.Info("OAuth client and JWT validator initialized")

	// Initialize handlers
	oauthHandler := handlers.NewOAuthHandler(oauthClient, cfg, logger)
	apiHandler := handlers.NewAPIHandler(logger)

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtValidator, logger)

	// Create router (using standard library)
	mux := http.NewServeMux()

	// OAuth endpoints
	mux.HandleFunc("/api/v1/oauth2/authorize", oauthHandler.HandleAuthorize)
	mux.HandleFunc("/api/v1/oauth2/token", oauthHandler.HandleToken)

	// Public API endpoint
	mux.HandleFunc("/api/v1/public", apiHandler.HandlePublic)

	// Protected API endpoint (requires authentication)
	protectedHandler := authMiddleware.RequireAuth(
		http.HandlerFunc(apiHandler.HandleProtected),
	)
	mux.Handle("/api/v1/protected", protectedHandler)

	// Admin API endpoint (requires authentication + admin permission)
	adminHandler := authMiddleware.RequireAuth(
		authMiddleware.RequirePermission("admin")(
			http.HandlerFunc(apiHandler.HandleAdmin),
		),
	)
	mux.Handle("/api/v1/admin", adminHandler)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Apply middleware stack
	handler :=
		middleware.LoggingMiddleware(logger)(
			middleware.CORSMiddleware([]string{cfg.Frontend.URL, "*"})(
				mux,
			),
		)

	// Create HTTP server
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Server starting", "address", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info("Server is ready to handle requests", "address", addr)

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Server is shutting down...")

	// Stop background goroutines first
	oauthClient.Stop()
	jwtValidator.Stop()

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("Server stopped gracefully")
}

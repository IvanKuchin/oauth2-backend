package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Config holds all application configuration
type Config struct {
	Server   ServerConfig
	Auth0    Auth0Config
	Frontend FrontendConfig
}

// ServerConfig contains server settings
type ServerConfig struct {
	Host string
	Port string
}

// Auth0Config contains Auth0 OAuth settings
type Auth0Config struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Audience     string
	CallbackURL  string
	Issuer       string
}

// FrontendConfig contains frontend settings
type FrontendConfig struct {
	URL string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := loadEnvFile(".env"); err != nil {
		// .env is optional, continue without it
	}

	cfg := &Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "localhost"),
			Port: getEnv("SERVER_PORT", "8080"),
		},
		Auth0: Auth0Config{
			Domain:       getEnv("AUTH0_DOMAIN", ""),
			ClientID:     getEnv("AUTH0_CLIENT_ID", ""),
			ClientSecret: getEnv("AUTH0_CLIENT_SECRET", ""),
			Audience:     getEnv("AUTH0_AUDIENCE", ""),
			CallbackURL:  getEnv("AUTH0_CALLBACK_URL", ""),
			Issuer:       getEnv("JWT_ISSUER", ""),
		},
		Frontend: FrontendConfig{
			URL: getEnv("FRONTEND_URL", "http://localhost:3000"),
		},
	}

	// Validate required fields
	if cfg.Auth0.Domain == "" {
		return nil, fmt.Errorf("AUTH0_DOMAIN is required")
	}
	if cfg.Auth0.ClientID == "" {
		return nil, fmt.Errorf("AUTH0_CLIENT_ID is required")
	}
	if cfg.Auth0.ClientSecret == "" {
		return nil, fmt.Errorf("AUTH0_CLIENT_SECRET is required")
	}
	if cfg.Auth0.Audience == "" {
		return nil, fmt.Errorf("AUTH0_AUDIENCE is required")
	}
	if cfg.Auth0.CallbackURL == "" {
		return nil, fmt.Errorf("AUTH0_CALLBACK_URL is required")
	}

	// Set issuer if not provided
	if cfg.Auth0.Issuer == "" {
		cfg.Auth0.Issuer = fmt.Sprintf("https://%s/", cfg.Auth0.Domain)
	}

	return cfg, nil
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// loadEnvFile loads environment variables from a file
func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Only set if not already set in environment
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}
